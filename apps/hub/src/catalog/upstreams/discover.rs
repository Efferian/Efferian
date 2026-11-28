use std::collections::BTreeSet;
use std::io::{self, Write};
use std::time::Duration;

use axum::{Json, extract::State};
use efferian_authz::authorize_admin;
use efferian_protocol::{
    AccountId, AccountKind, AccountSecretPayload, AccountVisibility, DiscoveredUpstreamTool,
    EgressUrlMode, PrincipalId, ProblemDetails, ToolAnnotations, UpstreamId, error_codes as code,
    validate_egress_url, validate_http_headers_no_auth_collision, validate_slug,
};
use http::StatusCode;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::catalog::accounts::{
    AccountMetadata, account_by_id, account_by_slug, bound_account_id, load_account_secret,
    open_account,
};
use crate::http::{ApiCaller, ApiError, ApiJson, ApiPath, ApiResult, AppState};
use crate::storage::WriteTxError;
use crate::upstream_dispatch::{DiscoverUpstream, UpstreamCredential, UpstreamDispatchError};
use crate::vault::auth::refresh_api;

use super::{UpstreamConfig, read_upstream_config, upstream_id};

const MAX_DISCOVERED_TOOLS: usize = 512;
const MAX_DISCOVERY_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema)]
pub(crate) struct DiscoveredToolSummary {
    pub tool_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub input_schema: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<ToolAnnotations>,
}

impl DiscoveredToolSummary {
    pub(crate) fn into_discovered(self, upstream_id: UpstreamId) -> DiscoveredUpstreamTool {
        DiscoveredUpstreamTool {
            upstream_id,
            tool_name: self.tool_name,
            description: self.description,
            input_schema: self.input_schema,
            annotations: self.annotations,
        }
    }
}

#[derive(Deserialize, ToSchema)]
#[serde(untagged)]
enum DiscoverSelection {
    ById(DiscoverById),
    BySlug(DiscoverBySlug),
    Bound(DiscoverBound),
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct DiscoverById {
    account_id: AccountId,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct DiscoverBySlug {
    account_slug: String,
    visibility: Option<AccountVisibility>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
struct DiscoverBound {}

#[derive(Serialize, ToSchema)]
struct DiscoverResponse {
    upstream_id: UpstreamId,
    #[schema(minimum = 1)]
    config_version: u64,
    discovered_at_ms: i64,
    discovered_tool_count: usize,
    tools: Vec<DiscoveredToolSummary>,
}

#[derive(PartialEq, Eq)]
enum SelectedAccount {
    Anonymous,
    Missing,
    Match(AccountMetadata),
}

impl DiscoverSelection {
    fn validate(&self) -> ApiResult<()> {
        if let Self::BySlug(request) = self {
            validate_slug(&request.account_slug).map_err(|_| ApiError::bad_input())?;
        }
        Ok(())
    }

    fn account(
        &self,
        conn: &Connection,
        principal: PrincipalId,
        upstream: UpstreamId,
    ) -> rusqlite::Result<SelectedAccount> {
        let account = match self {
            Self::ById(request) => account_by_id(conn, request.account_id)?,
            Self::BySlug(request) => account_by_slug(
                conn,
                &request.account_slug,
                request.visibility.unwrap_or(AccountVisibility::Private),
                principal,
            )?,
            Self::Bound(DiscoverBound {}) => {
                let Some(account_id) = bound_account_id(conn, principal, upstream)? else {
                    return Ok(SelectedAccount::Anonymous);
                };
                account_by_id(conn, account_id)?
            }
        };
        Ok(account.map_or(SelectedAccount::Missing, SelectedAccount::Match))
    }
}

struct DiscoverySnapshot {
    upstream_id: UpstreamId,
    principal_id: PrincipalId,
    config: UpstreamConfig,
    discovered_at_ms: Option<i64>,
    account: Option<(AccountMetadata, Vec<u8>)>,
}

pub(super) fn route() -> OpenApiRouter<AppState> {
    OpenApiRouter::new().routes(routes!(discover))
}

#[utoipa::path(
    post,
    path = "/v1/upstreams/{slug}/discover",
    tag = "Upstreams",
    params(("slug" = String, Path, description = "Upstream slug")),
    request_body = DiscoverSelection,
    responses(
        (status = 200, description = "Refreshed discovery cache", body = DiscoverResponse),
        (status = 400, description = "Invalid account selection or conflicting HTTP headers", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Upstream or account does not exist", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Upstream disabled or discovery dependencies changed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 502, description = "Upstream rejected authentication or discovery failed", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 504, description = "Upstream discovery timed out", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn discover(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
    ApiJson(selection): ApiJson<DiscoverSelection>,
) -> ApiResult<Json<DiscoverResponse>> {
    validate_slug(&slug).map_err(|_| ApiError::bad_input())?;
    selection.validate()?;
    let credential = caller.credential.clone();
    let clock = state.clock;
    let (starting, selection) = state
        .storage
        .read_snapshot(move |conn| -> ApiResult<_> {
            let ctx = refresh_api(conn, &credential, clock.wall_now_ms())?;
            authorize_admin(&ctx)?;
            Ok((
                discovery_snapshot(conn, &selection, ctx.caller.principal_id, &slug)?,
                selection,
            ))
        })
        .await?;

    let DiscoverySnapshot {
        upstream_id,
        principal_id,
        config,
        discovered_at_ms,
        account,
    } = starting;
    let (account, auth) = match account {
        Some((metadata, envelope)) => {
            let AccountSecretPayload::HttpAuth { auth: secret } =
                open_account(&state.vault, &metadata, &envelope)?
            else {
                return Err(ApiError::internal());
            };
            let credential = UpstreamCredential {
                account_id: metadata.account_id,
                secret_version: metadata.secret_version,
                secret,
            };
            (SelectedAccount::Match(metadata), Some(credential))
        }
        None => (SelectedAccount::Anonymous, None),
    };

    validate_egress_url(
        &config.url,
        state.egress.policy(),
        EgressUrlMode::RequireHttpsByDefault,
    )
    .map_err(|_| ApiError::bad_input())?;
    validate_http_headers_no_auth_collision(
        &config.headers,
        auth.as_ref().map(|auth| auth.secret.header_name()),
    )
    .map_err(|_| ApiError::bad_input())?;

    let config_version = config.config_version;
    let request = DiscoverUpstream {
        upstream_id,
        config_version,
        principal_id,
        url: config.url,
        headers: config.headers,
        auth,
    };
    let discovered = tokio::time::timeout(
        Duration::from_millis(state.config.upstream_hard_timeout_ms),
        state.upstream.discover(request),
    )
    .await
    .map_err(|_| dispatch_error(UpstreamDispatchError::TimedOut))?
    .map_err(dispatch_error)?;
    let (tools, json) = prepare_discovery(upstream_id, discovered)?;

    let discovered_at_ms = state
        .storage
        .execute_work(json.len(), move |tx| {
            let ctx = refresh_api(tx.conn(), &caller.credential, tx.now_ms())?;
            authorize_admin(&ctx)?;
            if selection.account(tx.conn(), ctx.caller.principal_id, upstream_id)? != account {
                return Err(discovery_conflict().into());
            }
            // Concurrent refreshes may share the same wall-clock tick. A
            // successful refresh must always consume its expected generation.
            let now = tx.now_ms();
            let next = match discovered_at_ms {
                Some(previous) if previous >= now => {
                    previous
                        .checked_add(1)
                        .ok_or(WriteTxError::InvalidDatabase(
                            "upstream discovery timestamp overflow",
                        ))?
                }
                _ => now,
            };
            let changed = tx
                .conn()
                .prepare_cached(
                    "UPDATE upstreams SET discovered_tools_json = ?4, discovered_at_ms = ?5
                 WHERE upstream_id = ?1 AND config_version = ?2 AND discovered_at_ms IS ?3
                   AND disabled_at_ms IS NULL",
                )?
                .execute(params![
                    upstream_id.to_string(),
                    config_version,
                    discovered_at_ms,
                    json,
                    next
                ])?;
            if changed == 0 {
                return Err(discovery_conflict().into());
            }
            Ok::<_, WriteTxError<ApiError>>(next)
        })
        .await?;
    Ok(Json(DiscoverResponse {
        upstream_id,
        config_version,
        discovered_at_ms,
        discovered_tool_count: tools.len(),
        tools,
    }))
}

fn discovery_snapshot(
    conn: &Connection,
    selection: &DiscoverSelection,
    principal: PrincipalId,
    slug: &str,
) -> ApiResult<DiscoverySnapshot> {
    let upstream_id = upstream_id(conn, slug)?.ok_or_else(ApiError::not_found)?;
    let config = read_upstream_config(conn, upstream_id)?.ok_or_else(ApiError::not_found)?;
    if config.disabled_at_ms.is_some() {
        return Err(ApiError::conflict(code::TOOL_DISABLED));
    }
    let discovered_at_ms = conn
        .prepare_cached("SELECT discovered_at_ms FROM upstreams WHERE upstream_id = ?1")?
        .query_row([upstream_id.to_string()], |row| row.get(0))?;
    let account = match selection.account(conn, principal, upstream_id)? {
        SelectedAccount::Anonymous => None,
        SelectedAccount::Missing => return Err(ApiError::not_found()),
        SelectedAccount::Match(metadata) => {
            if metadata.kind != AccountKind::HttpAuth || metadata.upstream_id != Some(upstream_id) {
                return Err(ApiError::bad_input());
            }
            let envelope = load_account_secret(conn, &metadata)?;
            Some((metadata, envelope))
        }
    };
    Ok(DiscoverySnapshot {
        upstream_id,
        principal_id: principal,
        config,
        discovered_at_ms,
        account,
    })
}

fn discovery_conflict() -> ApiError {
    ApiError::conflict(code::RESOURCE_IN_USE)
}

fn dispatch_error(error: UpstreamDispatchError) -> ApiError {
    match error {
        UpstreamDispatchError::TimedOut => {
            ApiError::new(StatusCode::GATEWAY_TIMEOUT, code::UPSTREAM_TIMEOUT).retryable()
        }
        UpstreamDispatchError::AuthFailed => {
            ApiError::new(StatusCode::BAD_GATEWAY, code::UPSTREAM_AUTH_FAILED)
        }
        UpstreamDispatchError::InvalidResponse => {
            ApiError::new(StatusCode::BAD_GATEWAY, code::UPSTREAM_INVALID_RESPONSE)
        }
        UpstreamDispatchError::Unavailable | UpstreamDispatchError::Disconnected => {
            ApiError::new(StatusCode::BAD_GATEWAY, code::UPSTREAM_UNAVAILABLE).retryable()
        }
    }
}

fn prepare_discovery(
    upstream_id: UpstreamId,
    discovered: Vec<DiscoveredUpstreamTool>,
) -> ApiResult<(Vec<DiscoveredToolSummary>, String)> {
    let invalid = || dispatch_error(UpstreamDispatchError::InvalidResponse);
    if discovered.len() > MAX_DISCOVERED_TOOLS {
        return Err(invalid());
    }
    let mut names = BTreeSet::new();
    for tool in &discovered {
        if tool.upstream_id != upstream_id
            || tool.tool_name.trim().is_empty()
            || tool.tool_name.bytes().any(|byte| byte.is_ascii_control())
            || !tool.input_schema.is_object()
            || !names.insert(tool.tool_name.as_str())
        {
            return Err(invalid());
        }
    }
    let tools = discovered
        .into_iter()
        .map(|tool| DiscoveredToolSummary {
            tool_name: tool.tool_name,
            description: tool.description,
            input_schema: tool.input_schema,
            annotations: tool.annotations,
        })
        .collect::<Vec<_>>();
    let mut json = DiscoveryJson(Vec::new());
    serde_json::to_writer(&mut json, &tools).map_err(|_| invalid())?;
    Ok((
        tools,
        String::from_utf8(json.0).map_err(|_| ApiError::internal())?,
    ))
}

struct DiscoveryJson(Vec<u8>);

impl Write for DiscoveryJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_DISCOVERY_BYTES - self.0.len() {
            return Err(io::Error::other("upstream discovery cache too large"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
