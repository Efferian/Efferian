//! Authoring and immutable revisions for individual tools.

use axum::{Json, extract::State};
use efferian_authz::authorize_admin;
use efferian_protocol::{
    AccountId, AccountKind, AccountVisibility, DiscoveredUpstreamTool, NodeId, ProblemDetails,
    TargetSelector, ToolDefinition, ToolId, ToolKind, ToolRevisionDefinition, ToolSpec, UpstreamId,
    error_codes as code, validate_slug,
};
use http::StatusCode;
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::Serialize;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::http::{
    ApiCaller, ApiError, ApiJson, ApiPath, ApiQuery, ApiResult, AppState, EmptyBody, Page,
    PageQuery, RouteGroups,
};
use crate::storage::{PriorityKind, WriteTx, WriteTxError, id, json, scalar, scalar_text};
use crate::vault::auth::{AuthenticatedApi, refresh_api};

use super::Outcome;
use super::accounts::{AccountMetadata, account_by_id};
use super::references::tool_in_use;
use super::schema;
use super::upstreams::{read_upstream_by_id, upstream_discovery_matches};

type WriteResult<T> = Result<T, WriteTxError<ApiError>>;

pub(super) fn routes() -> RouteGroups {
    RouteGroups {
        application: OpenApiRouter::new()
            .routes(routes!(list))
            .routes(routes!(get, put, delete))
            .routes(routes!(enable)),
        control: OpenApiRouter::new().routes(routes!(disable)),
        ..RouteGroups::default()
    }
}

#[derive(Clone, Serialize, ToSchema)]
pub(crate) struct ToolSummary {
    pub(crate) tool_id: ToolId,
    pub(crate) slug: String,
    pub(crate) kind: ToolKind,
    #[schema(minimum = 1)]
    pub(crate) current_version: u64,
    pub(crate) input_schema_sha256: String,
    pub(crate) disabled_at_ms: Option<i64>,
    pub(crate) created_at_ms: i64,
    pub(crate) updated_at_ms: i64,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ToolDetail {
    #[serde(flatten)]
    pub(crate) summary: ToolSummary,
    /// Upstream tools expose the effective revision annotations and omit the discovery-supplied input schema.
    pub(crate) definition: ToolDefinition,
}

impl ToolDetail {
    fn authoring_view(mut self) -> Self {
        if self.summary.kind == ToolKind::UpstreamRef {
            self.definition.input_schema = None;
        }
        self
    }
}

pub(crate) struct ToolRevision {
    pub(crate) tool_id: ToolId,
    pub(crate) version: u64,
    pub(crate) disabled_at_ms: Option<i64>,
    pub(crate) input_schema_sha256: String,
    pub(crate) definition: ToolDefinition,
}

#[derive(Serialize, ToSchema)]
struct ToolPutResponse {
    outcome: Outcome,
    tool: ToolDetail,
}

#[utoipa::path(
    get, path = "/v1/tools", tag = "Tools",
    params(
        ("limit" = Option<u16>, Query, minimum = 1, maximum = 200, description = "Page size (default 50)"),
        ("cursor" = Option<ToolId>, Query, description = "Return items after this tool ID")
    ),
    responses((status = 200, description = "Tools page", body = Page<ToolSummary>)),
    security(("api_bearer" = []))
)]
async fn list(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiQuery(query): ApiQuery<PageQuery<ToolId>>,
) -> ApiResult<Json<Page<ToolSummary>>> {
    let limit = query.checked_limit()?;
    let cursor = query.cursor.map(|value| value.to_string());
    let clock = state.clock;
    let page = state
        .storage
        .read_snapshot(move |conn| -> ApiResult<_> {
            authorize_admin(&refresh_api(conn, &caller.credential, clock.wall_now_ms())?)?;
            let mut stmt = conn.prepare_cached(
                "SELECT t.tool_id, t.slug, t.kind, t.current_version, r.input_schema_sha256,
                        t.disabled_at_ms, t.created_at_ms, t.updated_at_ms
                 FROM tools t LEFT JOIN tool_revisions r
                   ON r.tool_id = t.tool_id AND r.version = t.current_version
                 WHERE t.tool_id COLLATE BINARY > ?1 ORDER BY t.tool_id COLLATE BINARY LIMIT ?2",
            )?;
            let rows = stmt
                .query_map(
                    params![cursor.as_deref().unwrap_or(""), limit + 1],
                    read_summary,
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(Page::from_rows(rows, limit, |tool| tool.tool_id))
        })
        .await?;
    Ok(Json(page))
}

#[utoipa::path(
    get, path = "/v1/tools/{slug}", tag = "Tools",
    params(("slug" = String, Path, description = "Tool slug")),
    responses(
        (status = 200, description = "Tool and its current definition", body = ToolDetail),
        (status = 404, description = "Tool does not exist", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn get(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
) -> ApiResult<Json<ToolDetail>> {
    validate_slug(&slug).map_err(|_| ApiError::bad_input())?;
    let clock = state.clock;
    let tool = state
        .storage
        .read_snapshot(move |conn| -> ApiResult<_> {
            authorize_admin(&refresh_api(conn, &caller.credential, clock.wall_now_ms())?)?;
            read_tool(conn, &slug)?.ok_or_else(ApiError::not_found)
        })
        .await?;
    Ok(Json(tool.authoring_view()))
}

#[utoipa::path(
    put, path = "/v1/tools/{slug}", tag = "Tools",
    params(("slug" = String, Path, description = "Tool slug")),
    request_body = ToolDefinition,
    responses(
        (status = 200, description = "Tool updated or unchanged", body = ToolPutResponse),
        (status = 201, description = "Tool created", body = ToolPutResponse),
        (status = 400, description = "Invalid definition, schema or dependency", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 404, description = "Referenced dependency does not exist", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Upstream discovery changed during the write", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn put(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
    ApiJson(request): ApiJson<ToolDefinition>,
) -> ApiResult<(StatusCode, Json<ToolPutResponse>)> {
    validate_slug(&slug).map_err(|_| ApiError::bad_input())?;
    let discovery = {
        let clock = state.clock.clone();
        let credential = caller.credential.clone();
        let requested = match &request.spec {
            ToolSpec::UpstreamRef {
                upstream_id,
                upstream_tool_name,
                ..
            } => Some((*upstream_id, upstream_tool_name.clone())),
            _ => None,
        };
        state
            .storage
            .read_snapshot(move |conn| -> ApiResult<_> {
                authorize_admin(&refresh_api(conn, &credential, clock.wall_now_ms())?)?;
                requested
                    .map(|(upstream_id, name)| read_discovered_tool(conn, upstream_id, &name))
                    .transpose()
            })
            .await?
    };
    let config = state.config;
    let policy = config.egress_policy().map_err(|_| ApiError::internal())?;
    let (revision, definition_json, discovery) = tokio::task::spawn_blocking(move || {
        let discovered = discovery.as_ref().map(|entry| &entry.tool);
        let revision = request
            .freeze_revision(
                discovered,
                config.max_runtime_ms,
                config.upstream_hard_timeout_ms,
                &policy,
            )
            .map_err(|_| ApiError::bad_input())?;
        let schema = revision
            .definition
            .input_schema
            .as_ref()
            .ok_or_else(ApiError::internal)?;
        schema::compile(schema).map_err(|_| ApiError::bad_input())?;
        let serialized =
            serde_json::to_string(&revision.definition).map_err(|_| ApiError::internal())?;
        let stamp = discovery.map(|entry| entry.stamp);
        Ok::<_, ApiError>((revision, serialized, stamp))
    })
    .await
    .map_err(|_| ApiError::internal())??;
    let bytes = definition_json.len() + slug.len();
    let new_id = ToolId::new();
    let result = state
        .storage
        .execute_work(bytes, move |tx| {
            let ctx = refresh_api(tx.conn(), &caller.credential, tx.now_ms())?;
            authorize_admin(&ctx)?;
            if let Some(discovery) = discovery
                && !upstream_discovery_matches(
                    tx.conn(),
                    discovery.upstream_id,
                    discovery.config_version,
                    discovery.discovered_at_ms,
                )?
            {
                return Err(ApiError::conflict(code::RESOURCE_IN_USE).into());
            }
            validate_dependencies(tx.conn(), &revision.definition)?;
            upsert_tool(
                tx,
                &slug,
                new_id,
                ctx.caller.principal_id,
                revision,
                definition_json,
            )
        })
        .await?;
    Ok((result.outcome.status(), Json(result)))
}

#[utoipa::path(
    delete, path = "/v1/tools/{slug}", tag = "Tools",
    params(("slug" = String, Path, description = "Tool slug")),
    responses(
        (status = 204, description = "Tool and its revisions deleted"),
        (status = 404, description = "Tool does not exist", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 409, description = "Tool still has a live reference", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn delete(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
    _: EmptyBody,
) -> ApiResult<StatusCode> {
    validate_slug(&slug).map_err(|_| ApiError::bad_input())?;
    state
        .storage
        .execute_work(slug.len(), move |tx| {
            authorize_admin(&refresh_api(tx.conn(), &caller.credential, tx.now_ms())?)?;
            let (tool, _) = tool_status(tx.conn(), &slug)?;
            if tool_in_use(tx.conn(), tool)? {
                return Err(ApiError::conflict(code::RESOURCE_IN_USE).into());
            }
            let tool = tool.to_string();
            tx.conn()
                .prepare_cached("DELETE FROM tool_revisions WHERE tool_id = ?1")?
                .execute([&tool])?;
            tx.conn()
                .prepare_cached("DELETE FROM tools WHERE tool_id = ?1")?
                .execute([&tool])?;
            Ok::<_, WriteTxError<ApiError>>(())
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post, path = "/v1/tools/{slug}/disable", tag = "Tools",
    params(("slug" = String, Path, description = "Tool slug")),
    responses(
        (status = 204, description = "Tool disabled"),
        (status = 404, description = "Tool does not exist", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn disable(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
    _: EmptyBody,
) -> ApiResult<StatusCode> {
    set_disabled(state, caller, slug, true).await
}

#[utoipa::path(
    post, path = "/v1/tools/{slug}/enable", tag = "Tools",
    params(("slug" = String, Path, description = "Tool slug")),
    responses(
        (status = 204, description = "Tool enabled"),
        (status = 404, description = "Tool does not exist", body = ProblemDetails, content_type = "application/problem+json")
    ),
    security(("api_bearer" = []))
)]
async fn enable(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(slug): ApiPath<String>,
    _: EmptyBody,
) -> ApiResult<StatusCode> {
    set_disabled(state, caller, slug, false).await
}

async fn set_disabled(
    state: AppState,
    caller: AuthenticatedApi,
    slug: String,
    disabled: bool,
) -> ApiResult<StatusCode> {
    validate_slug(&slug).map_err(|_| ApiError::bad_input())?;
    let bytes = slug.len();
    let update =
        move |tx: &mut WriteTx<'_>| -> WriteResult<()> {
            authorize_admin(&refresh_api(tx.conn(), &caller.credential, tx.now_ms())?)?;
            let (tool, disabled_at) = tool_status(tx.conn(), &slug)?;
            if disabled_at.is_some() != disabled {
                tx.conn().prepare_cached(
                "UPDATE tools SET disabled_at_ms = ?1, updated_at_ms = ?2 WHERE tool_id = ?3",
            )?.execute(params![disabled.then_some(tx.now_ms()), tx.now_ms(), tool.to_string()])?;
            }
            Ok(())
        };
    if disabled {
        state
            .storage
            .execute_priority(PriorityKind::DisableTool, update)
            .await?;
    } else {
        state.storage.execute_work(bytes, update).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

fn tool_status(conn: &Connection, slug: &str) -> ApiResult<(ToolId, Option<i64>)> {
    conn.prepare_cached("SELECT tool_id, disabled_at_ms FROM tools WHERE slug = ?1")?
        .query_row([slug], |row| Ok((id(row, 0)?, row.get(1)?)))
        .optional()?
        .ok_or_else(ApiError::not_found)
}

fn read_summary(row: &Row<'_>) -> rusqlite::Result<ToolSummary> {
    Ok(ToolSummary {
        tool_id: id(row, 0)?,
        slug: row.get(1)?,
        kind: scalar(row, 2)?,
        current_version: row.get(3)?,
        input_schema_sha256: row.get(4)?,
        disabled_at_ms: row.get(5)?,
        created_at_ms: row.get(6)?,
        updated_at_ms: row.get(7)?,
    })
}

pub(crate) fn read_tool(conn: &Connection, slug: &str) -> rusqlite::Result<Option<ToolDetail>> {
    conn.prepare_cached(
        "SELECT t.tool_id, t.slug, t.kind, t.current_version, r.input_schema_sha256,
                t.disabled_at_ms, t.created_at_ms, t.updated_at_ms, r.definition_json
         FROM tools t LEFT JOIN tool_revisions r
           ON r.tool_id = t.tool_id AND r.version = t.current_version WHERE t.slug = ?1",
    )?
    .query_row([slug], |row| {
        Ok(ToolDetail {
            summary: read_summary(row)?,
            definition: json(row, 8)?,
        })
    })
    .optional()
}

pub(crate) fn read_tool_revision(
    conn: &Connection,
    tool_id: ToolId,
    version: u64,
) -> rusqlite::Result<Option<ToolRevision>> {
    let Ok(version_i64) = i64::try_from(version) else {
        return Ok(None);
    };
    conn.prepare_cached(
        "SELECT t.disabled_at_ms, r.input_schema_sha256, r.definition_json
         FROM tool_revisions r JOIN tools t ON t.tool_id = r.tool_id
         WHERE r.tool_id = ?1 AND r.version = ?2",
    )?
    .query_row(params![tool_id.to_string(), version_i64], |row| {
        Ok(ToolRevision {
            tool_id,
            version,
            disabled_at_ms: row.get(0)?,
            input_schema_sha256: row.get(1)?,
            definition: json(row, 2)?,
        })
    })
    .optional()
}

struct DiscoverySnapshot {
    stamp: DiscoveryStamp,
    tool: DiscoveredUpstreamTool,
}

struct DiscoveryStamp {
    upstream_id: UpstreamId,
    config_version: u64,
    discovered_at_ms: Option<i64>,
}

fn read_discovered_tool(
    conn: &Connection,
    upstream_id: UpstreamId,
    name: &str,
) -> ApiResult<DiscoverySnapshot> {
    let upstream = read_upstream_by_id(conn, upstream_id)?.ok_or_else(ApiError::not_found)?;
    let tool = upstream
        .discovered_tools
        .into_iter()
        .find(|tool| tool.tool_name == name)
        .ok_or_else(ApiError::bad_input)?;
    Ok(DiscoverySnapshot {
        stamp: DiscoveryStamp {
            upstream_id,
            config_version: upstream.summary.config_version,
            discovered_at_ms: upstream.summary.discovered_at_ms,
        },
        tool: tool.into_discovered(upstream_id),
    })
}

#[derive(Clone, Copy)]
pub(crate) struct StaticAccount {
    pub(crate) account_id: AccountId,
    pub(crate) kind: AccountKind,
    pub(crate) upstream_id: Option<UpstreamId>,
}

impl StaticAccount {
    pub(crate) fn matches(self, account: &AccountMetadata) -> bool {
        account.account_id == self.account_id
            && account.visibility == AccountVisibility::Shared
            && account.kind == self.kind
            && account.upstream_id == self.upstream_id
    }
}

pub(crate) fn static_account(definition: &ToolDefinition) -> Option<StaticAccount> {
    let (account_id, kind, upstream_id) = match &definition.spec {
        ToolSpec::Command { account_id, .. } | ToolSpec::Script { account_id, .. } => {
            (*account_id, AccountKind::SecretKv, None)
        }
        ToolSpec::Http { account_id, .. } => (*account_id, AccountKind::HttpAuth, None),
        ToolSpec::Ssh { account_id, .. } => (*account_id, AccountKind::SshKey, None),
        ToolSpec::UpstreamRef {
            shared_account_id,
            upstream_id,
            ..
        } => (
            *shared_account_id,
            AccountKind::HttpAuth,
            Some(*upstream_id),
        ),
    };
    Some(StaticAccount {
        account_id: account_id?,
        kind,
        upstream_id,
    })
}

pub(super) fn validate_dependencies(
    conn: &Connection,
    definition: &ToolDefinition,
) -> WriteResult<()> {
    if let ToolSpec::UpstreamRef { upstream_id, .. } = definition.spec {
        let exists: bool = conn
            .prepare_cached("SELECT EXISTS(SELECT 1 FROM upstreams WHERE upstream_id = ?1)")?
            .query_row([upstream_id.to_string()], |row| row.get(0))?;
        if !exists {
            return Err(ApiError::not_found().into());
        }
    }
    if let Some(expected) = static_account(definition) {
        let account = account_by_id(conn, expected.account_id)?.ok_or_else(ApiError::not_found)?;
        if !expected.matches(&account) {
            return Err(ApiError::bad_input().into());
        }
    }
    if let Some(TargetSelector::Fixed { node_ids }) = definition.spec.target_selector() {
        let mut node = conn.prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM nodes WHERE node_id = ?1 AND revoked_at_ms IS NULL)",
        )?;
        for &node_id in node_ids {
            if !node.query_row([node_id.to_string()], |row| row.get::<_, bool>(0))? {
                return Err(ApiError::not_found().into());
            }
        }
    }
    Ok(())
}

pub(super) fn validate_binding_node(
    conn: &Connection,
    definition: &ToolDefinition,
    node_id: NodeId,
) -> WriteResult<()> {
    let matches = match definition.spec.target_selector() {
        Some(TargetSelector::Fixed { node_ids }) => node_ids.contains(&node_id),
        Some(TargetSelector::Tag { tag }) => {
            let tags = conn
                .prepare_cached(
                    "SELECT tags_json FROM nodes WHERE node_id = ?1 AND revoked_at_ms IS NULL",
                )?
                .query_row([node_id.to_string()], |row| json::<Vec<String>>(row, 0))
                .optional()?
                .ok_or_else(ApiError::not_found)?;
            tags.contains(tag)
        }
        None => false,
    };
    if !matches {
        return Err(ApiError::bad_input().into());
    }
    Ok(())
}

fn upsert_tool(
    tx: &WriteTx<'_>,
    slug: &str,
    new_id: ToolId,
    creator: efferian_protocol::PrincipalId,
    revision: ToolRevisionDefinition,
    definition_json: String,
) -> WriteResult<ToolPutResponse> {
    let existing = read_tool(tx.conn(), slug)?;
    if let Some(ref existing) = existing
        && existing.definition == revision.definition
        && existing.summary.input_schema_sha256 == revision.input_schema_sha256
    {
        return Ok(ToolPutResponse {
            outcome: Outcome::Unchanged,
            tool: ToolDetail {
                summary: existing.summary.clone(),
                definition: revision.definition,
            }
            .authoring_view(),
        });
    }
    let now = tx.now_ms();
    let kind = revision.definition.kind();
    let kind_text = scalar_text(kind)?;
    let (outcome, tool, version, disabled_at_ms, created_at_ms) = if let Some(existing) = existing {
        let version = existing
            .summary
            .current_version
            .checked_add(1)
            .filter(|&version| i64::try_from(version).is_ok())
            .ok_or_else(ApiError::internal)?;
        let tool = existing.summary.tool_id;
        tx.conn().prepare_cached(
            "UPDATE tools SET kind = ?1, current_version = ?2, updated_at_ms = ?3 WHERE tool_id = ?4",
        )?.execute(params![kind_text, version, now, tool.to_string()])?;
        (
            Outcome::Updated,
            tool,
            version,
            existing.summary.disabled_at_ms,
            existing.summary.created_at_ms,
        )
    } else {
        tx.conn()
            .prepare_cached(
                "INSERT INTO tools(tool_id, slug, kind, created_by, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            )?
            .execute(params![
                new_id.to_string(),
                slug,
                kind_text,
                creator.to_string(),
                now
            ])?;
        (Outcome::Created, new_id, 1, None, now)
    };
    tx.conn().prepare_cached(
        "INSERT INTO tool_revisions(tool_id, version, input_schema_sha256, created_at_ms, definition_json)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?.execute(params![tool.to_string(), version, revision.input_schema_sha256, now, definition_json])?;
    Ok(ToolPutResponse {
        outcome,
        tool: ToolDetail {
            summary: ToolSummary {
                tool_id: tool,
                slug: slug.to_owned(),
                kind,
                current_version: version,
                input_schema_sha256: revision.input_schema_sha256,
                disabled_at_ms,
                created_at_ms,
                updated_at_ms: now,
            },
            definition: revision.definition,
        }
        .authoring_view(),
    })
}
