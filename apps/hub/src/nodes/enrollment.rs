use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode};
use efferian_authz::{
    AuthContext, EnrollmentRequest, MAX_ORCHESTRATOR_ENROLLMENT_TTL_MS, OrchestratorLimits,
    authorize_admin, authorize_node_enrollment,
};
use efferian_protocol::{
    EnrollmentId, HubId, NodeId, PrincipalId, ProblemDetails, SecretString, error_codes,
    validate_node_tag, validate_resource_name,
};
use rusqlite::{Connection, params};
use serde::{Deserialize, Deserializer, Serialize, de::IgnoredAny};
use utoipa::ToSchema;

use crate::http::{ApiCaller, ApiError, ApiJson, ApiPath, ApiResult, AppState, EnrollmentCaller};
use crate::node_bridge::{BridgeCloseReason, NodeBridgeControl};
use crate::storage::{PrincipalLiveness, WriteTx, WriteTxError, principal_liveness};
use crate::vault::{
    IssuedCredential,
    auth::{CredentialError, EnrollmentRecord, recheck_enrollment, refresh_api},
};

use super::{NodeWriteResult, domain, stored_node};

const DEFAULT_TTL_MS: i64 = MAX_ORCHESTRATOR_ENROLLMENT_TTL_MS;

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct MintEnrollment {
    target_node_name: String,
    #[serde(default)]
    tags: Vec<String>,
    /// Time to live in milliseconds. Defaults to 900,000 for administrators. For orchestrators the
    /// default is the smaller of 900,000 and the configured `orchestrator_enrollment_ttl_ms` limit.
    #[schema(minimum = 1)]
    ttl_ms: Option<i64>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct MintReenrollment {
    #[schema(minimum = 1, default = 900000)]
    ttl_ms: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub(super) struct EnrollmentIssued {
    enrollment_id: EnrollmentId,
    #[schema(value_type = String)]
    enrollment_token: SecretString,
    expires_at_ms: i64,
}

/// An object whose fields are reserved for future protocol extensions.
#[derive(ToSchema)]
pub(super) struct ExchangeEnrollment {}

impl<'de> Deserialize<'de> for ExchangeEnrollment {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        BTreeMap::<String, IgnoredAny>::deserialize(deserializer)?;
        Ok(Self {})
    }
}

#[derive(Serialize, ToSchema)]
pub(super) struct EnrollmentExchanged {
    hub_id: HubId,
    node_id: NodeId,
    #[schema(value_type = String)]
    node_token: SecretString,
}

#[utoipa::path(
    post, path = "/v1/enrollment/tokens", tag = "Nodes",
    request_body = MintEnrollment,
    security(("api_bearer" = [])),
    responses((status = 201, body = EnrollmentIssued), (status = 400, body = ProblemDetails, content_type = "application/problem+json"),
              (status = 403, body = ProblemDetails, content_type = "application/problem+json"), (status = 409, body = ProblemDetails, content_type = "application/problem+json"))
)]
pub(super) async fn mint_enrollment(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiJson(input): ApiJson<MintEnrollment>,
) -> ApiResult<(StatusCode, Json<EnrollmentIssued>)> {
    validate_resource_name(&input.target_node_name).map_err(|_| ApiError::bad_input())?;
    let tags: BTreeSet<_> = input.tags.into_iter().collect();
    for tag in &tags {
        validate_node_tag(tag).map_err(|_| ApiError::bad_input())?;
    }
    let tags_json = serde_json::to_string(&tags).map_err(|_| ApiError::internal())?;
    let bytes = input.target_node_name.len()
        + tags_json.len()
        + tags.iter().map(String::len).sum::<usize>();
    let enrollment_id = EnrollmentId::new();
    let IssuedCredential {
        key_id,
        verifier,
        secret,
    } = state.vault.issue_enrollment(enrollment_id)?;
    let expires_at_ms = state
        .storage
        .execute_work(bytes, move |tx| -> NodeWriteResult<i64> {
            let conn = tx.conn();
            let now = tx.now_ms();
            let ctx = refresh_api(conn, &caller.credential, now)?;
            let policy = OrchestratorLimits {
                enrollment_ttl_ms: state.config.orchestrator_enrollment_ttl_ms,
                ..OrchestratorLimits::default()
            };
            let (manager, default_ttl) = if ctx.caller.is_orchestrator {
                (
                    Some(ctx.caller.principal_id),
                    DEFAULT_TTL_MS.min(policy.enrollment_ttl_ms),
                )
            } else {
                (None, DEFAULT_TTL_MS)
            };
            let ttl_ms = input.ttl_ms.unwrap_or(default_ttl);
            let expires_at_ms = expiry(now, ttl_ms)?;
            authorize_node_enrollment(
                &ctx,
                &EnrollmentRequest {
                    is_reenroll: false,
                    requested_tags: tags,
                    managed_by_principal_id: manager,
                    ttl_ms,
                },
                &policy,
            )
            .map_err(domain)?;
            require_available_name(conn, &input.target_node_name, None)?;
            insert_enrollment(
                conn,
                PendingEnrollment {
                    id: enrollment_id,
                    key_id,
                    verifier,
                    target: EnrollmentTarget::Name {
                        name: input.target_node_name,
                        tags_json,
                        manager,
                    },
                    issuer: ctx.caller.principal_id,
                    created_at_ms: now,
                    expires_at_ms,
                },
                now,
                state.config.max_pending_enrollments_per_issuer,
            )?;
            Ok(expires_at_ms)
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(EnrollmentIssued {
            enrollment_id,
            enrollment_token: secret,
            expires_at_ms,
        }),
    ))
}

#[utoipa::path(
    post, path = "/v1/nodes/{id}/reenroll-tokens", tag = "Nodes",
    params(("id" = NodeId, Path)),
    request_body = MintReenrollment,
    security(("api_bearer" = [])),
    responses((status = 201, body = EnrollmentIssued), (status = 400, body = ProblemDetails, content_type = "application/problem+json"),
              (status = 403, body = ProblemDetails, content_type = "application/problem+json"), (status = 404, body = ProblemDetails, content_type = "application/problem+json"),
              (status = 409, body = ProblemDetails, content_type = "application/problem+json"))
)]
pub(super) async fn mint_reenrollment(
    State(state): State<AppState>,
    ApiCaller(caller): ApiCaller,
    ApiPath(node_id): ApiPath<NodeId>,
    ApiJson(input): ApiJson<MintReenrollment>,
) -> ApiResult<(StatusCode, Json<EnrollmentIssued>)> {
    let enrollment_id = EnrollmentId::new();
    let IssuedCredential {
        key_id,
        verifier,
        secret,
    } = state.vault.issue_enrollment(enrollment_id)?;
    let expires_at_ms = state
        .storage
        .execute_work(0, move |tx| -> NodeWriteResult<i64> {
            let conn = tx.conn();
            let now = tx.now_ms();
            let ctx = refresh_api(conn, &caller.credential, now)?;
            let expires_at_ms = prepare_reenrollment(&ctx, input.ttl_ms)?;
            let node = stored_node(conn, node_id)?.ok_or_else(|| domain(ApiError::not_found()))?;
            if let Some(manager) = node.target.managed_by_principal_id
                && principal_liveness(conn, manager)? != PrincipalLiveness::Enabled
            {
                return Err(domain(ApiError::new(
                    StatusCode::FORBIDDEN,
                    error_codes::MANAGED_BY_DISABLED,
                )));
            }
            require_available_name(conn, &node.name, Some(node_id))?;
            let created_at_ms = match node.revoked_at_ms {
                Some(revoked_at_ms) => revoked_at_ms
                    .checked_add(1)
                    .ok_or(WriteTxError::InvalidDatabase(
                        "node revocation timestamp overflow",
                    ))?
                    .max(now),
                None => now,
            };
            insert_enrollment(
                conn,
                PendingEnrollment {
                    id: enrollment_id,
                    key_id,
                    verifier,
                    target: EnrollmentTarget::Id(node_id),
                    issuer: ctx.caller.principal_id,
                    created_at_ms,
                    expires_at_ms,
                },
                now,
                state.config.max_pending_enrollments_per_issuer,
            )?;
            Ok(expires_at_ms)
        })
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(EnrollmentIssued {
            enrollment_id,
            enrollment_token: secret,
            expires_at_ms,
        }),
    ))
}

fn prepare_reenrollment(ctx: &AuthContext, ttl_ms: Option<i64>) -> NodeWriteResult<i64> {
    authorize_admin(ctx).map_err(domain)?;
    expiry(ctx.now_ms, ttl_ms.unwrap_or(DEFAULT_TTL_MS))
}

fn expiry(now_ms: i64, ttl_ms: i64) -> NodeWriteResult<i64> {
    now_ms
        .checked_add(ttl_ms)
        .filter(|expires_at_ms| *expires_at_ms > now_ms)
        .ok_or_else(|| domain(ApiError::bad_input()))
}

enum EnrollmentTarget {
    Name {
        name: String,
        tags_json: String,
        manager: Option<PrincipalId>,
    },
    Id(NodeId),
}

struct PendingEnrollment {
    id: EnrollmentId,
    key_id: u16,
    verifier: String,
    target: EnrollmentTarget,
    issuer: PrincipalId,
    created_at_ms: i64,
    expires_at_ms: i64,
}

fn insert_enrollment(
    conn: &Connection,
    ticket: PendingEnrollment,
    now_ms: i64,
    limit: usize,
) -> NodeWriteResult<()> {
    let issuer = ticket.issuer.to_string();
    let count: usize = conn.query_row(
        "SELECT count(*) FROM node_enrollments
         WHERE created_by = ?1 AND revoked_at_ms IS NULL AND consumed_at_ms IS NULL
           AND expires_at_ms > ?2",
        params![issuer, now_ms],
        |row| row.get(0),
    )?;
    if count >= limit {
        return Err(domain(ApiError::conflict(error_codes::QUOTA_EXCEEDED)));
    }
    let (name, node_id, tags, manager) = match ticket.target {
        EnrollmentTarget::Name {
            name,
            tags_json,
            manager,
        } => (
            Some(name),
            None,
            tags_json,
            manager.map(|id| id.to_string()),
        ),
        EnrollmentTarget::Id(id) => (None, Some(id.to_string()), "[]".to_owned(), None),
    };
    conn.execute(
        "INSERT INTO node_enrollments
            (enrollment_id, key_id, verifier_hmac, target_node_name, target_node_id,
             tags_json, managed_by_principal_id, created_by, expires_at_ms, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            ticket.id.to_string(),
            ticket.key_id,
            ticket.verifier,
            name,
            node_id,
            tags,
            manager,
            issuer,
            ticket.expires_at_ms,
            ticket.created_at_ms,
        ],
    )?;
    Ok(())
}

fn require_available_name(
    conn: &Connection,
    name: &str,
    except: Option<NodeId>,
) -> NodeWriteResult<()> {
    let taken: bool = conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM nodes WHERE name = ?1 AND revoked_at_ms IS NULL AND node_id IS NOT ?2
        )",
        params![name, except.map(|id| id.to_string())],
        |row| row.get(0),
    )?;
    if taken {
        return Err(domain(ApiError::conflict(error_codes::NODE_NAME_IN_USE)));
    }
    Ok(())
}

#[utoipa::path(
    post, path = "/v1/enrollment/exchange", tag = "Nodes",
    request_body = ExchangeEnrollment,
    security(("enrollment_bearer" = [])),
    responses((status = 200, body = EnrollmentExchanged), (status = 400, body = ProblemDetails, content_type = "application/problem+json"),
              (status = 401, body = ProblemDetails, content_type = "application/problem+json"), (status = 409, body = ProblemDetails, content_type = "application/problem+json"))
)]
pub(super) async fn exchange(
    State(state): State<AppState>,
    EnrollmentCaller(caller): EnrollmentCaller,
    ApiJson(_request): ApiJson<ExchangeEnrollment>,
) -> ApiResult<Json<EnrollmentExchanged>> {
    let (node_id, rotation, bytes) = match caller.record {
        EnrollmentRecord::New { name, tags, .. } => {
            let bytes = name.len() + tags.iter().map(String::len).sum::<usize>();
            (NodeId::new(), false, bytes)
        }
        EnrollmentRecord::Reenroll { node_id } => (node_id, true, 0),
    };
    let IssuedCredential {
        key_id,
        verifier,
        secret,
    } = state.vault.issue_node(node_id)?;
    let hub_id = *state.storage.hub_id();
    state
        .storage
        .execute_work(bytes, move |tx| -> NodeWriteResult<()> {
            let now = tx.now_ms();
            let record = recheck_enrollment(tx.conn(), &caller.credential, now)?;
            let consumed = tx.conn().execute(
                "UPDATE node_enrollments SET consumed_at_ms = ?1
                 WHERE enrollment_id = ?2 AND key_id = ?3 AND verifier_hmac = ?4
                   AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL AND expires_at_ms > ?1",
                params![
                    now,
                    caller.credential.id().to_string(),
                    caller.credential.key_id(),
                    caller.credential.verifier()
                ],
            )?;
            if consumed != 1 {
                return Err(domain(CredentialError::Unauthenticated));
            }
            let limit = state.config.max_active_nodes_per_orchestrator;
            match record {
                EnrollmentRecord::New {
                    name,
                    tags,
                    managed_by,
                } if !rotation => {
                    check_active_node_quota(tx.conn(), managed_by, limit)?;
                    let tags =
                        serde_json::to_string(&tags).map_err(|_| domain(ApiError::internal()))?;
                    tx.conn()
                        .execute(
                            "INSERT INTO nodes
                            (node_id, name, key_id, credential_hmac, session_epoch, tags_json,
                             managed_by_principal_id, created_at_ms, updated_at_ms)
                         VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6, ?7, ?7)",
                            params![
                                node_id.to_string(),
                                name,
                                key_id,
                                verifier,
                                tags,
                                managed_by.map(|id| id.to_string()),
                                now
                            ],
                        )
                        .map_err(classify_node_write)?;
                }
                EnrollmentRecord::Reenroll { node_id: target_id }
                    if rotation && target_id == node_id =>
                {
                    rotate(tx, state.bridge, node_id, key_id, &verifier, limit)?;
                }
                _ => return Err(domain(CredentialError::Unauthenticated)),
            }
            Ok(())
        })
        .await?;
    Ok(Json(EnrollmentExchanged {
        hub_id,
        node_id,
        node_token: secret,
    }))
}

fn rotate(
    tx: &mut WriteTx<'_>,
    bridge: Arc<dyn NodeBridgeControl>,
    node_id: NodeId,
    key_id: u16,
    verifier: &str,
    limit: usize,
) -> NodeWriteResult<()> {
    let conn = tx.conn();
    let node =
        stored_node(conn, node_id)?.ok_or_else(|| domain(CredentialError::Unauthenticated))?;
    if node.revoked_at_ms.is_some() {
        check_active_node_quota(conn, node.target.managed_by_principal_id, limit)?;
    }
    let through_epoch = u64::try_from(node.session_epoch)
        .map_err(|_| WriteTxError::InvalidDatabase("invalid node session epoch"))?;
    let next_epoch = node
        .session_epoch
        .checked_add(1)
        .ok_or(WriteTxError::InvalidDatabase("node session epoch overflow"))?;
    conn.execute(
        "UPDATE nodes SET credential_hmac = ?1, key_id = ?2, revoked_at_ms = NULL,
                          session_epoch = ?3, updated_at_ms = ?4 WHERE node_id = ?5",
        params![
            verifier,
            key_id,
            next_epoch,
            tx.now_ms(),
            node_id.to_string()
        ],
    )
    .map_err(classify_node_write)?;
    tx.on_commit(move || {
        bridge.close_session(node_id, through_epoch, BridgeCloseReason::Superseded)
    });
    Ok(())
}

fn check_active_node_quota(
    conn: &Connection,
    manager: Option<PrincipalId>,
    limit: usize,
) -> NodeWriteResult<()> {
    if let Some(manager) = manager {
        let count: usize = conn.query_row(
            "SELECT count(*) FROM nodes
             WHERE managed_by_principal_id = ?1 AND revoked_at_ms IS NULL",
            [manager.to_string()],
            |row| row.get(0),
        )?;
        if count >= limit {
            return Err(domain(ApiError::conflict(error_codes::QUOTA_EXCEEDED)));
        }
    }
    Ok(())
}

fn classify_node_write(error: rusqlite::Error) -> WriteTxError<ApiError> {
    if let rusqlite::Error::SqliteFailure(code, Some(message)) = &error
        && code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
        && message == "UNIQUE constraint failed: nodes.name"
    {
        return domain(ApiError::conflict(error_codes::NODE_NAME_IN_USE));
    }
    error.into()
}
