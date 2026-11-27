use efferian_authz::{
    AuthContext, ExecutionAccess, ExecutionAuthTarget, authorize_admin, authorize_execution_access,
};
use efferian_protocol::{
    ExecutionId, ExecutionState, ExecutionSummary, ExecutorKind, InvokeKind, NodeId,
    OutputDiscardedReason, PrincipalId, ProfileId, RequestId, StoredResult, ToolId, UpstreamId,
};
use rusqlite::{Connection, OptionalExtension, Row, named_params};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::http::{ApiError, ApiResult, Page};
use crate::storage::{StorageError, id, json, opt_id, scalar, scalar_text};

#[derive(Serialize, ToSchema)]
pub(super) struct ExecutionFields {
    pub(super) execution_id: ExecutionId,
    #[schema(schema_with = RequestId::canonical_schema)]
    request_id: RequestId,
    invoke_kind: InvokeKind,
    pub(super) state: ExecutionState,
    pub(super) caller_principal_id: PrincipalId,
    profile_id: Option<ProfileId>,
    profile_version: Option<u64>,
    tool_id: ToolId,
    tool_version: u64,
    public_name: String,
    pub(super) executor_kind: ExecutorKind,
    pub(super) node_id: Option<NodeId>,
    upstream_id: Option<UpstreamId>,
    result_truncated: bool,
    pub(super) result_expired: bool,
    cancel_requested_at_ms: Option<i64>,
    created_at_ms: i64,
    started_at_ms: Option<i64>,
    finished_at_ms: Option<i64>,
}

#[derive(Serialize, ToSchema)]
struct SafeExecutionSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    effect_may_have_occurred: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_discarded_reason: Option<OutputDiscardedReason>,
}

impl From<ExecutionSummary> for SafeExecutionSummary {
    fn from(summary: ExecutionSummary) -> Self {
        Self {
            exit_code: summary.exit_code,
            http_status: summary.http_status,
            duration_ms: summary.duration_ms,
            error_code: summary.error_code,
            effect_may_have_occurred: summary.effect_may_have_occurred,
            output_discarded_reason: summary.output_discarded_reason,
        }
    }
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ExecutionMetadata {
    #[serde(flatten)]
    fields: ExecutionFields,
    summary: SafeExecutionSummary,
}

#[derive(Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum ResultAccess {
    NotRequested,
    Denied,
    Expired,
    Unavailable,
    Available,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ExecutionDetail {
    #[serde(flatten)]
    pub(super) fields: ExecutionFields,
    pub(super) summary: ExecutionSummary,
    pub(super) result_access: ResultAccess,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) result: Option<StoredResult>,
}

pub(super) struct ExecutionRow {
    pub(super) fields: ExecutionFields,
    pub(super) target: ExecutionAuthTarget,
    pub(super) summary: ExecutionSummary,
}

impl ExecutionRow {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        let fields = ExecutionFields {
            execution_id: id(row, 0)?,
            request_id: id(row, 1)?,
            invoke_kind: scalar(row, 2)?,
            state: scalar(row, 3)?,
            caller_principal_id: id(row, 4)?,
            profile_id: opt_id(row, 5)?,
            profile_version: row.get(6)?,
            tool_id: id(row, 7)?,
            tool_version: row.get(8)?,
            public_name: row.get(9)?,
            executor_kind: scalar(row, 10)?,
            node_id: opt_id(row, 11)?,
            upstream_id: opt_id(row, 12)?,
            result_truncated: row.get(13)?,
            result_expired: row.get(14)?,
            cancel_requested_at_ms: row.get(15)?,
            created_at_ms: row.get(16)?,
            started_at_ms: row.get(17)?,
            finished_at_ms: row.get(18)?,
        };
        let target = ExecutionAuthTarget {
            caller_principal_id: fields.caller_principal_id,
            caller_owner_principal_id: opt_id(row, 20)?,
            profile_id: fields.profile_id,
            node_id: fields.node_id,
        };
        Ok(Self {
            fields,
            target,
            summary: json(row, 19)?,
        })
    }

    pub(super) fn metadata(self) -> ExecutionMetadata {
        ExecutionMetadata {
            fields: self.fields,
            summary: self.summary.into(),
        }
    }

    pub(super) fn detail(self, result_access: ResultAccess) -> ExecutionDetail {
        ExecutionDetail {
            fields: self.fields,
            summary: self.summary,
            result_access,
            result: None,
        }
    }
}

pub(crate) fn execution_auth_target(
    conn: &Connection,
    caller_principal_id: PrincipalId,
    profile_id: Option<ProfileId>,
    node_id: Option<NodeId>,
) -> Result<ExecutionAuthTarget, StorageError> {
    let caller_owner_principal_id = conn
        .prepare_cached("SELECT owner_principal_id FROM principals WHERE principal_id = ?1")?
        .query_row([caller_principal_id.to_string()], |row| opt_id(row, 0))?;
    Ok(ExecutionAuthTarget {
        caller_principal_id,
        caller_owner_principal_id,
        profile_id,
        node_id,
    })
}

macro_rules! select_execution {
    ($suffix:literal) => {
        concat!(
            "SELECT e.execution_id, e.request_id, e.invoke_kind, e.state, e.caller_principal_id,
                    e.profile_id, e.profile_version, e.tool_id, e.tool_version, e.public_name,
                    e.executor_kind, e.node_id, e.upstream_id, e.result_truncated, e.result_expired,
                    e.cancel_requested_at_ms, e.created_at_ms, e.started_at_ms, e.finished_at_ms,
                    json_remove(e.summary_json, '$.error_message'), p.owner_principal_id
             FROM executions e JOIN principals p ON p.principal_id = e.caller_principal_id ",
            $suffix
        )
    };
}

pub(super) fn read_execution(
    conn: &Connection,
    id: ExecutionId,
) -> rusqlite::Result<Option<ExecutionRow>> {
    conn.prepare_cached(select_execution!("WHERE e.execution_id = ?1"))?
        .query_row([id.to_string()], ExecutionRow::from_row)
        .optional()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExecutionQuery {
    pub(super) state: Option<ExecutionState>,
    pub(super) principal_id: Option<PrincipalId>,
    pub(super) profile_id: Option<ProfileId>,
    pub(super) node_id: Option<NodeId>,
    pub(super) tool_id: Option<ToolId>,
    pub(super) limit: Option<u16>,
    pub(super) cursor: Option<String>,
}

pub(super) type ExecutionCursor = (i64, ExecutionId);

pub(super) fn parse_cursor(raw: &str) -> ApiResult<ExecutionCursor> {
    let (created, id) = raw.split_once('.').ok_or_else(ApiError::bad_input)?;
    let created = created.parse::<i64>().map_err(|_| ApiError::bad_input())?;
    let id = id
        .parse::<ExecutionId>()
        .map_err(|_| ApiError::bad_input())?;
    if raw != format!("{created}.{id}") {
        return Err(ApiError::bad_input());
    }
    Ok((created, id))
}

pub(super) fn read_execution_page(
    conn: &Connection,
    ctx: &AuthContext,
    query: ExecutionQuery,
    limit: usize,
    cursor: Option<ExecutionCursor>,
) -> ApiResult<Page<ExecutionMetadata>> {
    let params = scope_parameters(ctx)?;
    // Push visibility before the SQL limit. Recheck the authoritative policy
    // on returned rows to keep this projection fail closed if the policy evolves.
    let mut stmt = conn.prepare_cached(select_execution!(
        "WHERE (:admin OR (
             (e.caller_principal_id = :caller OR p.owner_principal_id = :caller)
             AND (:profiles IS NULL OR e.profile_id IN (SELECT value FROM json_each(:profiles)))
             AND (:nodes IS NULL OR e.node_id IN (SELECT value FROM json_each(:nodes)))
         ))
         AND (:state IS NULL OR e.state = :state)
         AND (:principal IS NULL OR e.caller_principal_id = :principal)
         AND (:profile IS NULL OR e.profile_id = :profile)
         AND (:node IS NULL OR e.node_id = :node)
         AND (:tool IS NULL OR e.tool_id = :tool)
         AND (:created IS NULL OR (e.created_at_ms, e.execution_id) < (:created, :cursor))
         ORDER BY e.created_at_ms DESC, e.execution_id COLLATE BINARY DESC
         LIMIT :limit"
    ))?;
    let rows = stmt
        .query_map(
            named_params! {
                ":admin": authorize_admin(ctx).is_ok(),
                ":caller": ctx.caller.principal_id.to_string(),
                ":profiles": params.0,
                ":nodes": params.1,
                ":state": query.state.map(scalar_text).transpose()?,
                ":principal": query.principal_id.map(|id| id.to_string()),
                ":profile": query.profile_id.map(|id| id.to_string()),
                ":node": query.node_id.map(|id| id.to_string()),
                ":tool": query.tool_id.map(|id| id.to_string()),
                ":created": cursor.map(|(created, _)| created),
                ":cursor": cursor.map(|(_, id)| id.to_string()),
                ":limit": limit + 1,
            },
            ExecutionRow::from_row,
        )?
        .map(|row| {
            let row = row?;
            authorize_execution_access(ctx, Some(&row.target), ExecutionAccess::ReadMetadata)?;
            Ok(row.metadata())
        })
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(Page::from_rows(rows, limit, |row| {
        format!("{}.{}", row.fields.created_at_ms, row.fields.execution_id)
    }))
}

fn scope_parameters(ctx: &AuthContext) -> ApiResult<(Option<String>, Option<String>)> {
    let profiles = ctx
        .token
        .allowed_profiles
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| ApiError::internal())?;
    let nodes = ctx
        .token
        .allowed_nodes
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| ApiError::internal())?;
    Ok((profiles, nodes))
}
