use std::collections::BTreeSet;

use efferian_authz::{
    AuthContext, PrincipalAccess, PrincipalView, authorize_admin, authorize_principal_manage,
    authorize_principal_upsert,
};
use efferian_protocol::{PrincipalId, PrincipalKind, error_codes as code};
use http::StatusCode;
use rusqlite::{Connection, Row, ffi, params};
use serde::{Deserialize, Deserializer, Serialize};
use utoipa::ToSchema;

use crate::config::Config;
use crate::http::{ApiError, ApiResult, Page, point_missing};
use crate::storage::{
    StorageError, WriteTx, WriteTxError, id, json, opt_id, read_principal, scalar,
};

pub(crate) const MAX_NODE_TAGS: usize = 64;

#[derive(Serialize, ToSchema)]
pub(super) struct Principal {
    pub principal_id: PrincipalId,
    pub name: String,
    pub kind: PrincipalKind,
    pub owner_principal_id: Option<PrincipalId>,
    pub managed_by_principal_id: Option<PrincipalId>,
    pub inherit_owner_bindings: bool,
    pub is_orchestrator: bool,
    pub allowed_node_tags: BTreeSet<String>,
    pub observe_executions: bool,
    pub disabled_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl Principal {
    pub(super) fn view(&self) -> PrincipalView {
        PrincipalView {
            principal_id: self.principal_id,
            kind: self.kind,
            owner_principal_id: self.owner_principal_id,
            managed_by_principal_id: self.managed_by_principal_id,
            inherit_owner_bindings: self.inherit_owner_bindings,
            is_orchestrator: self.is_orchestrator,
            allowed_node_tags: self.allowed_node_tags.clone(),
            observe_executions: self.observe_executions,
            disabled_at_ms: self.disabled_at_ms,
        }
    }

    fn read(row: &Row<'_>) -> Result<Self, StorageError> {
        let tags: Vec<String> = json(row, 7)?;
        let tag_count = tags.len();
        let principal = Self {
            principal_id: id(row, 0)?,
            name: row.get(1)?,
            kind: scalar(row, 2)?,
            owner_principal_id: opt_id(row, 3)?,
            managed_by_principal_id: opt_id(row, 4)?,
            inherit_owner_bindings: row.get(5)?,
            is_orchestrator: row.get(6)?,
            allowed_node_tags: tags.into_iter().collect(),
            observe_executions: row.get(8)?,
            disabled_at_ms: row.get(9)?,
            created_at_ms: row.get(10)?,
            updated_at_ms: row.get(11)?,
        };
        if principal.allowed_node_tags.len() != tag_count || principal.view().validate().is_err() {
            return Err(StorageError::InvalidDatabase(
                "invalid principal projection",
            ));
        }
        Ok(principal)
    }

    fn from_view(
        view: PrincipalView,
        name: String,
        created_at_ms: i64,
        updated_at_ms: i64,
    ) -> Self {
        Self {
            principal_id: view.principal_id,
            name,
            kind: view.kind,
            owner_principal_id: view.owner_principal_id,
            managed_by_principal_id: view.managed_by_principal_id,
            inherit_owner_bindings: view.inherit_owner_bindings,
            is_orchestrator: view.is_orchestrator,
            allowed_node_tags: view.allowed_node_tags,
            observe_executions: view.observe_executions,
            disabled_at_ms: view.disabled_at_ms,
            created_at_ms,
            updated_at_ms,
        }
    }
}

macro_rules! select_principal {
    ($filter:literal) => {
        concat!(
            "SELECT p.principal_id, p.name, p.kind, p.owner_principal_id, ",
            "p.managed_by_principal_id, p.inherit_owner_bindings, p.is_orchestrator, ",
            "p.allowed_node_tags_json, p.observe_executions, p.disabled_at_ms, ",
            "p.created_at_ms, p.updated_at_ms ",
            "FROM principals p JOIN hub_meta h ON h.id = 1 ",
            "WHERE p.principal_id IS NOT h.gc_purging_principal_id ",
            $filter
        )
    };
}

pub(super) fn principal_by_name(
    conn: &Connection,
    name: &str,
) -> Result<Option<Principal>, StorageError> {
    let mut stmt = conn.prepare_cached(select_principal!("AND p.name = ?1"))?;
    let mut rows = stmt.query([name])?;
    rows.next()?.map(Principal::read).transpose()
}

pub(super) fn principal_by_id(
    conn: &Connection,
    principal: PrincipalId,
) -> Result<Option<Principal>, StorageError> {
    let mut stmt = conn.prepare_cached(select_principal!("AND p.principal_id = ?1"))?;
    let mut rows = stmt.query([principal.to_string()])?;
    rows.next()?.map(Principal::read).transpose()
}

pub(super) fn owned_agent_principals(
    conn: &Connection,
    owner: PrincipalId,
) -> Result<Vec<Principal>, StorageError> {
    let mut stmt = conn.prepare_cached(select_principal!(
        "AND p.kind = 'agent' AND p.owner_principal_id = ?1 ORDER BY p.principal_id COLLATE BINARY ASC"
    ))?;
    let mut rows = stmt.query([owner.to_string()])?;
    let mut items = Vec::new();
    while let Some(row) = rows.next()? {
        items.push(Principal::read(row)?);
    }
    Ok(items)
}

pub(super) fn list_principals(
    conn: &Connection,
    ctx: &AuthContext,
    cursor: Option<&str>,
    limit: usize,
) -> ApiResult<Page<Principal>> {
    // Keep each SQL branch aligned with authorize_principal_manage(Read) so
    // SQLite uses principal/parent indexes and never truncates page windows.
    let cursor = cursor.unwrap_or_default();
    let fetch_limit = limit + 1;
    let mut items = Vec::new();
    if authorize_admin(ctx).is_ok() {
        let mut stmt = conn.prepare_cached(select_principal!(
            "AND p.principal_id COLLATE BINARY > ?1 ORDER BY p.principal_id COLLATE BINARY ASC LIMIT ?2"
        ))?;
        let mut rows = stmt.query(params![cursor, fetch_limit])?;
        while let Some(row) = rows.next()? {
            let principal = Principal::read(row)?;
            authorize_principal_manage(ctx, &principal.view(), PrincipalAccess::Read)?;
            items.push(principal);
        }
    } else {
        let sql = if ctx.caller.kind == PrincipalKind::Member {
            select_principal!(
                "AND p.principal_id COLLATE BINARY > ?1 \
                 AND (p.principal_id = ?2 OR (p.kind = 'agent' AND p.owner_principal_id = ?2)) \
                 ORDER BY p.principal_id COLLATE BINARY ASC LIMIT ?3"
            )
        } else if ctx.caller.is_orchestrator {
            select_principal!(
                "AND p.principal_id COLLATE BINARY > ?1 \
                 AND (p.principal_id = ?2 OR (p.kind = 'agent' AND p.owner_principal_id IS NULL AND p.managed_by_principal_id = ?2)) \
                 ORDER BY p.principal_id COLLATE BINARY ASC LIMIT ?3"
            )
        } else {
            select_principal!(
                "AND p.principal_id = ?2 AND p.principal_id COLLATE BINARY > ?1 \
                 ORDER BY p.principal_id COLLATE BINARY ASC LIMIT ?3"
            )
        };
        let mut stmt = conn.prepare_cached(sql)?;
        let mut rows = stmt.query(params![
            cursor,
            ctx.caller.principal_id.to_string(),
            fetch_limit
        ])?;
        while let Some(row) = rows.next()? {
            let principal = Principal::read(row)?;
            authorize_principal_manage(ctx, &principal.view(), PrincipalAccess::Read)?;
            items.push(principal);
        }
    }
    Ok(Page::from_rows(items, limit, |p| p.principal_id))
}

#[derive(Default)]
enum ParentField {
    #[default]
    Absent,
    Null,
    Value(PrincipalId),
}

impl<'de> Deserialize<'de> for ParentField {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Option::<PrincipalId>::deserialize(deserializer)
            .map(|value| value.map_or(Self::Null, Self::Value))
    }
}

impl ParentField {
    fn resolve(self, default: Option<PrincipalId>) -> Option<PrincipalId> {
        match self {
            Self::Absent => default,
            Self::Null => None,
            Self::Value(id) => Some(id),
        }
    }
}

fn specified_kind<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<PrincipalKind>, D::Error> {
    PrincipalKind::deserialize(deserializer).map(Some)
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct PrincipalPut {
    /// Administrators must supply a kind. When a Member or orchestrator omits it, it defaults to `agent`.
    #[serde(default, deserialize_with = "specified_kind")]
    #[schema(value_type = PrincipalKind, required = false)]
    kind: Option<PrincipalKind>,
    #[serde(default)]
    #[schema(value_type = Option<PrincipalId>)]
    owner_principal_id: ParentField,
    #[serde(default)]
    #[schema(value_type = Option<PrincipalId>)]
    managed_by_principal_id: ParentField,
    #[serde(default)]
    inherit_owner_bindings: bool,
    #[serde(default)]
    is_orchestrator: bool,
    #[serde(default)]
    #[schema(max_items = 64)]
    allowed_node_tags: Vec<String>,
    #[serde(default)]
    observe_executions: bool,
}

impl PrincipalPut {
    pub(super) fn new_id(&self) -> PrincipalId {
        PrincipalId::new_for_kind(self.kind.unwrap_or(PrincipalKind::Agent))
    }

    pub(super) fn work_bytes(&self) -> usize {
        core::mem::size_of::<Self>()
            + self.allowed_node_tags.len() * core::mem::size_of::<String>()
            + self
                .allowed_node_tags
                .iter()
                .map(String::len)
                .sum::<usize>()
    }

    fn draft(self, ctx: &AuthContext, principal_id: PrincipalId) -> ApiResult<PrincipalView> {
        let caller = &ctx.caller;
        let (kind, owner, manager) = match caller.kind {
            PrincipalKind::Admin => {
                authorize_admin(ctx)?;
                (
                    self.kind.ok_or_else(ApiError::bad_input)?,
                    self.owner_principal_id.resolve(None),
                    self.managed_by_principal_id.resolve(None),
                )
            }
            PrincipalKind::Member | PrincipalKind::Service
                if caller.kind == PrincipalKind::Member || caller.is_orchestrator =>
            {
                let member = caller.kind == PrincipalKind::Member;
                let owner = member.then_some(caller.principal_id);
                let manager = Some(caller.principal_id);
                if self.kind.is_some_and(|kind| kind != PrincipalKind::Agent)
                    || self.owner_principal_id.resolve(owner) != owner
                    || self.managed_by_principal_id.resolve(manager) != manager
                    || self.is_orchestrator
                    || self.observe_executions
                    || !self.allowed_node_tags.is_empty()
                    || (!member && self.inherit_owner_bindings)
                {
                    return Err(ApiError::forbidden());
                }
                (PrincipalKind::Agent, owner, manager)
            }
            _ => return Err(ApiError::forbidden()),
        };
        if self.allowed_node_tags.len() > MAX_NODE_TAGS {
            return Err(ApiError::bad_input());
        }
        let view = PrincipalView {
            principal_id,
            kind,
            owner_principal_id: owner,
            managed_by_principal_id: manager,
            inherit_owner_bindings: self.inherit_owner_bindings,
            is_orchestrator: self.is_orchestrator,
            allowed_node_tags: self.allowed_node_tags.into_iter().collect(),
            observe_executions: self.observe_executions,
            disabled_at_ms: None,
        };
        view.validate().map_err(|_| ApiError::bad_input())?;
        Ok(view)
    }
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
enum PutOutcome {
    Created,
    Updated,
    Unchanged,
}

#[derive(Serialize, ToSchema)]
pub(super) struct PrincipalPutResponse {
    outcome: PutOutcome,
    principal: Principal,
}

impl PrincipalPutResponse {
    pub(super) const fn status(&self) -> StatusCode {
        match self.outcome {
            PutOutcome::Created => StatusCode::CREATED,
            PutOutcome::Updated | PutOutcome::Unchanged => StatusCode::OK,
        }
    }
}

type WriteResult<T> = Result<T, WriteTxError<ApiError>>;

pub(super) fn upsert_principal(
    tx: &mut WriteTx<'_>,
    ctx: &AuthContext,
    config: &Config,
    name: String,
    new_id: PrincipalId,
    body: PrincipalPut,
) -> WriteResult<PrincipalPutResponse> {
    let mut requested = body.draft(ctx, new_id)?;
    let owner = requested_parent(tx.conn(), requested.owner_principal_id, ctx, is_owner_kind)?;
    let manager = requested_parent(
        tx.conn(),
        requested.managed_by_principal_id,
        ctx,
        is_manager_kind,
    )?;

    // Check the proposed relationships before looking up the name. The caller
    // receives the same denial for an unused name, someone else's, and their own.
    authorize_principal_upsert(ctx, &requested, None, owner.as_ref(), manager.as_ref())
        .map_err(ApiError::from)?;

    let existing = principal_by_name(tx.conn(), &name)?;
    let now = tx.now_ms();
    if let Some(existing) = existing {
        requested.principal_id = existing.principal_id;
        requested.disabled_at_ms = existing.disabled_at_ms;
        let current = existing.view();
        authorize_principal_upsert(
            ctx,
            &requested,
            Some(&current),
            owner.as_ref(),
            manager.as_ref(),
        )
        .map_err(ApiError::from)?;
        if requested == current {
            return Ok(PrincipalPutResponse {
                outcome: PutOutcome::Unchanged,
                principal: existing,
            });
        }
        if requested.is_orchestrator && !current.is_orchestrator {
            check_managed_quota(tx.conn(), Some(&requested), config, 0)?;
        }
        update_principal(tx, &current, &requested, now)?;
        Ok(PrincipalPutResponse {
            outcome: PutOutcome::Updated,
            principal: Principal::from_view(requested, name, existing.created_at_ms, now),
        })
    } else {
        check_managed_quota(tx.conn(), manager.as_ref(), config, 1)?;
        insert_principal(tx.conn(), &requested, &name, now)?;
        Ok(PrincipalPutResponse {
            outcome: PutOutcome::Created,
            principal: Principal::from_view(requested, name, now, now),
        })
    }
}

fn requested_parent(
    conn: &Connection,
    parent: Option<PrincipalId>,
    ctx: &AuthContext,
    kind_is_allowed: impl FnOnce(PrincipalKind) -> bool,
) -> WriteResult<Option<PrincipalView>> {
    let Some(parent) = parent else {
        return Ok(None);
    };
    if parent == ctx.caller.principal_id && ctx.caller.kind != PrincipalKind::Admin {
        return Ok(Some(ctx.caller.clone()));
    }
    let parent = read_principal(conn, parent)?.ok_or_else(|| point_missing(ctx, true))?;
    if !kind_is_allowed(parent.kind) {
        return Err(ApiError::bad_input().into());
    }
    Ok(Some(parent))
}

fn is_owner_kind(kind: PrincipalKind) -> bool {
    matches!(kind, PrincipalKind::Admin | PrincipalKind::Member)
}

fn is_manager_kind(kind: PrincipalKind) -> bool {
    matches!(
        kind,
        PrincipalKind::Admin | PrincipalKind::Member | PrincipalKind::Service
    )
}

fn check_managed_quota(
    conn: &Connection,
    manager: Option<&PrincipalView>,
    config: &Config,
    new_agents: usize,
) -> WriteResult<()> {
    let Some(manager) = manager else {
        return Ok(());
    };
    let limit = match manager.kind {
        PrincipalKind::Member => config.max_managed_agents_per_member,
        PrincipalKind::Service if manager.is_orchestrator => {
            config.max_managed_agents_per_orchestrator
        }
        _ => return Ok(()),
    };
    let count: usize = conn
        .prepare_cached(
            "SELECT count(*) FROM principals p JOIN hub_meta h ON h.id = 1
             WHERE p.kind = 'agent' AND p.managed_by_principal_id = ?1
               AND p.principal_id IS NOT h.gc_purging_principal_id",
        )?
        .query_row([manager.principal_id.to_string()], |row| row.get(0))?;
    if count.saturating_add(new_agents) > limit {
        return Err(ApiError::conflict(code::QUOTA_EXCEEDED).into());
    }
    Ok(())
}

fn insert_principal(
    conn: &Connection,
    view: &PrincipalView,
    name: &str,
    now: i64,
) -> WriteResult<()> {
    let tags = serde_json::to_string(&view.allowed_node_tags).map_err(|_| ApiError::internal())?;
    conn.prepare_cached(
        "INSERT INTO principals
         (principal_id, kind, name, owner_principal_id, managed_by_principal_id, inherit_owner_bindings,
          is_orchestrator, allowed_node_tags_json, observe_executions, created_at_ms, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
    )?
    .execute(params![
        view.principal_id.to_string(),
        principal_kind_name(view.kind),
        name,
        view.owner_principal_id.map(|id| id.to_string()),
        view.managed_by_principal_id.map(|id| id.to_string()),
        view.inherit_owner_bindings,
        view.is_orchestrator,
        tags,
        view.observe_executions,
        now,
    ])?;
    Ok(())
}

pub(super) const fn principal_kind_name(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::Admin => "admin",
        PrincipalKind::Member => "member",
        PrincipalKind::Agent => "agent",
        PrincipalKind::Service => "service",
    }
}

fn update_principal(
    tx: &mut WriteTx<'_>,
    current: &PrincipalView,
    requested: &PrincipalView,
    now: i64,
) -> WriteResult<()> {
    let tags =
        serde_json::to_string(&requested.allowed_node_tags).map_err(|_| ApiError::internal())?;
    tx.conn()
        .prepare_cached(
            "UPDATE principals SET inherit_owner_bindings = ?2, is_orchestrator = ?3,
                    allowed_node_tags_json = ?4, observe_executions = ?5, updated_at_ms = ?6
             WHERE principal_id = ?1",
        )?
        .execute(params![
            requested.principal_id.to_string(),
            requested.inherit_owner_bindings,
            requested.is_orchestrator,
            tags,
            requested.observe_executions,
            now,
        ])?;
    if (current.observe_executions && !requested.observe_executions)
        || (current.is_orchestrator && !requested.is_orchestrator)
        || (current.inherit_owner_bindings && !requested.inherit_owner_bindings)
    {
        tx.principal_permissions_reduced(requested.principal_id)?;
    }
    Ok(())
}

pub(super) fn enable_principal(tx: &mut WriteTx<'_>, target: &PrincipalView) -> WriteResult<()> {
    if target.disabled_at_ms.is_some() {
        tx.conn()
            .prepare_cached(
                "UPDATE principals SET disabled_at_ms = NULL, updated_at_ms = ?2
                 WHERE principal_id = ?1",
            )?
            .execute(params![target.principal_id.to_string(), tx.now_ms()])?;
    }
    Ok(())
}

pub(super) fn delete_principal(tx: &mut WriteTx<'_>, target: &PrincipalView) -> WriteResult<()> {
    let in_use = || ApiError::conflict(code::RESOURCE_IN_USE);
    if target.kind != PrincipalKind::Agent
        || target.managed_by_principal_id.is_none()
        || target.disabled_at_ms.is_none()
    {
        return Err(in_use().into());
    }
    let target_id = target.principal_id.to_string();
    let has_executions: bool = tx
        .conn()
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM executions WHERE caller_principal_id = ?1)")?
        .query_row([&target_id], |row| row.get(0))?;
    if has_executions {
        return Err(in_use().into());
    }
    let result = tx
        .conn()
        .prepare_cached("DELETE FROM principals WHERE principal_id = ?1")?
        .execute([target_id]);
    // SQLite reports an ON DELETE RESTRICT action as SQLITE_CONSTRAINT_TRIGGER.
    // The Hub schema has no application triggers.
    match result {
        Err(rusqlite::Error::SqliteFailure(error, _))
            if matches!(
                error.extended_code,
                ffi::SQLITE_CONSTRAINT_FOREIGNKEY | ffi::SQLITE_CONSTRAINT_TRIGGER
            ) =>
        {
            Err(in_use().into())
        }
        Err(error) => Err(error.into()),
        Ok(_) => Ok(()),
    }
}
