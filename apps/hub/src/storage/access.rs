use std::collections::BTreeSet;

use efferian_authz::PrincipalView;
use efferian_protocol::{
    ActorId, Event, ExecutionEventPayload, ExecutionId, ExecutionState, ExecutionSummary, GrantId,
    NodeId, PrincipalId, ProfileId, TokenId, ToolId, error_codes,
};
use rusqlite::{Connection, OptionalExtension, params};

use super::actor::WriteTx;
use super::events::{
    RevocationReason, RevocationSignal, id, json, json_write_error, opt_id, scalar,
};
use super::{ExecutionSnapshot, StorageError};

const LIVE_PRINCIPAL: &str = "SELECT p.disabled_at_ms FROM principals p
    JOIN hub_meta h ON h.id = 1
    WHERE p.principal_id = ?1 AND p.principal_id IS NOT h.gc_purging_principal_id";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrincipalLiveness {
    Missing,
    Disabled,
    Enabled,
}

/// A principal claimed by GC is logically absent, even while its rows are being removed.
pub fn principal_liveness(
    conn: &Connection,
    principal_id: PrincipalId,
) -> rusqlite::Result<PrincipalLiveness> {
    let mut stmt = conn.prepare_cached(LIVE_PRINCIPAL)?;
    match stmt
        .query_row([principal_id.to_string()], |row| {
            row.get::<_, Option<i64>>(0)
        })
        .optional()?
    {
        None => Ok(PrincipalLiveness::Missing),
        Some(Some(_)) => Ok(PrincipalLiveness::Disabled),
        Some(None) => Ok(PrincipalLiveness::Enabled),
    }
}

/// Decode the database projection used by authorization. Invalid persisted
/// tags, duplicates, IDs, or flags fail closed and never fall back to a default scope.
pub fn read_principal(
    conn: &Connection,
    principal_id: PrincipalId,
) -> Result<Option<PrincipalView>, StorageError> {
    let mut stmt = conn.prepare_cached(
        "SELECT p.principal_id, p.kind, p.owner_principal_id, p.managed_by_principal_id,
                p.inherit_owner_bindings, p.is_orchestrator, p.allowed_node_tags_json,
                p.observe_executions, p.disabled_at_ms
         FROM principals p JOIN hub_meta h ON h.id = 1
         WHERE p.principal_id = ?1 AND p.principal_id IS NOT h.gc_purging_principal_id",
    )?;
    let decoded = stmt
        .query_row([principal_id.to_string()], |row| {
            let raw_tags: Vec<String> = json(row, 6)?;
            Ok((
                PrincipalView {
                    principal_id: id(row, 0)?,
                    kind: scalar(row, 1)?,
                    owner_principal_id: opt_id(row, 2)?,
                    managed_by_principal_id: opt_id(row, 3)?,
                    inherit_owner_bindings: row.get(4)?,
                    is_orchestrator: row.get(5)?,
                    allowed_node_tags: BTreeSet::new(),
                    observe_executions: row.get(7)?,
                    disabled_at_ms: row.get(8)?,
                },
                raw_tags,
            ))
        })
        .optional()?;
    let Some((mut view, raw_tags)) = decoded else {
        return Ok(None);
    };
    let count = raw_tags.len();
    view.allowed_node_tags = raw_tags.into_iter().collect();
    if view.allowed_node_tags.len() != count {
        return Err(StorageError::InvalidDatabase(
            "duplicate principal node tags",
        ));
    }
    view.validate()
        .map_err(|_| StorageError::InvalidDatabase("invalid principal projection"))?;
    Ok(Some(view))
}

#[cfg(test)]
impl super::StorageHandle {
    pub(crate) async fn revoke_token(
        &self,
        actor: ActorId,
        token: TokenId,
    ) -> Result<bool, super::WriteError<std::convert::Infallible>> {
        self.execute_priority(super::actor::PriorityKind::RevokeToken, move |tx| {
            Ok(tx.revoke_token(actor, token)?)
        })
        .await
    }

    pub(crate) async fn disable_principal(
        &self,
        actor: ActorId,
        principal: PrincipalId,
    ) -> Result<Option<Vec<(NodeId, u64)>>, super::WriteError<std::convert::Infallible>> {
        self.execute_priority(super::actor::PriorityKind::DisablePrincipal, move |tx| {
            Ok(tx.disable_principal(actor, principal)?)
        })
        .await
    }

    pub(crate) async fn revoke_grant(
        &self,
        grant: GrantId,
    ) -> Result<bool, super::WriteError<std::convert::Infallible>> {
        self.execute_priority(super::actor::PriorityKind::RevokeGrant, move |tx| {
            Ok(tx.revoke_grant(grant)?)
        })
        .await
    }

    pub(crate) async fn revoke_node(
        &self,
        actor: ActorId,
        node: NodeId,
    ) -> Result<Option<(NodeId, u64)>, super::WriteError<std::convert::Infallible>> {
        self.execute_priority(super::actor::PriorityKind::RevokeNode, move |tx| {
            Ok(tx.revoke_node(actor, node)?)
        })
        .await
    }

    pub(crate) async fn disable_edition(
        &self,
        profile: ProfileId,
        version: u64,
    ) -> Result<bool, super::WriteError<std::convert::Infallible>> {
        self.execute_priority(super::actor::PriorityKind::DisableEdition, move |tx| {
            Ok(tx.disable_edition(profile, version)?)
        })
        .await
    }

    pub(crate) async fn cancel_execution(
        &self,
        execution: ExecutionId,
    ) -> Result<bool, super::WriteError<std::convert::Infallible>> {
        self.execute_priority(super::actor::PriorityKind::CancelExecution, move |tx| {
            Ok(tx.cancel_execution(execution)?)
        })
        .await
    }
}

#[allow(dead_code, reason = "identity and access write seams for hub modules")]
impl WriteTx<'_> {
    pub(crate) fn revoke_token(
        &mut self,
        actor: ActorId,
        token: TokenId,
    ) -> Result<bool, StorageError> {
        let owner = {
            let mut stmt = self.conn().prepare_cached(
                "UPDATE auth_tokens SET revoked_at_ms = ?1
                 WHERE token_id = ?2 AND revoked_at_ms IS NULL
                   AND principal_id IS NOT (SELECT gc_purging_principal_id FROM hub_meta WHERE id = 1)
                 RETURNING principal_id",
            )?;
            stmt.query_row(params![self.now_ms(), token.to_string()], |row| id(row, 0))
                .optional()?
        };
        if let Some(owner) = owner {
            self.append_event(actor, Event::TokenRevoked(token))?;
            self.stage_revocation(RevocationSignal {
                reason: RevocationReason::TokenRevoked(token),
                affected_principals: vec![owner],
                affected_nodes: Vec::new(),
            });
            return Ok(true);
        }
        Ok(false)
    }

    /// Disable an active principal and return the revoked session fences. An
    /// already disabled or absent principal has no new effects.
    pub(crate) fn disable_principal(
        &mut self,
        actor: ActorId,
        principal: PrincipalId,
    ) -> Result<Option<Vec<(NodeId, u64)>>, StorageError> {
        let principal_id = principal.to_string();
        let kind: Option<String> = {
            let mut stmt = self.conn().prepare_cached(
                "UPDATE principals SET disabled_at_ms = ?1, updated_at_ms = ?1
                 WHERE principal_id = ?2 AND disabled_at_ms IS NULL
                   AND principal_id IS NOT (SELECT gc_purging_principal_id FROM hub_meta WHERE id = 1)
                 RETURNING kind",
            )?;
            stmt.query_row(params![self.now_ms(), &principal_id], |row| row.get(0))
                .optional()?
        };
        let Some(kind) = kind else {
            return Ok(None);
        };
        if kind == "admin" {
            require_global_admin(self.conn())?;
        }
        self.append_event(actor, Event::PrincipalRevoked(principal))?;

        let nodes = managed_nodes(self.conn(), principal)?;
        stage_cascade(
            self,
            principal,
            RevocationReason::PrincipalDisabled(principal),
            nodes.clone(),
        )?;
        {
            let mut stmt = self.conn().prepare_cached(
                "UPDATE node_enrollments SET revoked_at_ms = ?1
                 WHERE (created_by = ?2 OR managed_by_principal_id = ?2
                   OR target_node_id IN (SELECT node_id FROM nodes WHERE managed_by_principal_id = ?2))
                   AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL",
            )?;
            stmt.execute(params![self.now_ms(), principal_id])?;
        }
        let mut revoked = Vec::with_capacity(nodes.len());
        for node in nodes {
            if let Some(session) =
                revoke_node_cascade(self, actor, node, Enrollments::AlreadyRevoked)?
            {
                revoked.push(session);
            }
        }
        Ok(Some(revoked))
    }

    pub(crate) fn revoke_grant(&mut self, grant: GrantId) -> Result<bool, StorageError> {
        let removed: Option<(PrincipalId, String, String)> = {
            let mut stmt = self.conn().prepare_cached(
                "DELETE FROM grants WHERE grant_id = ?1
                   AND principal_id IS NOT (SELECT gc_purging_principal_id FROM hub_meta WHERE id = 1)
                 RETURNING principal_id, scope_kind, capability",
            )?;
            stmt.query_row([grant.to_string()], |row| {
                Ok((id(row, 0)?, row.get(1)?, row.get(2)?))
            })
            .optional()?
        };
        if let Some((principal, scope_kind, capability)) = removed {
            if scope_kind == "global" && capability == "admin" {
                require_global_admin(self.conn())?;
            }
            let nodes = managed_nodes(self.conn(), principal)?;
            stage_cascade(
                self,
                principal,
                RevocationReason::GrantRevoked(grant),
                nodes,
            )?;
            return Ok(true);
        }
        Ok(false)
    }

    pub(crate) fn revoke_profile_grants(&mut self, profile: ProfileId) -> Result<(), StorageError> {
        let mut grantees: BTreeSet<PrincipalId> = {
            let mut stmt = self.conn().prepare_cached(
                "DELETE FROM grants WHERE scope_kind = 'profile' AND scope_id = ?1
                 RETURNING principal_id",
            )?;
            stmt.query_map([profile.to_string()], |row| id(row, 0))?
                .collect::<rusqlite::Result<_>>()?
        };
        let purging: Option<PrincipalId> = self.conn().query_row(
            "SELECT gc_purging_principal_id FROM hub_meta WHERE id = 1",
            [],
            |row| opt_id(row, 0),
        )?;
        if let Some(purging) = purging {
            grantees.remove(&purging);
        }
        let mut affected_principals = grantees.clone();
        let mut affected_nodes = BTreeSet::new();
        for principal in grantees {
            affected_principals.extend(related_agents(self.conn(), principal)?);
            affected_nodes.extend(managed_nodes(self.conn(), principal)?);
        }
        self.stage_revocation(RevocationSignal {
            reason: RevocationReason::ProfileDeleted(profile),
            affected_principals: affected_principals.into_iter().collect(),
            affected_nodes: affected_nodes.into_iter().collect(),
        });
        Ok(())
    }

    pub(crate) fn disable_edition(
        &mut self,
        profile: ProfileId,
        version: u64,
    ) -> Result<bool, StorageError> {
        let Ok(version_i64) = i64::try_from(version) else {
            return Ok(false);
        };
        let changed = {
            let mut stmt = self.conn().prepare_cached(
                "UPDATE profile_editions SET disabled_at_ms = ?1
                 WHERE profile_id = ?2 AND version = ?3 AND disabled_at_ms IS NULL",
            )?;
            stmt.execute(params![self.now_ms(), profile.to_string(), version_i64])? == 1
        };
        if changed {
            self.stage_revocation(RevocationSignal {
                reason: RevocationReason::EditionDisabled {
                    profile_id: profile,
                    version,
                },
                affected_principals: Vec::new(),
                affected_nodes: Vec::new(),
            });
        }
        Ok(changed)
    }

    /// Revoke the node and return its current epoch, including on repeat calls
    /// that only invalidate outstanding re-enrollment invitations.
    pub(crate) fn revoke_node(
        &mut self,
        actor: ActorId,
        node: NodeId,
    ) -> Result<Option<(NodeId, u64)>, StorageError> {
        revoke_node_cascade(self, actor, node, Enrollments::Revoke)
    }

    pub(crate) fn cancel_execution(&self, execution: ExecutionId) -> Result<bool, StorageError> {
        let mut stmt = self.conn().prepare_cached(
            "UPDATE executions SET cancel_requested_at_ms = ?1 WHERE execution_id = ?2
             AND state IN ('accepted', 'running') AND cancel_requested_at_ms IS NULL",
        )?;
        Ok(stmt.execute(params![self.now_ms(), execution.to_string()])? == 1)
    }

    /// Use in the same transaction that reduces a principal's permissions.
    pub(crate) fn principal_permissions_reduced(
        &mut self,
        principal: PrincipalId,
    ) -> Result<(), StorageError> {
        stage_cascade(
            self,
            principal,
            RevocationReason::PrincipalPermissionsReduced(principal),
            Vec::new(),
        )
    }

    pub(crate) fn principal_liveness(
        &self,
        principal: PrincipalId,
    ) -> rusqlite::Result<PrincipalLiveness> {
        principal_liveness(self.conn(), principal)
    }
}

fn require_global_admin(conn: &Connection) -> Result<(), StorageError> {
    let mut stmt = conn.prepare_cached(
        "SELECT EXISTS(SELECT 1 FROM principals p JOIN grants g ON g.principal_id = p.principal_id
           JOIN hub_meta h ON h.id = 1
         WHERE p.kind = 'admin' AND p.disabled_at_ms IS NULL
           AND p.principal_id IS NOT h.gc_purging_principal_id
           AND g.scope_kind = 'global' AND g.scope_id = '' AND g.capability = 'admin')",
    )?;
    if stmt.query_row([], |row| row.get(0))? {
        Ok(())
    } else {
        Err(StorageError::LastAdmin)
    }
}

fn managed_nodes(conn: &Connection, principal: PrincipalId) -> rusqlite::Result<Vec<NodeId>> {
    let mut nodes = conn.prepare_cached(
        "SELECT node_id FROM nodes
         WHERE managed_by_principal_id = ?1 AND revoked_at_ms IS NULL
         ORDER BY node_id",
    )?;
    nodes
        .query_map([principal.to_string()], |row| id(row, 0))?
        .collect()
}

enum Enrollments {
    Revoke,
    // A principal disable revokes invitations for all its managed nodes together.
    AlreadyRevoked,
}

fn revoke_node_cascade(
    tx: &mut WriteTx<'_>,
    actor: ActorId,
    node: NodeId,
    enrollments: Enrollments,
) -> Result<Option<(NodeId, u64)>, StorageError> {
    let node_id = node.to_string();
    let now = tx.now_ms();
    if matches!(enrollments, Enrollments::Revoke) {
        let mut stmt = tx.conn().prepare_cached(
            "UPDATE node_enrollments SET revoked_at_ms = ?1
             WHERE target_node_id = ?2 AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL",
        )?;
        stmt.execute(params![now, &node_id])?;
    }
    let found = {
        let mut stmt = tx
            .conn()
            .prepare_cached("SELECT revoked_at_ms, session_epoch FROM nodes WHERE node_id = ?1")?;
        stmt.query_row([&node_id], |row| {
            Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, u64>(1)?))
        })
        .optional()?
    };
    let Some((revoked_at, epoch)) = found else {
        return Ok(None);
    };
    if revoked_at.is_none() {
        tx.conn()
            .prepare_cached(
                "UPDATE nodes SET revoked_at_ms = ?1, updated_at_ms = ?1 WHERE node_id = ?2",
            )?
            .execute(params![now, &node_id])?;
        tx.append_event(actor, Event::NodeRevoked(node))?;
    }
    finish_revoked_node_executions(tx, actor, node, &node_id)?;
    Ok(Some((node, epoch)))
}

struct ActiveExecution {
    id: ExecutionId,
    profile: Option<ProfileId>,
    tool: ToolId,
    public_name: String,
    started_or_created_at_ms: i64,
}

fn finish_revoked_node_executions(
    tx: &mut WriteTx<'_>,
    actor: ActorId,
    node: NodeId,
    node_id: &str,
) -> Result<(), StorageError> {
    let active = {
        let mut stmt = tx.conn().prepare_cached(
            "SELECT execution_id, profile_id, tool_id, public_name, COALESCE(started_at_ms, created_at_ms)
             FROM executions WHERE node_id = ?1 AND state IN ('accepted', 'running')",
        )?;
        stmt.query_map([node_id], |row| {
            Ok(ActiveExecution {
                id: id(row, 0)?,
                profile: opt_id(row, 1)?,
                tool: id(row, 2)?,
                public_name: row.get(3)?,
                started_or_created_at_ms: row.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let now = tx.now_ms();
    for execution in active {
        let duration_ms = Some(
            now.saturating_sub(execution.started_or_created_at_ms)
                .max(0) as u64,
        );
        let summary = ExecutionSummary {
            duration_ms,
            error_code: Some(error_codes::NODE_REVOKED.to_owned()),
            effect_may_have_occurred: Some(true),
            ..ExecutionSummary::default()
        };
        let summary_json = serde_json::to_string(&summary).map_err(json_write_error)?;
        tx.conn()
            .prepare_cached(
                "UPDATE executions SET state = 'unknown', summary_json = ?1, finished_at_ms = ?2,
                   late_receipt_at_ms = NULL WHERE execution_id = ?3",
            )?
            .execute(params![summary_json, now, execution.id.to_string()])?;
        tx.append_event(
            actor,
            Event::ExecutionFinished(ExecutionEventPayload {
                execution_id: execution.id,
                state: ExecutionState::Unknown,
                profile_id: execution.profile,
                tool_id: execution.tool,
                public_name: execution.public_name,
                node_id: Some(node),
                exit_code: None,
                error_code: summary.error_code,
                duration_ms,
            }),
        )?;
        tx.stage_waiter_finish(
            execution.id,
            ExecutionSnapshot {
                state: ExecutionState::Unknown,
                finished_at_ms: Some(now),
            },
        );
    }
    Ok(())
}

fn stage_cascade(
    tx: &mut WriteTx<'_>,
    principal: PrincipalId,
    reason: RevocationReason,
    affected_nodes: Vec<NodeId>,
) -> Result<(), StorageError> {
    let mut affected_principals = vec![principal];
    affected_principals.extend(related_agents(tx.conn(), principal)?);
    tx.stage_revocation(RevocationSignal {
        reason,
        affected_principals,
        affected_nodes,
    });
    Ok(())
}

fn related_agents(conn: &Connection, principal: PrincipalId) -> rusqlite::Result<Vec<PrincipalId>> {
    let mut agents = conn.prepare_cached(
        "SELECT p.principal_id FROM principals p JOIN hub_meta h ON h.id = 1
         WHERE p.kind = 'agent' AND p.principal_id != ?1 AND p.principal_id IS NOT h.gc_purging_principal_id
         AND (p.owner_principal_id = ?1 OR p.managed_by_principal_id = ?1) ORDER BY p.principal_id",
    )?;
    agents
        .query_map([principal.to_string()], |row| id(row, 0))?
        .collect()
}
