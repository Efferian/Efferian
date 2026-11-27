use std::collections::BTreeSet;

use efferian_authz::PrincipalView;
use efferian_protocol::{
    ActorId, Event, ExecutionId, GrantId, NodeId, PrincipalId, ProfileId, TokenId,
};
use rusqlite::{Connection, OptionalExtension, params};

use super::StorageError;
use super::actor::WriteTx;
use super::events::{RevocationReason, RevocationSignal, id, json, opt_id, scalar};

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
    ) -> Result<bool, super::WriteError<std::convert::Infallible>> {
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
    ) -> Result<bool, super::WriteError<std::convert::Infallible>> {
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

    pub(crate) fn disable_principal(
        &mut self,
        actor: ActorId,
        principal: PrincipalId,
    ) -> Result<bool, StorageError> {
        let changed = {
            let mut stmt = self.conn().prepare_cached(
                "UPDATE principals SET disabled_at_ms = ?1, updated_at_ms = ?1
                 WHERE principal_id = ?2 AND disabled_at_ms IS NULL
                   AND principal_id IS NOT (SELECT gc_purging_principal_id FROM hub_meta WHERE id = 1)",
            )?;
            stmt.execute(params![self.now_ms(), principal.to_string()])? == 1
        };
        if changed {
            self.append_event(actor, Event::PrincipalRevoked(principal))?;
            stage_cascade(
                self,
                principal,
                RevocationReason::PrincipalDisabled(principal),
                true,
            )?;
        }
        Ok(changed)
    }

    pub(crate) fn revoke_grant(&mut self, grant: GrantId) -> Result<bool, StorageError> {
        let principal = {
            let mut stmt = self.conn().prepare_cached(
                "DELETE FROM grants WHERE grant_id = ?1
                   AND principal_id IS NOT (SELECT gc_purging_principal_id FROM hub_meta WHERE id = 1)
                 RETURNING principal_id",
            )?;
            stmt.query_row([grant.to_string()], |row| id(row, 0))
                .optional()?
        };
        if let Some(principal) = principal {
            stage_cascade(self, principal, RevocationReason::GrantRevoked(grant), true)?;
            return Ok(true);
        }
        Ok(false)
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

    pub(crate) fn revoke_node(
        &mut self,
        actor: ActorId,
        node: NodeId,
    ) -> Result<bool, StorageError> {
        let changed = {
            let mut stmt = self.conn().prepare_cached(
                "UPDATE nodes SET revoked_at_ms = ?1, updated_at_ms = ?1
                 WHERE node_id = ?2 AND revoked_at_ms IS NULL",
            )?;
            stmt.execute(params![self.now_ms(), node.to_string()])? == 1
        };
        if changed {
            self.append_event(actor, Event::NodeRevoked(node))?;
        }
        Ok(changed)
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
            false,
        )
    }

    pub(crate) fn principal_liveness(
        &self,
        principal: PrincipalId,
    ) -> rusqlite::Result<PrincipalLiveness> {
        principal_liveness(self.conn(), principal)
    }
}

fn stage_cascade(
    tx: &mut WriteTx<'_>,
    principal: PrincipalId,
    reason: RevocationReason,
    include_nodes: bool,
) -> Result<(), StorageError> {
    let mut affected_principals = vec![principal];
    let mut affected_nodes = Vec::new();
    let principal_id = principal.to_string();
    {
        let conn = tx.conn();
        let mut agents = conn.prepare_cached(
            "SELECT p.principal_id FROM principals p JOIN hub_meta h ON h.id = 1
             WHERE p.kind = 'agent' AND p.principal_id != ?1 AND p.principal_id IS NOT h.gc_purging_principal_id
             AND (p.owner_principal_id = ?1 OR p.managed_by_principal_id = ?1) ORDER BY p.principal_id",
        )?;
        for agent in agents.query_map([&principal_id], |row| id(row, 0))? {
            affected_principals.push(agent?);
        }
        if include_nodes {
            let mut nodes = conn.prepare_cached(
                "SELECT node_id FROM nodes WHERE managed_by_principal_id = ?1 ORDER BY node_id",
            )?;
            for node in nodes.query_map([&principal_id], |row| id(row, 0))? {
                affected_nodes.push(node?);
            }
        }
    }
    tx.stage_revocation(RevocationSignal {
        reason,
        affected_principals,
        affected_nodes,
    });
    Ok(())
}
