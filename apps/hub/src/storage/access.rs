use efferian_authz::PrincipalView;
use efferian_protocol::{
    ActorId, Event, ExecutionId, GrantId, NodeId, PrincipalId, ProfileId, TokenId,
};
use rusqlite::{Connection, OptionalExtension, params};

use super::actor::{PriorityKind, WriteTx};
use super::events::{RevocationReason, RevocationSignal, id, json, opt_id, scalar};
use super::{StorageError, StorageHandle, WriteError};

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
    match conn
        .query_row(LIVE_PRINCIPAL, [principal_id.to_string()], |row| {
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
/// tags, IDs, or flags fail closed and never fall back to a default scope.
pub fn read_principal(
    conn: &Connection,
    principal_id: PrincipalId,
) -> Result<Option<PrincipalView>, StorageError> {
    let view = conn
        .query_row(
            "SELECT p.principal_id, p.kind, p.owner_principal_id, p.managed_by_principal_id,
                p.inherit_owner_bindings, p.is_orchestrator, p.allowed_node_tags_json,
                p.observe_executions, p.disabled_at_ms
         FROM principals p JOIN hub_meta h ON h.id = 1
         WHERE p.principal_id = ?1 AND p.principal_id IS NOT h.gc_purging_principal_id",
            [principal_id.to_string()],
            |row| {
                Ok(PrincipalView {
                    principal_id: id(row, 0)?,
                    kind: scalar(row, 1)?,
                    owner_principal_id: opt_id(row, 2)?,
                    managed_by_principal_id: opt_id(row, 3)?,
                    inherit_owner_bindings: row.get(4)?,
                    is_orchestrator: row.get(5)?,
                    allowed_node_tags: json(row, 6)?,
                    observe_executions: row.get(7)?,
                    disabled_at_ms: row.get(8)?,
                })
            },
        )
        .optional()?;
    if let Some(view) = &view {
        view.validate()
            .map_err(|_| StorageError::InvalidDatabase("invalid principal projection"))?;
    }
    Ok(view)
}

impl StorageHandle {
    pub async fn revoke_token(
        &self,
        actor: ActorId,
        token: TokenId,
    ) -> Result<bool, WriteError<std::convert::Infallible>> {
        self.execute_priority(PriorityKind::RevokeToken, move |tx| {
            let changed = tx.conn().execute(
                "UPDATE auth_tokens SET revoked_at_ms = ?1 WHERE token_id = ?2 AND revoked_at_ms IS NULL",
                params![tx.now_ms(), token.to_string()],
            )? == 1;
            if changed {
                tx.append_event(actor, Event::TokenRevoked(token))?;
                let owner = tx.conn().query_row(
                    "SELECT principal_id FROM auth_tokens WHERE token_id = ?1",
                    [token.to_string()],
                    |row| id(row, 0),
                )?;
                tx.stage_revocation(RevocationSignal {
                    reason: RevocationReason::TokenRevoked(token),
                    affected_principals: vec![owner],
                    affected_nodes: Vec::new(),
                });
            }
            Ok(changed)
        }).await
    }

    pub async fn disable_principal(
        &self,
        actor: ActorId,
        principal: PrincipalId,
    ) -> Result<bool, WriteError<std::convert::Infallible>> {
        self.execute_priority(PriorityKind::DisablePrincipal, move |tx| {
            let changed = tx.conn().execute(
                "UPDATE principals SET disabled_at_ms = ?1, updated_at_ms = ?1
                 WHERE principal_id = ?2 AND disabled_at_ms IS NULL",
                params![tx.now_ms(), principal.to_string()],
            )? == 1;
            if changed {
                tx.append_event(actor, Event::PrincipalRevoked(principal))?;
                stage_cascade(
                    tx,
                    principal,
                    RevocationReason::PrincipalDisabled(principal),
                    true,
                )?;
            }
            Ok(changed)
        })
        .await
    }

    pub async fn revoke_grant(
        &self,
        grant: GrantId,
    ) -> Result<bool, WriteError<std::convert::Infallible>> {
        self.execute_priority(PriorityKind::RevokeGrant, move |tx| {
            let principal = tx
                .conn()
                .query_row(
                    "DELETE FROM grants WHERE grant_id = ?1 RETURNING principal_id",
                    [grant.to_string()],
                    |row| id(row, 0),
                )
                .optional()?;
            if let Some(principal) = principal {
                stage_cascade(tx, principal, RevocationReason::GrantRevoked(grant), true)?;
            }
            Ok(principal.is_some())
        })
        .await
    }

    pub async fn revoke_node(
        &self,
        actor: ActorId,
        node: NodeId,
    ) -> Result<bool, WriteError<std::convert::Infallible>> {
        self.execute_priority(PriorityKind::RevokeNode, move |tx| {
            let changed = tx.conn().execute(
                "UPDATE nodes SET revoked_at_ms = ?1, updated_at_ms = ?1
                 WHERE node_id = ?2 AND revoked_at_ms IS NULL",
                params![tx.now_ms(), node.to_string()],
            )? == 1;
            if changed {
                tx.append_event(actor, Event::NodeRevoked(node))?;
            }
            Ok(changed)
        })
        .await
    }

    pub async fn disable_edition(
        &self,
        profile: ProfileId,
        version: u64,
    ) -> Result<bool, WriteError<std::convert::Infallible>> {
        self.execute_priority(PriorityKind::DisableEdition, move |tx| {
            let changed = tx.conn().execute(
                "UPDATE profile_editions SET disabled_at_ms = ?1
                 WHERE profile_id = ?2 AND version = ?3 AND disabled_at_ms IS NULL",
                params![tx.now_ms(), profile.to_string(), version],
            )? == 1;
            if changed {
                tx.stage_revocation(RevocationSignal {
                    reason: RevocationReason::EditionDisabled {
                        profile_id: profile,
                        version,
                    },
                    affected_principals: Vec::new(),
                    affected_nodes: Vec::new(),
                });
            }
            Ok(changed)
        })
        .await
    }

    pub async fn cancel_execution(
        &self,
        execution: ExecutionId,
    ) -> Result<bool, WriteError<std::convert::Infallible>> {
        self.execute_priority(PriorityKind::CancelExecution, move |tx| {
            Ok(tx.conn().execute(
                "UPDATE executions SET cancel_requested_at_ms = ?1 WHERE execution_id = ?2
                 AND state IN ('accepted', 'running') AND cancel_requested_at_ms IS NULL",
                params![tx.now_ms(), execution.to_string()],
            )? == 1)
        })
        .await
    }
}

impl WriteTx<'_> {
    /// Use in the same transaction that reduces a principal's permissions.
    #[allow(dead_code, reason = "catalog and authorization write seam")]
    pub(crate) fn principal_permissions_reduced(
        &mut self,
        principal: PrincipalId,
    ) -> rusqlite::Result<()> {
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
) -> rusqlite::Result<()> {
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
