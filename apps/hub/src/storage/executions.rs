use std::num::NonZeroU64;

use efferian_protocol::{
    AccountId, ActorId, Event, ExecutionEventPayload, ExecutionId, ExecutionState,
    ExecutionSummary, InvokeKind, NodeId, PreparedArgumentsDigest, PrincipalId, ProfileId,
    ProfileToolBinding, RequestDigestMetadata, RequestId, TerminalExecutionState, TokenId, ToolId,
    UpstreamId, validate_profile_bindings, validate_terminal_summary,
};
use rusqlite::{Connection, OptionalExtension, params};
use tokio::sync::watch;

use super::actor::{ExecutionSnapshot, WriteTx, WriteTxError};
use super::events::{id, json, opt_id, scalar, scalar_text};
use super::{PrincipalLiveness, StorageError, WriteError};

mod transitions;

pub(crate) use transitions::{CloseExecutions, PreparedOutcome, TRANSITION_BATCH};

#[derive(Clone, Copy)]
#[allow(dead_code, reason = "execution admission seam for hub modules")]
pub(crate) enum InvokeResource {
    Profile {
        profile_id: ProfileId,
        version: NonZeroU64,
    },
    ToolTest {
        tool_id: ToolId,
        resolved_version: NonZeroU64,
        requested_version: Option<NonZeroU64>,
    },
}

impl InvokeResource {
    fn kind(self) -> InvokeKind {
        match self {
            Self::Profile { .. } => InvokeKind::Profile,
            Self::ToolTest { .. } => InvokeKind::ToolTest,
        }
    }
}

#[derive(Clone, Copy)]
#[allow(dead_code, reason = "execution target seam for hub modules")]
pub(crate) enum ExecutionTarget {
    Node { node_id: NodeId, session_epoch: u64 },
    Upstream(UpstreamId),
}

/// Recorded execution metadata returned by [`WriteTx::lookup_invocation_replay`]
/// so the caller can re-authorize replay against current permissions before
/// checking the request digest or exposing execution state.
#[derive(Clone, Debug)]
#[allow(dead_code, reason = "replay authorization seam for hub modules")]
pub(crate) struct RecordedInvocation {
    pub execution_id: ExecutionId,
    pub invoke_kind: InvokeKind,
    pub request_digest: String,
    pub caller_principal_id: PrincipalId,
    pub caller_token_id: TokenId,
    pub profile_id: Option<ProfileId>,
    pub profile_version: Option<u64>,
    pub tool_id: ToolId,
    pub tool_version: u64,
    pub public_name: String,
    pub node_id: Option<NodeId>,
    pub upstream_id: Option<UpstreamId>,
    pub snapshot: ExecutionSnapshot,
}

/// Client-supplied intent fields needed to verify an authorized replay without
/// resolving a live target or active edition first.
#[allow(dead_code, reason = "replay verification seam for hub modules")]
pub(crate) struct InvokeReplayInput<'a> {
    pub resource: InvokeResource,
    pub public_name: &'a str,
    pub requested_target: Option<&'a str>,
    pub arguments: &'a PreparedArgumentsDigest,
}

/// Fully authorized parameters for inserting a brand-new execution after
/// `lookup_invocation_replay` returns `None`.
#[allow(dead_code, reason = "new execution admission seam for hub modules")]
pub(crate) struct NewExecutionWrite {
    pub execution_id: ExecutionId,
    pub request_id: RequestId,
    pub caller: PrincipalId,
    pub token: TokenId,
    pub resource: InvokeResource,
    pub public_name: String,
    pub requested_target: Option<String>,
    pub arguments: PreparedArgumentsDigest,
    pub executor: ExecutionTarget,
    pub account_id: Option<AccountId>,
    pub deadline_at_ms: i64,
}

#[derive(Debug)]
#[allow(dead_code, reason = "invoke outcome fields for hub modules")]
pub(crate) struct InvokeOutcome {
    pub execution_id: ExecutionId,
    pub snapshot: ExecutionSnapshot,
    pub replayed: bool,
    pub waiter: Option<watch::Receiver<ExecutionSnapshot>>,
}

#[derive(Debug, thiserror::Error)]
#[allow(dead_code, reason = "invoke write error variants for hub modules")]
pub(crate) enum InvokeWriteError {
    #[error("request ID was already used for a different invocation")]
    RequestIdConflict,
    #[error("invocation profile binding is unavailable")]
    BindingUnavailable,
    #[error("invocation principal is unavailable")]
    PrincipalUnavailable,
    #[error("invocation does not match the resolved tool version")]
    InvalidToolVersion,
    #[error("invocation numeric field exceeds SQLite signed integer range")]
    IntegerOutOfRange,
    #[error(transparent)]
    Digest(#[from] efferian_protocol::DigestError),
}

#[allow(dead_code, reason = "receipt write seam for hub modules")]
pub(crate) struct ReceiptWrite {
    pub execution_id: ExecutionId,
    pub node_id: NodeId,
    pub state: TerminalExecutionState,
    pub frame_epoch: u64,
    pub summary: ExecutionSummary,
    pub sealed_result_blob: Option<Vec<u8>>,
    pub result_truncated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code, reason = "receipt outcome seam for hub modules")]
pub(crate) enum ReceiptOutcome {
    AppliedTerminal,
    LateReceiptRecorded,
    AlreadyTerminalOwned,
    NotOwnedOrNotFound,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid terminal receipt metadata")]
pub(crate) struct InvalidReceipt;

#[allow(dead_code, reason = "prepared receipt seam for hub modules")]
pub(crate) struct PreparedReceipt {
    receipt: ReceiptWrite,
    payload_bytes: usize,
}

#[allow(dead_code, reason = "prepared receipt seam for hub modules")]
impl PreparedReceipt {
    pub(crate) fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }
}

#[allow(dead_code, reason = "receipt preparation seam for hub modules")]
impl ReceiptWrite {
    pub(crate) fn prepare(self) -> Result<PreparedReceipt, WriteError<InvalidReceipt>> {
        let has_blob = match &self.sealed_result_blob {
            Some(blob) if blob.is_empty() => return Err(WriteError::Domain(InvalidReceipt)),
            Some(_) => true,
            None => false,
        };
        if validate_terminal_summary(self.state, &self.summary, has_blob, self.result_truncated)
            .is_err()
        {
            return Err(WriteError::Domain(InvalidReceipt));
        }
        let payload_bytes =
            transitions::terminal_work_bytes(&self.summary, self.sealed_result_blob.as_deref())?;
        Ok(PreparedReceipt {
            receipt: self,
            payload_bytes,
        })
    }
}

#[cfg(test)]
pub(crate) struct InvokeWrite {
    pub request_id: RequestId,
    pub caller: PrincipalId,
    pub token: TokenId,
    pub resource: InvokeResource,
    pub public_name: String,
    pub requested_target: Option<String>,
    pub arguments: serde_json::Map<String, serde_json::Value>,
    pub executor: ExecutionTarget,
    pub account_id: Option<AccountId>,
    pub deadline_at_ms: i64,
}

#[cfg(test)]
impl super::StorageHandle {
    pub(crate) async fn invoke(
        &self,
        request: InvokeWrite,
    ) -> Result<InvokeOutcome, WriteError<InvokeWriteError>> {
        let arguments = PreparedArgumentsDigest::new(&request.arguments)
            .map_err(|error| WriteError::Domain(InvokeWriteError::Digest(error)))?;
        let work_bytes = request
            .public_name
            .len()
            .saturating_add(request.requested_target.as_ref().map_or(0, String::len));
        let write = NewExecutionWrite {
            execution_id: ExecutionId::new(),
            request_id: request.request_id,
            caller: request.caller,
            token: request.token,
            resource: request.resource,
            public_name: request.public_name,
            requested_target: request.requested_target,
            arguments,
            executor: request.executor,
            account_id: request.account_id,
            deadline_at_ms: request.deadline_at_ms,
        };
        self.execute_work(work_bytes, move |tx| {
            if tx.principal_liveness(write.caller)? != PrincipalLiveness::Enabled {
                return Err(WriteTxError::Domain(InvokeWriteError::PrincipalUnavailable));
            }
            if let Some(recorded) = tx.lookup_invocation_replay(write.caller, write.request_id)? {
                return tx.verify_invocation_replay(
                    &recorded,
                    &InvokeReplayInput {
                        resource: write.resource,
                        public_name: &write.public_name,
                        requested_target: write.requested_target.as_deref(),
                        arguments: &write.arguments,
                    },
                );
            }
            tx.insert_execution(write)
        })
        .await
    }
}

impl super::StorageHandle {
    #[allow(
        dead_code,
        reason = "managed terminal receipt seam for the node bridge"
    )]
    pub(crate) async fn apply_receipt(
        &self,
        receipt: ReceiptWrite,
    ) -> Result<ReceiptOutcome, WriteError<InvalidReceipt>> {
        let receipt = receipt.prepare()?;
        self.execute_work(receipt.payload_bytes(), move |tx| tx.apply_receipt(receipt))
            .await
    }
}

#[allow(dead_code, reason = "execution write seams for hub modules")]
impl WriteTx<'_> {
    /// Look up an existing `(caller, request_id)` row inside the active write
    /// snapshot (including earlier uncommitted savepoints in the same batch).
    pub(crate) fn lookup_invocation_replay(
        &self,
        caller: PrincipalId,
        request_id: RequestId,
    ) -> Result<Option<RecordedInvocation>, StorageError> {
        lookup_invocation_replay(self.conn(), caller, request_id)
    }

    /// Verify client intent against a previously recorded invocation after the
    /// caller has re-authorized access to `recorded`. Reads historical profile
    /// editions regardless of `disabled_at_ms` so replays after republishing
    /// compare against the original `fixed_node_id`.
    pub(crate) fn verify_invocation_replay(
        &self,
        recorded: &RecordedInvocation,
        input: &InvokeReplayInput<'_>,
    ) -> Result<InvokeOutcome, WriteTxError<InvokeWriteError>> {
        let conflict = || WriteTxError::Domain(InvokeWriteError::RequestIdConflict);
        if recorded.invoke_kind != input.resource.kind()
            || recorded.public_name != input.public_name
        {
            return Err(conflict());
        }
        let (fixed_node_id, requested_version) = match input.resource {
            InvokeResource::Profile { profile_id, .. } => {
                if recorded.profile_id != Some(profile_id) {
                    return Err(conflict());
                }
                let version = recorded
                    .profile_version
                    .ok_or(WriteTxError::InvalidDatabase(
                        "missing profile version on execution",
                    ))?;
                let original =
                    load_binding(self, profile_id, version, &recorded.public_name, false)?
                        .filter(|binding| binding.tool_id == recorded.tool_id)
                        .ok_or(WriteTxError::InvalidDatabase(
                            "missing recorded profile binding",
                        ))?;
                (original.fixed_node_id, None)
            }
            InvokeResource::ToolTest {
                tool_id,
                requested_version,
                ..
            } => {
                if recorded.tool_id != tool_id {
                    return Err(conflict());
                }
                (None, requested_version)
            }
        };
        let computed = finish_digest(
            input.arguments,
            input.resource.kind(),
            recorded.profile_id,
            recorded.tool_id,
            input.public_name,
            input.requested_target,
            fixed_node_id,
            requested_version,
        )?;
        if computed != recorded.request_digest {
            return Err(conflict());
        }
        let waiter = if recorded.snapshot.state.is_terminal() {
            None
        } else {
            // An active row always has either a committed or a staged sender.
            Some(
                self.waiter(recorded.execution_id)
                    .ok_or(WriteTxError::InvalidDatabase(
                        "missing active execution waiter",
                    ))?,
            )
        };
        Ok(InvokeOutcome {
            execution_id: recorded.execution_id,
            snapshot: recorded.snapshot,
            replayed: true,
            waiter,
        })
    }

    /// Admit a brand-new execution after replay lookup misses and caller
    /// authorization succeeds. Checks hard storage pressure, principal liveness,
    /// and active profile/edition state.
    pub(crate) fn insert_execution(
        &mut self,
        request: NewExecutionWrite,
    ) -> Result<InvokeOutcome, WriteTxError<InvokeWriteError>> {
        self.check_hard_storage_pressure()?;
        if self.principal_liveness(request.caller)? != PrincipalLiveness::Enabled {
            return Err(WriteTxError::Domain(InvokeWriteError::PrincipalUnavailable));
        }

        let (profile_id, profile_version, tool_id, tool_version, fixed_node_id, requested_version) =
            match request.resource {
                InvokeResource::Profile {
                    profile_id,
                    version,
                } => {
                    let version_i64 = i64::try_from(version.get())
                        .map_err(|_| WriteTxError::Domain(InvokeWriteError::BindingUnavailable))?;
                    let binding =
                        load_binding(self, profile_id, version.get(), &request.public_name, true)?
                            .ok_or(WriteTxError::Domain(InvokeWriteError::BindingUnavailable))?;
                    let tool_version_i64 = i64::try_from(binding.tool_version)
                        .map_err(|_| WriteTxError::Domain(InvokeWriteError::IntegerOutOfRange))?;
                    (
                        Some(profile_id),
                        Some(version_i64),
                        binding.tool_id,
                        tool_version_i64,
                        binding.fixed_node_id,
                        None,
                    )
                }
                InvokeResource::ToolTest {
                    tool_id,
                    resolved_version,
                    requested_version,
                } => {
                    if requested_version.is_some_and(|pin| pin != resolved_version) {
                        return Err(WriteTxError::Domain(InvokeWriteError::InvalidToolVersion));
                    }
                    let tool_version_i64 = i64::try_from(resolved_version.get())
                        .map_err(|_| WriteTxError::Domain(InvokeWriteError::IntegerOutOfRange))?;
                    (
                        None,
                        None,
                        tool_id,
                        tool_version_i64,
                        None,
                        requested_version,
                    )
                }
            };
        let digest = finish_digest(
            &request.arguments,
            request.resource.kind(),
            profile_id,
            tool_id,
            &request.public_name,
            request.requested_target.as_deref(),
            fixed_node_id,
            requested_version,
        )?;
        let (executor_kind, node_id, node_epoch, upstream_id, initial_state, started_at_ms) =
            match request.executor {
                ExecutionTarget::Node {
                    node_id,
                    session_epoch,
                } => {
                    let epoch_i64 = i64::try_from(session_epoch)
                        .map_err(|_| WriteTxError::Domain(InvokeWriteError::IntegerOutOfRange))?;
                    (
                        "node",
                        Some(node_id),
                        Some(epoch_i64),
                        None,
                        ExecutionState::Accepted,
                        None,
                    )
                }
                ExecutionTarget::Upstream(upstream_id) => (
                    "upstream",
                    None,
                    None,
                    Some(upstream_id),
                    ExecutionState::Running,
                    Some(self.now_ms()),
                ),
            };
        let execution_id = request.execution_id;
        let now = self.now_ms();
        {
            let mut insert = self.conn().prepare_cached(
                "INSERT INTO executions(execution_id, invoke_kind, request_id, request_digest,
                     caller_principal_id, caller_token_id, profile_id, profile_version, tool_id, tool_version,
                     public_name, executor_kind, node_id, node_session_epoch, upstream_id, account_id,
                     state, deadline_at_ms, started_at_ms, created_at_ms, result_expires_at_ms, expires_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                     ?17, ?18, ?19, ?20, ?21, ?22)",
            )?;
            insert.execute(params![
                execution_id.to_string(),
                scalar_text(request.resource.kind())?,
                request.request_id.canonical_str(),
                digest,
                request.caller.to_string(),
                request.token.to_string(),
                profile_id.map(|id| id.to_string()),
                profile_version,
                tool_id.to_string(),
                tool_version,
                request.public_name,
                executor_kind,
                node_id.map(|id| id.to_string()),
                node_epoch,
                upstream_id.map(|id| id.to_string()),
                request.account_id.map(|id| id.to_string()),
                scalar_text(initial_state)?,
                request.deadline_at_ms,
                started_at_ms,
                now,
                now.saturating_add(self.config.result_ttl_ms),
                now.saturating_add(self.config.execution_ttl_ms),
            ])?;
        }
        if initial_state == ExecutionState::Running {
            self.append_event(
                ActorId::Principal(request.caller),
                Event::ExecutionStarted(ExecutionEventPayload {
                    execution_id,
                    state: ExecutionState::Running,
                    profile_id,
                    tool_id,
                    public_name: request.public_name,
                    node_id: None,
                    exit_code: None,
                    error_code: None,
                    duration_ms: None,
                }),
            )?;
        }
        let snapshot = ExecutionSnapshot {
            state: initial_state,
            finished_at_ms: None,
        };
        let waiter = self.stage_waiter_register(execution_id, snapshot);
        Ok(InvokeOutcome {
            execution_id,
            snapshot,
            replayed: false,
            waiter: Some(waiter),
        })
    }
}

pub(crate) fn lookup_invocation_replay(
    conn: &Connection,
    caller: PrincipalId,
    request_id: RequestId,
) -> Result<Option<RecordedInvocation>, StorageError> {
    let mut stmt = conn.prepare_cached(
        "SELECT execution_id, invoke_kind, request_digest, caller_principal_id,
                caller_token_id, profile_id, profile_version, tool_id, tool_version,
                public_name, node_id, upstream_id, state, finished_at_ms
         FROM executions WHERE caller_principal_id = ?1 AND request_id = ?2",
    )?;
    let recorded = stmt
        .query_row(
            params![caller.to_string(), request_id.canonical_str()],
            |row| {
                Ok(RecordedInvocation {
                    execution_id: id(row, 0)?,
                    invoke_kind: scalar(row, 1)?,
                    request_digest: row.get(2)?,
                    caller_principal_id: id(row, 3)?,
                    caller_token_id: id(row, 4)?,
                    profile_id: opt_id(row, 5)?,
                    profile_version: row.get(6)?,
                    tool_id: id(row, 7)?,
                    tool_version: row.get(8)?,
                    public_name: row.get(9)?,
                    node_id: opt_id(row, 10)?,
                    upstream_id: opt_id(row, 11)?,
                    snapshot: ExecutionSnapshot {
                        state: scalar(row, 12)?,
                        finished_at_ms: row.get(13)?,
                    },
                })
            },
        )
        .optional()?;
    Ok(recorded)
}

fn load_binding(
    tx: &WriteTx<'_>,
    profile_id: ProfileId,
    version: u64,
    name: &str,
    require_active: bool,
) -> Result<Option<ProfileToolBinding>, StorageError> {
    let Ok(version) = i64::try_from(version) else {
        return Ok(None);
    };
    let sql = if require_active {
        "SELECT pe.bindings_json FROM profile_editions pe
         JOIN profiles p ON p.profile_id = pe.profile_id
         WHERE pe.profile_id = ?1 AND pe.version = ?2
           AND p.disabled_at_ms IS NULL AND pe.disabled_at_ms IS NULL"
    } else {
        "SELECT bindings_json FROM profile_editions WHERE profile_id = ?1 AND version = ?2"
    };
    let mut stmt = tx.conn().prepare_cached(sql)?;
    let bindings: Option<Vec<ProfileToolBinding>> = stmt
        .query_row(params![profile_id.to_string(), version], |row| json(row, 0))
        .optional()?;
    let Some(bindings) = bindings else {
        return Ok(None);
    };
    validate_profile_bindings(&bindings)
        .map_err(|_| StorageError::InvalidDatabase("invalid profile edition bindings"))?;
    Ok(bindings
        .into_iter()
        .find(|binding| binding.public_name == name))
}

#[allow(clippy::too_many_arguments)]
fn finish_digest(
    arguments: &PreparedArgumentsDigest,
    invoke_kind: InvokeKind,
    profile_id: Option<ProfileId>,
    tool_id: ToolId,
    public_name: &str,
    requested_target: Option<&str>,
    fixed_node_id: Option<NodeId>,
    requested_tool_version: Option<NonZeroU64>,
) -> Result<String, WriteTxError<InvokeWriteError>> {
    arguments
        .finish(&RequestDigestMetadata {
            invoke_kind,
            profile_id,
            tool_id,
            public_name,
            requested_target,
            fixed_node_id,
            requested_tool_version,
        })
        .map_err(|error| WriteTxError::Domain(error.into()))
}
