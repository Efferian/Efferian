use std::num::NonZeroU64;

use efferian_protocol::{
    AccountId, ActorId, Event, ExecutionEventPayload, ExecutionId, ExecutionState,
    ExecutionSummary, InvokeKind, MAX_EXECUTION_ERROR_MESSAGE_BYTES, NodeId, PrincipalId,
    ProfileId, ProfileToolBinding, RequestDigestInput, RequestId, TerminalExecutionState, TokenId,
    ToolId, UpstreamId, compute_request_digest, validate_profile_bindings,
};
use rusqlite::{OptionalExtension, params};
use serde_json::{Map, Value};
use tokio::sync::watch;

use super::actor::{ExecutionSnapshot, WriteTx, WriteTxError};
use super::events::{id, json, json_write_error, opt_id, scalar, scalar_text};
use super::{PrincipalLiveness, StorageError, StorageHandle, WriteError};

#[derive(Clone, Copy)]
pub enum InvokeResource {
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
pub enum ExecutionTarget {
    Node { node_id: NodeId, session_epoch: u64 },
    Upstream(UpstreamId),
}

/// The application resolves the target and authorizes the request before admission.
pub struct InvokeWrite {
    pub request_id: RequestId,
    pub caller: PrincipalId,
    pub token: TokenId,
    pub resource: InvokeResource,
    pub public_name: String,
    pub requested_target: Option<String>,
    pub arguments: Map<String, Value>,
    pub executor: ExecutionTarget,
    pub account_id: Option<AccountId>,
    pub deadline_at_ms: i64,
}

#[derive(Debug)]
pub struct InvokeOutcome {
    pub execution_id: ExecutionId,
    pub snapshot: ExecutionSnapshot,
    pub replayed: bool,
    pub waiter: Option<watch::Receiver<ExecutionSnapshot>>,
}

#[derive(Debug, thiserror::Error)]
pub enum InvokeWriteError {
    #[error("request ID was already used for a different invocation")]
    RequestIdConflict,
    #[error("invocation profile binding is unavailable")]
    BindingUnavailable,
    #[error("invocation principal is unavailable")]
    PrincipalUnavailable,
    #[error("invocation does not match the resolved tool version")]
    InvalidToolVersion,
    #[error(transparent)]
    Digest(#[from] efferian_protocol::DigestError),
}

pub struct ReceiptWrite {
    pub execution_id: ExecutionId,
    pub node_id: NodeId,
    pub state: TerminalExecutionState,
    pub finished_at_ms: i64,
    pub summary: ExecutionSummary,
    pub sealed_result_blob: Option<Vec<u8>>,
    pub result_truncated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptOutcome {
    AppliedTerminal,
    LateReceiptRecorded,
    AlreadyTerminalOwned,
    NotOwnedOrNotFound,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid terminal receipt metadata")]
pub struct InvalidReceipt;

impl InvokeWrite {
    pub(crate) fn payload_bytes(&self) -> Result<usize, StorageError> {
        Ok(serde_json::to_vec(&self.arguments)
            .map_err(json_write_error)?
            .len()
            .saturating_add(self.public_name.len())
            .saturating_add(self.requested_target.as_ref().map_or(0, String::len)))
    }
}

pub(crate) struct PreparedReceipt {
    receipt: ReceiptWrite,
    summary_json: String,
}

impl PreparedReceipt {
    pub(crate) fn payload_bytes(&self) -> usize {
        self.summary_json
            .len()
            .saturating_add(self.receipt.sealed_result_blob.as_ref().map_or(0, Vec::len))
    }
}

impl ReceiptWrite {
    pub(crate) fn prepare(self) -> Result<PreparedReceipt, WriteError<InvalidReceipt>> {
        if self.summary.effect_may_have_occurred.is_none()
            || self
                .summary
                .error_message
                .as_ref()
                .is_some_and(|message| message.len() > MAX_EXECUTION_ERROR_MESSAGE_BYTES)
            || self.sealed_result_blob.as_ref().is_some_and(Vec::is_empty)
        {
            return Err(WriteError::Domain(InvalidReceipt));
        }
        let summary_json = serde_json::to_string(&self.summary)
            .map_err(json_write_error)
            .map_err(StorageError::from)?;
        Ok(PreparedReceipt {
            receipt: self,
            summary_json,
        })
    }
}

impl StorageHandle {
    pub async fn invoke(
        &self,
        request: InvokeWrite,
    ) -> Result<InvokeOutcome, WriteError<InvokeWriteError>> {
        self.execute_work(request.payload_bytes()?, move |tx| tx.invoke(request))
            .await
    }

    pub async fn apply_receipt(
        &self,
        receipt: ReceiptWrite,
    ) -> Result<ReceiptOutcome, WriteError<InvalidReceipt>> {
        let receipt = receipt.prepare()?;
        self.execute_work(receipt.payload_bytes(), move |tx| tx.apply_receipt(receipt))
            .await
    }
}

impl WriteTx<'_> {
    pub(crate) fn invoke(
        &mut self,
        request: InvokeWrite,
    ) -> Result<InvokeOutcome, WriteTxError<InvokeWriteError>> {
        let caller = request.caller.to_string();
        let request_id = request.request_id.canonical_str();
        let recorded = self
            .conn()
            .query_row(
                "SELECT execution_id, invoke_kind, request_digest, profile_id, profile_version,
                    tool_id, public_name, state, finished_at_ms
             FROM executions WHERE caller_principal_id = ?1 AND request_id = ?2",
                params![caller, request_id],
                |row| {
                    Ok(RecordedInvocation {
                        execution_id: id(row, 0)?,
                        kind: scalar(row, 1)?,
                        digest: row.get(2)?,
                        profile_id: opt_id(row, 3)?,
                        profile_version: row.get(4)?,
                        tool_id: id(row, 5)?,
                        public_name: row.get(6)?,
                        snapshot: ExecutionSnapshot {
                            state: scalar(row, 7)?,
                            finished_at_ms: row.get(8)?,
                        },
                    })
                },
            )
            .optional()?;

        if let Some(recorded) = recorded {
            return replay(self, &request, recorded);
        }
        self.check_hard_storage_pressure()?;
        if self.principal_liveness(request.caller)? != PrincipalLiveness::Enabled {
            return Err(WriteTxError::Domain(InvokeWriteError::PrincipalUnavailable));
        }

        let (profile_id, profile_version, tool_id, version, fixed_node_id, requested_version) =
            match request.resource {
                InvokeResource::Profile {
                    profile_id,
                    version,
                } => {
                    let binding =
                        binding(self, profile_id, version.get(), &request.public_name)?
                            .ok_or(WriteTxError::Domain(InvokeWriteError::BindingUnavailable))?;
                    (
                        Some(profile_id),
                        Some(version.get()),
                        binding.tool_id,
                        binding.tool_version,
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
                    (
                        None,
                        None,
                        tool_id,
                        resolved_version.get(),
                        None,
                        requested_version,
                    )
                }
            };
        let digest = digest(
            &request,
            profile_id,
            tool_id,
            fixed_node_id,
            requested_version,
        )?;
        let (kind, node_id, node_epoch, upstream_id) = match request.executor {
            ExecutionTarget::Node {
                node_id,
                session_epoch,
            } => ("node", Some(node_id), Some(session_epoch), None),
            ExecutionTarget::Upstream(upstream_id) => ("upstream", None, None, Some(upstream_id)),
        };
        let execution_id = ExecutionId::new();
        let now = self.now_ms();
        self.conn().execute(
            "INSERT INTO executions(execution_id, invoke_kind, request_id, request_digest,
                 caller_principal_id, caller_token_id, profile_id, profile_version, tool_id, tool_version,
                 public_name, executor_kind, node_id, node_session_epoch, upstream_id, account_id,
                 state, deadline_at_ms, created_at_ms, result_expires_at_ms, expires_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                 'accepted', ?17, ?18, ?19, ?20)",
            params![execution_id.to_string(), scalar_text(request.resource.kind())?, request_id, digest, caller,
                request.token.to_string(), profile_id.map(|id| id.to_string()), profile_version,
                tool_id.to_string(), version, request.public_name, kind, node_id.map(|id| id.to_string()),
                node_epoch, upstream_id.map(|id| id.to_string()), request.account_id.map(|id| id.to_string()),
                request.deadline_at_ms, now, now.saturating_add(self.config.result_ttl_ms),
                now.saturating_add(self.config.execution_ttl_ms)],
        )?;
        let snapshot = ExecutionSnapshot {
            state: ExecutionState::Accepted,
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

    pub(crate) fn apply_receipt(
        &mut self,
        prepared: PreparedReceipt,
    ) -> Result<ReceiptOutcome, WriteTxError<InvalidReceipt>> {
        let PreparedReceipt {
            receipt,
            summary_json,
        } = prepared;
        let execution_id = receipt.execution_id.to_string();
        let node_id = receipt.node_id.to_string();
        let Some((old_state, profile, tool, public_name)) = self
            .conn()
            .query_row(
                "SELECT state, profile_id, tool_id, public_name FROM executions
             WHERE execution_id = ?1 AND node_id = ?2",
                params![execution_id, node_id],
                |row| {
                    Ok((
                        scalar::<ExecutionState>(row, 0)?,
                        opt_id(row, 1)?,
                        id(row, 2)?,
                        row.get(3)?,
                    ))
                },
            )
            .optional()?
        else {
            return Ok(ReceiptOutcome::NotOwnedOrNotFound);
        };
        let state = ExecutionState::from(receipt.state);
        let payload = ExecutionEventPayload {
            execution_id: receipt.execution_id,
            state,
            profile_id: profile,
            tool_id: tool,
            public_name,
            node_id: Some(receipt.node_id),
            exit_code: receipt.summary.exit_code,
            error_code: receipt.summary.error_code,
            duration_ms: receipt.summary.duration_ms,
        };
        let actor = ActorId::Node(receipt.node_id);
        if old_state == ExecutionState::Unknown {
            let changed = self.conn().execute(
                "UPDATE executions SET late_receipt_at_ms = ?1 WHERE execution_id = ?2
                 AND node_id = ?3 AND state = 'unknown' AND late_receipt_at_ms IS NULL",
                params![self.now_ms(), execution_id, node_id],
            )?;
            if changed == 0 {
                return Ok(ReceiptOutcome::AlreadyTerminalOwned);
            }
            self.append_event(actor, Event::ExecutionLateReceipt(payload))?;
            return Ok(ReceiptOutcome::LateReceiptRecorded);
        }
        if old_state.is_terminal() {
            return Ok(ReceiptOutcome::AlreadyTerminalOwned);
        }

        let bytes = receipt.sealed_result_blob.as_ref().map_or(0, Vec::len);
        // A receipt can itself report Unknown. Record that it was seen so a
        // retransmission does not look like the first late receipt.
        self.conn().execute(
            "UPDATE executions SET state = ?1, summary_json = ?2, sealed_result_blob = ?3, result_bytes = ?4,
                 result_truncated = ?5, finished_at_ms = ?6, late_receipt_at_ms = ?7
             WHERE execution_id = ?8",
            params![scalar_text(state)?, summary_json, receipt.sealed_result_blob, bytes, receipt.result_truncated,
                receipt.finished_at_ms, (state == ExecutionState::Unknown).then_some(self.now_ms()),
                execution_id],
        )?;
        let event = if state == ExecutionState::Cancelled {
            Event::ExecutionCancelled(payload)
        } else {
            Event::ExecutionFinished(payload)
        };
        self.append_event(actor, event)?;
        self.stage_waiter_finish(
            receipt.execution_id,
            ExecutionSnapshot {
                state,
                finished_at_ms: Some(receipt.finished_at_ms),
            },
        );
        Ok(ReceiptOutcome::AppliedTerminal)
    }
}

struct RecordedInvocation {
    execution_id: ExecutionId,
    kind: InvokeKind,
    digest: String,
    profile_id: Option<ProfileId>,
    profile_version: Option<u64>,
    tool_id: ToolId,
    public_name: String,
    snapshot: ExecutionSnapshot,
}

fn replay(
    tx: &WriteTx<'_>,
    request: &InvokeWrite,
    recorded: RecordedInvocation,
) -> Result<InvokeOutcome, WriteTxError<InvokeWriteError>> {
    let conflict = || WriteTxError::Domain(InvokeWriteError::RequestIdConflict);
    if recorded.kind != request.resource.kind() || recorded.public_name != request.public_name {
        return Err(conflict());
    }
    let (fixed_node_id, requested_version) = match request.resource {
        InvokeResource::Profile { profile_id, .. } => {
            if recorded.profile_id != Some(profile_id) {
                return Err(conflict());
            }
            let original = binding(
                tx,
                profile_id,
                recorded
                    .profile_version
                    .ok_or(rusqlite::Error::InvalidQuery)?,
                &recorded.public_name,
            )?
            .filter(|binding| binding.tool_id == recorded.tool_id)
            .ok_or(rusqlite::Error::InvalidQuery)?;
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
    if digest(
        request,
        recorded.profile_id,
        recorded.tool_id,
        fixed_node_id,
        requested_version,
    )? != recorded.digest
    {
        return Err(conflict());
    }
    let waiter = if recorded.snapshot.state.is_terminal() {
        None
    } else {
        // An active row always has either a committed or a staged sender.
        Some(
            tx.waiter(recorded.execution_id)
                .ok_or(rusqlite::Error::InvalidQuery)?,
        )
    };
    Ok(InvokeOutcome {
        execution_id: recorded.execution_id,
        snapshot: recorded.snapshot,
        replayed: true,
        waiter,
    })
}

fn binding(
    tx: &WriteTx<'_>,
    profile_id: ProfileId,
    version: u64,
    name: &str,
) -> rusqlite::Result<Option<ProfileToolBinding>> {
    let bindings: Option<Vec<ProfileToolBinding>> = tx
        .conn()
        .query_row(
            "SELECT bindings_json FROM profile_editions WHERE profile_id = ?1 AND version = ?2",
            params![profile_id.to_string(), version],
            |row| json(row, 0),
        )
        .optional()?;
    let Some(bindings) = bindings else {
        return Ok(None);
    };
    validate_profile_bindings(&bindings).map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(bindings
        .into_iter()
        .find(|binding| binding.public_name == name))
}

fn digest(
    request: &InvokeWrite,
    profile_id: Option<ProfileId>,
    tool_id: ToolId,
    fixed_node_id: Option<NodeId>,
    requested_tool_version: Option<NonZeroU64>,
) -> Result<String, WriteTxError<InvokeWriteError>> {
    compute_request_digest(&RequestDigestInput {
        invoke_kind: request.resource.kind(),
        profile_id,
        tool_id,
        public_name: &request.public_name,
        requested_target: request.requested_target.as_deref(),
        fixed_node_id,
        arguments: &request.arguments,
        requested_tool_version,
    })
    .map_err(|error| WriteTxError::Domain(error.into()))
}
