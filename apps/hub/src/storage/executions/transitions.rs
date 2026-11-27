use std::convert::Infallible;

use efferian_protocol::{
    ActorId, Event, ExecuteAckPayload, ExecutionEventPayload, ExecutionId, ExecutionState,
    ExecutionSummary, ExecutorKind, NodeId, PrincipalId, ProfileId, TerminalExecutionState, ToolId,
    validate_terminal_summary,
};
use rusqlite::{OptionalExtension, Row, params};

use super::super::actor::{ExecutionSnapshot, WriteTx, WriteTxError};
use super::super::events::{id, json_write_error, opt_id, scalar, scalar_text};
use super::super::{PrincipalLiveness, StorageError, WriteError};
use super::{InvalidReceipt, PreparedReceipt, ReceiptOutcome};

pub(crate) const TRANSITION_BATCH: usize = 32;

// Charge the serialized summary using the longest possible Hub-computed duration.
pub(super) fn terminal_work_bytes(
    summary: &ExecutionSummary,
    blob: Option<&[u8]>,
) -> Result<usize, StorageError> {
    let mut summary = summary.clone();
    summary.duration_ms = Some(u64::MAX);
    Ok(serde_json::to_string(&summary)
        .map_err(json_write_error)?
        .len()
        .saturating_add(blob.map_or(0, <[u8]>::len)))
}

pub(crate) struct PreparedOutcome {
    state: TerminalExecutionState,
    summary: ExecutionSummary,
    blob: Option<Vec<u8>>,
    payload_bytes: usize,
}

impl PreparedOutcome {
    pub(crate) fn new(
        state: TerminalExecutionState,
        summary: ExecutionSummary,
        blob: Option<Vec<u8>>,
    ) -> Result<Self, InvalidReceipt> {
        validate_terminal_summary(state, &summary, blob.is_some(), false)
            .map_err(|_| InvalidReceipt)?;
        let payload_bytes =
            terminal_work_bytes(&summary, blob.as_deref()).map_err(|_| InvalidReceipt)?;
        Ok(Self {
            state,
            summary,
            blob,
            payload_bytes,
        })
    }

    pub(crate) fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }
}

#[derive(Clone, Copy)]
pub(crate) enum CloseExecutions {
    Deadline,
    Restart,
    Shutdown,
}

impl CloseExecutions {
    fn reason(self) -> &'static str {
        match self {
            Self::Deadline => "deadline_exceeded",
            Self::Restart => "hub_restarted",
            Self::Shutdown => "hub_shutting_down",
        }
    }
}

struct TransitionRow {
    id: ExecutionId,
    profile: Option<ProfileId>,
    tool: ToolId,
    public_name: String,
    node: Option<NodeId>,
    executor: ExecutorKind,
    state: ExecutionState,
    started_or_created_at_ms: i64,
}

const TRANSITION_FIELDS: &str = "execution_id, profile_id, tool_id, public_name, node_id,
    executor_kind, state, COALESCE(started_at_ms, created_at_ms)";

impl TransitionRow {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: id(row, 0)?,
            profile: opt_id(row, 1)?,
            tool: id(row, 2)?,
            public_name: row.get(3)?,
            node: opt_id(row, 4)?,
            executor: scalar(row, 5)?,
            state: scalar(row, 6)?,
            started_or_created_at_ms: row.get(7)?,
        })
    }

    fn event(&self, state: ExecutionState, summary: &ExecutionSummary) -> ExecutionEventPayload {
        ExecutionEventPayload {
            execution_id: self.id,
            state,
            profile_id: self.profile,
            tool_id: self.tool,
            public_name: self.public_name.clone(),
            node_id: self.node,
            exit_code: summary.exit_code,
            error_code: summary.error_code.clone(),
            duration_ms: summary.duration_ms,
        }
    }

    fn duration_ms(&self, now_ms: i64) -> u64 {
        now_ms.saturating_sub(self.started_or_created_at_ms).max(0) as u64
    }
}

impl super::super::StorageHandle {
    /// Acknowledgments use the same epoch and ownership fences as terminal receipts.
    #[allow(dead_code, reason = "managed acknowledgment seam for the node bridge")]
    pub(crate) async fn apply_execute_ack(
        &self,
        node_id: NodeId,
        frame_epoch: u64,
        ack: ExecuteAckPayload,
    ) -> Result<bool, WriteError<Infallible>> {
        self.execute_work(0, move |tx| {
            Ok(tx.apply_execute_ack(node_id, frame_epoch, ack.execution_id)?)
        })
        .await
    }
}

impl WriteTx<'_> {
    fn transition_row(
        &self,
        execution_id: ExecutionId,
    ) -> Result<Option<TransitionRow>, StorageError> {
        let sql = format!("SELECT {TRANSITION_FIELDS} FROM executions WHERE execution_id = ?1");
        Ok(self
            .conn()
            .prepare_cached(&sql)?
            .query_row([execution_id.to_string()], TransitionRow::read)
            .optional()?)
    }

    pub(crate) fn active_node_epoch(&self, node_id: NodeId) -> Result<Option<u64>, StorageError> {
        let node = self
            .conn()
            .prepare_cached(
                "SELECT session_epoch, managed_by_principal_id FROM nodes
             WHERE node_id = ?1 AND revoked_at_ms IS NULL",
            )?
            .query_row([node_id.to_string()], |row| {
                Ok((row.get::<_, u64>(0)?, opt_id(row, 1)?))
            })
            .optional()?;
        let Some((epoch, manager)) = node else {
            return Ok(None);
        };
        if let Some(manager) = manager
            && self.principal_liveness(manager)? != PrincipalLiveness::Enabled
        {
            return Ok(None);
        }
        Ok(Some(epoch))
    }

    fn apply_execute_ack(
        &mut self,
        node_id: NodeId,
        frame_epoch: u64,
        execution_id: ExecutionId,
    ) -> Result<bool, StorageError> {
        if self.active_node_epoch(node_id)? != Some(frame_epoch) {
            return Ok(false);
        }
        let Some(row) = self
            .transition_row(execution_id)?
            .filter(|row| row.node == Some(node_id) && row.state == ExecutionState::Accepted)
        else {
            return Ok(false);
        };
        self.conn().prepare_cached(
            "UPDATE executions SET state = 'running', started_at_ms = ?1 WHERE execution_id = ?2",
        )?.execute(params![self.now_ms(), execution_id.to_string()])?;
        self.append_event(
            ActorId::Node(node_id),
            Event::ExecutionStarted(
                row.event(ExecutionState::Running, &ExecutionSummary::default()),
            ),
        )?;
        self.stage_waiter_update(
            execution_id,
            ExecutionSnapshot {
                state: ExecutionState::Running,
                finished_at_ms: None,
            },
        );
        Ok(true)
    }

    pub(crate) fn apply_receipt(
        &mut self,
        prepared: PreparedReceipt,
    ) -> Result<ReceiptOutcome, WriteTxError<InvalidReceipt>> {
        let receipt = prepared.receipt;
        if self.active_node_epoch(receipt.node_id)? != Some(receipt.frame_epoch) {
            return Ok(ReceiptOutcome::NotOwnedOrNotFound);
        }
        let Some(row) = self
            .transition_row(receipt.execution_id)?
            .filter(|row| row.node == Some(receipt.node_id))
        else {
            return Ok(ReceiptOutcome::NotOwnedOrNotFound);
        };
        let actor = ActorId::Node(receipt.node_id);
        if row.state == ExecutionState::Unknown {
            let changed = self
                .conn()
                .prepare_cached(
                    "UPDATE executions SET late_receipt_at_ms = ?1 WHERE execution_id = ?2
                 AND state = 'unknown' AND late_receipt_at_ms IS NULL",
                )?
                .execute(params![self.now_ms(), receipt.execution_id.to_string()])?;
            if changed == 0 {
                return Ok(ReceiptOutcome::AlreadyTerminalOwned);
            }
            let mut summary = receipt.summary;
            summary.duration_ms = Some(row.duration_ms(self.now_ms()));
            self.append_event(
                actor,
                Event::ExecutionLateReceipt(row.event(receipt.state.into(), &summary)),
            )?;
            return Ok(ReceiptOutcome::LateReceiptRecorded);
        }
        if row.state.is_terminal() {
            return Ok(ReceiptOutcome::AlreadyTerminalOwned);
        }
        self.finish_active(
            &row,
            actor,
            receipt.state,
            &receipt.summary,
            receipt.sealed_result_blob.as_deref(),
            receipt.result_truncated,
        )?;
        if receipt.state == TerminalExecutionState::Unknown {
            // A receipt that reports Unknown is already seen. Its retransmission is not a late result.
            self.conn()
                .prepare_cached(
                    "UPDATE executions SET late_receipt_at_ms = ?1 WHERE execution_id = ?2",
                )?
                .execute(params![self.now_ms(), receipt.execution_id.to_string()])?;
        }
        Ok(ReceiptOutcome::AppliedTerminal)
    }

    pub(crate) fn fail_node_dispatch(
        &mut self,
        execution_id: ExecutionId,
        error_code: &'static str,
    ) -> Result<(), StorageError> {
        let Some(row) = self.transition_row(execution_id)?.filter(|row| {
            row.executor == ExecutorKind::Node && row.state == ExecutionState::Accepted
        }) else {
            return Ok(());
        };
        self.finish_active(
            &row,
            ActorId::Hub(self.hub_id),
            TerminalExecutionState::Failed,
            &closure_summary(error_code, false),
            None,
            false,
        )?;
        Ok(())
    }

    pub(crate) fn finish_upstream(
        &mut self,
        execution_id: ExecutionId,
        outcome: &PreparedOutcome,
    ) -> Result<bool, StorageError> {
        let Some(row) = self
            .transition_row(execution_id)?
            .filter(|row| row.executor == ExecutorKind::Upstream && !row.state.is_terminal())
        else {
            return Ok(false);
        };
        self.finish_active(
            &row,
            ActorId::Hub(self.hub_id),
            outcome.state,
            &outcome.summary,
            outcome.blob.as_deref(),
            false,
        )
    }

    pub(crate) fn cancel_upstream_execution(
        &mut self,
        execution_id: ExecutionId,
        caller: PrincipalId,
    ) -> Result<bool, StorageError> {
        let Some(row) = self
            .transition_row(execution_id)?
            .filter(|row| row.executor == ExecutorKind::Upstream && !row.state.is_terminal())
        else {
            return Ok(false);
        };
        self.cancel_execution(execution_id)?;
        self.finish_active(
            &row,
            ActorId::Principal(caller),
            TerminalExecutionState::Cancelled,
            &ExecutionSummary {
                effect_may_have_occurred: Some(true),
                ..Default::default()
            },
            None,
            false,
        )
    }

    /// Returns the number processed and IDs whose upstream I/O should stop after commit.
    pub(crate) fn close_executions(
        &mut self,
        cause: CloseExecutions,
    ) -> Result<(usize, Vec<ExecutionId>), StorageError> {
        let suffix = match cause {
            CloseExecutions::Deadline => {
                "AND deadline_at_ms <= ?1 ORDER BY deadline_at_ms, execution_id LIMIT ?2"
            }
            CloseExecutions::Restart | CloseExecutions::Shutdown => {
                "AND executor_kind = 'upstream' ORDER BY deadline_at_ms, execution_id LIMIT ?2"
            }
        };
        let sql = format!(
            "SELECT {TRANSITION_FIELDS} FROM executions WHERE state IN ('accepted', 'running') {suffix}"
        );
        let rows = self
            .conn()
            .prepare_cached(&sql)?
            .query_map(
                params![self.now_ms(), TRANSITION_BATCH],
                TransitionRow::read,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut upstreams = Vec::new();
        for row in &rows {
            self.finish_active(
                row,
                ActorId::Hub(self.hub_id),
                TerminalExecutionState::Unknown,
                &closure_summary(cause.reason(), true),
                None,
                false,
            )?;
            if row.executor == ExecutorKind::Upstream {
                upstreams.push(row.id);
            }
        }
        Ok((rows.len(), upstreams))
    }

    fn finish_active(
        &mut self,
        row: &TransitionRow,
        actor: ActorId,
        state: TerminalExecutionState,
        summary: &ExecutionSummary,
        blob: Option<&[u8]>,
        result_truncated: bool,
    ) -> Result<bool, StorageError> {
        let now = self.now_ms();
        let mut summary = summary.clone();
        summary.duration_ms = Some(row.duration_ms(now));
        let summary_json = serde_json::to_string(&summary).map_err(json_write_error)?;
        let state = ExecutionState::from(state);
        let changed = self
            .conn()
            .prepare_cached(
                "UPDATE executions SET state = ?1, summary_json = ?2, sealed_result_blob = ?3,
                 result_bytes = ?4, result_truncated = ?5, finished_at_ms = ?6
             WHERE execution_id = ?7 AND executor_kind = ?8 AND state IN ('accepted', 'running')",
            )?
            .execute(params![
                scalar_text(state)?,
                summary_json,
                blob,
                blob.map_or(0, <[u8]>::len),
                result_truncated,
                now,
                row.id.to_string(),
                scalar_text(row.executor)?,
            ])?;
        if changed == 0 {
            return Ok(false);
        }
        if blob.is_some() {
            self.note_result_blob_written();
        }
        let payload = row.event(state, &summary);
        let event = if state == ExecutionState::Cancelled {
            Event::ExecutionCancelled(payload)
        } else {
            Event::ExecutionFinished(payload)
        };
        self.append_event(actor, event)?;
        self.stage_waiter_finish(
            row.id,
            ExecutionSnapshot {
                state,
                finished_at_ms: Some(now),
            },
        );
        Ok(true)
    }
}

fn closure_summary(error_code: &str, effect_may_have_occurred: bool) -> ExecutionSummary {
    ExecutionSummary {
        error_code: Some(error_code.to_owned()),
        effect_may_have_occurred: Some(effect_may_have_occurred),
        ..Default::default()
    }
}
