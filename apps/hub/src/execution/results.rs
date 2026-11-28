use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use efferian_protocol::{
    ExecuteResPayload, ExecutionId, ExecutionState, ExecutionSummary, MAX_OUTPUT_BYTES, NodeId,
    PrincipalId, StoredResult, TerminalExecutionState, ToolDefinition, UpstreamMcpResult,
    UpstreamMcpResultType, error_codes,
};
use rmcp::model::CallToolResult;
use rusqlite::{OptionalExtension, params};
use zeroize::{Zeroize, Zeroizing};

use crate::http::{ApiError, ApiResult, AppState};
use crate::storage::{
    PreparedOutcome, ReceiptOutcome, ReceiptWrite, StorageError, StorageHandle, WriteError, id,
    optional_json, scalar,
};
use crate::upstream_dispatch::{InvokeUpstream, UpstreamDispatchError};
use crate::vault::{ExecutionAad, Vault};

use super::state::UpstreamReservation;

const FORMAT_V1: u8 = 1;
const MANAGED: u8 = 0;
const UPSTREAM_MCP: u8 = 1;
const MAX_MANAGED_TEXT_BYTES: usize = 3 * MAX_OUTPUT_BYTES as usize;
const MAX_UPSTREAM_BYTES: usize = 2 * 1024 * 1024;
const OFFLOAD_BYTES: usize = 64 * 1024;
const MAX_TERMINAL_COMMIT_RETRIES: u8 = 4;
const TERMINAL_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(25);
const TERMINAL_RETRY_MAX_DELAY: Duration = Duration::from_millis(250);

#[derive(Debug, thiserror::Error)]
#[error("invalid stored execution result")]
struct InvalidResult;

/// Typed errors for the in-process node bridge receipt seam (`#7`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[allow(dead_code, reason = "classified receipt errors for the node bridge")]
pub(crate) enum NodeReceiptError {
    #[error("node receipt payload violates protocol limits or invariants")]
    InvalidPayload,
    #[error("storage queue is overloaded")]
    Overloaded,
    #[error("receipt commit aborted or outcome unknown; caller may retry")]
    RetryableCommit,
    #[error("hub storage is shutting down")]
    ShuttingDown,
    #[error("hub storage actor has stopped")]
    ActorStopped,
    #[error("internal storage or vault failure")]
    Internal,
}

impl From<StorageError> for NodeReceiptError {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::Overloaded => Self::Overloaded,
            StorageError::ShuttingDown => Self::ShuttingDown,
            StorageError::ActorStopped => Self::ActorStopped,
            _ => Self::Internal,
        }
    }
}

/// Seal a managed result using its original revision and the writer's
/// current-session fence.
#[allow(dead_code, reason = "managed result seam for the node bridge")]
pub(crate) async fn apply_node_result(
    storage: &StorageHandle,
    vault: &Arc<Vault>,
    node_id: NodeId,
    frame_epoch: u64,
    payload: ExecuteResPayload,
) -> Result<ReceiptOutcome, NodeReceiptError> {
    let execution_id = payload.execution_id;
    let Ok(sql_epoch) = i64::try_from(frame_epoch) else {
        return Ok(ReceiptOutcome::NotOwnedOrNotFound);
    };
    let target = storage
        .read_snapshot(move |conn| {
            let record = conn
                .prepare_cached(
                    "SELECT e.caller_principal_id, e.state, r.definition_json
             FROM executions e JOIN nodes n ON n.node_id = e.node_id
             LEFT JOIN tool_revisions r ON r.tool_id = e.tool_id AND r.version = e.tool_version
             WHERE e.execution_id = ?1 AND e.node_id = ?2 AND n.session_epoch = ?3
               AND n.revoked_at_ms IS NULL",
                )?
                .query_row(
                    params![execution_id.to_string(), node_id.to_string(), sql_epoch],
                    |row| {
                        Ok((
                            id::<PrincipalId>(row, 0)?,
                            scalar::<ExecutionState>(row, 1)?,
                            optional_json::<ToolDefinition>(row, 2)?,
                        ))
                    },
                )
                .optional()?;
            Ok::<_, StorageError>(record)
        })
        .await?;
    let Some((caller_principal_id, state_before, definition)) = target else {
        return Ok(ReceiptOutcome::NotOwnedOrNotFound);
    };
    let max_output = if let Some(definition) = definition {
        definition
            .spec
            .max_output_bytes()
            .ok_or(NodeReceiptError::Internal)?
    } else if state_before.is_terminal() {
        // Terminal rows do not pin revisions. A late receipt can record metadata
        // but can never replace the settled terminal payload.
        MAX_OUTPUT_BYTES
    } else {
        return Err(NodeReceiptError::Internal);
    };
    let summary = payload
        .summary(None)
        .map_err(|_| NodeReceiptError::InvalidPayload)?;
    let terminal_state = payload.state;
    let result_truncated = payload.truncated;
    let prepared_result =
        prepare_managed_result(payload, max_output, !state_before.is_terminal()).await?;
    let sealed_result_blob = if let Some(plaintext) = prepared_result {
        let aad = ExecutionAad {
            execution_id,
            caller_principal_id,
        };
        Some(
            vault
                .seal_execution_async(aad, plaintext)
                .await
                .map_err(|_| NodeReceiptError::Internal)?,
        )
    } else {
        None
    };
    storage
        .apply_receipt(ReceiptWrite {
            execution_id,
            node_id,
            frame_epoch,
            state: terminal_state,
            summary,
            sealed_result_blob,
            result_truncated,
        })
        .await
        .map_err(|error| match error {
            WriteError::Domain(_) => NodeReceiptError::InvalidPayload,
            WriteError::Storage(error) => error.into(),
            WriteError::PreCommitAborted | WriteError::CommitOutcomeUnknown => {
                NodeReceiptError::RetryableCommit
            }
        })
}

async fn prepare_managed_result(
    mut payload: ExecuteResPayload,
    max_output: u32,
    store_output: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>, NodeReceiptError> {
    // The payload crosses this function by value so encoded output can be
    // zeroized and freed before allocating the normalized UTF-8 plaintext.
    let encoded_bytes = payload
        .stdout_b64
        .as_ref()
        .map_or(0, String::len)
        .saturating_add(payload.stderr_b64.as_ref().map_or(0, String::len));
    let prepare = move || {
        let decoded = payload.decode_and_validate_output(max_output);
        let has_output = payload.stdout_b64.is_some()
            || payload.stderr_b64.is_some()
            || payload.exit_code.is_some()
            || payload.http_status.is_some();
        let exit_code = payload.exit_code;
        let http_status = payload.http_status;
        let discarded = payload.output_discarded_reason.is_some();
        payload.stdout_b64.zeroize();
        payload.stderr_b64.zeroize();
        drop(payload);
        let decoded = decoded.map_err(|_| NodeReceiptError::InvalidPayload)?;
        if !store_output || discarded || !has_output {
            return Ok(None);
        }
        let stored = StoredResult::managed_from_bytes(
            &decoded.stdout,
            &decoded.stderr,
            exit_code,
            http_status,
            max_output,
        )
        .map_err(|_| NodeReceiptError::InvalidPayload)?;
        drop(decoded);
        encode_managed(stored)
            .map(Some)
            .map_err(|_| NodeReceiptError::Internal)
    };
    if encoded_bytes >= OFFLOAD_BYTES {
        tokio::task::spawn_blocking(prepare)
            .await
            .map_err(|_| NodeReceiptError::Internal)?
    } else {
        prepare()
    }
}

/// Owns one accepted upstream outcome until a terminal CAS commits or the
/// writer/deadline ends delivery. Retrying the write never replays the MCP call.
pub(crate) async fn run_upstream(
    state: AppState,
    request: InvokeUpstream,
    reservation: UpstreamReservation,
    caller_principal_id: PrincipalId,
    timeout: Duration,
    deadline_at_ms: i64,
) {
    let execution_id = request.execution_id;
    let cancellation = reservation.cancellation();
    if cancellation.is_cancelled() || state.clock.wall_now_ms() >= deadline_at_ms {
        return;
    }
    let invoke = state.upstream.invoke(request, cancellation.clone());
    let result = tokio::time::timeout(timeout, invoke).await;
    // Shutdown cancels transport I/O before its writer sweep. The sweep
    // supplies the durable cause for work interrupted by that signal.
    if !state.execution.is_accepting() && !matches!(&result, Ok(Ok(_))) {
        return;
    }
    // Skip expensive validation/sealing when user cancel or shutdown already settled the row.
    if cancellation.is_cancelled() {
        return;
    }
    let outcome = match result {
        Ok(Ok(result)) => {
            prepare_upstream(&state.vault, execution_id, caller_principal_id, result).await
        }
        Ok(Err(error)) => upstream_failure(error),
        Err(_) => {
            state.upstream.cancel(execution_id);
            upstream_failure(UpstreamDispatchError::TimedOut)
        }
    };
    let Ok(outcome) = outcome else {
        tracing::error!(%execution_id, "could not prepare execution outcome");
        return;
    };
    finish_upstream(&state, execution_id, Arc::new(outcome), deadline_at_ms).await;
    // Keep the slot even if a concurrent user cancel already settled its row.
    drop(reservation);
}

async fn finish_upstream(
    state: &AppState,
    execution_id: ExecutionId,
    outcome: Arc<PreparedOutcome>,
    deadline_at_ms: i64,
) {
    let mut commit_retries = 0;
    let mut delay = TERMINAL_RETRY_INITIAL_DELAY;
    let mut attempted = false;
    loop {
        if attempted && state.clock.wall_now_ms() >= deadline_at_ms {
            tracing::warn!(%execution_id, "execution outcome delivery reached deadline");
            return;
        }
        attempted = true;
        let prepared = Arc::clone(&outcome);
        let written = state
            .storage
            .execute_work(outcome.payload_bytes(), move |tx| {
                Ok::<_, crate::storage::WriteTxError<Infallible>>(
                    tx.finish_upstream(execution_id, &prepared)?,
                )
            })
            .await;
        match written {
            Ok(_)
            | Err(WriteError::Storage(StorageError::ActorStopped | StorageError::ShuttingDown)) => {
                return;
            }
            Err(WriteError::Storage(StorageError::Overloaded)) => {}
            Err(WriteError::PreCommitAborted | WriteError::CommitOutcomeUnknown)
                if commit_retries < MAX_TERMINAL_COMMIT_RETRIES =>
            {
                commit_retries += 1;
            }
            Err(error) => {
                tracing::warn!(%execution_id, %error, "execution outcome delivery stopped");
                return;
            }
        }
        tokio::time::sleep(delay).await;
        delay = delay.saturating_mul(2).min(TERMINAL_RETRY_MAX_DELAY);
    }
}

async fn prepare_upstream(
    vault: &Arc<Vault>,
    execution_id: ExecutionId,
    caller_principal_id: PrincipalId,
    raw: Bytes,
) -> Result<PreparedOutcome, crate::storage::InvalidReceipt> {
    if raw.len() > MAX_UPSTREAM_BYTES {
        return upstream_failure(UpstreamDispatchError::InvalidResponse);
    }
    let len = raw.len();
    let prepare = move || {
        // Validate the same normalization path used when the payload is opened.
        project_mcp(&raw)?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(raw.len() + 2));
        plaintext.extend_from_slice(&[FORMAT_V1, UPSTREAM_MCP]);
        plaintext.extend_from_slice(&raw);
        Ok::<_, InvalidResult>(plaintext)
    };
    let plaintext = if len >= OFFLOAD_BYTES {
        match tokio::task::spawn_blocking(prepare).await {
            Ok(plaintext) => plaintext,
            Err(_) => return Err(crate::storage::InvalidReceipt),
        }
    } else {
        prepare()
    };
    let Ok(plaintext) = plaintext else {
        return upstream_failure(UpstreamDispatchError::InvalidResponse);
    };
    let aad = ExecutionAad {
        execution_id,
        caller_principal_id,
    };
    let Ok(blob) = vault.seal_execution_async(aad, plaintext).await else {
        return failure(
            TerminalExecutionState::Failed,
            error_codes::RESULT_STORAGE_FAILED,
            true,
        );
    };
    PreparedOutcome::new(
        TerminalExecutionState::Succeeded,
        ExecutionSummary {
            effect_may_have_occurred: Some(true),
            ..Default::default()
        },
        Some(blob),
    )
}

fn upstream_failure(
    error: UpstreamDispatchError,
) -> Result<PreparedOutcome, crate::storage::InvalidReceipt> {
    let (state, code, possible_effect) = match error {
        UpstreamDispatchError::Unavailable => (
            TerminalExecutionState::Failed,
            error_codes::UPSTREAM_UNAVAILABLE,
            false,
        ),
        UpstreamDispatchError::AuthFailed => (
            TerminalExecutionState::Failed,
            error_codes::UPSTREAM_AUTH_FAILED,
            false,
        ),
        UpstreamDispatchError::TimedOut => (
            TerminalExecutionState::TimedOut,
            error_codes::UPSTREAM_TIMEOUT,
            true,
        ),
        UpstreamDispatchError::InvalidResponse => (
            TerminalExecutionState::Failed,
            error_codes::UPSTREAM_INVALID_RESPONSE,
            true,
        ),
        UpstreamDispatchError::Disconnected => (
            TerminalExecutionState::Unknown,
            error_codes::UPSTREAM_DISCONNECTED,
            true,
        ),
    };
    failure(state, code, possible_effect)
}

fn failure(
    state: TerminalExecutionState,
    code: &str,
    possible_effect: bool,
) -> Result<PreparedOutcome, crate::storage::InvalidReceipt> {
    PreparedOutcome::new(
        state,
        ExecutionSummary {
            error_code: Some(code.to_owned()),
            effect_may_have_occurred: Some(possible_effect),
            ..Default::default()
        },
        None,
    )
}

pub(crate) async fn open_result(
    vault: &Arc<Vault>,
    aad: ExecutionAad,
    envelope: Vec<u8>,
) -> ApiResult<StoredResult> {
    let plaintext = vault.open_execution_async(aad, envelope).await?;
    let result = if plaintext.len() >= OFFLOAD_BYTES {
        tokio::task::spawn_blocking(move || decode_result(&plaintext))
            .await
            .map_err(|_| ApiError::internal())?
    } else {
        decode_result(&plaintext)
    };
    result.map_err(|_| ApiError::internal())
}

fn encode_managed(result: StoredResult) -> Result<Zeroizing<Vec<u8>>, InvalidResult> {
    let StoredResult::Managed {
        stdout,
        stderr,
        exit_code,
        http_status,
    } = result
    else {
        return Err(InvalidResult);
    };
    let stdout = Zeroizing::new(stdout);
    let stderr = Zeroizing::new(stderr);
    let bytes = stdout
        .len()
        .checked_add(stderr.len())
        .filter(|&len| len <= MAX_MANAGED_TEXT_BYTES)
        .ok_or(InvalidResult)?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(bytes + 17));
    let flags = u8::from(exit_code.is_some()) | (u8::from(http_status.is_some()) << 1);
    plaintext.extend_from_slice(&[FORMAT_V1, MANAGED, flags]);
    for stream in [&*stdout, &*stderr] {
        let len = u32::try_from(stream.len()).map_err(|_| InvalidResult)?;
        plaintext.extend_from_slice(&len.to_be_bytes());
        plaintext.extend_from_slice(stream.as_bytes());
    }
    if let Some(code) = exit_code {
        plaintext.extend_from_slice(&code.to_be_bytes());
    }
    if let Some(status) = http_status {
        plaintext.extend_from_slice(&status.to_be_bytes());
    }
    Ok(plaintext)
}

fn decode_result(raw: &[u8]) -> Result<StoredResult, InvalidResult> {
    match raw {
        [FORMAT_V1, MANAGED, body @ ..] => decode_managed(body),
        [FORMAT_V1, UPSTREAM_MCP, body @ ..] if body.len() <= MAX_UPSTREAM_BYTES => {
            project_mcp(body).map(|result| StoredResult::UpstreamMcp { result })
        }
        _ => Err(InvalidResult),
    }
}

fn decode_managed(mut body: &[u8]) -> Result<StoredResult, InvalidResult> {
    let [flags] = take_fixed(&mut body)?;
    if flags & !0b11 != 0 {
        return Err(InvalidResult);
    }
    let stdout = take_text(&mut body)?;
    let stderr = take_text(&mut body)?;
    if stdout.len().saturating_add(stderr.len()) > MAX_MANAGED_TEXT_BYTES {
        return Err(InvalidResult);
    }
    let exit_code = (flags & 1 != 0)
        .then(|| take_fixed(&mut body).map(i32::from_be_bytes))
        .transpose()?;
    let http_status = (flags & 2 != 0)
        .then(|| take_fixed(&mut body).map(u16::from_be_bytes))
        .transpose()?;
    if !body.is_empty() {
        return Err(InvalidResult);
    }
    Ok(StoredResult::Managed {
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
        exit_code,
        http_status,
    })
}

fn take_fixed<const N: usize>(body: &mut &[u8]) -> Result<[u8; N], InvalidResult> {
    let (head, tail) = body.split_first_chunk::<N>().ok_or(InvalidResult)?;
    *body = tail;
    Ok(*head)
}

fn take_text<'a>(body: &mut &'a [u8]) -> Result<&'a str, InvalidResult> {
    let len = u32::from_be_bytes(take_fixed(body)?) as usize;
    let (text, tail) = body.split_at_checked(len).ok_or(InvalidResult)?;
    *body = tail;
    std::str::from_utf8(text).map_err(|_| InvalidResult)
}

fn project_mcp(raw: &[u8]) -> Result<UpstreamMcpResult, InvalidResult> {
    let parsed: CallToolResult = serde_json::from_slice(raw).map_err(|_| InvalidResult)?;
    // Through JSON text, f32 values keep their wire decimal and nested SDK
    // content blocks cannot leak fields absent from the supported model.
    let content = serde_json::to_vec(&parsed.content).map_err(|_| InvalidResult)?;
    let content = serde_json::from_slice(&content).map_err(|_| InvalidResult)?;
    Ok(UpstreamMcpResult {
        result_type: parsed.result_type.map(|_| UpstreamMcpResultType::Complete),
        content,
        structured_content: parsed.structured_content,
        is_error: parsed.is_error,
        meta: parsed.meta.map(|object| object.0.into_iter().collect()),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "fixtures must encode and decode")]

    use super::*;

    #[test]
    fn result_envelope_decode_rejects_malformed_frames() {
        let valid = StoredResult::Managed {
            stdout: "out".to_owned(),
            stderr: "err".to_owned(),
            exit_code: Some(42),
            http_status: Some(200),
        };
        let encoded = encode_managed(valid.clone()).unwrap();
        assert_eq!(decode_result(&encoded).unwrap(), valid);

        // Trailing bytes, bad format version, unknown kind, and reserved flag bits.
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(decode_result(&trailing).is_err());

        let mut bad_version = encoded.to_vec();
        bad_version[0] = 2;
        assert!(decode_result(&bad_version).is_err());

        let mut bad_kind = encoded.to_vec();
        bad_kind[1] = 9;
        assert!(decode_result(&bad_kind).is_err());

        let mut bad_flags = encoded.to_vec();
        bad_flags[2] |= 0b100;
        assert!(decode_result(&bad_flags).is_err());

        // Truncation at every prefix length must fail cleanly.
        for len in 0..encoded.len() {
            assert!(decode_result(&encoded[..len]).is_err(), "len={len}");
        }

        // Invalid UTF-8 in stdout.
        let mut bad_utf8 = vec![FORMAT_V1, MANAGED, 0];
        bad_utf8.extend_from_slice(&2u32.to_be_bytes());
        bad_utf8.extend_from_slice(&[0xff, 0xfe]);
        bad_utf8.extend_from_slice(&0u32.to_be_bytes());
        assert!(decode_result(&bad_utf8).is_err());

        // Combined managed text exceeding MAX_MANAGED_TEXT_BYTES.
        let half = (MAX_MANAGED_TEXT_BYTES / 2) + 1;
        let mut oversized_managed = vec![FORMAT_V1, MANAGED, 0];
        oversized_managed.extend_from_slice(&(half as u32).to_be_bytes());
        oversized_managed.resize(oversized_managed.len() + half, b'a');
        oversized_managed.extend_from_slice(&(half as u32).to_be_bytes());
        oversized_managed.resize(oversized_managed.len() + half, b'b');
        assert!(decode_result(&oversized_managed).is_err());

        // Oversized and malformed upstream payloads.
        let mut oversized_upstream = vec![FORMAT_V1, UPSTREAM_MCP];
        oversized_upstream.resize(2 + MAX_UPSTREAM_BYTES + 1, b' ');
        assert!(decode_result(&oversized_upstream).is_err());
        assert!(decode_result(&[FORMAT_V1, UPSTREAM_MCP, b'{']).is_err());
    }
}
