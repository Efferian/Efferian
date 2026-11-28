use std::convert::Infallible;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use efferian_protocol::{
    DiscoveredUpstreamTool, ExecutionId, ExecutionState, PreparedArgumentsDigest, RequestId,
    TokenId, ToolId, UpstreamId,
};
use http::{Method, StatusCode};
use serde_json::json;
use tokio::sync::{mpsc, oneshot, watch};

use crate::config::Config;
use crate::execution::results::run_upstream;
use crate::storage::{
    ExecutionSnapshot, ExecutionTarget, InvokeResource, NewExecutionWrite, PriorityKind,
    WriteError, WriteTxError,
};
use crate::test_support::{TestHub, TestResult};
use crate::upstream_dispatch::{
    DiscoverUpstream, DispatchFuture, InvokeUpstream, UpstreamCancellation, UpstreamDispatchError,
    UpstreamDispatcher,
};

use super::super::{UpstreamReservation, control, sweep_deadlines};
use super::{CountingUpstream, ResultUpstream, add_upstream_tool, blob_lengths, get};

const TEST_TIMEOUT: Duration = Duration::from_secs(3);

struct PendingUpstream {
    request: InvokeUpstream,
    reservation: UpstreamReservation,
    waiter: watch::Receiver<ExecutionSnapshot>,
    deadline: i64,
}

async fn prepare_worker(hub: &TestHub, deadline: i64) -> TestResult<PendingUpstream> {
    let control = Arc::clone(&hub.state.execution);
    let caller = hub.admin_id;
    let execution_id = ExecutionId::new();
    let upstream_id = UpstreamId::new();
    let (outcome, reservation) = hub
        .state
        .storage
        .execute_work(0, move |tx| {
            let reservation = control
                .reserve_upstream(execution_id, upstream_id, caller)
                .ok_or(WriteTxError::InvalidDatabase(
                    "fixture upstream reservation rejected",
                ))?;
            let inserted = tx.insert_execution(NewExecutionWrite {
                execution_id,
                request_id: RequestId::new(),
                caller,
                token: TokenId::new_user_or_agent(),
                resource: InvokeResource::ToolTest {
                    tool_id: ToolId::new(),
                    resolved_version: NonZeroU64::MIN,
                    requested_version: None,
                },
                public_name: "echo".to_owned(),
                requested_target: None,
                arguments: PreparedArgumentsDigest::new(&serde_json::Map::new())
                    .map_err(|_| WriteTxError::InvalidDatabase("fixture arguments rejected"))?,
                executor: ExecutionTarget::Upstream(upstream_id),
                account_id: None,
                deadline_at_ms: deadline,
                resolved_binding: None,
            })?;
            Ok((inserted, reservation))
        })
        .await?;
    Ok(PendingUpstream {
        request: InvokeUpstream {
            execution_id,
            principal_id: caller,
            upstream_id,
            config_version: 1,
            url: "https://example.com/mcp".to_owned(),
            headers: Default::default(),
            auth: None,
            tool_name: "echo".to_owned(),
            arguments: Default::default(),
        },
        reservation,
        waiter: outcome.waiter.ok_or("fixture active waiter missing")?,
        deadline,
    })
}

#[tokio::test]
async fn upstream_cancel_signals_after_commit_and_stays_clear_after_rollback() -> TestResult {
    for rollback in [false, true] {
        let now = RequestId::new().timestamp_ms();
        let upstream = Arc::new(CountingUpstream::default());
        let hub = TestHub::start_with_dispatchers(
            "first-upstream-io",
            Config::default(),
            now,
            None,
            Arc::clone(&upstream) as Arc<dyn UpstreamDispatcher>,
        )
        .await?;
        let PendingUpstream {
            request,
            reservation,
            waiter,
            deadline,
        } = prepare_worker(&hub, now + 90_000).await?;
        let id = request.execution_id;
        let caller = hub.admin_id;
        let app = hub.state.clone();
        let cancellation_handle = reservation.cancellation();

        let result = app
            .storage
            .execute_priority(PriorityKind::CancelExecution, move |tx| {
                control::cancel_upstream(tx, &app.execution, app.upstream, id, caller)?;
                if rollback {
                    tx.conn().execute_batch("ROLLBACK")?;
                }
                Ok::<_, WriteTxError<Infallible>>(())
            })
            .await;
        if rollback {
            assert!(matches!(result, Err(WriteError::PreCommitAborted)));
            assert!(!cancellation_handle.is_cancelled());
            assert_eq!(get(&hub, id, "").await?["state"], "running");
        } else {
            result?;
            assert!(cancellation_handle.is_cancelled());
            assert_eq!(get(&hub, id, "").await?["state"], "cancelled");
        }

        tokio::time::timeout(
            TEST_TIMEOUT,
            run_upstream(
                hub.state.clone(),
                request,
                reservation,
                caller,
                TEST_TIMEOUT,
                deadline,
            ),
        )
        .await?;
        let expected_state = if rollback {
            ExecutionState::Succeeded
        } else {
            ExecutionState::Cancelled
        };
        assert_eq!(waiter.borrow().state, expected_state);
        assert_eq!(upstream.calls.load(Ordering::SeqCst), usize::from(rollback));
        assert_eq!(
            upstream.cancellations.load(Ordering::SeqCst),
            usize::from(!rollback)
        );
        hub.shutdown().await;
    }
    Ok(())
}

struct ControlledReplies(mpsc::UnboundedSender<(ExecutionId, oneshot::Sender<Bytes>)>);

impl UpstreamDispatcher for ControlledReplies {
    fn discover(
        &self,
        request: DiscoverUpstream,
    ) -> DispatchFuture<'_, Result<Vec<DiscoveredUpstreamTool>, UpstreamDispatchError>> {
        ResultUpstream.discover(request)
    }

    fn invoke(
        &self,
        request: InvokeUpstream,
        cancellation: UpstreamCancellation,
    ) -> DispatchFuture<'_, Result<Bytes, UpstreamDispatchError>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(UpstreamDispatchError::Unavailable);
            }
            let (send, receive) = oneshot::channel();
            self.0
                .send((request.execution_id, send))
                .map_err(|_| UpstreamDispatchError::Disconnected)?;
            receive
                .await
                .map_err(|_| UpstreamDispatchError::Disconnected)
        })
    }
}

async fn post_upstream(hub: &TestHub, status: StatusCode) -> TestResult<serde_json::Value> {
    let (actual, body) = hub
        .request_admin(
            Method::POST,
            "/v1/tools/mcp/test",
            Some(json!({"wait_ms": 0})),
        )
        .await?;
    assert_eq!(actual, status, "{body}");
    Ok(body)
}

type DeferredHandoff = (ExecutionId, oneshot::Sender<()>, oneshot::Receiver<bool>);

struct PreparingTransport(mpsc::UnboundedSender<DeferredHandoff>);

impl UpstreamDispatcher for PreparingTransport {
    fn discover(
        &self,
        request: DiscoverUpstream,
    ) -> DispatchFuture<'_, Result<Vec<DiscoveredUpstreamTool>, UpstreamDispatchError>> {
        ResultUpstream.discover(request)
    }

    fn invoke(
        &self,
        request: InvokeUpstream,
        cancellation: UpstreamCancellation,
    ) -> DispatchFuture<'_, Result<Bytes, UpstreamDispatchError>> {
        Box::pin(async move {
            let (resume, preparation) = oneshot::channel();
            let (report, handed_off) = oneshot::channel();
            self.0
                .send((request.execution_id, resume, handed_off))
                .map_err(|_| UpstreamDispatchError::Disconnected)?;
            preparation
                .await
                .map_err(|_| UpstreamDispatchError::Disconnected)?;
            let submitted = !cancellation.is_cancelled();
            let _ = report.send(submitted);
            Err(UpstreamDispatchError::Unavailable)
        })
    }
}

#[tokio::test]
async fn cancel_during_transport_preparation_prevents_the_handoff() -> TestResult {
    let now = RequestId::new().timestamp_ms();
    let (send, mut preparing) = mpsc::unbounded_channel();
    let hub = TestHub::start_with_dispatchers(
        "cancel-during-upstream-preparation",
        Config::default(),
        now,
        None,
        Arc::new(PreparingTransport(send)),
    )
    .await?;
    add_upstream_tool(&hub).await?;
    let admitted = post_upstream(&hub, StatusCode::ACCEPTED).await?;
    let (id, resume, handed_off) = tokio::time::timeout(TEST_TIMEOUT, preparing.recv())
        .await?
        .ok_or("transport did not begin preparation")?;
    assert_eq!(admitted["execution_id"], id.to_string());
    let (status, body) = hub
        .request_admin(Method::POST, &format!("/v1/executions/{id}/cancel"), None)
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "cancelled");
    resume
        .send(())
        .map_err(|()| "transport dropped preparation")?;
    assert!(!tokio::time::timeout(TEST_TIMEOUT, handed_off).await??);
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn upstream_results_are_correlated_when_the_second_request_finishes_first() -> TestResult {
    let now = RequestId::new().timestamp_ms();
    let (send, mut replies) = mpsc::unbounded_channel();
    let hub = TestHub::start_with_dispatchers(
        "result-order",
        Config::default(),
        now,
        None,
        Arc::new(ControlledReplies(send)),
    )
    .await?;
    add_upstream_tool(&hub).await?;
    let first = post_upstream(&hub, StatusCode::ACCEPTED).await?;
    let (first_id, first_reply) = tokio::time::timeout(TEST_TIMEOUT, replies.recv())
        .await?
        .ok_or("first upstream caller not started")?;
    assert_eq!(first["execution_id"], json!(first_id));
    let second = post_upstream(&hub, StatusCode::ACCEPTED).await?;
    let (second_id, second_reply) = tokio::time::timeout(TEST_TIMEOUT, replies.recv())
        .await?
        .ok_or("second upstream caller not started")?;
    assert_eq!(second["execution_id"], json!(second_id));

    second_reply
        .send(Bytes::from_static(br#"{"structuredContent":null}"#))
        .map_err(|_| "second worker left before the result")?;
    let second = get(&hub, second_id, "?sensitive=true&wait_ms=2000").await?;
    assert_eq!(second["state"], "succeeded");
    assert_eq!(
        second["result"]["result"]["structuredContent"],
        serde_json::Value::Null
    );
    assert_eq!(get(&hub, first_id, "").await?["state"], "running");

    first_reply
        .send(Bytes::from_static(br#"{"structuredContent":{"index":1}}"#))
        .map_err(|_| "first worker left before the result")?;
    let first = get(&hub, first_id, "?sensitive=true&wait_ms=2000").await?;
    assert_eq!(first["state"], "succeeded");
    assert_eq!(
        first["result"]["result"]["structuredContent"],
        json!({"index":1})
    );
    assert_ne!(
        blob_lengths(&hub, first_id).await?,
        blob_lengths(&hub, second_id).await?
    );
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn started_upstream_keeps_its_slot_after_user_cancel_until_the_worker_finishes() -> TestResult
{
    let now = RequestId::new().timestamp_ms();
    let (send, mut replies) = mpsc::unbounded_channel();
    let config: Config = toml::from_str("max_concurrent_upstream_executions = 1")?;
    let hub = TestHub::start_with_dispatchers(
        "upstream-cancel-slot",
        config,
        now,
        None,
        Arc::new(ControlledReplies(send)),
    )
    .await?;
    add_upstream_tool(&hub).await?;
    post_upstream(&hub, StatusCode::ACCEPTED).await?;
    let (id, reply) = tokio::time::timeout(TEST_TIMEOUT, replies.recv())
        .await?
        .ok_or("upstream caller not started")?;
    let (status, cancelled) = hub
        .request_admin(Method::POST, &format!("/v1/executions/{id}/cancel"), None)
        .await?;
    assert_eq!(status, StatusCode::OK, "{cancelled}");
    assert_eq!(cancelled["state"], "cancelled");
    let busy = post_upstream(&hub, StatusCode::TOO_MANY_REQUESTS).await?;
    assert_eq!(busy["code"], "upstream_busy");

    reply
        .send(Bytes::from_static(
            br#"{"structuredContent":{"tooLate":true}}"#,
        ))
        .map_err(|_| "cancelled worker left early")?;
    let mut accepted = None;
    tokio::time::timeout(TEST_TIMEOUT, async {
        while accepted.is_none() {
            let (status, value) = hub
                .request_admin(
                    Method::POST,
                    "/v1/tools/mcp/test",
                    Some(json!({"wait_ms": 0})),
                )
                .await?;
            if status == StatusCode::ACCEPTED {
                accepted = Some(value);
            } else {
                assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{value}");
                tokio::task::yield_now().await;
            }
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    let (replacement, next_reply) = tokio::time::timeout(TEST_TIMEOUT, replies.recv())
        .await?
        .ok_or("replacement upstream caller not started")?;
    next_reply
        .send(Bytes::from_static(br#"{"content":[]}"#))
        .map_err(|_| "replacement worker left before result")?;
    assert_eq!(
        get(&hub, replacement, "?wait_ms=2000").await?["state"],
        "succeeded"
    );
    let detail = get(&hub, id, "?sensitive=true").await?;
    assert_eq!(detail["state"], "cancelled");
    assert_eq!(detail["result_access"], "unavailable");
    assert_eq!(blob_lengths(&hub, id).await?, (0, None));
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn persistent_terminal_write_rollback_releases_slot_and_leaves_deadline_to_settle()
-> TestResult {
    let now = RequestId::new().timestamp_ms();
    let upstream = Arc::new(CountingUpstream::default());
    let config: Config = toml::from_str("max_concurrent_upstream_executions = 1")?;
    let hub = TestHub::start_with_dispatchers(
        "terminal-rollback-budget",
        config,
        now,
        None,
        Arc::clone(&upstream) as Arc<dyn UpstreamDispatcher>,
    )
    .await?;
    let PendingUpstream {
        request,
        reservation,
        waiter,
        deadline,
    } = prepare_worker(&hub, now + 90_000).await?;
    let id = request.execution_id;

    // A connection-local test fault aborts each terminal write without
    // modifying the on-disk schema or stopping the actor.
    hub.write(|conn| {
        conn.execute_batch(
            "CREATE TEMP TRIGGER reject_terminal_result BEFORE UPDATE ON executions
         WHEN NEW.sealed_result_blob IS NOT NULL
         BEGIN SELECT RAISE(ROLLBACK, 'terminal result write fault'); END;",
        )
    })
    .await?;
    tokio::time::timeout(
        TEST_TIMEOUT,
        run_upstream(
            hub.state.clone(),
            request,
            reservation,
            hub.admin_id,
            TEST_TIMEOUT,
            deadline,
        ),
    )
    .await?;
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    assert_eq!(waiter.borrow().state, ExecutionState::Running);
    assert_eq!(blob_lengths(&hub, id).await?, (0, None));
    assert!(
        hub.state
            .execution
            .reserve_upstream(ExecutionId::new(), UpstreamId::new(), hub.admin_id)
            .is_some()
    );

    hub.clock.set(deadline);
    sweep_deadlines(&hub.state).await?;
    assert_eq!(waiter.borrow().state, ExecutionState::Unknown);
    assert_eq!(
        get(&hub, id, "").await?["summary"]["error_code"],
        "deadline_exceeded"
    );
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn completed_upstream_reply_during_shutdown_commits_succeeded_before_sweep() -> TestResult {
    let now = RequestId::new().timestamp_ms();
    let (send, mut replies) = mpsc::unbounded_channel();
    let hub = TestHub::start_with_dispatchers(
        "shutdown-completed-reply",
        Config::default(),
        now,
        None,
        Arc::new(ControlledReplies(send)),
    )
    .await?;
    add_upstream_tool(&hub).await?;
    let admitted = post_upstream(&hub, StatusCode::ACCEPTED).await?;
    let (id, reply) = tokio::time::timeout(TEST_TIMEOUT, replies.recv())
        .await?
        .ok_or("upstream caller not started")?;
    assert_eq!(admitted["execution_id"], json!(id));

    // Signal graceful shutdown before the in-flight upstream call resolves with Ok(bytes).
    hub.state.execution.stop();
    reply
        .send(Bytes::from_static(
            br#"{"structuredContent":{"saved":true}}"#,
        ))
        .map_err(|_| "upstream worker left early")?;

    // Wait for the upstream worker to commit its terminal succeeded outcome, then run the
    // shutdown sweep and verify the completed result was NOT overwritten with hub_shutting_down.
    let detail = tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            let view = get(&hub, id, "?sensitive=true").await?;
            if view["state"] != "running" {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(view);
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    assert_eq!(detail["state"], "succeeded");
    assert_eq!(detail["result_access"], "available");
    assert_eq!(
        detail["result"]["result"]["structuredContent"],
        json!({"saved": true})
    );
    super::super::finish_upstreams_for_shutdown(&hub.state).await?;
    assert_eq!(get(&hub, id, "?sensitive=true").await?, detail);
    hub.shutdown().await;
    Ok(())
}
