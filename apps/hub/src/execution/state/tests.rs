use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use efferian_protocol::{
    CancelReqPayload, DiscoveredUpstreamTool, ExecuteAckPayload, ExecuteReqPayload,
    ExecuteResPayload, ExecutionId, MAX_OUTPUT_BYTES, NodeId, RequestId, TerminalExecutionState,
    UpstreamId,
};
use http::{Method, StatusCode};
use serde_json::{Value, json};

use crate::config::Config;
use crate::execution::results::apply_node_result;
use crate::node_bridge::{
    BridgeCloseReason, NodeDispatcher, NodeLiveStatus, NodeSendError, ReadyNode,
};
use crate::storage::{ReceiptOutcome, StorageError};
use crate::test_support::{TestHub, TestResult};
use crate::upstream_dispatch::{
    DiscoverUpstream, DispatchFuture, InvokeUpstream, OfflineUpstreamDispatcher,
    UpstreamCancellation, UpstreamDispatchError, UpstreamDispatcher,
};

struct TestNode {
    id: NodeId,
    epoch: AtomicU64,
    cancellations: Mutex<Vec<(NodeId, u64, ExecutionId)>>,
}

impl NodeDispatcher for TestNode {
    fn live_status(&self, id: NodeId) -> NodeLiveStatus {
        if self.ready_node(id).is_some() {
            NodeLiveStatus::Ready
        } else {
            NodeLiveStatus::Offline
        }
    }

    fn online_nodes_count(&self) -> usize {
        1
    }

    fn close_session(&self, _: NodeId, _: u64, _: BridgeCloseReason) {}

    fn ready_node(&self, id: NodeId) -> Option<ReadyNode> {
        (id == self.id).then_some(ReadyNode {
            epoch: self.epoch.load(Ordering::SeqCst),
            max_concurrent_executions: 64,
        })
    }

    fn try_send_execute(
        &self,
        _: NodeId,
        _: u64,
        _: ExecuteReqPayload,
    ) -> Result<(), NodeSendError> {
        Ok(())
    }

    fn try_send_cancel(
        &self,
        id: NodeId,
        epoch: u64,
        request: CancelReqPayload,
    ) -> Result<(), NodeSendError> {
        let mut cancellations = self
            .cancellations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        cancellations.push((id, epoch, request.execution_id));
        // The first cancel fails transport delivery. The second must still be sent.
        if cancellations.len() == 1 {
            Err(NodeSendError::Full)
        } else {
            Ok(())
        }
    }
}

async fn add_managed_tool(
    hub: &TestHub,
    node: NodeId,
    slug: &str,
    output_limit: u32,
) -> TestResult {
    let (status, tool) = hub
        .request_admin(
            Method::PUT,
            &format!("/v1/tools/{slug}"),
            Some(json!({
                "description": "A managed fixture tool",
                "input_schema": {"type":"object"},
                "spec": {
                    "kind":"command",
                    "program":"/bin/echo",
                    "cwd":"/",
                    "args":[],
                    "env":{},
                    "target_selector":{"kind":"fixed","node_ids":[node]},
                    "runtime_ms":60000,
                    "max_output_bytes":output_limit
                }
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{tool}");
    Ok(())
}

async fn start_managed() -> TestResult<(TestHub, Arc<TestNode>, i64)> {
    let node = Arc::new(TestNode {
        id: NodeId::new(),
        epoch: AtomicU64::new(1),
        cancellations: Mutex::default(),
    });
    let now = RequestId::new().timestamp_ms();
    let config: Config = toml::from_str("max_concurrent_waiters_per_principal = 1")?;
    let hub = TestHub::start_with_dispatchers(
        "result-node",
        config,
        now,
        Some(Arc::clone(&node) as Arc<dyn NodeDispatcher>),
        Arc::new(OfflineUpstreamDispatcher),
    )
    .await?;
    let id = node.id;
    hub.write(move |conn| {
        conn.execute(
            "INSERT INTO nodes(node_id, name, credential_hmac, session_epoch, created_at_ms, updated_at_ms)
             VALUES (?1, 'worker', 'fixture-verifier', 1, ?2, ?2)",
            rusqlite::params![id.to_string(), now],
        )?;
        Ok(())
    }).await?;
    add_managed_tool(&hub, node.id, "emit", MAX_OUTPUT_BYTES).await?;
    add_managed_tool(&hub, node.id, "small", 4).await?;
    Ok((hub, node, now))
}

async fn start_node_execution(hub: &TestHub, slug: &str) -> TestResult<ExecutionId> {
    let (status, metadata) = hub
        .request_admin(
            Method::POST,
            &format!("/v1/tools/{slug}/test"),
            Some(json!({"wait_ms":0})),
        )
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{metadata}");
    assert_eq!(metadata["state"], "accepted");
    assert!(metadata.get("result").is_none());
    assert!(metadata.get("result_access").is_none());
    Ok(serde_json::from_value(metadata["execution_id"].clone())?)
}

fn receipt(id: ExecutionId) -> ExecuteResPayload {
    ExecuteResPayload {
        execution_id: id,
        state: TerminalExecutionState::Succeeded,
        effect_may_have_occurred: true,
        exit_code: None,
        http_status: None,
        error_code: None,
        error_message: None,
        stdout_b64: None,
        stderr_b64: None,
        truncated: false,
        output_discarded_reason: None,
        finished_at_ms: -99,
    }
}

fn base64_nuls(len: usize) -> String {
    let mut b64 = "AAAA".repeat(len / 3);
    b64.push_str(match len % 3 {
        0 => "",
        1 => "AA==",
        _ => "AAA=",
    });
    b64
}

async fn get(hub: &TestHub, id: ExecutionId, query: &str) -> TestResult<Value> {
    let (status, value) = hub
        .request_admin(Method::GET, &format!("/v1/executions/{id}{query}"), None)
        .await?;
    assert_eq!(status, StatusCode::OK, "{value}");
    Ok(value)
}

async fn blob_lengths(hub: &TestHub, id: ExecutionId) -> TestResult<(usize, Option<usize>)> {
    Ok(hub.state.storage.read_snapshot(move |conn| {
        Ok::<_, StorageError>(conn.query_row(
            "SELECT result_bytes, length(sealed_result_blob) FROM executions WHERE execution_id = ?1",
            [id.to_string()], |row| Ok((row.get(0)?, row.get(1)?)),
        )?)
    }).await?)
}

async fn collect_results(hub: &TestHub, now: i64, ids: &[ExecutionId]) -> TestResult {
    // Drive the production budgeted GC lane past result TTL but within metadata TTL.
    hub.clock.set(now + 8 * 86_400_000);
    hub.clock.set_monotonic(Duration::from_secs(61));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            hub.write(|_| Ok(())).await?;
            let mut done = true;
            for &id in ids {
                done &= blob_lengths(hub, id).await? == (0, None);
            }
            if done {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
        }
    })
    .await??;
    for &id in ids {
        let view = get(hub, id, "?sensitive=true").await?;
        assert_eq!(view["result_access"], "expired");
        assert_eq!(view["result_expired"], true);
        assert!(view.get("result").is_none());
    }
    Ok(())
}

#[tokio::test]
async fn managed_receipts_use_current_epoch_and_hub_clock_and_keep_full_output_until_gc()
-> TestResult {
    let (hub, node, now) = start_managed().await?;
    let nul = start_node_execution(&hub, "emit").await?;
    hub.clock.set(now + 5);
    assert!(
        hub.state
            .storage
            .apply_execute_ack(
                node.id,
                1,
                ExecuteAckPayload {
                    execution_id: nul,
                    started_at_ms: 1_000_000_000_000,
                }
            )
            .await?
    );
    let running = get(&hub, nul, "").await?;
    assert_eq!(running["state"], "running");
    assert_eq!(running["started_at_ms"], now + 5);

    node.epoch.store(2, Ordering::SeqCst);
    let node_id = node.id;
    hub.write(move |conn| {
        conn.execute(
            "UPDATE nodes SET session_epoch = 2 WHERE node_id = ?1",
            [node_id.to_string()],
        )?;
        Ok(())
    })
    .await?;
    assert_eq!(
        apply_node_result(&hub.state, node.id, 1, receipt(nul)).await?,
        ReceiptOutcome::NotOwnedOrNotFound,
    );
    assert_eq!(get(&hub, nul, "").await?["state"], "running");

    let mut big = receipt(nul);
    big.stdout_b64 = Some(base64_nuls(MAX_OUTPUT_BYTES as usize));
    big.exit_code = Some(7);
    big.error_message = Some("sensitive diagnostic".to_owned());
    hub.clock.set(now + 20);
    assert_eq!(
        apply_node_result(&hub.state, node.id, 2, big).await?,
        ReceiptOutcome::AppliedTerminal
    );
    let no_result = get(&hub, nul, "").await?;
    assert_eq!(no_result["result_access"], "not_requested");
    assert!(no_result.get("result").is_none());
    assert!(no_result["summary"].get("error_message").is_none());
    let with = get(&hub, nul, "?sensitive=true").await?;
    assert_eq!(with["result_access"], "available");
    assert_eq!(with["result_truncated"], false);
    assert_eq!(with["finished_at_ms"], now + 20);
    assert_eq!(with["summary"]["duration_ms"], 15);
    assert_eq!(with["summary"]["error_message"], "sensitive diagnostic");
    assert_eq!(
        with["result"],
        json!({
            "kind":"managed","stdout":"\u{0}".repeat(MAX_OUTPUT_BYTES as usize),"stderr":"","exit_code":7
        })
    );
    let (bytes, length) = blob_lengths(&hub, nul).await?;
    assert_eq!(Some(bytes), length);
    assert!((MAX_OUTPUT_BYTES as usize..MAX_OUTPUT_BYTES as usize + 100).contains(&bytes));

    let invalid_utf8 = start_node_execution(&hub, "small").await?;
    let mut invalid = receipt(invalid_utf8);
    // A UTF-8 sequence split across streams, followed by an invalid byte.
    invalid.stdout_b64 = Some("4oI=".to_owned());
    invalid.stderr_b64 = Some("rP8=".to_owned());
    invalid.http_status = Some(206);
    invalid.truncated = true;
    let mut oversized = invalid.clone();
    oversized.stderr_b64 = Some("rP8A".to_owned());
    assert!(
        apply_node_result(&hub.state, node.id, 2, oversized)
            .await
            .is_err()
    );
    assert_eq!(blob_lengths(&hub, invalid_utf8).await?, (0, None));
    assert_eq!(
        apply_node_result(&hub.state, node.id, 2, invalid).await?,
        ReceiptOutcome::AppliedTerminal
    );
    let view = get(&hub, invalid_utf8, "?sensitive=true").await?;
    assert_eq!(view["result_truncated"], true);
    assert_eq!(
        view["result"],
        json!({
            "kind":"managed","stdout":"�","stderr":"��","http_status":206
        })
    );
    let (bytes, length) = blob_lengths(&hub, invalid_utf8).await?;
    assert_eq!(Some(bytes), length);
    assert!(bytes > 0);

    for discarded in [false, true] {
        let empty = start_node_execution(&hub, "small").await?;
        let mut payload = receipt(empty);
        payload.state = TerminalExecutionState::Unknown;
        if discarded {
            payload.truncated = true;
            payload.exit_code = Some(8);
            payload.output_discarded_reason =
                Some(efferian_protocol::OutputDiscardedReason::RamCap);
        }
        assert_eq!(
            apply_node_result(&hub.state, node.id, 2, payload).await?,
            ReceiptOutcome::AppliedTerminal
        );
        let view = get(&hub, empty, "?sensitive=true").await?;
        assert_eq!(view["result_access"], "unavailable");
        assert_eq!(view["result_truncated"], discarded);
        assert_eq!(blob_lengths(&hub, empty).await?, (0, None));
    }

    collect_results(&hub, now, &[nul, invalid_utf8]).await?;
    assert_eq!(get(&hub, invalid_utf8, "").await?["result_truncated"], true);
    hub.shutdown().await;
    Ok(())
}

struct ResultUpstream;

impl UpstreamDispatcher for ResultUpstream {
    fn discover(
        &self,
        request: DiscoverUpstream,
    ) -> DispatchFuture<'_, Result<Vec<DiscoveredUpstreamTool>, UpstreamDispatchError>> {
        Box::pin(async move {
            Ok(vec![DiscoveredUpstreamTool {
                upstream_id: request.upstream_id,
                tool_name: "echo".to_owned(),
                description: None,
                input_schema: json!({"type":"object"}),
                annotations: None,
            }])
        })
    }

    fn invoke(
        &self,
        request: InvokeUpstream,
        _: UpstreamCancellation,
    ) -> DispatchFuture<'_, Result<Bytes, UpstreamDispatchError>> {
        Box::pin(async move {
            let bytes = match request.arguments["case"].as_str() {
                Some("null") => Bytes::from_static(br#"{"resultType":"complete","content":[{"type":"image","data":"YQ==","mimeType":"image/png","annotations":{"priority":0.9},"internal":"strip"}],"isError":true,"_meta":{"meta":"kept"},"structuredContent":null}"#),
                Some("numbers") => {
                    let mut raw = String::from(r#"{"content":[],"structuredContent":["#);
                    raw.push_str(&"1e14,".repeat(400_000));
                    raw.pop();
                    raw.push_str("]}");
                    Bytes::from(raw)
                }
                Some("oversized") => Bytes::from(vec![b' '; 2 * 1024 * 1024 + 1]),
                _ => Bytes::from_static(br#"{"content":[]}"#),
            };
            Ok(bytes)
        })
    }
}

async fn add_upstream_tool(hub: &TestHub) -> TestResult {
    let (status, value) = hub
        .request_admin(
            Method::PUT,
            "/v1/upstreams/mock",
            Some(json!({"url":"https://example.com/mcp"})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let upstream: UpstreamId = serde_json::from_value(value["upstream"]["upstream_id"].clone())?;
    let (status, value) = hub
        .request_admin(Method::POST, "/v1/upstreams/mock/discover", Some(json!({})))
        .await?;
    assert_eq!(status, StatusCode::OK, "{value}");
    let (status, value) = hub
        .request_admin(
            Method::PUT,
            "/v1/tools/mcp",
            Some(json!({
                "spec":{
                    "kind":"upstream_ref",
                    "account_mode":"none",
                    "upstream_id":upstream,
                    "upstream_tool_name":"echo",
                    "runtime_ms":60000
                }
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    Ok(())
}

#[tokio::test]
async fn upstream_results_round_trip_complete_wire_values_and_gc_in_budget() -> TestResult {
    let now = RequestId::new().timestamp_ms();
    let hub = TestHub::start_with_dispatchers(
        "result-upstream",
        Config::default(),
        now,
        None,
        Arc::new(ResultUpstream),
    )
    .await?;
    add_upstream_tool(&hub).await?;

    let mut ids = Vec::new();
    for case in ["null", "absent", "numbers", "oversized"] {
        let (status, view) = hub
            .request_admin(
                Method::POST,
                "/v1/tools/mcp/test",
                Some(json!({
                    "arguments":{"case":case},
                    "wait_ms":10000
                })),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{view}");
        let id: ExecutionId = serde_json::from_value(view["execution_id"].clone())?;
        let json = &view["result"]["result"];
        match case {
            "null" => assert_eq!(
                json,
                &serde_json::json!({
                    "resultType":"complete",
                    "content":[{"type":"image","data":"YQ==","mimeType":"image/png","annotations":{"priority":0.9}}],
                    "isError":true,
                    "_meta":{"meta":"kept"},
                    "structuredContent":null
                })
            ),
            "absent" => assert_eq!(json, &serde_json::json!({"content":[]})),
            "numbers" => {
                let numbers = json["structuredContent"]
                    .as_array()
                    .ok_or("expected an upstream array")?;
                assert_eq!(numbers.len(), 400_000);
                assert!(numbers.iter().all(|x| x.as_f64() == Some(1e14)));
            }
            _ => {
                assert_eq!(view["state"], "failed");
                assert_eq!(view["summary"]["error_code"], "upstream_invalid_response");
                assert_eq!(view["result_access"], "unavailable");
                assert_eq!(blob_lengths(&hub, id).await?, (0, None));
                continue;
            }
        }
        assert_eq!(view["state"], "succeeded");
        assert_eq!(view["result_access"], "available");
        assert_eq!(get(&hub, id, "?sensitive=true").await?, view);
        let (bytes, length) = blob_lengths(&hub, id).await?;
        assert!(bytes > 0 && bytes < 4 * 1024 * 1024);
        assert_eq!(Some(bytes), length);
        ids.push(id);
    }

    // Moving a sealed result to a different execution does not authenticate.
    let source = ids[0];
    let target = ids[1];
    hub.write(move |conn| {
        conn.execute(
            "UPDATE executions SET (sealed_result_blob, result_bytes) =
                 (SELECT sealed_result_blob, result_bytes FROM executions WHERE execution_id = ?1)
             WHERE execution_id = ?2",
            [source.to_string(), target.to_string()],
        )?;
        Ok(())
    })
    .await?;
    let (status, failure) = hub
        .request_admin(
            Method::GET,
            &format!("/v1/executions/{target}?sensitive=true"),
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{failure}");
    assert_eq!(
        get(&hub, target, "").await?["result_access"],
        "not_requested"
    );
    collect_results(&hub, now, &ids).await?;
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn node_cancel_uses_current_epoch_and_waiter_cap_returns_immediate_metadata() -> TestResult {
    let (hub, node, now) = start_managed().await?;
    let execution = start_node_execution(&hub, "small").await?;
    node.epoch.store(2, Ordering::SeqCst);
    let node_id = node.id;
    hub.write(move |conn| {
        conn.execute(
            "UPDATE nodes SET session_epoch = 2 WHERE node_id = ?1",
            [node_id.to_string()],
        )?;
        Ok(())
    })
    .await?;

    let router = hub.router.clone();
    let admin = hub.admin_token.clone();
    let first = tokio::spawn(async move {
        crate::test_support::send_json(
            &router,
            Method::GET,
            &format!("/v1/executions/{execution}?wait_ms=25000"),
            &admin,
            None,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        while hub.state.execution.reserve_waiter(hub.admin_id).is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let fallback = tokio::time::timeout(
        Duration::from_secs(3),
        get(&hub, execution, "?wait_ms=25000"),
    )
    .await??;
    assert_eq!(fallback["state"], "accepted");
    assert!(!first.is_finished());

    hub.clock.set(now + 1);
    for cancel_no in 0..2 {
        let (status, view) = hub
            .request_admin(
                Method::POST,
                &format!("/v1/executions/{execution}/cancel"),
                None,
            )
            .await?;
        assert_eq!(status, StatusCode::ACCEPTED, "{view}");
        assert_eq!(view["state"], "accepted");
        assert_eq!(view["cancel_requested_at_ms"], now + 1);
        assert!(view.get("result_access").is_none());
        hub.clock.set(now + cancel_no + 2);
    }
    assert_eq!(
        node.cancellations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_slice(),
        &[(node.id, 2, execution), (node.id, 2, execution),]
    );
    let mut result = receipt(execution);
    result.state = TerminalExecutionState::Cancelled;
    assert_eq!(
        apply_node_result(&hub.state, node.id, 2, result).await?,
        ReceiptOutcome::AppliedTerminal
    );
    let (status, view) = tokio::time::timeout(Duration::from_secs(3), first).await???;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["state"], "cancelled");
    assert_eq!(view["result_access"], "not_requested");
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn deadline_is_irreversible_and_current_epoch_records_only_one_late_receipt() -> TestResult {
    let (hub, node, now) = start_managed().await?;
    let execution = start_node_execution(&hub, "small").await?;
    let mut events = hub.state.storage.subscribe_events()?;
    hub.clock.set(now + 90_001);
    super::sweep_deadlines(&hub.state).await?;

    let event = events.recv().await?;
    assert!(matches!(
        &event.envelope.event,
        efferian_protocol::Event::ExecutionFinished(payload)
            if payload.execution_id == execution && payload.error_code.as_deref() == Some("deadline_exceeded")
    ));
    let timed_out = get(&hub, execution, "?sensitive=true").await?;
    assert_eq!(timed_out["state"], "unknown");
    assert_eq!(timed_out["finished_at_ms"], now + 90_001);

    let mut late = receipt(execution);
    late.stdout_b64 = Some("YQ==".to_owned());
    assert_eq!(
        apply_node_result(&hub.state, node.id, 0, late.clone()).await?,
        ReceiptOutcome::NotOwnedOrNotFound
    );
    assert_eq!(
        apply_node_result(&hub.state, node.id, 1, late.clone()).await?,
        ReceiptOutcome::LateReceiptRecorded
    );
    assert_eq!(
        apply_node_result(&hub.state, node.id, 1, late).await?,
        ReceiptOutcome::AlreadyTerminalOwned
    );
    let event = events.recv().await?;
    assert!(matches!(
        &event.envelope.event,
        efferian_protocol::Event::ExecutionLateReceipt(payload) if payload.execution_id == execution
    ));
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(get(&hub, execution, "?sensitive=true").await?, timed_out);
    assert_eq!(blob_lengths(&hub, execution).await?, (0, None));
    hub.shutdown().await;
    Ok(())
}

#[derive(Default)]
struct CountingUpstream {
    calls: std::sync::atomic::AtomicUsize,
    cancellations: std::sync::atomic::AtomicUsize,
}

impl UpstreamDispatcher for CountingUpstream {
    fn invoke(
        &self,
        _: InvokeUpstream,
        _: UpstreamCancellation,
    ) -> DispatchFuture<'_, Result<Bytes, UpstreamDispatchError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(Bytes::from_static(br#"{"structuredContent":null}"#)) })
    }

    fn cancel(&self, _: ExecutionId) {
        self.cancellations.fetch_add(1, Ordering::SeqCst);
    }
}

mod upstream_races;

#[tokio::test]
async fn upstream_completion_retries_writes_and_cannot_replace_a_committed_cancel() -> TestResult {
    use std::convert::Infallible;
    use std::num::NonZeroU64;
    use std::task::Poll;

    use efferian_protocol::{PreparedArgumentsDigest, TokenId, ToolId};

    use crate::storage::{
        ExecutionTarget, InvokeResource, NewExecutionWrite, PriorityKind, WriteError, WriteTxError,
    };

    let now = RequestId::new().timestamp_ms();
    let upstream = Arc::new(CountingUpstream::default());
    let hub = TestHub::start_with_dispatchers(
        "result-ingress",
        Config::default(),
        now,
        None,
        Arc::clone(&upstream) as Arc<dyn UpstreamDispatcher>,
    )
    .await?;
    let caller = hub.admin_id;
    for (index, (full, cancel)) in [(true, false), (false, false), (true, true)]
        .into_iter()
        .enumerate()
    {
        let state = hub.state.clone();
        let execution_id = ExecutionId::new();
        let upstream_id = UpstreamId::new();
        let control = Arc::clone(&state.execution);
        let (outcome, reservation) = state
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
                    deadline_at_ms: now + 90_000,
                })?;
                Ok((inserted, reservation))
            })
            .await?;
        let mut waiter = outcome.waiter.ok_or("active upstream waiter missing")?;
        let mut events = state.storage.subscribe_events()?;

        // Hold one real actor command open. Polling work futures once enqueues
        // them synchronously, so the delivery attempt sees the intended queue.
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let storage = state.storage.clone();
        let blocker = tokio::spawn(async move {
            storage
                .execute_work(0, move |_| {
                    let _ = entered_tx.send(());
                    release_rx
                        .recv()
                        .map_err(|_| WriteTxError::InvalidDatabase("fixture blocker dropped"))?;
                    Ok::<_, WriteTxError<Infallible>>(())
                })
                .await
        });
        entered_rx.await?;

        let mut queued = Vec::new();
        let mut poison = Box::pin(state.storage.execute_work(0, |tx| {
            tx.conn().execute_batch("ROLLBACK")?;
            Ok::<_, WriteTxError<Infallible>>(())
        }));
        if full {
            let mut observed_full = false;
            for _ in 0..=256 {
                let mut filler = Box::pin(
                    state
                        .storage
                        .execute_work(0, |_| Ok::<_, WriteTxError<Infallible>>(())),
                );
                match futures_util::poll!(filler.as_mut()) {
                    Poll::Pending => queued.push(filler),
                    Poll::Ready(Err(WriteError::Storage(StorageError::Overloaded))) => {
                        observed_full = true;
                        break;
                    }
                    _ => return Err("unexpected result filling work ingress".into()),
                }
            }
            assert!(observed_full);
        } else {
            assert!(futures_util::poll!(poison.as_mut()).is_pending());
        }

        let mut worker = Box::pin(crate::execution::results::run_upstream(
            state.clone(),
            InvokeUpstream {
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
            caller,
            Duration::from_secs(5),
            now + 90_000,
        ));
        assert!(futures_util::poll!(worker.as_mut()).is_pending());
        assert_eq!(upstream.calls.load(Ordering::SeqCst), index + 1);
        let dispatcher = Arc::clone(&state.upstream);
        let control = Arc::clone(&state.execution);
        let mut cancel_write = Box::pin(state.storage.execute_priority(
            PriorityKind::CancelExecution,
            move |tx| {
                super::control::cancel_upstream(tx, &control, dispatcher, execution_id, caller)?;
                Ok::<_, WriteTxError<Infallible>>(())
            },
        ));
        if cancel {
            assert!(futures_util::poll!(cancel_write.as_mut()).is_pending());
        }
        release_tx.send(())?;
        blocker.await??;
        if cancel {
            cancel_write.await?;
        }
        for command in queued {
            command.await?;
        }
        if !full {
            assert!(matches!(poison.await, Err(WriteError::PreCommitAborted)));
        }
        tokio::time::timeout(Duration::from_secs(3), worker).await?;
        assert_eq!(upstream.calls.load(Ordering::SeqCst), index + 1);
        let terminal = *waiter
            .wait_for(|snapshot| snapshot.state.is_terminal())
            .await?;
        let event = events.try_recv()?;
        let result = get(&hub, execution_id, "?sensitive=true").await?;
        if cancel {
            assert_eq!(terminal.state, efferian_protocol::ExecutionState::Cancelled);
            assert_eq!(result["result_access"], "unavailable");
            assert_eq!(blob_lengths(&hub, execution_id).await?, (0, None));
            assert!(matches!(
                &event.envelope.event,
                efferian_protocol::Event::ExecutionCancelled(payload) if payload.execution_id == execution_id
            ));
        } else {
            assert_eq!(terminal.state, efferian_protocol::ExecutionState::Succeeded);
            assert_eq!(result["result_access"], "available");
            assert_eq!(result["result"]["result"]["structuredContent"], Value::Null);
            assert!(matches!(
                &event.envelope.event,
                efferian_protocol::Event::ExecutionFinished(payload) if payload.execution_id == execution_id
            ));
        }
        assert!(matches!(
            events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
    }
    hub.shutdown().await;
    Ok(())
}

#[derive(Default)]
struct ShutdownUpstream(tokio::sync::Notify);

impl UpstreamDispatcher for ShutdownUpstream {
    fn discover(
        &self,
        request: DiscoverUpstream,
    ) -> DispatchFuture<'_, Result<Vec<DiscoveredUpstreamTool>, UpstreamDispatchError>> {
        ResultUpstream.discover(request)
    }

    fn invoke(
        &self,
        _: InvokeUpstream,
        mut cancellation: UpstreamCancellation,
    ) -> DispatchFuture<'_, Result<Bytes, UpstreamDispatchError>> {
        Box::pin(async move {
            self.0.notify_one();
            cancellation.cancelled().await;
            Err(UpstreamDispatchError::Disconnected)
        })
    }
}

#[tokio::test]
async fn transport_interrupted_by_shutdown_keeps_the_durable_shutdown_cause() -> TestResult {
    let now = RequestId::new().timestamp_ms();
    let transport = Arc::new(ShutdownUpstream::default());
    let config: Config = toml::from_str("max_concurrent_upstream_executions = 1")?;
    let hub = TestHub::start_with_dispatchers(
        "result-shutdown",
        config,
        now,
        None,
        Arc::clone(&transport) as Arc<dyn UpstreamDispatcher>,
    )
    .await?;
    add_upstream_tool(&hub).await?;
    let (status, running) = hub
        .request_admin(
            Method::POST,
            "/v1/tools/mcp/test",
            Some(json!({"wait_ms": 0})),
        )
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{running}");
    let execution = serde_json::from_value(running["execution_id"].clone())?;
    tokio::time::timeout(Duration::from_secs(3), transport.0.notified()).await?;
    hub.state.execution.stop();
    let slot_id = ExecutionId::new();
    let resource = UpstreamId::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if hub
                .state
                .execution
                .reserve_upstream(slot_id, resource, hub.admin_id)
                .is_some()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert_eq!(get(&hub, execution, "").await?["state"], "running");
    super::finish_upstreams_for_shutdown(&hub.state).await?;
    let finished = get(&hub, execution, "").await?;
    assert_eq!(finished["state"], "unknown");
    assert_eq!(finished["summary"]["error_code"], "hub_shutting_down");
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn execution_list_scopes_before_limit_and_withheld_reads_skip_vault() -> TestResult {
    let (hub, node, now) = start_managed().await?;
    let (status, tool) = hub
        .request_admin(Method::GET, "/v1/tools/small", None)
        .await?;
    assert_eq!(status, StatusCode::OK, "{tool}");
    let (status, profile) = hub
        .request_admin(
            Method::PUT,
            "/v1/profiles/paginated",
            Some(json!({
                "discovery_mode": "full",
                "bindings": [{
                    "public_name": "echo", "tool_id": tool["tool_id"], "tool_version": 1,
                    "execution_mode": "async"
                }]
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{profile}");
    let (status, edition) = hub
        .request_admin(Method::POST, "/v1/profiles/paginated/publish", None)
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{edition}");

    let (status, member) = hub
        .request_admin(
            Method::PUT,
            "/v1/principals/reader",
            Some(json!({"kind":"member"})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{member}");
    let principal = &member["principal"]["principal_id"];
    let (status, grant) = hub
        .request_admin(
            Method::PUT,
            "/v1/grants",
            Some(json!({
                "principal_id": principal, "scope": {"scope_kind":"global"}, "capability":"invoke"
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{grant}");
    let (status, minted) = hub
        .request_admin(
            Method::POST,
            "/v1/tokens",
            Some(json!({
                "principal_id": principal, "label": "withheld-fixture",
                "allowed_nodes": [node.id], "withhold_sensitive": true
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{minted}");
    let token = minted["token"]
        .as_str()
        .ok_or("token missing from fixture")?;

    let mut own = Vec::<ExecutionId>::new();
    for _ in 0..2 {
        let (status, response) = hub
            .request(
                Method::POST,
                "/v1/profiles/paginated/invoke",
                token,
                Some(json!({"public_name":"echo"})),
            )
            .await?;
        assert_eq!(status, StatusCode::ACCEPTED, "{response}");
        own.push(serde_json::from_value(response["execution_id"].clone())?);
    }
    own.sort_unstable_by_key(|id| std::cmp::Reverse(id.to_string()));
    hub.clock.set(now + 2);
    let hidden = start_node_execution(&hub, "small").await?;
    assert!(!own.contains(&hidden));

    let path = format!("/v1/executions?limit=1&state=accepted&node_id={}", node.id);
    let (status, first) = hub.request(Method::GET, &path, token, None).await?;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["items"][0]["execution_id"], json!(own[0]));
    assert_eq!(first["items"][0]["created_at_ms"], now);
    let cursor = first["next_cursor"]
        .as_str()
        .ok_or("expected a second execution page")?;
    let (status, second) = hub
        .request(Method::GET, &format!("{path}&cursor={cursor}"), token, None)
        .await?;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(second["items"][0]["execution_id"], json!(own[1]));
    assert_eq!(second["items"][0]["created_at_ms"], now);
    assert_eq!(second["next_cursor"], Value::Null);
    assert!(second["items"][0].get("result_access").is_none());

    let mut terminal = receipt(own[0]);
    terminal.stdout_b64 = Some("YQ==".to_owned());
    terminal.error_message = Some("sensitive fixture".to_owned());
    assert_eq!(
        apply_node_result(&hub.state, node.id, 1, terminal).await?,
        ReceiptOutcome::AppliedTerminal
    );
    let execution = own[0];
    hub.write(move |conn| {
        conn.execute(
            "UPDATE executions SET sealed_result_blob = zeroblob(result_bytes) WHERE execution_id = ?1",
            [execution.to_string()],
        )?;
        Ok(())
    }).await?;
    let read = format!("/v1/executions/{execution}?sensitive=true");
    let (status, visible) = hub.request(Method::GET, &read, token, None).await?;
    assert_eq!(status, StatusCode::OK, "{visible}");
    assert_eq!(visible["result_access"], "denied");
    assert!(visible.get("result").is_none());
    assert!(visible["summary"].get("error_message").is_none());
    let (status, _) = hub.request_admin(Method::GET, &read, None).await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    hub.shutdown().await;
    Ok(())
}
