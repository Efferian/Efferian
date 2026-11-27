#![allow(clippy::unwrap_used, reason = "fixtures require valid test data")]

mod editions;
mod writer;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use efferian_protocol::{
    DiscoveredUpstreamTool, ExecuteReqPayload, HttpAuthSecret, NodeId, PrincipalId, RequestId,
    ToolId,
};
use http::{Method, StatusCode};
use rusqlite::params;
use serde_json::{Value, json};
use tokio::sync::oneshot;

use crate::config::Config;
use crate::http::{ApiCaller, ApiError};
use crate::node_bridge::{
    BridgeCloseReason, NodeDispatcher, NodeLiveStatus, NodeSendError, ReadyNode,
};
use crate::test_support::{TestHub, TestResult};
use crate::upstream_dispatch::{
    DiscoverUpstream, DispatchFuture, InvokeUpstream, OfflineUpstreamDispatcher,
    UpstreamCancellation, UpstreamDispatchError, UpstreamDispatcher,
};

type DispatchGate = (
    oneshot::Sender<efferian_protocol::ExecutionId>,
    oneshot::Receiver<()>,
);

#[derive(Default)]
struct NodeMock {
    ready: Mutex<BTreeMap<NodeId, Option<ReadyNode>>>,
    sent: Mutex<Vec<(NodeId, ExecuteReqPayload)>>,
    fail: Mutex<Option<NodeSendError>>,
    dispatch_gate: Mutex<Option<DispatchGate>>,
}

impl NodeMock {
    fn set(&self, node_id: NodeId, ready: Option<ReadyNode>) {
        self.ready.lock().unwrap().insert(node_id, ready);
    }
}

impl NodeDispatcher for NodeMock {
    fn live_status(&self, node_id: NodeId) -> NodeLiveStatus {
        match self.ready.lock().unwrap().get(&node_id) {
            Some(Some(_)) => NodeLiveStatus::Ready,
            Some(None) => NodeLiveStatus::Syncing,
            None => NodeLiveStatus::Offline,
        }
    }

    fn online_nodes_count(&self) -> usize {
        self.ready.lock().unwrap().len()
    }

    fn close_session(&self, node_id: NodeId, _epoch: u64, _reason: BridgeCloseReason) {
        self.ready.lock().unwrap().remove(&node_id);
    }

    fn ready_node(&self, node_id: NodeId) -> Option<ReadyNode> {
        self.ready.lock().unwrap().get(&node_id).copied().flatten()
    }

    fn try_send_execute(
        &self,
        node_id: NodeId,
        epoch: u64,
        request: ExecuteReqPayload,
    ) -> Result<(), NodeSendError> {
        if self
            .ready_node(node_id)
            .is_none_or(|ready| ready.epoch != epoch)
        {
            return Err(NodeSendError::Closed);
        }
        let gate = self.dispatch_gate.lock().unwrap().take();
        if let Some((entered, release)) = gate {
            let _ = entered.send(request.execution_id);
            let _ = release.blocking_recv();
        }
        if let Some(error) = *self.fail.lock().unwrap() {
            return Err(error);
        }
        self.sent.lock().unwrap().push((node_id, request));
        Ok(())
    }
}

async fn seed_node(hub: &TestHub, name: &'static str, tags: &'static str) -> TestResult<NodeId> {
    let node_id = NodeId::new();
    hub.write(move |conn| {
        let id = node_id.to_string();
        conn.execute(
            "INSERT INTO nodes (node_id, name, credential_hmac, session_epoch,
             tags_json, created_at_ms, updated_at_ms) VALUES (?1, ?2, ?1, 1, ?3, 1, 1)",
            params![id, name, tags],
        )?;
        Ok(())
    })
    .await?;
    Ok(node_id)
}

fn command(program: &str, selector: Value) -> Value {
    json!({
        "description": "A managed fixture tool",
        "input_schema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"]
        },
        "spec": {
            "kind": "command", "program": program,
            "args": [{"kind": "arg", "name": "text"}],
            "cwd": "/work", "env": {},
            "target_selector": selector, "runtime_ms": 60000, "max_output_bytes": 1024
        }
    })
}

async fn put_tool(hub: &TestHub, definition: Value, status: StatusCode) -> TestResult<ToolId> {
    let (actual, response) = hub
        .request_admin(Method::PUT, "/v1/tools/echo", Some(definition))
        .await?;
    assert_eq!(actual, status, "{response}");
    Ok(serde_json::from_value(response["tool"]["tool_id"].clone())?)
}

async fn publish(
    hub: &TestHub,
    tool: ToolId,
    name: &str,
    version: u64,
    mode: &str,
    fixed: Option<NodeId>,
) -> TestResult {
    let (status, response) = hub
        .request_admin(
            Method::PUT,
            "/v1/profiles/demo",
            Some(json!({
                "discovery_mode": "full",
                "bindings": [{
                    "public_name": name, "tool_id": tool, "tool_version": version,
                    "execution_mode": mode, "fixed_node_id": fixed,
                }]
            })),
        )
        .await?;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "{status}: {response}"
    );
    let (status, response) = hub
        .request_admin(Method::POST, "/v1/profiles/demo/publish", None)
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{response}");
    Ok(())
}

async fn managed_fixture(now: i64) -> TestResult<(TestHub, Arc<NodeMock>, NodeId, ToolId)> {
    let bridge = Arc::new(NodeMock::default());
    let mut config = Config::default();
    config.max_node_concurrent_executions = 1;
    let hub = TestHub::start_with_dispatchers(
        "invoke",
        config,
        now,
        Some(bridge.clone()),
        Arc::new(OfflineUpstreamDispatcher),
    )
    .await?;
    let node = seed_node(&hub, "node-one", "[\"test\"]").await?;
    bridge.set(
        node,
        Some(ReadyNode {
            epoch: 1,
            max_concurrent_executions: 2,
        }),
    );
    let tool = put_tool(
        &hub,
        command("/bin/echo", json!({"kind": "fixed", "node_ids": [node]})),
        StatusCode::CREATED,
    )
    .await?;
    Ok((hub, bridge, node, tool))
}

async fn admin_caller(hub: &TestHub) -> TestResult<ApiCaller> {
    use efferian_protocol::TokenId;
    use http::{HeaderMap, HeaderValue, header::AUTHORIZATION};

    use crate::vault::auth::{ParsedBearer, authenticate_api};

    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", hub.admin_token))?,
    );
    let bearer = ParsedBearer::<TokenId>::from_headers(&headers)?;
    let vault = hub.state.vault.clone();
    let clock = hub.state.clock.clone();
    let caller = hub
        .state
        .storage
        .read_snapshot(move |conn| {
            authenticate_api(&vault, conn, bearer, clock.wall_now_ms()).map_err(ApiError::from)
        })
        .await?;
    Ok(ApiCaller(caller))
}

#[tokio::test]
async fn concurrent_replay_beats_capacity_disconnect_and_catalog_changes() -> TestResult {
    let request_id = RequestId::new();
    let (hub, bridge, node, tool) = managed_fixture(request_id.timestamp_ms()).await?;
    publish(&hub, tool, "echo", 1, "async", None).await?;
    let path = "/v1/profiles/demo/invoke";
    let body = json!({
        "public_name": "echo", "arguments": {"text": "once"}, "request_id": request_id
    });
    let (one, two) = tokio::join!(
        hub.request_admin(Method::POST, path, Some(body.clone())),
        hub.request_admin(Method::POST, path, Some(body.clone())),
    );
    let (one_status, one) = one?;
    let (two_status, two) = two?;
    assert_eq!(one_status, StatusCode::ACCEPTED, "{one}");
    assert_eq!(two_status, StatusCode::ACCEPTED, "{two}");
    assert_eq!(one["execution_id"], two["execution_id"]);
    {
        let sent = bridge.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, node);
        assert_eq!(one["execution_id"], json!(sent[0].1.execution_id));
    }
    let (status, problem) = hub
        .request_admin(
            Method::POST,
            path,
            Some(json!({
                "public_name": "echo", "arguments": {"text": "busy"}
            })),
        )
        .await?;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("node_busy"))
    );

    bridge.ready.lock().unwrap().remove(&node);
    let (status, problem) = hub
        .request_admin(
            Method::POST,
            path,
            Some(json!({
                "public_name": "echo", "arguments": {"text": "offline"}
            })),
        )
        .await?;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("node_offline"))
    );
    let (status, replay) = hub
        .request_admin(Method::POST, path, Some(body.clone()))
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{replay}");
    assert_eq!(replay["execution_id"], one["execution_id"]);

    publish(&hub, tool, "renamed", 1, "async", Some(node)).await?;
    for route in [
        "/v1/profiles/demo/versions/1/disable",
        "/v1/tools/echo/disable",
    ] {
        let (status, response) = hub.request_admin(Method::POST, route, None).await?;
        assert_eq!(status, StatusCode::NO_CONTENT, "{response}");
    }
    hub.clock
        .set(request_id.timestamp_ms() + 25 * 60 * 60 * 1000);
    let (status, replay) = hub
        .request_admin(Method::POST, path, Some(body.clone()))
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{replay}");
    assert_eq!(replay["execution_id"], one["execution_id"]);

    let mut changed = body;
    changed["target"] = json!("node-one");
    let (status, problem) = hub.request_admin(Method::POST, path, Some(changed)).await?;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::CONFLICT, Some("request_id_conflict"))
    );
    assert_eq!(bridge.sent.lock().unwrap().len(), 1);
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn immediate_dispatch_rejection_finishes_before_reply_and_frees_slot() -> TestResult {
    let (hub, bridge, _, tool) = managed_fixture(RequestId::new().timestamp_ms()).await?;
    publish(&hub, tool, "echo", 1, "async", None).await?;
    for (failure, code) in [
        (NodeSendError::Full, "node_ws_backpressure"),
        (NodeSendError::Closed, "node_disconnected_before_dispatch"),
    ] {
        *bridge.fail.lock().unwrap() = Some(failure);
        let (status, detail) = hub
            .request_admin(
                Method::POST,
                "/v1/profiles/demo/invoke",
                Some(json!({
                    "public_name": "echo", "arguments": {"text": "rejected"}, "wait_ms": 0,
                })),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{detail}");
        assert_eq!(detail["state"], "failed");
        assert_eq!(detail["summary"]["error_code"], code);
        assert_eq!(detail["summary"]["effect_may_have_occurred"], false);
        assert_eq!(detail["result_access"], "unavailable");
    }
    *bridge.fail.lock().unwrap() = None;
    let (status, accepted) = hub
        .request_admin(
            Method::POST,
            "/v1/profiles/demo/invoke",
            Some(json!({
                "public_name": "echo", "arguments": {"text": "accepted"}, "wait_ms": 0,
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    assert_eq!(bridge.sent.lock().unwrap().len(), 1);
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn tool_test_replays_original_unpinned_revision_and_conflicts_on_pin() -> TestResult {
    let request_id = RequestId::new();
    let (hub, bridge, node, tool) = managed_fixture(request_id.timestamp_ms()).await?;
    let path = "/v1/tools/echo/test";
    let body = json!({"arguments": {"text": "before"}, "request_id": request_id, "wait_ms": 0});
    let (status, one) = hub
        .request_admin(Method::POST, path, Some(body.clone()))
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{one}");
    assert_eq!(one["tool_version"], 1);
    assert_eq!(one["invoke_kind"], "tool_test");

    let updated = put_tool(
        &hub,
        command("/bin/printf", json!({"kind": "fixed", "node_ids": [node]})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(tool, updated);
    let (status, replay) = hub
        .request_admin(Method::POST, path, Some(body.clone()))
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{replay}");
    assert_eq!(replay["execution_id"], one["execution_id"]);
    assert_eq!(replay["tool_version"], 1);
    let (status, problem) = hub
        .request_admin(Method::POST, "/v1/tools/echo/test?version=1", Some(body))
        .await?;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::CONFLICT, Some("request_id_conflict"))
    );
    assert_eq!(bridge.sent.lock().unwrap().len(), 1);
    hub.shutdown().await;
    Ok(())
}

async fn member(
    hub: &TestHub,
    name: &str,
    allowed_nodes: Option<Vec<NodeId>>,
) -> TestResult<(PrincipalId, String)> {
    let (status, principal) = hub
        .request_admin(
            Method::PUT,
            &format!("/v1/principals/{name}"),
            Some(json!({"kind": "member"})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{principal}");
    let principal_id: PrincipalId =
        serde_json::from_value(principal["principal"]["principal_id"].clone())?;
    let (status, grant) = hub.request_admin(Method::PUT, "/v1/grants", Some(json!({
        "principal_id": principal_id, "scope": {"scope_kind": "global"}, "capability": "invoke"
    }))).await?;
    assert_eq!(status, StatusCode::CREATED, "{grant}");
    let token = mint(hub, principal_id, allowed_nodes).await?;
    Ok((principal_id, token))
}

async fn mint(
    hub: &TestHub,
    principal_id: PrincipalId,
    allowed_nodes: Option<Vec<NodeId>>,
) -> TestResult<String> {
    let (status, token) = hub
        .request_admin(
            Method::POST,
            "/v1/tokens",
            Some(json!({
                "principal_id": principal_id, "label": "fixture", "allowed_nodes": allowed_nodes,
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{token}");
    Ok(serde_json::from_value(token["token"].clone())?)
}

#[tokio::test]
async fn tag_discovery_and_selection_do_not_expose_filtered_targets() -> TestResult {
    let request_id = RequestId::new();
    let (hub, bridge, one, _) = managed_fixture(request_id.timestamp_ms()).await?;
    let two = seed_node(&hub, "node-two", "[\"test\"]").await?;
    let hidden = seed_node(&hub, "elsewhere", "[]").await?;
    bridge.set(
        two,
        Some(ReadyNode {
            epoch: 1,
            max_concurrent_executions: 1,
        }),
    );
    let tag = put_tool(
        &hub,
        command("/bin/echo", json!({"kind": "tag", "tag": "test"})),
        StatusCode::OK,
    )
    .await?;
    publish(&hub, tag, "tag", 2, "async", None).await?;

    let (principal, token) = member(&hub, "member", Some(vec![one])).await?;
    let (status, discovery) = hub
        .request(Method::GET, "/v1/profiles/demo/tools/tag", &token, None)
        .await?;
    assert_eq!(status, StatusCode::OK, "{discovery}");
    assert_eq!(
        discovery["available_targets"],
        json!([{"node_id": one, "name": "node-one"}])
    );

    let path = "/v1/profiles/demo/invoke";
    let body =
        json!({"public_name": "tag", "arguments": {"text": "once"}, "request_id": request_id});
    let (status, problem) = hub
        .request_admin(Method::POST, path, Some(body.clone()))
        .await?;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("ambiguous_target"))
    );
    assert_eq!(
        problem["extensions"]["available_targets"],
        json!(["node-one", "node-two"])
    );
    let mut explicit = body.clone();
    explicit["target"] = json!(hidden);
    let (status, problem) = hub
        .request(Method::POST, path, &token, Some(explicit.clone()))
        .await?;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );
    let (status, problem) = hub
        .request_admin(Method::POST, path, Some(explicit))
        .await?;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_arguments"))
    );
    let (status, accepted) = hub
        .request(Method::POST, path, &token, Some(body.clone()))
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    assert_eq!(accepted["node_id"], json!(one));

    let narrowed = mint(&hub, principal, Some(vec![two])).await?;
    let mut changed = body;
    changed["arguments"]["text"] = json!("different");
    let (status, problem) = hub
        .request(Method::POST, path, &narrowed, Some(changed))
        .await?;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );
    let stale = RequestId::new();
    hub.clock.set(stale.timestamp_ms() + 25 * 60 * 60 * 1000);
    let mut request = json!({
        "public_name": "tag", "arguments": {"text": "stale"},
        "target": two, "request_id": stale,
    });
    let (status, problem) = hub
        .request(Method::POST, path, &token, Some(request.clone()))
        .await?;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );
    bridge.set(one, None);
    request["target"] = json!(one);
    let (status, problem) = hub
        .request(Method::POST, path, &token, Some(request))
        .await?;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("request_id_expired"))
    );
    assert_eq!(bridge.sent.lock().unwrap().len(), 1);
    hub.shutdown().await;
    Ok(())
}

#[derive(Default)]
struct RemoteMock {
    auths: Mutex<Vec<HttpAuthSecret>>,
}

impl UpstreamDispatcher for RemoteMock {
    fn discover(
        &self,
        request: DiscoverUpstream,
    ) -> DispatchFuture<'_, Result<Vec<DiscoveredUpstreamTool>, UpstreamDispatchError>> {
        Box::pin(async move {
            Ok(vec![DiscoveredUpstreamTool {
                upstream_id: request.upstream_id,
                tool_name: "echo".to_owned(),
                description: None,
                input_schema: json!({"type": "object"}),
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
            let Some(auth) = request.auth else {
                return Err(UpstreamDispatchError::AuthFailed);
            };
            self.auths.lock().unwrap().push(auth.secret);
            Ok(Bytes::from_static(
                br#"{"content":[{"type":"text","text":"ok"}]}"#,
            ))
        })
    }
}

#[tokio::test]
async fn caller_bound_uses_each_members_account_and_never_falls_back() -> TestResult {
    let remote = Arc::new(RemoteMock::default());
    let hub = TestHub::start_with_dispatchers(
        "caller-bound",
        Config::default(),
        RequestId::new().timestamp_ms(),
        None,
        remote.clone(),
    )
    .await?;
    let (status, upstream) = hub
        .request_admin(
            Method::PUT,
            "/v1/upstreams/example",
            Some(json!({
                "url": "https://example.com/mcp"
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{upstream}");
    let upstream_id = upstream["upstream"]["upstream_id"].clone();
    let (status, discovery) = hub
        .request_admin(
            Method::POST,
            "/v1/upstreams/example/discover",
            Some(json!({})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{discovery}");
    let tool = put_tool(
        &hub,
        json!({
            "spec": {"kind": "upstream_ref", "upstream_id": upstream_id,
                "upstream_tool_name": "echo", "account_mode": "caller_bound", "runtime_ms": 60000},
        }),
        StatusCode::CREATED,
    )
    .await?;
    publish(&hub, tool, "remote", 1, "auto", None).await?;
    let (_, a) = member(&hub, "member-a", None).await?;
    let (member_b, b) = member(&hub, "member-b", None).await?;
    let invoke = "/v1/profiles/demo/invoke";
    let body = json!({"public_name": "remote", "request_id": RequestId::new(), "wait_ms": 5000});
    for (token, secret) in [(&a, "fixture-a"), (&b, "fixture-b")] {
        let (status, account) = hub
            .request(
                Method::PUT,
                "/v1/accounts/own",
                token,
                Some(json!({
                    "upstream_id": upstream_id,
                    "secret": {"kind": "http_auth", "auth": {"kind": "bearer", "token": secret}},
                })),
            )
            .await?;
        assert_eq!(status, StatusCode::CREATED, "{account}");
        let (status, response) = hub
            .request(
                Method::PUT,
                "/v1/account-bindings/me/example",
                token,
                Some(json!({"account_slug": "own"})),
            )
            .await?;
        assert_eq!(status, StatusCode::CREATED, "{response}");
        let (status, execution) = hub
            .request(Method::POST, invoke, token, Some(body.clone()))
            .await?;
        assert_eq!(status, StatusCode::OK, "{execution}");
        assert_eq!(execution["state"], "succeeded");
        assert_eq!(execution["result_access"], "available");
    }
    let (status, token) = hub
        .request_admin(
            Method::POST,
            "/v1/tokens",
            Some(json!({
                "principal_id": member_b, "label": "no-output", "withhold_sensitive": true,
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{token}");
    let token: String = serde_json::from_value(token["token"].clone())?;
    let (status, replay) = hub
        .request(Method::POST, invoke, &token, Some(body))
        .await?;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay["state"], "succeeded");
    assert_eq!(replay["result_access"], "denied");
    assert!(replay.get("result").is_none());

    let (status, _) = hub
        .request(Method::DELETE, "/v1/account-bindings/me/example", &b, None)
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, problem) = hub
        .request(
            Method::POST,
            invoke,
            &b,
            Some(json!({"public_name": "remote"})),
        )
        .await?;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("account_not_bound"))
    );
    assert_eq!(problem["extensions"]["upstream_slug"], "example");
    {
        let auths = remote.auths.lock().unwrap();
        let received: Vec<_> = auths
            .iter()
            .filter_map(|auth| match auth {
                HttpAuthSecret::Bearer { token } => Some(token.expose_secret()),
                _ => None,
            })
            .collect();
        assert_eq!(received, ["fixture-a", "fixture-b"]);
    }
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn archived_invocations_fail_closed_when_a_dependency_was_deleted() -> TestResult {
    use std::num::NonZeroU64;

    use axum::response::IntoResponse;

    use super::{ProfileInvokeRequest, invoke_profile_edition};

    let now = RequestId::new().timestamp_ms();
    let (hub, bridge, node, tool) = managed_fixture(now).await?;
    let selector = json!({"kind": "fixed", "node_ids": [node]});
    let (status, account) = hub
        .request_admin(
            Method::PUT,
            "/v1/accounts/shared?visibility=shared",
            Some(json!({
                "secret": {"kind": "secret_kv", "entries": {"fixture": "example"}}
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{account}");
    let mut definition = command("/bin/echo", selector.clone());
    definition["spec"]["account_id"] = account["account"]["account_id"].clone();
    put_tool(&hub, definition, StatusCode::OK).await?;
    publish(&hub, tool, "old", 2, "auto", None).await?;
    put_tool(&hub, command("/bin/printf", selector), StatusCode::OK).await?;
    publish(&hub, tool, "new", 3, "auto", None).await?;
    let (status, problem) = hub
        .request_admin(
            Method::DELETE,
            "/v1/accounts/shared?visibility=shared",
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{problem}");
    let (status, problem) = hub
        .request_admin(
            Method::POST,
            "/v1/tools/echo/test?version=2",
            Some(json!({
                "arguments": {"text": "missing"}, "wait_ms": 0,
            })),
        )
        .await?;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::GONE, Some("account_not_found"))
    );

    let (status, profile) = hub
        .request_admin(
            Method::PUT,
            "/v1/profiles/demo",
            Some(json!({
                "discovery_mode": "full", "bindings": []
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{profile}");
    let (status, profile) = hub
        .request_admin(Method::POST, "/v1/profiles/demo/publish", None)
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{profile}");
    let (status, problem) = hub
        .request_admin(Method::DELETE, "/v1/tools/echo", None)
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{problem}");

    let err = invoke_profile_edition(
        &hub.state,
        admin_caller(&hub).await?,
        "demo".to_owned(),
        NonZeroU64::new(1),
        serde_json::from_value::<ProfileInvokeRequest>(json!({
            "public_name": "old", "arguments": {"text": "missing"}, "wait_ms": 0,
        }))?,
    )
    .await
    .unwrap_err();
    let problem = err.into_response();
    assert_eq!(problem.status(), StatusCode::GONE);
    let bytes = axum::body::to_bytes(problem.into_body(), 1024).await?;
    let body = serde_json::from_slice::<Value>(&bytes)?;
    assert_eq!(body["code"], "tool_not_found");
    assert!(bridge.sent.lock().unwrap().is_empty());
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn owner_disable_after_http_auth_hides_an_explicit_out_of_scope_target() -> TestResult {
    use std::time::Duration;

    use axum::Router;
    use axum::body::{Body, to_bytes};
    use http::Request;
    use tokio::sync::oneshot;
    use tower_service::Service;

    type PendingRequest = (
        oneshot::Sender<()>,
        tokio::task::JoinHandle<TestResult<(StatusCode, Value)>>,
    );

    async fn hold_body(
        mut router: Router,
        token: &str,
        payload: Value,
    ) -> TestResult<PendingRequest> {
        let (entered, ready) = oneshot::channel();
        let (release, blocked) = oneshot::channel();
        let bytes = Bytes::from(serde_json::to_vec(&payload)?);
        let body = Body::from_stream(futures_util::stream::once(async move {
            let _ = entered.send(());
            blocked.await.map_err(std::io::Error::other)?;
            Ok::<Bytes, std::io::Error>(bytes)
        }));
        let request = Request::builder()
            .method(Method::POST)
            .uri("/v1/profiles/demo/invoke")
            .header("host", "localhost:8080")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(body)?;
        let pending = tokio::spawn(async move {
            let response = router.call(request).await?;
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 64 * 1024).await?;
            Ok((status, serde_json::from_slice(&bytes)?))
        });
        tokio::time::timeout(Duration::from_secs(5), ready).await??;
        Ok((release, pending))
    }

    let now = RequestId::new().timestamp_ms();
    let (hub, bridge, visible, _) = managed_fixture(now).await?;
    let hidden = seed_node(&hub, "node-hidden", "[\"test\"]").await?;
    let tag = put_tool(
        &hub,
        command("/bin/echo", json!({"kind": "tag", "tag": "test"})),
        StatusCode::OK,
    )
    .await?;
    publish(&hub, tag, "tag", 2, "async", None).await?;
    let (owner, _) = member(&hub, "owner", None).await?;
    let (status, agent) = hub
        .request_admin(
            Method::PUT,
            "/v1/principals/owned-agent",
            Some(json!({
                "kind": "agent", "owner_principal_id": owner, "managed_by_principal_id": owner,
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{agent}");
    let agent: PrincipalId = serde_json::from_value(agent["principal"]["principal_id"].clone())?;
    let (status, grant) = hub
        .request_admin(
            Method::PUT,
            "/v1/grants",
            Some(json!({
                "principal_id": agent, "scope": {"scope_kind": "global"}, "capability": "invoke"
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{grant}");
    let token = mint(&hub, agent, Some(vec![visible])).await?;
    let payload = json!({"public_name": "tag", "arguments": {"text": "pending"}});
    let (allow, allowed) = hold_body(hub.router.clone(), &token, payload.clone()).await?;
    let mut explicit = payload;
    explicit["target"] = json!(hidden);
    let (hide, hidden) = hold_body(hub.router.clone(), &token, explicit).await?;

    let (status, problem) = hub
        .request_admin(
            Method::POST,
            &format!("/v1/principals/{owner}/disable"),
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{problem}");
    allow.send(()).map_err(|_| "allowed request dropped")?;
    hide.send(()).map_err(|_| "hidden request dropped")?;

    let (status, problem) = tokio::time::timeout(Duration::from_secs(5), allowed).await???;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("owner_disabled"))
    );
    let (status, problem) = tokio::time::timeout(Duration::from_secs(5), hidden).await???;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );
    assert!(problem.get("extensions").is_none());
    assert!(bridge.sent.lock().unwrap().is_empty());

    hub.shutdown().await;
    Ok(())
}
