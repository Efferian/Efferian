use std::sync::{Arc, Mutex};
use std::time::Duration;

use efferian_protocol::{AccountId, DiscoveredUpstreamTool, HttpAuthSecret, UpstreamId};
use http::{Method, StatusCode};
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::test_support::{TestHub, TestResult, send_json};
use crate::upstream_dispatch::{
    DiscoverUpstream, DispatchFuture, UpstreamDispatchError, UpstreamDispatcher,
    UpstreamInvalidation,
};

type Outcome = Result<Vec<DiscoveredUpstreamTool>, UpstreamDispatchError>;
type Call = (DiscoverUpstream, oneshot::Sender<Outcome>);
type Response = (StatusCode, Value);

struct DiscoveryDispatcher {
    calls: mpsc::UnboundedSender<Call>,
    invalidations: Mutex<Vec<UpstreamInvalidation>>,
}

impl UpstreamDispatcher for DiscoveryDispatcher {
    fn discover(&self, request: DiscoverUpstream) -> DispatchFuture<'_, Outcome> {
        Box::pin(async move {
            let (send, recv) = oneshot::channel();
            self.calls
                .send((request, send))
                .map_err(|_| UpstreamDispatchError::Disconnected)?;
            recv.await
                .map_err(|_| UpstreamDispatchError::Disconnected)?
        })
    }

    fn invalidate(&self, invalidation: UpstreamInvalidation) {
        if let Ok(mut invalidations) = self.invalidations.lock() {
            invalidations.push(invalidation);
        }
    }
}

async fn start() -> TestResult<(
    TestHub,
    Arc<DiscoveryDispatcher>,
    mpsc::UnboundedReceiver<Call>,
)> {
    let (calls, pending) = mpsc::unbounded_channel();
    let dispatcher = Arc::new(DiscoveryDispatcher {
        calls,
        invalidations: Mutex::new(Vec::new()),
    });
    let hub = TestHub::start_with_dispatchers(
        "upstream-catalog",
        Config::default(),
        1_800_000_000_000,
        None,
        Arc::clone(&dispatcher) as Arc<dyn UpstreamDispatcher>,
    )
    .await?;
    Ok((hub, dispatcher, pending))
}

async fn put(hub: &TestHub, url: &str, headers: Value) -> TestResult<Response> {
    hub.request_admin(
        Method::PUT,
        "/v1/upstreams/primary",
        Some(json!({"url": url, "headers": headers})),
    )
    .await
}

async fn detail(hub: &TestHub) -> TestResult<Value> {
    let (status, response) = hub
        .request_admin(Method::GET, "/v1/upstreams/primary", None)
        .await?;
    assert_eq!(status, StatusCode::OK);
    Ok(response)
}

async fn account(hub: &TestHub, upstream_id: UpstreamId, secret: &str) -> TestResult<Response> {
    hub.request_admin(
        Method::PUT,
        "/v1/accounts/admin-credential",
        Some(json!({
            "upstream_id": upstream_id,
            "secret": { "kind": "http_auth", "auth": { "kind": "bearer", "token": secret } }
        })),
    )
    .await
}

fn discover(hub: &TestHub, selection: Value) -> JoinHandle<TestResult<Response>> {
    let router = hub.router.clone();
    let token = hub.admin_token.clone();
    tokio::spawn(async move {
        send_json(
            &router,
            Method::POST,
            "/v1/upstreams/primary/discover",
            &token,
            Some(selection),
        )
        .await
    })
}

async fn next_call(pending: &mut mpsc::UnboundedReceiver<Call>) -> TestResult<Call> {
    let call = tokio::time::timeout(Duration::from_secs(5), pending.recv()).await?;
    call.ok_or_else(|| "missing discovery call".into())
}

fn tool(upstream_id: UpstreamId, name: &str) -> DiscoveredUpstreamTool {
    DiscoveredUpstreamTool {
        upstream_id,
        tool_name: name.into(),
        description: Some("An example tool".into()),
        input_schema: json!({"type": "object"}),
        annotations: None,
    }
}

fn respond(send: oneshot::Sender<Outcome>, outcome: Outcome) {
    assert!(
        send.send(outcome).is_ok(),
        "discover should be waiting for its dispatcher"
    );
}

#[tokio::test]
async fn origin_lock_and_switches_preserve_the_intended_cache_and_version() -> TestResult {
    let (hub, dispatcher, mut pending) = start().await?;
    let url = "https://[::ffff:8.8.8.8]:443/mcp";
    let (status, created) = put(&hub, url, json!({"X-Client": "catalog"})).await?;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["outcome"], "created");
    assert_eq!(created["upstream"]["config_version"], 1);
    let upstream_id: UpstreamId =
        serde_json::from_value(created["upstream"]["upstream_id"].clone())?;
    let (status, _) = hub
        .request_admin(
            Method::PUT,
            "/v1/upstreams/another",
            Some(json!({"url":"https://another.example/"})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED);
    let (status, page) = hub
        .request_admin(Method::GET, "/v1/upstreams?limit=1", None)
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        page["items"].as_array().ok_or("missing upstreams")?.len(),
        1
    );
    assert!(page["items"][0].get("discovered_tools").is_none());
    let cursor = page["next_cursor"]
        .as_str()
        .ok_or("missing upstream cursor")?;
    let (_, last) = hub
        .request_admin(
            Method::GET,
            &format!("/v1/upstreams?limit=1&cursor={cursor}"),
            None,
        )
        .await?;
    assert_ne!(
        page["items"][0]["upstream_id"],
        last["items"][0]["upstream_id"]
    );
    assert!(last["next_cursor"].is_null());

    let refresh = discover(&hub, json!({}));
    let (sent, send) = next_call(&mut pending).await?;
    assert_eq!(sent.upstream_id, upstream_id);
    assert_eq!(sent.config_version, 1);
    assert_eq!(
        sent.headers.get("x-client").map(String::as_str),
        Some("catalog")
    );
    assert!(sent.auth.is_none());
    respond(send, Ok(vec![tool(upstream_id, "cached")]));
    assert_eq!(refresh.await??.0, StatusCode::OK);
    assert_eq!(
        detail(&hub).await?["discovered_tools"][0]["tool_name"],
        "cached"
    );

    let (status, unchanged) = put(&hub, url, json!({"x-client": "catalog"})).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(unchanged["outcome"], "unchanged");
    assert_eq!(unchanged["upstream"]["discovered_tool_count"], 1);

    let (status, _) = account(&hub, upstream_id, "fixture-token").await?;
    assert_eq!(status, StatusCode::CREATED);
    let (status, problem) = put(&hub, "https://8.8.4.4/mcp", json!({})).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["code"], "resource_in_use");
    let before_switch = detail(&hub).await?;
    assert_eq!(before_switch["config_version"], 1);
    assert_eq!(before_switch["discovered_tool_count"], 1);

    for action in ["disable", "disable"] {
        let uri = format!("/v1/upstreams/primary/{action}");
        assert_eq!(
            hub.request_admin(Method::POST, &uri, None).await?.0,
            StatusCode::NO_CONTENT
        );
    }
    let (status, _) = hub
        .request_admin(
            Method::POST,
            "/v1/upstreams/primary/discover",
            Some(json!({})),
        )
        .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(matches!(
        pending.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert_eq!(detail(&hub).await?["config_version"], 2);
    assert_eq!(
        hub.request_admin(Method::POST, "/v1/upstreams/primary/enable", None)
            .await?
            .0,
        StatusCode::NO_CONTENT
    );
    let enabled = detail(&hub).await?;
    assert_eq!(enabled["config_version"], 3);
    assert_eq!(enabled["discovered_tool_count"], 1);
    assert!(enabled["disabled_at_ms"].is_null());

    let (status, updated) = put(&hub, "https://8.8.8.8:443/path?query=ok", json!({})).await?;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["outcome"], "updated");
    assert_eq!(updated["upstream"]["url"], "https://8.8.8.8/path?query=ok");
    assert_eq!(updated["upstream"]["config_version"], 4);
    assert_eq!(updated["upstream"]["discovered_tool_count"], 0);
    assert!(updated["upstream"]["discovered_at_ms"].is_null());
    assert_eq!(
        hub.request_admin(Method::DELETE, "/v1/upstreams/primary", None)
            .await?
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        hub.request_admin(Method::DELETE, "/v1/accounts/admin-credential", None)
            .await?
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        hub.request_admin(Method::DELETE, "/v1/upstreams/primary", None)
            .await?
            .0,
        StatusCode::NO_CONTENT
    );

    {
        let invalidations = dispatcher
            .invalidations
            .lock()
            .map_err(|_| "poisoned invalidation log")?;
        assert_eq!(
            invalidations
                .iter()
                .filter(|event| **event == UpstreamInvalidation::Upstream(upstream_id))
                .count(),
            5
        );
    }
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn discovery_uses_the_selected_account_and_rejects_stale_writes_in_one_tick() -> TestResult {
    let (hub, _, mut pending) = start().await?;
    let (_, created) = put(&hub, "https://upstream.example/mcp", json!({})).await?;
    let upstream_id: UpstreamId =
        serde_json::from_value(created["upstream"]["upstream_id"].clone())?;
    let (status, created) = account(&hub, upstream_id, "first-fixture-token").await?;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let account_id: AccountId = serde_json::from_value(created["account"]["account_id"].clone())?;
    let (status, binding) = hub
        .request_admin(
            Method::PUT,
            "/v1/account-bindings/me/primary",
            Some(json!({"account_id":account_id})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{binding}");

    let initial = discover(&hub, json!({}));
    let (request, send) = next_call(&mut pending).await?;
    assert_eq!(request.url, "https://upstream.example/mcp");
    assert_eq!(request.principal_id, hub.admin_id);
    let credential = request
        .auth
        .ok_or("discovery did not use the administrator's binding")?;
    assert_eq!(credential.account_id, account_id);
    assert_eq!(credential.secret_version, 1);
    assert!(
        matches!(credential.secret, HttpAuthSecret::Bearer { token } if token.expose_secret() == "first-fixture-token"),
        "discovery used different account credentials"
    );
    respond(send, Ok(vec![tool(upstream_id, "first")]));
    let (status, first) = initial.await??;
    assert_eq!(status, StatusCode::OK);

    let first_refresh = discover(&hub, json!({"account_id":account_id}));
    let (_, first_send) = next_call(&mut pending).await?;
    let second_refresh = discover(&hub, json!({"account_slug":"admin-credential"}));
    let (_, second_send) = next_call(&mut pending).await?;
    respond(first_send, Ok(vec![tool(upstream_id, "winner")]));
    let (status, winner) = first_refresh.await??;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(winner["discovered_at_ms"], first["discovered_at_ms"]);
    respond(second_send, Ok(vec![tool(upstream_id, "stale")]));
    assert_eq!(second_refresh.await??.0, StatusCode::CONFLICT);

    let during_rotation = discover(&hub, json!({}));
    let (_, send) = next_call(&mut pending).await?;
    assert_eq!(
        account(&hub, upstream_id, "rotated-fixture-token").await?.0,
        StatusCode::OK
    );
    respond(send, Ok(vec![tool(upstream_id, "stale-account")]));
    assert_eq!(during_rotation.await??.0, StatusCode::CONFLICT);

    let during_switch = discover(&hub, json!({}));
    let (request, send) = next_call(&mut pending).await?;
    let credential = request
        .auth
        .ok_or("discovery did not use the rotated credential")?;
    assert_eq!(credential.account_id, account_id);
    assert_eq!(credential.secret_version, 2);
    for action in ["disable", "enable"] {
        let uri = format!("/v1/upstreams/primary/{action}");
        assert_eq!(
            hub.request_admin(Method::POST, &uri, None).await?.0,
            StatusCode::NO_CONTENT
        );
    }
    respond(send, Ok(vec![tool(upstream_id, "stale-config")]));
    assert_eq!(during_switch.await??.0, StatusCode::CONFLICT);

    for selection in [
        json!({"account_id": account_id, "account_slug": "admin-credential"}),
        json!({"visibility":"private"}),
    ] {
        let (status, _) = hub
            .request_admin(
                Method::POST,
                "/v1/upstreams/primary/discover",
                Some(selection),
            )
            .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    assert!(matches!(
        pending.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    let current = detail(&hub).await?;
    assert_eq!(current["discovered_at_ms"], winner["discovered_at_ms"]);
    assert_eq!(current["discovered_tools"][0]["tool_name"], "winner");

    let (status, _) = hub
        .request_admin(
            Method::POST,
            "/v1/upstreams/primary/discover",
            Some(json!({"account_id": AccountId::new()})),
        )
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = put(
        &hub,
        "https://upstream.example/mcp",
        json!({"x-client": "public"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    let (status, collision) = hub
        .request_admin(
            Method::PUT,
            "/v1/accounts/header-credential",
            Some(json!({
                "upstream_id": upstream_id,
                "secret": {
                    "kind": "http_auth",
                    "auth": { "kind": "header", "name": "X-Client", "value": "fixture-header-secret" }
                }
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{collision}");
    let (status, _) = hub
        .request_admin(
            Method::POST,
            "/v1/upstreams/primary/discover",
            Some(json!({"account_slug": "header-credential"})),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(matches!(
        pending.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn malformed_or_large_discovery_preserves_the_last_successful_cache() -> TestResult {
    let (hub, _, mut pending) = start().await?;
    let (_, created) = put(&hub, "https://upstream.example/mcp", json!({})).await?;
    let upstream_id: UpstreamId =
        serde_json::from_value(created["upstream"]["upstream_id"].clone())?;

    for (outcome, expected) in [
        (Ok(vec![tool(upstream_id, "cached")]), StatusCode::OK),
        (
            Ok(vec![tool(upstream_id, "duplicate"); 2]),
            StatusCode::BAD_GATEWAY,
        ),
        (
            Ok(vec![tool(upstream_id, "too-many"); 513]),
            StatusCode::BAD_GATEWAY,
        ),
        (
            Ok(vec![DiscoveredUpstreamTool {
                description: Some("a".repeat(1024 * 1024)),
                ..tool(upstream_id, "too-large")
            }]),
            StatusCode::BAD_GATEWAY,
        ),
        (
            Err(UpstreamDispatchError::AuthFailed),
            StatusCode::BAD_GATEWAY,
        ),
        (
            Err(UpstreamDispatchError::TimedOut),
            StatusCode::GATEWAY_TIMEOUT,
        ),
    ] {
        let refresh = discover(&hub, json!({}));
        let (_, send) = next_call(&mut pending).await?;
        respond(send, outcome);
        assert_eq!(refresh.await??.0, expected);
        let current = detail(&hub).await?;
        assert_eq!(current["discovered_tool_count"], 1);
        assert_eq!(current["discovered_tools"][0]["tool_name"], "cached");
    }
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn upstream_tool_detail_preserves_effective_annotations_across_read_and_put() -> TestResult {
    let (hub, _, mut pending) = start().await?;
    let (status, upstream) = put(&hub, "https://example.com/mcp", json!({})).await?;
    assert_eq!(status, StatusCode::CREATED);
    let id = serde_json::from_value(upstream["upstream"]["upstream_id"].clone())?;
    let refresh = discover(&hub, json!({}));
    let (_, send) = next_call(&mut pending).await?;
    let mut discovered = tool(id, "echo");
    let inherited = json!({"title": "Upstream hint", "read_only_hint": true});
    discovered.annotations = Some(serde_json::from_value(inherited.clone())?);
    respond(send, Ok(vec![discovered]));
    assert_eq!(refresh.await??.0, StatusCode::OK);

    for (slug, authored) in [
        ("inherited", None),
        (
            "custom",
            Some(json!({"title":"Operator hint", "destructive_hint":true})),
        ),
    ] {
        let uri = format!("/v1/tools/{slug}");
        let mut definition = json!({"spec": {"kind":"upstream_ref", "upstream_id":id, "upstream_tool_name":"echo", "account_mode":"none", "runtime_ms":1000}});
        if let Some(annotations) = &authored {
            definition["annotations"] = annotations.clone();
        }
        let (status, created) = hub
            .request_admin(Method::PUT, &uri, Some(definition))
            .await?;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let (status, detail) = hub.request_admin(Method::GET, &uri, None).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(detail, created["tool"]);
        assert!(detail["definition"].get("input_schema").is_none());
        assert_eq!(
            &detail["definition"]["annotations"],
            authored.as_ref().unwrap_or(&inherited)
        );
        let (status, replay) = hub
            .request_admin(Method::PUT, &uri, Some(detail["definition"].clone()))
            .await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(replay["outcome"], "unchanged");
        assert_eq!(replay["tool"]["current_version"], 1);
    }
    hub.shutdown().await;
    Ok(())
}
