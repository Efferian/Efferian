use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::response::Response;
use efferian_protocol::{
    ActorId, Event, ExecutionEventPayload, ExecutionId, ExecutionState, GrantScope, NodeId,
    PrincipalId, ProfileId, RequestId, TokenId, ToolId,
};
use futures_util::FutureExt;
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use rusqlite::params;
use serde_json::{Value, json};
use tokio::sync::Semaphore;
use tokio::time::{advance, pause, timeout};
use tower_service::Service;

use crate::config::Config;
use crate::storage::{RevocationReason, RevocationSignal, StorageError, WriteTxError};
use crate::test_support::{TestHub, TestResult};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

async fn open_stream(hub: &TestHub, path: &str, token: &str) -> TestResult<Response> {
    Ok(hub
        .router
        .clone()
        .call(
            Request::builder()
                .uri(path)
                .header("host", "localhost:8080")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?)
}

async fn stream(hub: &TestHub, path: &str, token: &str) -> TestResult<Body> {
    let response = open_stream(hub, path, token).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/x-ndjson");
    assert_eq!(response.headers()["x-accel-buffering"], "no");
    assert_eq!(response.headers()["cache-control"], "no-store");
    Ok(response.into_body())
}

async fn ndjson(body: &mut Body) -> TestResult<Option<Value>> {
    decode_frame(timeout(TEST_TIMEOUT, body.frame()).await?)
}

fn decode_frame(
    frame: Option<Result<hyper::body::Frame<bytes::Bytes>, axum::Error>>,
) -> TestResult<Option<Value>> {
    let Some(frame) = frame.transpose()? else {
        return Ok(None);
    };
    let bytes = frame.into_data().map_err(|_| "expected a data frame")?;
    assert!(bytes.ends_with(b"\n"));
    Ok(Some(serde_json::from_slice(&bytes)?))
}

async fn append(hub: &TestHub, events: impl IntoIterator<Item = Event>) -> TestResult {
    let actor = ActorId::Hub(*hub.state.storage.hub_id());
    let events: Vec<_> = events.into_iter().collect();
    hub.state
        .storage
        .execute_work::<_, Infallible, _>(0, move |tx| {
            for event in events {
                tx.append_event(actor, event)?;
            }
            Ok(())
        })
        .await?;
    Ok(())
}

async fn mint(
    hub: &TestHub,
    principal: PrincipalId,
    expires_at_ms: Option<i64>,
) -> TestResult<(TokenId, String)> {
    let (status, result) = hub
        .request_admin(
            Method::POST,
            "/v1/tokens",
            Some(json!({
                "principal_id": principal,
                "label": "events",
                "expires_at_ms": expires_at_ms
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    let token_id = serde_json::from_value(result["token_id"].clone())?;
    let token = result["token"].as_str().ok_or("missing token")?.to_owned();
    Ok((token_id, token))
}

async fn create_principal(hub: &TestHub, name: &str, definition: Value) -> TestResult<PrincipalId> {
    let (status, result) = hub
        .request_admin(
            Method::PUT,
            &format!("/v1/principals/{name}"),
            Some(definition),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    Ok(serde_json::from_value(
        result["principal"]["principal_id"].clone(),
    )?)
}

async fn prune_through(hub: &TestHub, cursor: i64) -> TestResult {
    // Commit a deterministic prefix prune without changing the real broadcaster.
    hub.write(move |conn| {
        conn.execute("DELETE FROM events WHERE seq <= ?1", [cursor])?;
        conn.execute(
            "UPDATE hub_meta SET events_pruned_through_seq = ?1 WHERE id = 1",
            [cursor],
        )?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn json_and_ndjson_keep_a_raw_cursor_over_hidden_events() -> TestResult {
    let hub = TestHub::start("event-pages", Config::default(), 10_000).await?;
    let member = create_principal(&hub, "member", json!({"kind": "member"})).await?;
    let (_, token) = mint(&hub, member, None).await?;
    let (status, empty) = hub.request(Method::GET, "/v1/events", &token, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        empty,
        json!({
            "items": [], "next_seq": 0, "oldest_available_seq": 1, "latest_seq": 0, "has_more": false
        })
    );

    let visible = Event::PrincipalRevoked(member);
    let hidden = Event::PrincipalRevoked(hub.admin_id);
    append(&hub, [visible.clone(), hidden, visible.clone()]).await?;

    let (status, all) = hub.request(Method::GET, "/v1/events", &token, None).await?;
    assert_eq!(status, StatusCode::OK);
    let items = all["items"].as_array().ok_or("missing events")?;
    assert_eq!(
        items.iter().map(|event| &event["seq"]).collect::<Vec<_>>(),
        [&json!(1), &json!(3)]
    );
    assert_eq!(all["next_seq"], 3);
    let (status, page) = hub
        .request(Method::GET, "/v1/events?after=1&limit=1", &token, None)
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["items"], json!([]));
    assert_eq!(page["next_seq"], 2);
    assert_eq!(page["has_more"], true);
    let (_, final_page) = hub
        .request(Method::GET, "/v1/events?after=2&limit=1", &token, None)
        .await?;
    assert_eq!(final_page["items"], json!([items[1]]));
    assert_eq!(final_page["has_more"], false);

    let mut body = stream(
        &hub,
        "/v1/events/stream?kinds=profile.published,auth.revoked",
        &token,
    )
    .await?;
    append(&hub, [visible]).await?;
    assert_eq!(
        ndjson(&mut body).await?,
        Some(json!({"type": "event", "event": items[0]}))
    );
    assert_eq!(
        ndjson(&mut body).await?,
        Some(json!({"type": "event", "event": items[1]}))
    );
    assert_eq!(
        ndjson(&mut body).await?.ok_or("expected event")?["event"]["seq"],
        4
    );
    drop(body);

    for suffix in [
        "after=-1",
        "kinds=",
        "kinds=unknown",
        "kinds=auth.revoked,",
        "kinds=%20auth.revoked",
    ] {
        for path in ["/v1/events", "/v1/events/stream"] {
            let uri = format!("{path}?{suffix}");
            let (status, problem) =
                timeout(TEST_TIMEOUT, hub.request(Method::GET, &uri, &token, None)).await??;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{path}?{suffix}: {problem}"
            );
            assert_eq!(problem["code"], "invalid_input");
        }
    }
    for suffix in ["limit=0", "limit=501"] {
        let (status, _) = hub
            .request(Method::GET, &format!("/v1/events?{suffix}"), &token, None)
            .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    prune_through(&hub, 2).await?;
    for after in [1, 5] {
        for path in ["/v1/events", "/v1/events/stream"] {
            let uri = format!("{path}?after={after}");
            let (status, problem) =
                timeout(TEST_TIMEOUT, hub.request(Method::GET, &uri, &token, None)).await??;
            assert_eq!(status, StatusCode::GONE);
            assert_eq!(problem["code"], "resync_required");
            assert_eq!(
                problem["extensions"],
                json!({"oldest_available_seq": 3, "latest_seq": 4})
            );
        }
    }
    for after in [0, 2, 4] {
        let (status, page) = hub
            .request(
                Method::GET,
                &format!("/v1/events?after={after}"),
                &token,
                None,
            )
            .await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["next_seq"], 4);
        assert_eq!(
            page["items"].as_array().ok_or("missing items")?.len(),
            if after == 4 { 0 } else { 2 }
        );
    }
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn broadcast_lag_catches_up_or_resyncs_even_from_zero() -> TestResult {
    let hub = TestHub::start("event-lag", Config::default(), 10_000).await?;
    let path = "/v1/events/stream?kinds=profile.published";
    let mut recoverable = stream(&hub, path, &hub.admin_token).await?;
    let mut gapped = stream(&hub, path, &hub.admin_token).await?;

    let hidden = Event::PrincipalRevoked(hub.admin_id);
    let visible = Event::ProfilePublished(ProfileId::new());
    let events = std::iter::repeat_n(hidden, 1_025).chain([visible.clone()]);
    append(&hub, events).await?;
    assert_eq!(
        ndjson(&mut recoverable)
            .await?
            .ok_or("expected recovered frame")?["event"]["seq"],
        1_026
    );
    append(&hub, [visible]).await?;
    assert_eq!(
        ndjson(&mut recoverable)
            .await?
            .ok_or("expected live frame")?["event"]["seq"],
        1_027
    );
    drop(recoverable);

    prune_through(&hub, 1).await?;
    assert_eq!(
        ndjson(&mut gapped).await?,
        Some(json!({"type": "resync_required", "oldest_available_seq": 2, "latest_seq": 1_027}))
    );
    assert_eq!(ndjson(&mut gapped).await?, None);
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn lag_recovery_intersects_opening_grants_and_current_durable_permissions() -> TestResult {
    let hub = TestHub::start("event-lag-auth", Config::default(), 10_000).await?;
    let member = create_principal(&hub, "member", json!({"kind": "member"})).await?;
    let (_, token) = mint(&hub, member, None).await?;
    let (revoked_id, revoked_token) = mint(&hub, member, None).await?;
    let original = ProfileId::new();
    let gained = ProfileId::new();
    hub.write(move |conn| {
        conn.execute(
            "INSERT INTO profiles (profile_id, slug, discovery_mode, created_at_ms, updated_at_ms)
             VALUES (?1, 'original', 'full', 10000, 10000), (?2, 'gained', 'full', 10000, 10000)",
            params![original.to_string(), gained.to_string()],
        )?;
        Ok(())
    })
    .await?;
    let grant = |profile| {
        hub.request_admin(
            Method::PUT,
            "/v1/grants",
            Some(json!({
                "principal_id": member,
                "scope": GrantScope::Profile(profile),
                "capability": "discover"
            })),
        )
    };
    let (status, response) = grant(original).await?;
    assert_eq!(status, StatusCode::CREATED, "{response}");
    let mut active = stream(&hub, "/v1/events/stream", &token).await?;
    let mut revoked = stream(&hub, "/v1/events/stream", &revoked_token).await?;

    // Model the window after COMMIT and before RevocationWatch publishes.
    hub.write(move |conn| {
        conn.execute(
            "DELETE FROM grants WHERE principal_id = ?1 AND scope_kind = 'profile' AND scope_id = ?2",
            params![member.to_string(), original.to_string()],
        )?;
        conn.execute(
            "UPDATE auth_tokens SET revoked_at_ms = 10000 WHERE token_id = ?1",
            [revoked_id.to_string()],
        )?;
        Ok(())
    })
    .await?;
    let (status, response) = grant(gained).await?;
    assert_eq!(status, StatusCode::CREATED, "{response}");
    let hidden = Event::PrincipalRevoked(hub.admin_id);
    append(
        &hub,
        std::iter::repeat_n(hidden, 1_025).chain([
            Event::ProfilePublished(original),
            Event::ProfilePublished(gained),
            Event::PrincipalRevoked(member),
        ]),
    )
    .await?;

    // The original grant was revoked and the newly granted profile is outside the opening scope.
    let frame = ndjson(&mut active)
        .await?
        .ok_or("expected the caller's event")?;
    assert_eq!(frame["event"]["kind"], "auth.revoked");
    assert_eq!(frame["event"]["aggregate_id"], member.to_string());
    assert_eq!(frame["event"]["seq"], 1_028);
    assert_eq!(ndjson(&mut revoked).await?, None);
    drop(active);
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn a_prune_between_initial_catch_up_pages_emits_one_resync() -> TestResult {
    let hub = TestHub::start("event-page-prune", Config::default(), 10_000).await?;
    let visible = Event::ProfilePublished(ProfileId::new());
    let hidden = Event::PrincipalRevoked(hub.admin_id);
    append(
        &hub,
        [visible.clone()]
            .into_iter()
            .chain(std::iter::repeat_n(hidden, 500))
            .chain([visible]),
    )
    .await?;
    let mut body = stream(
        &hub,
        "/v1/events/stream?kinds=profile.published",
        &hub.admin_token,
    )
    .await?;
    assert_eq!(
        ndjson(&mut body).await?.ok_or("expected initial event")?["event"]["seq"],
        1
    );
    prune_through(&hub, 501).await?;
    assert_eq!(
        ndjson(&mut body).await?,
        Some(json!({"type": "resync_required", "oldest_available_seq": 502, "latest_seq": 502}))
    );
    assert_eq!(ndjson(&mut body).await?, None);
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn live_frames_do_not_use_the_read_pool() -> TestResult {
    let hub = TestHub::start("event-live-readers", Config::default(), 10_000).await?;
    let mut body = stream(&hub, "/v1/events/stream", &hub.admin_token).await?;

    // Occupy the six general reader slots while a live frame is emitted.
    let release = Arc::new(Semaphore::new(0));
    let (ready, mut waiting) = tokio::sync::mpsc::channel(6);
    let mut blockers = Vec::new();
    for _ in 0..6 {
        let storage = hub.state.storage.clone();
        let release = Arc::clone(&release);
        let ready = ready.clone();
        let rt = tokio::runtime::Handle::current();
        blockers.push(tokio::spawn(async move {
            storage
                .read_snapshot::<_, StorageError>(move |_| {
                    let _ = ready.blocking_send(());
                    rt.block_on(release.acquire())
                        .map_err(|_| StorageError::ShuttingDown)?
                        .forget();
                    Ok(())
                })
                .await
        }));
    }
    let live = async {
        for _ in 0..6 {
            timeout(TEST_TIMEOUT, waiting.recv())
                .await?
                .ok_or("missing reader barrier")?;
        }
        append(&hub, [Event::ProfilePublished(ProfileId::new())]).await?;
        ndjson(&mut body).await
    }
    .await;
    release.add_permits(6);
    for blocker in blockers {
        blocker.await??;
    }
    assert_eq!(live?.ok_or("expected live frame")?["event"]["seq"], 1);
    drop(body);
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn pings_ignore_filtered_traffic_and_a_quiet_expired_stream_ends() -> TestResult {
    let hub = TestHub::start("event-ping", Config::default(), 10_000).await?;
    let (_, token) = mint(&hub, hub.admin_id, Some(30_000)).await?;
    // The actor runs on an OS thread. Keep Tokio from automatically advancing
    // a paused clock while awaiting a commit on that thread.
    let (release, keep_clock_manual) = tokio::sync::oneshot::channel::<()>();
    let blocker = tokio::task::spawn_blocking(move || keep_clock_manual.blocking_recv());
    pause();
    let mut body = stream(&hub, "/v1/events/stream?kinds=profile.published", &token).await?;
    assert!(body.frame().now_or_never().is_none());

    for elapsed in [5, 10, 15] {
        hub.clock.set(10_000 + elapsed * 1_000);
        append(&hub, [Event::PrincipalRevoked(hub.admin_id)]).await?;
        advance(Duration::from_secs(5)).await;
        if elapsed < 15 {
            assert!(body.frame().now_or_never().is_none());
        }
    }
    drop(release);
    let _ = blocker.await?;
    let ping = timeout(Duration::from_millis(10), body.frame()).await?;
    assert_eq!(decode_frame(ping)?, Some(json!({"type": "ping"})));

    hub.clock.set(30_000);
    advance(Duration::from_secs(5)).await;
    let frame = body
        .frame()
        .now_or_never()
        .ok_or("expired stream stayed open")?;
    assert_eq!(decode_frame(frame)?, None);
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn scoped_revocation_targets_only_the_matching_token_and_lag_ends_a_stream() -> TestResult {
    let mut config = Config::default();
    config.max_event_streams_per_principal = 2;
    let hub = TestHub::start("event-revoked", config, 10_000).await?;
    let (revoked_token, first) = mint(&hub, hub.admin_id, None).await?;
    let (_, sibling) = mint(&hub, hub.admin_id, None).await?;
    append(&hub, [Event::ProfilePublished(ProfileId::new())]).await?;
    let mut revoked = stream(&hub, "/v1/events/stream", &first).await?;
    let mut active = stream(&hub, "/v1/events/stream", &sibling).await?;
    assert_limited(&hub).await?;

    let (status, reason) = hub
        .request_admin(
            Method::POST,
            &format!("/v1/tokens/{revoked_token}/revoke"),
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{reason}");
    assert_eq!(ndjson(&mut revoked).await?, None);
    drop(stream(&hub, "/v1/events/stream", &sibling).await?);
    assert_eq!(
        ndjson(&mut active).await?.ok_or("missing sibling frame")?["event"]["seq"],
        1
    );
    assert_eq!(
        ndjson(&mut active).await?.ok_or("missing sibling frame")?["event"]["kind"],
        "auth.revoked"
    );

    let profile_id = ProfileId::new();
    let reason = RevocationReason::EditionDisabled {
        profile_id,
        version: 1,
    };
    let send = |count: usize| {
        hub.state.storage.execute_work(0, move |tx| {
            for _ in 0..count {
                tx.stage_revocation(RevocationSignal {
                    reason,
                    affected_principals: Vec::new(),
                    affected_nodes: Vec::new(),
                });
            }
            Ok::<_, WriteTxError<Infallible>>(())
        })
    };
    send(1).await?;
    append(&hub, [Event::ProfilePublished(profile_id)]).await?;
    assert_eq!(
        ndjson(&mut active)
            .await?
            .ok_or("edition signal closed the stream")?["event"]["seq"],
        3
    );

    send(129).await?;
    append(&hub, [Event::ProfilePublished(profile_id)]).await?;
    assert_eq!(ndjson(&mut active).await?, None);
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn observers_receive_execution_events_only_with_current_grants() -> TestResult {
    let hub = TestHub::start("event-observer", Config::default(), 10_000).await?;
    let observer = create_principal(
        &hub,
        "observer",
        json!({"kind": "service", "observe_executions": true}),
    )
    .await?;
    let (_, token) = mint(&hub, observer, None).await?;
    let profile = ProfileId::new();
    let execution = ExecutionId::new();
    let node = NodeId::new();
    let tool = ToolId::new();
    let admin = hub.admin_id;
    hub.write(move |conn| {
        conn.execute(
            "INSERT INTO profiles (profile_id, slug, discovery_mode, created_at_ms, updated_at_ms)
             VALUES (?1, 'test-profile', 'full', 10000, 10000)",
            [profile.to_string()],
        )?;
        conn.execute(
            "INSERT INTO executions (
                execution_id, invoke_kind, request_id, request_digest, caller_principal_id,
                caller_token_id, profile_id, profile_version, tool_id, tool_version, public_name,
                executor_kind, node_id, node_session_epoch, state, deadline_at_ms, created_at_ms,
                result_expires_at_ms, expires_at_ms
             ) VALUES (?1, 'profile', ?2, ?3, ?4, ?5, ?6, 1, ?7, 1, 'probe', 'node', ?8, 1,
                       'running', 1000000, 10000, 1000000, 1000000)",
            params![
                execution.to_string(),
                RequestId::new().to_string(),
                "0".repeat(64),
                admin.to_string(),
                TokenId::new_user_or_agent().to_string(),
                profile.to_string(),
                tool.to_string(),
                node.to_string()
            ],
        )?;
        Ok(())
    })
    .await?;
    let (status, response) = hub
        .request_admin(
            Method::PUT,
            "/v1/grants",
            Some(json!({
                "principal_id": observer,
                "scope": GrantScope::Profile(profile),
                "capability": "discover"
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{response}");
    let event = Event::ExecutionStarted(ExecutionEventPayload {
        execution_id: execution,
        state: ExecutionState::Running,
        profile_id: Some(profile),
        tool_id: tool,
        public_name: "probe".to_owned(),
        node_id: Some(node),
        exit_code: None,
        error_code: None,
        duration_ms: None,
    });
    append(&hub, [event.clone()]).await?;
    let (_, visible) = hub.request(Method::GET, "/v1/events", &token, None).await?;
    assert_eq!(visible["items"][0]["aggregate_id"], execution.to_string());
    assert!(visible["items"][0]["payload"].get("arguments").is_none());
    assert!(
        visible["items"][0]["payload"]
            .get("error_message")
            .is_none()
    );
    assert_eq!(
        hub.request(
            Method::GET,
            &format!("/v1/executions/{execution}"),
            &token,
            None
        )
        .await?
        .0,
        StatusCode::NOT_FOUND
    );
    let mut body = stream(&hub, "/v1/events/stream", &token).await?;
    let (status, response) = hub
        .request_admin(
            Method::PUT,
            "/v1/principals/observer",
            Some(json!({"kind": "service", "observe_executions": false})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{response}");
    append(&hub, [event]).await?;
    assert_eq!(ndjson(&mut body).await?, None);
    let (status, page) = hub.request(Method::GET, "/v1/events", &token, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["items"], json!([]));
    assert_eq!(page["next_seq"], 2);
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn node_events_use_the_manager_recorded_when_they_were_written() -> TestResult {
    let hub = TestHub::start("event-node-manager", Config::default(), 10_000).await?;
    let orchestrator_body = json!({"kind": "service", "is_orchestrator": true});
    let old = create_principal(&hub, "old-manager", orchestrator_body.clone()).await?;
    let new = create_principal(&hub, "new-manager", orchestrator_body).await?;
    let (_, old_token) = mint(&hub, old, None).await?;
    let (_, new_token) = mint(&hub, new, None).await?;
    let node = NodeId::new();
    hub.write(move |conn| {
        conn.execute(
            "INSERT INTO nodes (
                node_id, name, credential_hmac, managed_by_principal_id, created_at_ms, updated_at_ms
             ) VALUES (?1, 'probe', 'fixture', ?2, 10000, 10000)",
            params![node.to_string(), old.to_string()],
        )?;
        Ok(())
    })
    .await?;
    append(&hub, [Event::NodeConnected(node)]).await?;
    hub.write(move |conn| {
        conn.execute(
            "UPDATE nodes SET managed_by_principal_id = ?2 WHERE node_id = ?1",
            params![node.to_string(), new.to_string()],
        )?;
        Ok(())
    })
    .await?;
    let (_, old_events) = hub
        .request(
            Method::GET,
            "/v1/events?kinds=node.connected",
            &old_token,
            None,
        )
        .await?;
    let (_, new_events) = hub
        .request(
            Method::GET,
            "/v1/events?kinds=node.connected",
            &new_token,
            None,
        )
        .await?;
    assert_eq!(old_events["items"][0]["aggregate_id"], node.to_string());
    assert_eq!(old_events["items"][0]["payload"], json!({}));
    assert_eq!(new_events["items"], json!([]));
    assert_eq!(new_events["next_seq"], 1);
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn revoked_profile_permissions_close_an_owned_agent_stream() -> TestResult {
    let hub = TestHub::start("event-agent-cascade", Config::default(), 10_000).await?;
    let owner = create_principal(&hub, "owner", json!({"kind": "member"})).await?;
    let agent = create_principal(
        &hub,
        "agent",
        json!({"kind": "agent", "owner_principal_id": owner, "managed_by_principal_id": owner}),
    )
    .await?;
    let (_, agent_token) = mint(&hub, agent, None).await?;
    let profile = ProfileId::new();
    hub.write(move |conn| {
        conn.execute(
            "INSERT INTO profiles (profile_id, slug, discovery_mode, created_at_ms, updated_at_ms)
             VALUES (?1, 'test-profile', 'full', 10000, 10000)",
            [profile.to_string()],
        )?;
        Ok(())
    })
    .await?;
    let grant = || {
        hub.request_admin(
            Method::PUT,
            "/v1/grants",
            Some(json!({
                "principal_id": owner,
                "scope": GrantScope::Profile(profile),
                "capability": "discover"
            })),
        )
    };
    let (status, result) = grant().await?;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    let grant_id = result["grant"]["grant_id"]
        .as_str()
        .ok_or("missing grant ID")?;
    let mut body = stream(&hub, "/v1/events/stream", &agent_token).await?;
    let (status, result) = hub
        .request_admin(Method::DELETE, &format!("/v1/grants/{grant_id}"), None)
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{result}");
    assert_eq!(ndjson(&mut body).await?, None);

    let (status, result) = grant().await?;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    let mut body = stream(&hub, "/v1/events/stream", &agent_token).await?;
    let (status, result) = hub
        .request_admin(Method::DELETE, "/v1/profiles/test-profile", None)
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{result}");
    assert_eq!(ndjson(&mut body).await?, None);
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn shutdown_closes_before_buffered_frames_are_sent() -> TestResult {
    let hub = TestHub::start("event-shutdown", Config::default(), 10_000).await?;
    append(&hub, [Event::ProfilePublished(ProfileId::new())]).await?;
    let mut body = stream(&hub, "/v1/events/stream", &hub.admin_token).await?;
    hub.state.execution.stop();
    assert_eq!(ndjson(&mut body).await?, None);
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn streams_have_separate_global_and_per_principal_admission() -> TestResult {
    let mut config = Config::default();
    config.max_app_requests = 1;
    config.max_requests_per_principal = 1;
    let hub = TestHub::start("event-principal-limit", config, 10_000).await?;
    let mut streams = Vec::new();
    for _ in 0..8 {
        streams.push(stream(&hub, "/v1/events/stream", &hub.admin_token).await?);
    }
    assert_limited(&hub).await?;
    assert_eq!(
        hub.request_admin(Method::GET, "/v1/events", None).await?.0,
        StatusCode::OK
    );
    drop(streams.pop());
    drop(stream(&hub, "/v1/events/stream", &hub.admin_token).await?);
    drop(streams);
    hub.shutdown().await;

    let mut config = Config::default();
    config.max_event_streams_per_principal = config.max_event_streams + 1;
    let hub = TestHub::start("event-global-limit", config, 10_000).await?;
    let mut streams = Vec::new();
    for _ in 0..256 {
        streams.push(stream(&hub, "/v1/events/stream", &hub.admin_token).await?);
    }
    assert_limited(&hub).await?;
    drop(streams.pop());
    drop(stream(&hub, "/v1/events/stream", &hub.admin_token).await?);
    drop(streams);
    hub.shutdown().await;
    Ok(())
}

async fn assert_limited(hub: &TestHub) -> TestResult {
    let response = open_stream(hub, "/v1/events/stream", &hub.admin_token).await?;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let data = response.into_body().collect().await?.to_bytes();
    let problem: Value = serde_json::from_slice(&data)?;
    assert_eq!(problem["code"], "overloaded");
    assert_eq!(problem["retryable"], true);
    Ok(())
}
