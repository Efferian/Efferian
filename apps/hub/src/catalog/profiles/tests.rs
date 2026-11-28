use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request};
use efferian_protocol::{AccountId, EventKind, EventStreamFrame, GrantId, NodeId};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::time::timeout;
use tower_service::Service;

use super::*;
use crate::{
    config::Config,
    storage::RevocationReason,
    test_support::{TestHub, TestResult},
};

fn command_definition(schema: Value, tags: Value, account: Option<AccountId>) -> Value {
    let mut definition = json!({
        "description": "Echo a value",
        "input_schema": schema,
        "spec": {
            "kind": "command",
            "program": "/bin/echo",
            "args": [], "cwd": "/tmp", "env": {},
            "target_selector": tags,
            "runtime_ms": 1_000, "max_output_bytes": 4_096
        }
    });
    if let Some(account) = account {
        definition["spec"]["account_id"] = json!(account);
    }
    definition
}

fn binding(tool_id: &Value, version: u64, fixed: Option<NodeId>) -> Value {
    json!({"public_name": "echo", "tool_id": tool_id, "tool_version": version, "fixed_node_id": fixed})
}

#[tokio::test]
async fn publish_pins_an_immutable_tool_and_republishes_a_disabled_edition() -> TestResult {
    let hub = TestHub::start("catalog-publish", Config::default(), 1000).await?;
    let node = NodeId::new();
    hub.write(move |conn| {
        conn.execute(
            "INSERT INTO nodes(node_id, name, credential_hmac, tags_json, created_at_ms, updated_at_ms)
             VALUES (?1, 'one', 'node-test-hmac', '[\"lab\"]', 1, 1)",
            [node.to_string()],
        )?;
        Ok(())
    }).await?;
    let selector = json!({"kind": "tag", "tag": "lab"});
    let invalid = command_definition(
        json!({"type": "object", "properties": {"remote": {"$ref": "https://example.invalid/s"}}}),
        selector.clone(),
        None,
    );
    assert_eq!(
        hub.request_admin(Method::PUT, "/v1/tools/one", Some(invalid))
            .await?
            .0,
        StatusCode::BAD_REQUEST
    );
    let mut definition = command_definition(json!({"type": "object"}), selector.clone(), None);
    let (status, created) = hub
        .request_admin(Method::PUT, "/v1/tools/one", Some(definition.clone()))
        .await?;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["outcome"], "created");
    assert_eq!(created["tool"]["current_version"], 1);
    assert_eq!(created["tool"]["definition"], definition);
    let tool_id = &created["tool"]["tool_id"];
    let same = hub
        .request_admin(Method::PUT, "/v1/tools/one", Some(definition.clone()))
        .await?;
    assert_eq!(same.0, StatusCode::OK);
    assert_eq!(same.1["outcome"], "unchanged");
    assert_eq!(same.1["tool"], created["tool"]);

    let draft = json!({"discovery_mode": "full", "bindings": [binding(tool_id, 1, Some(node))]});
    let mut invalid_draft = draft.clone();
    invalid_draft["bindings"][0]["public_name"] = json!("efferian_invoke");
    assert_eq!(
        hub.request_admin(Method::PUT, "/v1/profiles/one", Some(invalid_draft))
            .await?
            .0,
        StatusCode::BAD_REQUEST
    );
    let mut missing_node = draft.clone();
    missing_node["bindings"][0]["fixed_node_id"] = json!(NodeId::new());
    assert_eq!(
        hub.request_admin(Method::PUT, "/v1/profiles/one", Some(missing_node))
            .await?
            .0,
        StatusCode::NOT_FOUND
    );
    let (status, problem) = hub
        .request_admin(Method::PUT, "/v1/profiles/one", Some(json!(["full", []])))
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(problem["code"], "invalid_input");
    assert_eq!(
        hub.request_admin(Method::GET, "/v1/profiles/one", None)
            .await?
            .0,
        StatusCode::NOT_FOUND
    );
    let (status, profile) = hub
        .request_admin(Method::PUT, "/v1/profiles/one", Some(draft.clone()))
        .await?;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(profile["profile"]["published_version"], 0);
    assert!(profile["profile"]["published_edition"].is_null());

    let mut events = hub.state.storage.subscribe_events()?;
    let publish = "/v1/profiles/one/publish";
    let (status, first) = hub.request_admin(Method::POST, publish, None).await?;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(first["edition"]["version"], 1);
    assert_eq!(
        events.try_recv()?.envelope.event.kind(),
        EventKind::ProfilePublished
    );
    let (status, unchanged) = hub.request_admin(Method::POST, publish, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(unchanged["outcome"], "unchanged");
    assert_eq!(unchanged["edition"], first["edition"]);
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    // A tool update must leave the published binding on the exact old revision.
    hub.clock.set(2000);
    definition["input_schema"] = json!({"type": "object", "required": ["new"]});
    let (status, updated) = hub
        .request_admin(Method::PUT, "/v1/tools/one", Some(definition))
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["tool"]["current_version"], 2);
    assert_ne!(
        updated["tool"]["input_schema_sha256"],
        created["tool"]["input_schema_sha256"]
    );
    let (_, detail) = hub
        .request_admin(Method::GET, "/v1/profiles/one", None)
        .await?;
    assert_eq!(
        detail["published_edition"]["bindings"][0]["tool_version"],
        1
    );

    let mut revoked = hub.state.storage.subscribe_revocations()?;
    let disable = "/v1/profiles/one/versions/1/disable";
    assert_eq!(
        hub.request_admin(Method::POST, disable, None).await?.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        hub.request_admin(Method::POST, disable, None).await?.0,
        StatusCode::NO_CONTENT
    );
    assert!(matches!(
        revoked.try_recv()?.reason,
        RevocationReason::EditionDisabled { version: 1, .. }
    ));
    assert!(matches!(
        revoked.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    let (status, republished) = hub.request_admin(Method::POST, publish, None).await?;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(republished["edition"]["version"], 2);
    assert_eq!(
        republished["edition"]["bindings"],
        first["edition"]["bindings"]
    );
    assert!(republished["edition"]["disabled_at_ms"].is_null());

    // A reversible profile switch keeps draft and current active references live.
    assert_eq!(
        hub.request_admin(Method::POST, "/v1/profiles/one/disable", None)
            .await?
            .0,
        StatusCode::NO_CONTENT
    );
    let tool_path = "/v1/tools/one";
    assert_eq!(
        hub.request_admin(Method::DELETE, tool_path, None).await?.1["code"],
        code::RESOURCE_IN_USE
    );
    let empty = json!({"discovery_mode": "full", "bindings": []});
    assert_eq!(
        hub.request_admin(Method::PUT, "/v1/profiles/one", Some(empty))
            .await?
            .0,
        StatusCode::OK
    );
    assert_eq!(
        hub.request_admin(Method::DELETE, tool_path, None).await?.1["code"],
        code::RESOURCE_IN_USE
    );
    assert_eq!(
        hub.request_admin(Method::POST, "/v1/profiles/one/versions/2/disable", None)
            .await?
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        hub.request_admin(Method::DELETE, tool_path, None).await?.0,
        StatusCode::NO_CONTENT
    );
    let (_, profile) = hub
        .request_admin(Method::GET, "/v1/profiles/one", None)
        .await?;
    assert_eq!(
        profile["published_edition"]["bindings"][0]["tool_id"],
        *tool_id
    );
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn delete_profile_emits_one_revocation_for_all_affected_principals() -> TestResult {
    let hub = TestHub::start("catalog-revoke", Config::default(), 1000).await?;
    let profile = create_empty_profile(&hub, "wide").await?;
    let separate_profile = create_empty_profile(&hub, "separate").await?;
    let admin = hub.admin_id;
    let member = PrincipalId::new_user();
    let unrelated = PrincipalId::new_user();
    let agent = PrincipalId::new_agent();
    let purging = PrincipalId::new_agent();
    let orchestrator = PrincipalId::new_service();
    let node = NodeId::new();
    hub.write(move |conn| {
        let mut insert_principal = conn.prepare(
            "INSERT INTO principals(principal_id, name, kind, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, 'member', 1, 1)",
        )?;
        let mut insert_grant = conn.prepare(
            "INSERT INTO grants (grant_id, principal_id, scope_kind, scope_id, capability, created_by, created_at_ms)
             VALUES (?1, ?2, 'profile', ?3, 'discover', ?4, 1)",
        )?;
        let mut grant = |principal: PrincipalId, profile: ProfileId| {
            insert_grant.execute(params![
                GrantId::new().to_string(), principal.to_string(), profile.to_string(), admin.to_string()
            ])
        };
        for index in 0..140 {
            let principal = if index == 0 { member } else { PrincipalId::new_user() };
            insert_principal.execute(params![principal.to_string(), format!("member-{index}")])?;
            grant(principal, profile)?;
        }
        insert_principal.execute(params![unrelated.to_string(), "unrelated"])?;
        grant(unrelated, separate_profile)?;
        conn.execute(
            "INSERT INTO principals(principal_id, name, kind, owner_principal_id, managed_by_principal_id,
                created_at_ms, updated_at_ms) VALUES (?1, 'owned-agent', 'agent', ?2, ?2, 1, 1)",
            params![agent.to_string(), member.to_string()],
        )?;
        conn.execute(
            "INSERT INTO principals(principal_id, name, kind, is_orchestrator, created_at_ms, updated_at_ms)
             VALUES (?1, 'orchestrator', 'service', 1, 1, 1)",
            [orchestrator.to_string()],
        )?;
        grant(orchestrator, profile)?;
        conn.execute(
            "INSERT INTO principals(principal_id, name, kind, managed_by_principal_id,
                disabled_at_ms, created_at_ms, updated_at_ms)
             VALUES (?1, '~purging:' || ?1, 'agent', ?2, 1, 1, 1)",
            params![purging.to_string(), orchestrator.to_string()],
        )?;
        grant(purging, profile)?;
        grant(purging, separate_profile)?;
        conn.execute(
            "INSERT INTO nodes(node_id, name, credential_hmac, managed_by_principal_id, created_at_ms, updated_at_ms)
             VALUES (?1, 'managed', 'node-test-hmac', ?2, 1, 1)",
            params![node.to_string(), orchestrator.to_string()],
        )?;
        Ok(())
    }).await?;
    let mut affected_stream = open_profile_events(&hub, member).await?;
    let mut unrelated_stream = open_profile_events(&hub, unrelated).await?;
    assert_eq!(
        hub.request_admin(Method::POST, "/v1/profiles/wide/publish", None)
            .await?
            .0,
        StatusCode::CREATED
    );
    assert_published_frame(&mut affected_stream, profile).await?;

    // Model a committed GC claim with its child rows still present. The manual
    // monotonic clock stays fixed, so the periodic sweep cannot finish it.
    hub.write(move |conn| {
        conn.execute(
            "UPDATE hub_meta SET gc_purging_principal_id = ?1 WHERE id = 1",
            [purging.to_string()],
        )?;
        Ok(())
    })
    .await?;
    let claimed_grant: bool = hub
        .state
        .storage
        .read_snapshot(move |conn| {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM grants g JOIN hub_meta h ON h.id = 1
                 WHERE g.principal_id = h.gc_purging_principal_id AND g.scope_id = ?1)",
                [profile.to_string()],
                |row| row.get(0),
            )
            .map_err(crate::storage::StorageError::from)
        })
        .await?;
    assert!(claimed_grant);
    let mut watcher = hub.state.storage.subscribe_revocations()?;
    assert_eq!(
        hub.request_admin(Method::DELETE, "/v1/profiles/wide", None)
            .await?
            .0,
        StatusCode::NO_CONTENT
    );
    let signal = watcher.try_recv()?;
    assert_eq!(signal.reason, RevocationReason::ProfileDeleted(profile));
    assert_eq!(signal.affected_principals.len(), 142);
    assert!(signal.affected_principals.contains(&agent));
    assert!(!signal.affected_principals.contains(&purging));
    assert!(!signal.affected_principals.contains(&unrelated));
    assert_eq!(signal.affected_nodes, vec![node]);
    assert!(matches!(
        watcher.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert!(
        timeout(Duration::from_secs(5), affected_stream.frame())
            .await?
            .is_none()
    );
    let (remaining, claim, separate_grant) =
        hub.state
            .storage
            .read_snapshot(move |conn| {
                conn.query_row(
                "SELECT (SELECT count(*) FROM grants WHERE scope_id = ?1), gc_purging_principal_id,
                        EXISTS(SELECT 1 FROM grants WHERE principal_id = ?2 AND scope_id = ?3)
                 FROM hub_meta WHERE id = 1",
                params![profile.to_string(), purging.to_string(), separate_profile.to_string()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, bool>(2)?)),
            )
            .map_err(crate::storage::StorageError::from)
            })
            .await?;
    assert_eq!(remaining, 0);
    assert_eq!(claim, purging.to_string());
    assert!(separate_grant);
    assert_eq!(
        hub.request_admin(Method::POST, "/v1/profiles/separate/publish", None)
            .await?
            .0,
        StatusCode::CREATED
    );
    assert_published_frame(&mut unrelated_stream, separate_profile).await?;
    drop((affected_stream, unrelated_stream));
    hub.shutdown().await;
    Ok(())
}

async fn create_empty_profile(hub: &TestHub, slug: &str) -> TestResult<ProfileId> {
    let (status, created) = hub
        .request_admin(
            Method::PUT,
            &format!("/v1/profiles/{slug}"),
            Some(json!({"discovery_mode": "full", "bindings": []})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    Ok(serde_json::from_value(
        created["profile"]["profile_id"].clone(),
    )?)
}

async fn open_profile_events(hub: &TestHub, principal: PrincipalId) -> TestResult<Body> {
    let (status, created) = hub
        .request_admin(
            Method::POST,
            "/v1/tokens",
            Some(json!({"principal_id": principal, "label": "profile-events"})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED);
    let token = created["token"].as_str().ok_or("missing token")?;
    let request = Request::builder()
        .uri("/v1/events/stream?kinds=profile.published")
        .header("host", "localhost:8080")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())?;
    let response = hub.router.clone().call(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/x-ndjson");
    Ok(response.into_body())
}

async fn assert_published_frame(stream: &mut Body, profile: ProfileId) -> TestResult {
    let frame = timeout(Duration::from_secs(5), stream.frame())
        .await?
        .ok_or("stream closed")??;
    let bytes = frame.into_data().map_err(|_| "expected a data frame")?;
    assert!(bytes.ends_with(b"\n"));
    let frame: EventStreamFrame = serde_json::from_slice(&bytes)?;
    let EventStreamFrame::Event { event } = frame else {
        return Err("expected a profile publication".into());
    };
    assert_eq!(event.event, Event::ProfilePublished(profile));
    Ok(())
}

#[tokio::test]
async fn shared_account_is_retained_by_exact_live_revisions_only() -> TestResult {
    let hub = TestHub::start("catalog-account-refs", Config::default(), 1000).await?;
    let credential = json!({"secret": {"kind": "secret_kv", "entries": {"key": "sample"}}});
    let account_path = "/v1/accounts/for-tool?visibility=shared";
    let (status, shared) = hub
        .request_admin(Method::PUT, account_path, Some(credential.clone()))
        .await?;
    assert_eq!(status, StatusCode::CREATED);
    let (status, private) = hub
        .request_admin(Method::PUT, "/v1/accounts/for-tool", Some(credential))
        .await?;
    assert_eq!(status, StatusCode::CREATED);
    let private_id = serde_json::from_value(private["account"]["account_id"].clone())?;
    let shared_id = serde_json::from_value(shared["account"]["account_id"].clone())?;
    let definition = |account| {
        command_definition(
            json!({"type": "object"}),
            json!({"kind": "tag", "tag": "lab"}),
            account,
        )
    };
    let tool = "/v1/tools/with-account";
    assert_eq!(
        hub.request_admin(Method::PUT, tool, Some(definition(Some(private_id))))
            .await?
            .0,
        StatusCode::BAD_REQUEST
    );
    let (status, created) = hub
        .request_admin(Method::PUT, tool, Some(definition(Some(shared_id))))
        .await?;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        hub.request_admin(Method::DELETE, account_path, None)
            .await?
            .1["code"],
        code::RESOURCE_IN_USE
    );
    let draft = |version| {
        json!({
            "discovery_mode": "full", "bindings": [binding(&created["tool"]["tool_id"], version, None)],
        })
    };
    let profile = "/v1/profiles/with-account";
    let publish = "/v1/profiles/with-account/publish";
    assert_eq!(
        hub.request_admin(Method::PUT, profile, Some(draft(1)))
            .await?
            .0,
        StatusCode::CREATED
    );
    assert_eq!(
        hub.request_admin(Method::POST, publish, None).await?.0,
        StatusCode::CREATED
    );
    assert_eq!(
        hub.request_admin(Method::PUT, tool, Some(definition(None)))
            .await?
            .0,
        StatusCode::OK
    );
    assert_eq!(
        hub.request_admin(Method::PUT, profile, Some(draft(2)))
            .await?
            .0,
        StatusCode::OK
    );
    assert_eq!(
        hub.request_admin(Method::DELETE, account_path, None)
            .await?
            .1["code"],
        code::RESOURCE_IN_USE
    );
    assert_eq!(
        hub.request_admin(Method::POST, publish, None).await?.0,
        StatusCode::CREATED
    );
    assert_eq!(
        hub.request_admin(Method::DELETE, account_path, None)
            .await?
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        hub.request_admin(Method::PUT, profile, Some(draft(1)))
            .await?
            .0,
        StatusCode::NOT_FOUND
    );
    hub.shutdown().await;
    Ok(())
}
