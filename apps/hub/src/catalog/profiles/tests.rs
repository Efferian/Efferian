use axum::http::Method;
use efferian_protocol::{AccountId, EventKind, GrantId, NodeId};
use serde_json::{Value, json};

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
    let (_, created) = hub
        .request_admin(
            Method::PUT,
            "/v1/profiles/wide",
            Some(json!({"discovery_mode": "full", "bindings": []})),
        )
        .await?;
    let profile: ProfileId = serde_json::from_value(created["profile"]["profile_id"].clone())?;
    let admin = hub.admin_id;
    let member = PrincipalId::new_user();
    let agent = PrincipalId::new_agent();
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
        for index in 0..140 {
            let principal = if index == 0 { member } else { PrincipalId::new_user() };
            insert_principal.execute(params![principal.to_string(), format!("member-{index}")])?;
            insert_grant.execute(params![GrantId::new().to_string(), principal.to_string(), profile.to_string(), admin.to_string()])?;
        }
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
        insert_grant.execute(params![GrantId::new().to_string(), orchestrator.to_string(), profile.to_string(), admin.to_string()])?;
        conn.execute(
            "INSERT INTO nodes(node_id, name, credential_hmac, managed_by_principal_id, created_at_ms, updated_at_ms)
             VALUES (?1, 'managed', 'node-test-hmac', ?2, 1, 1)",
            params![node.to_string(), orchestrator.to_string()],
        )?;
        Ok(())
    }).await?;
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
    assert_eq!(signal.affected_nodes, vec![node]);
    assert!(matches!(
        watcher.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    let remaining: i64 = hub
        .state
        .storage
        .read_snapshot(move |conn| {
            conn.query_row(
                "SELECT count(*) FROM grants WHERE scope_id = ?1",
                [profile.to_string()],
                |row| row.get(0),
            )
            .map_err(crate::storage::StorageError::from)
        })
        .await?;
    assert_eq!(remaining, 0);
    hub.shutdown().await;
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
