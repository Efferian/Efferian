use efferian_protocol::{ExecutionId, PrincipalId, RequestId};
use http::{Method, StatusCode};
use serde_json::{Value, json};

use super::{
    NodeSendError, TestResult, command, create_owned_agent, managed_fixture, member, mint, publish,
    put_tool, seed_node,
};

#[tokio::test]
async fn tag_selection_intersects_manager_and_token_scopes() -> TestResult {
    let (hub, _, managed, _) = managed_fixture(RequestId::new().timestamp_ms()).await?;
    let foreign = seed_node(&hub, "foreign", "[\"test\"]").await?;
    let tool = put_tool(
        &hub,
        command("/bin/echo", json!({"kind":"tag", "tag":"test"})),
        StatusCode::OK,
    )
    .await?;
    publish(&hub, tool, "echo", 2, "async", None).await?;
    let (status, result) = hub
        .request_admin(
            Method::PUT,
            "/v1/principals/fleet",
            Some(json!({"kind":"service", "is_orchestrator":true})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    let manager: PrincipalId = serde_json::from_value(result["principal"]["principal_id"].clone())?;
    let (status, result) = hub
        .request_admin(
            Method::PUT,
            "/v1/principals/worker",
            Some(json!({"kind":"agent", "managed_by_principal_id":manager})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{result}");
    let agent: PrincipalId = serde_json::from_value(result["principal"]["principal_id"].clone())?;
    for principal in [manager, agent] {
        let grant = json!({
            "principal_id": principal,
            "scope": {"scope_kind": "global"},
            "capability": "invoke"
        });
        let (status, result) = hub
            .request_admin(Method::PUT, "/v1/grants", Some(grant))
            .await?;
        assert_eq!(status, StatusCode::CREATED, "{result}");
    }
    hub.write(move |conn| {
        conn.execute(
            "UPDATE nodes SET managed_by_principal_id = ?1 WHERE node_id = ?2",
            [manager.to_string(), managed.to_string()],
        )?;
        Ok(())
    })
    .await?;
    let detail = "/v1/profiles/demo/tools/echo";
    for allowed in [None, Some(vec![foreign, managed])] {
        let token = mint(&hub, agent, allowed).await?;
        let (status, tool) = hub.request(Method::GET, detail, &token, None).await?;
        assert_eq!(status, StatusCode::OK, "{tool}");
        assert_eq!(
            tool["available_targets"],
            json!([{"node_id":managed,"name":"node-one"}])
        );
    }
    let token = mint(&hub, agent, Some(vec![foreign])).await?;
    assert_eq!(
        hub.request(Method::GET, detail, &token, None).await?.0,
        StatusCode::NOT_FOUND
    );
    let token = mint(&hub, agent, None).await?;
    let (status, execution) = hub
        .request(
            Method::POST,
            "/v1/profiles/demo/invoke",
            &token,
            Some(json!({"public_name":"echo", "arguments":{"text":"ok"}})),
        )
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{execution}");
    assert_eq!(execution["node_id"], json!(managed));
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn execution_pages_merge_owned_callers_before_applying_the_page_limit() -> TestResult {
    let now = RequestId::new().timestamp_ms();
    let (hub, bridge, _, tool) = managed_fixture(now).await?;
    publish(&hub, tool, "echo", 1, "async", None).await?;
    // Settle each invocation immediately so the node's one-slot limit stays free.
    *bridge.fail.lock().unwrap() = Some(NodeSendError::Full);
    let (parent, token) = member(&hub, "parent", None).await?;
    let child = create_owned_agent(&hub, parent).await?;
    let child_token = mint(&hub, child, None).await?;
    let foreign = hub.admin_id;
    let mut ids = Vec::<ExecutionId>::new();
    for caller in [
        &child_token,
        &token,
        &child_token,
        &token,
        &child_token,
        &hub.admin_token,
    ] {
        hub.clock.set(now + i64::try_from(ids.len())?);
        let (status, execution) = hub
            .request(
                Method::POST,
                "/v1/profiles/demo/invoke",
                caller,
                Some(json!({
                    "public_name": "echo", "arguments": {"text": "page"}, "wait_ms": 0
                })),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "{execution}");
        assert_eq!(execution["state"], "failed");
        ids.push(serde_json::from_value(execution["execution_id"].clone())?);
    }
    let first_page = "/v1/executions?state=failed&limit=2";
    let (status, page) = hub.request(Method::GET, first_page, &token, None).await?;
    assert_eq!(status, StatusCode::OK);
    let page_ids = |page: &Value| -> TestResult<Vec<ExecutionId>> {
        Ok(page["items"]
            .as_array()
            .ok_or("missing items")?
            .iter()
            .map(|row| serde_json::from_value(row["execution_id"].clone()))
            .collect::<Result<_, _>>()?)
    };
    assert_eq!(page_ids(&page)?, [ids[4], ids[3]]);
    let cursor = page["next_cursor"].as_str().ok_or("missing cursor")?;
    let (_, second) = hub
        .request(
            Method::GET,
            &format!("{first_page}&cursor={cursor}"),
            &token,
            None,
        )
        .await?;
    assert_eq!(page_ids(&second)?, [ids[2], ids[1]]);
    let filtered = format!("{first_page}&principal_id={child}");
    let (_, visible) = hub.request(Method::GET, &filtered, &token, None).await?;
    assert_eq!(page_ids(&visible)?, [ids[4], ids[2]]);
    let (_, admin) = hub.request_admin(Method::GET, &filtered, None).await?;
    assert_eq!(page_ids(&admin)?, page_ids(&visible)?);
    let (_, hidden) = hub
        .request(
            Method::GET,
            &format!("{first_page}&principal_id={foreign}"),
            &token,
            None,
        )
        .await?;
    assert!(page_ids(&hidden)?.is_empty());
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn out_of_selector_target_respects_visibility_capability_and_disabled_precedence()
-> TestResult {
    let now = RequestId::new().timestamp_ms();
    let (hub, _, _node_one, tool) = managed_fixture(now).await?;
    let other_node = seed_node(&hub, "other-node", "[]").await?;
    publish(&hub, tool, "echo", 1, "async", None).await?;

    // Create an orchestrator that manages `other_node` so `authorize_node_read`
    // succeeds for `other_node` and exercises the out_of_selector_readable path.
    let (status, orch_res) = hub
        .request_admin(
            Method::PUT,
            "/v1/principals/orch",
            Some(json!({"kind": "service", "is_orchestrator": true})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{orch_res}");
    let orch_id: PrincipalId =
        serde_json::from_value(orch_res["principal"]["principal_id"].clone())?;
    let (status, grant) = hub
        .request_admin(
            Method::PUT,
            "/v1/grants",
            Some(json!({
                "principal_id": orch_id,
                "scope": {"scope_kind": "global"},
                "capability": "invoke"
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{grant}");
    hub.write(move |conn| {
        conn.execute(
            "UPDATE nodes SET managed_by_principal_id = ?1 WHERE node_id = ?2",
            [orch_id.to_string(), other_node.to_string()],
        )?;
        Ok(())
    })
    .await?;

    // 1. Orchestrator token narrowed away from node_one gets 404 (not 400) for readable other_node.
    let hidden_token = mint(&hub, orch_id, Some(vec![other_node])).await?;
    let (status, problem) = hub
        .request(
            Method::POST,
            "/v1/profiles/demo/invoke",
            &hidden_token,
            Some(json!({"public_name": "echo", "target": other_node})),
        )
        .await?;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );

    // 2. Discover-only orchestrator on visible tool gets 403 (not 400) for readable other_node.
    let (status, disc_res) = hub
        .request_admin(
            Method::POST,
            "/v1/tokens",
            Some(json!({
                "principal_id": orch_id, "label": "disc-only", "max_capability": "discover"
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{disc_res}");
    let disc_token = disc_res["token"].as_str().ok_or("missing token")?;
    let (status, problem) = hub
        .request(
            Method::POST,
            "/v1/profiles/demo/invoke",
            disc_token,
            Some(json!({"public_name": "echo", "target": other_node})),
        )
        .await?;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("forbidden"))
    );

    // 3. Orchestrator with invoke on visible enabled tool gets 400 invalid_arguments.
    let invoke_token = mint(&hub, orch_id, None).await?;
    let (status, problem) = hub
        .request(
            Method::POST,
            "/v1/profiles/demo/invoke",
            &invoke_token,
            Some(json!({"public_name": "echo", "target": other_node})),
        )
        .await?;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_arguments"))
    );

    // 4. Disabling the tool yields 409 tool_disabled before 400 invalid_arguments.
    let (status, _) = hub
        .request_admin(Method::POST, "/v1/tools/echo/disable", None)
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, problem) = hub
        .request(
            Method::POST,
            "/v1/profiles/demo/invoke",
            &invoke_token,
            Some(json!({"public_name": "echo", "target": other_node})),
        )
        .await?;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::CONFLICT, Some("tool_disabled"))
    );

    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn archived_fixed_node_mismatch_and_expired_request_id_precede_gone() -> TestResult {
    use std::num::NonZeroU64;

    use axum::response::IntoResponse;

    use super::super::{ProfileInvokeRequest, invoke_profile_edition};
    use super::admin_caller;

    let now = RequestId::new().timestamp_ms();
    let (hub, _, node_one, tool) = managed_fixture(now).await?;
    let other_node = seed_node(&hub, "node-other", "[]").await?;
    publish(&hub, tool, "pinned", 1, "async", Some(node_one)).await?;
    // Publish empty edition 2 and delete the tool so edition 1 has a deleted tool dependency.
    assert_eq!(
        hub.request_admin(
            Method::PUT,
            "/v1/profiles/demo",
            Some(json!({"discovery_mode": "full", "bindings": []})),
        )
        .await?
        .0,
        StatusCode::OK
    );
    assert_eq!(
        hub.request_admin(Method::POST, "/v1/profiles/demo/publish", None)
            .await?
            .0,
        StatusCode::CREATED
    );
    assert_eq!(
        hub.request_admin(Method::DELETE, "/v1/tools/echo", None)
            .await?
            .0,
        StatusCode::NO_CONTENT
    );

    // Contradictory target against fixed_node_id must return 404 (not 410).
    let err = invoke_profile_edition(
        &hub.state,
        admin_caller(&hub).await?,
        "demo".to_owned(),
        NonZeroU64::new(1),
        serde_json::from_value::<ProfileInvokeRequest>(json!({
            "public_name": "pinned",
            "target": other_node,
            "wait_ms": 0,
        }))?,
    )
    .await
    .unwrap_err()
    .into_response();
    assert_eq!(err.status(), StatusCode::NOT_FOUND);

    // Expired request_id with matching fixed_node_id must return 400 request_id_expired (not 410).
    let stale = RequestId::new();
    hub.clock.set(stale.timestamp_ms() + 25 * 60 * 60 * 1000);
    let err = invoke_profile_edition(
        &hub.state,
        admin_caller(&hub).await?,
        "demo".to_owned(),
        NonZeroU64::new(1),
        serde_json::from_value::<ProfileInvokeRequest>(json!({
            "public_name": "pinned",
            "target": node_one,
            "request_id": stale,
            "wait_ms": 0,
        }))?,
    )
    .await
    .unwrap_err()
    .into_response();
    assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    let body =
        serde_json::from_slice::<Value>(&axum::body::to_bytes(err.into_body(), 4096).await?)?;
    assert_eq!(body["code"], "request_id_expired");

    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn profile_tool_discovery_paginates_with_cursor_and_search() -> TestResult {
    let now = RequestId::new().timestamp_ms();
    let (hub, bridge, _, tool) = managed_fixture(now).await?;
    // Switch tool to tag selector so deleting node-one later is unblocked after terminal finish.
    let tag_tool = put_tool(
        &hub,
        command("/bin/echo", json!({"kind": "tag", "tag": "test"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(tag_tool, tool);
    let bindings = json!([
        {"public_name": "alpha", "tool_id": tool, "tool_version": 2, "execution_mode": "async", "description_override": "match one"},
        {"public_name": "beta", "tool_id": tool, "tool_version": 2, "execution_mode": "async", "description_override": "other"},
        {"public_name": "gamma", "tool_id": tool, "tool_version": 2, "execution_mode": "async", "description_override": "match two"},
    ]);
    assert_eq!(
        hub.request_admin(
            Method::PUT,
            "/v1/profiles/demo",
            Some(json!({"discovery_mode": "full", "bindings": bindings})),
        )
        .await?
        .0,
        StatusCode::CREATED
    );
    assert_eq!(
        hub.request_admin(Method::POST, "/v1/profiles/demo/publish", None)
            .await?
            .0,
        StatusCode::CREATED
    );

    let (status, page1) = hub
        .request_admin(Method::GET, "/v1/profiles/demo/tools?limit=2", None)
        .await?;
    assert_eq!(status, StatusCode::OK, "{page1}");
    assert_eq!(page1["items"].as_array().map(Vec::len), Some(2));
    assert_eq!(page1["items"][0]["public_name"], "alpha");
    assert_eq!(page1["items"][1]["public_name"], "beta");
    assert_eq!(page1["next_cursor"], "beta");

    let (status, page2) = hub
        .request_admin(
            Method::GET,
            "/v1/profiles/demo/tools?limit=2&cursor=beta",
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{page2}");
    assert_eq!(page2["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(page2["items"][0]["public_name"], "gamma");
    assert_eq!(page2["next_cursor"], Value::Null);

    let (status, filtered) = hub
        .request_admin(Method::GET, "/v1/profiles/demo/tools?q=MATCH&limit=1", None)
        .await?;
    assert_eq!(status, StatusCode::OK, "{filtered}");
    assert_eq!(filtered["items"][0]["public_name"], "alpha");
    assert_eq!(filtered["next_cursor"], "alpha");

    let (status, bad) = hub
        .request_admin(
            Method::GET,
            "/v1/profiles/demo/tools?cursor=bad%20cursor",
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");

    // Empty target string is rejected with 400 invalid_arguments; node name selects node; replay survives node deletion.
    let (status, problem) = hub
        .request_admin(
            Method::POST,
            "/v1/profiles/demo/invoke",
            Some(json!({"public_name": "alpha", "target": ""})),
        )
        .await?;
    assert_eq!(
        (status, problem["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_arguments"))
    );

    // Settle invocation immediately via backpressure so node-one can be deleted, then verify replay survives DELETE node.
    *bridge.fail.lock().unwrap() = Some(NodeSendError::Full);
    let req_id = RequestId::new();
    let payload = json!({
        "public_name": "alpha", "arguments": {"text": "by-name"},
        "target": "node-one", "request_id": req_id, "wait_ms": 0
    });
    let (status, created) = hub
        .request_admin(
            Method::POST,
            "/v1/profiles/demo/invoke",
            Some(payload.clone()),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["state"], "failed");
    let node_id: efferian_protocol::NodeId = serde_json::from_value(created["node_id"].clone())?;
    assert_eq!(
        hub.request_admin(Method::POST, &format!("/v1/nodes/{node_id}/revoke"), None)
            .await?
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        hub.request_admin(Method::DELETE, &format!("/v1/nodes/{node_id}"), None)
            .await?
            .0,
        StatusCode::NO_CONTENT
    );
    let (status, replayed) = hub
        .request_admin(Method::POST, "/v1/profiles/demo/invoke", Some(payload))
        .await?;
    assert_eq!(status, StatusCode::OK, "{replayed}");
    assert_eq!(replayed["execution_id"], created["execution_id"]);
    assert_eq!(replayed["node_id"], created["node_id"]);

    hub.shutdown().await;
    Ok(())
}
