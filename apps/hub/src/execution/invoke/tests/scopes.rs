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
