use std::num::NonZeroU64;

use axum::{body::to_bytes, response::IntoResponse};
use efferian_protocol::{RequestId, error_codes as code};
use http::{Method, StatusCode};
use serde_json::{Value, json};

use super::super::{ProfileInvokeRequest, invoke_profile_edition};
use super::{
    ReadyNode, TestHub, TestResult, admin_caller, command, managed_fixture, publish, put_tool,
    seed_node,
};

async fn pinned(hub: &TestHub, version: u64, body: Value) -> TestResult<(StatusCode, Value)> {
    let response = invoke_profile_edition(
        &hub.state,
        admin_caller(hub).await?,
        "demo".to_owned(),
        NonZeroU64::new(version),
        serde_json::from_value::<ProfileInvokeRequest>(body)?,
    )
    .await
    .unwrap_or_else(IntoResponse::into_response);
    let status = response.status();
    let data = to_bytes(response.into_body(), 8 * 1024).await?;
    Ok((status, serde_json::from_slice(&data)?))
}

#[tokio::test]
async fn explicit_edition_pin_matches_the_recorded_version_and_unpinned_rest_stays_historical()
-> TestResult {
    let request_id = RequestId::new();
    let (hub, bridge, first_node, tool) = managed_fixture(request_id.timestamp_ms()).await?;
    let second_node = seed_node(&hub, "node-two", "[]").await?;
    bridge.set(
        second_node,
        Some(ReadyNode {
            epoch: 1,
            max_concurrent_executions: 1,
        }),
    );
    publish(&hub, tool, "echo", 1, "async", None).await?;
    let original_body = json!({
        "public_name": "echo", "arguments": {"text": "hello"}, "request_id": request_id, "wait_ms": 0
    });
    let (status, original) = pinned(&hub, 1, original_body.clone()).await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{original}");
    assert_eq!(original["profile_version"], 1);
    assert_eq!(original["node_id"], json!(first_node));

    put_tool(
        &hub,
        command(
            "/bin/printf",
            json!({"kind": "fixed", "node_ids": [second_node]}),
        ),
        StatusCode::OK,
    )
    .await?;
    publish(&hub, tool, "echo", 2, "async", None).await?;
    let (status, replay) = pinned(&hub, 1, original_body.clone()).await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{replay}");
    assert_eq!(replay["execution_id"], original["execution_id"]);
    for version in [2, 999] {
        let (status, problem) = pinned(&hub, version, original_body.clone()).await?;
        assert_eq!(status, StatusCode::CONFLICT, "{problem}");
        assert_eq!(problem["code"], code::REQUEST_ID_CONFLICT);
    }
    let (status, replay) = hub
        .request_admin(
            Method::POST,
            "/v1/profiles/demo/invoke",
            Some(original_body.clone()),
        )
        .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{replay}");
    assert_eq!(replay["execution_id"], original["execution_id"]);
    assert_eq!(replay["profile_version"], 1);

    let mut fresh_body = original_body;
    fresh_body["request_id"] = json!(RequestId::new());
    let (status, problem) = pinned(&hub, 999, fresh_body.clone()).await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{problem}");
    let (status, problem) = pinned(&hub, 1, fresh_body.clone()).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{problem}");
    assert_eq!(problem["code"], code::NODE_BUSY);
    let (status, second) = pinned(&hub, 2, fresh_body).await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{second}");
    assert_eq!(second["profile_version"], 2);
    assert_eq!(second["node_id"], json!(second_node));
    assert_ne!(second["execution_id"], original["execution_id"]);
    assert_eq!(bridge.sent.lock().unwrap().len(), 2);

    hub.shutdown().await;
    Ok(())
}
