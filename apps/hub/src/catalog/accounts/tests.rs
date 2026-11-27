use std::sync::Mutex;

use axum::http::{Method, StatusCode};
use efferian_protocol::{GrantId, ProfileId, ToolId};
use serde_json::{Value, json};

use super::*;
use crate::config::Config;
use crate::test_support::{TestHub, TestResult};
use crate::upstream_dispatch::UpstreamDispatcher;

#[derive(Default)]
struct Invalidations(Mutex<Vec<UpstreamInvalidation>>);

impl UpstreamDispatcher for Invalidations {
    fn invalidate(&self, invalidation: UpstreamInvalidation) {
        self.0.lock().unwrap().push(invalidation);
    }
}

async fn add_member(hub: &TestHub, name: &str) -> TestResult<(PrincipalId, String)> {
    add_human(hub, name, PrincipalKind::Member).await
}

async fn add_human(
    hub: &TestHub,
    name: &str,
    kind: PrincipalKind,
) -> TestResult<(PrincipalId, String)> {
    let (status, principal) = hub
        .request_admin(
            Method::PUT,
            &format!("/v1/principals/{name}"),
            Some(json!({"kind": kind})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{principal}");
    let principal_id: PrincipalId =
        serde_json::from_value(principal["principal"]["principal_id"].clone())?;
    let (status, token) = hub
        .request_admin(
            Method::POST,
            "/v1/tokens",
            Some(json!({"principal_id": principal_id, "label": "account-tests"})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{token}");
    Ok((principal_id, token["token"].as_str().unwrap().to_owned()))
}

fn secret_kv(value: &str) -> Value {
    json!({"secret": {"kind": "secret_kv", "entries": {"TOKEN": value}}})
}

fn http_auth(upstream: UpstreamId) -> Value {
    json!({
        "upstream_id": upstream,
        "secret": {"kind": "http_auth", "auth": {"kind": "bearer", "token": "fake"}},
    })
}

#[tokio::test]
async fn private_accounts_are_isolated_and_secret_writes_are_idempotent() -> TestResult {
    let invalidations = Arc::new(Invalidations::default());
    let hub = TestHub::start_with_dispatchers(
        "accounts",
        Config::default(),
        10_000,
        None,
        invalidations.clone(),
    )
    .await?;
    let (alice_id, alice) = add_member(&hub, "alice").await?;
    let (bobby_id, bobby) = add_member(&hub, "bobby").await?;
    let uri = "/v1/accounts/sample";
    let a = || hub.request(Method::PUT, uri, &alice, Some(secret_kv("alice-fixture")));
    let (first, second) = tokio::join!(a(), a());
    let (first, second) = (first?, second?);
    let (created, repeated) = if first.0 == StatusCode::CREATED {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(created.0, StatusCode::CREATED, "{}", created.1);
    assert_eq!(repeated.0, StatusCode::OK, "{}", repeated.1);
    assert_eq!(created.1["outcome"], "created");
    assert_eq!(repeated.1["outcome"], "unchanged");
    assert_eq!(created.1["account"], repeated.1["account"]);
    let alice_account: AccountId =
        serde_json::from_value(created.1["account"]["account_id"].clone())?;

    let (status, b_account) = hub
        .request(Method::PUT, uri, &bobby, Some(secret_kv("bobby-fixture")))
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{b_account}");
    let bobby_account: AccountId =
        serde_json::from_value(b_account["account"]["account_id"].clone())?;
    assert_ne!(bobby_account, alice_account);
    assert_eq!(b_account["account"]["owner_principal_id"], json!(bobby_id));

    for (method, body) in [
        (Method::GET, None),
        (Method::PUT, Some(secret_kv("attempt"))),
        (Method::DELETE, None),
    ] {
        for suffix in [
            "visibility=shared".to_owned(),
            format!("owner={alice_id}"),
            format!("owner={bobby_id}"),
        ] {
            let (status, problem) = hub
                .request(
                    method.clone(),
                    &format!("{uri}?{suffix}"),
                    &alice,
                    body.clone(),
                )
                .await?;
            assert_eq!(status, StatusCode::FORBIDDEN, "{problem}");
        }
    }
    let (status, page) = hub
        .request(Method::GET, "/v1/accounts", &alice, None)
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["items"], json!([created.1["account"]]));
    let (status, page) = hub
        .request(Method::GET, "/v1/accounts?visibility=shared", &alice, None)
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{page}");

    let read_blob = || {
        hub.state
            .storage
            .read_snapshot(move |conn| -> ApiResult<_> {
                let account =
                    account_by_id(conn, alice_account)?.ok_or_else(ApiError::not_found)?;
                let sealed = load_account_secret(conn, &account)?;
                Ok((account, sealed))
            })
    };
    let (original, original_blob) = read_blob().await?;
    assert_eq!(original.secret_version, 1);
    assert_eq!(&original_blob[..4], b"EFS1");
    assert!(
        !original_blob
            .windows(b"alice-fixture".len())
            .any(|part| part == b"alice-fixture")
    );

    hub.clock.set(20_000);
    let change = || hub.request(Method::PUT, uri, &alice, Some(secret_kv("rotated-fixture")));
    let (left, right) = tokio::join!(change(), change());
    let (left, right) = (left?, right?);
    assert_eq!(left.0, StatusCode::OK, "{}", left.1);
    assert_eq!(right.0, StatusCode::OK, "{}", right.1);
    assert_ne!(left.1["outcome"], right.1["outcome"]);
    assert_eq!(left.1["account"], right.1["account"]);
    assert_eq!(left.1["account"]["secret_version"], 2);
    let (rotated, rotated_blob) = read_blob().await?;
    assert!(open_account(&hub.state.vault, &rotated, &original_blob).is_err());
    assert_eq!(
        serde_json::to_value(open_account(&hub.state.vault, &rotated, &rotated_blob)?)?,
        secret_kv("rotated-fixture")["secret"]
    );

    let (status, problem) = hub
        .request(
            Method::PUT,
            uri,
            &alice,
            Some(json!({
                "secret": {"kind": "http_auth", "auth": {"kind": "bearer", "token": "new-kind"}},
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["code"], "resource_in_use");
    let (status, metadata) = hub.request(Method::GET, uri, &alice, None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(metadata, left.1["account"]);
    assert!(!metadata.to_string().contains("rotated-fixture"));
    assert_eq!(
        *invalidations.0.lock().unwrap(),
        [
            UpstreamInvalidation::Account(alice_account),
            UpstreamInvalidation::Account(bobby_account),
            UpstreamInvalidation::Account(alice_account),
        ]
    );
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn a_second_admin_preserves_the_owner_of_a_shared_account() -> TestResult {
    let hub = TestHub::start("shared-account", Config::default(), 10_000).await?;
    let (delegate_id, delegate) = add_human(&hub, "delegate", PrincipalKind::Admin).await?;
    let (status, grant) = hub
        .request_admin(
            Method::PUT,
            "/v1/grants",
            Some(json!({
                "principal_id": delegate_id,
                "scope": {"scope_kind": "global"},
                "capability": "admin",
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{grant}");
    let uri = "/v1/accounts/shared?visibility=shared";
    let (status, original) = hub
        .request_admin(Method::PUT, uri, Some(secret_kv("shared-fixture")))
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{original}");
    let (status, repeated) = hub
        .request(
            Method::PUT,
            uri,
            &delegate,
            Some(secret_kv("shared-fixture")),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{repeated}");
    assert_eq!(repeated["outcome"], "unchanged");
    assert_eq!(repeated["account"], original["account"]);
    assert_eq!(
        repeated["account"]["owner_principal_id"],
        json!(hub.admin_id)
    );
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn bindings_use_pinned_visibility_and_hide_foreign_accounts() -> TestResult {
    let hub = TestHub::start("bindings", Config::default(), 10_000).await?;
    let (alice_id, alice) = add_member(&hub, "alice").await?;
    let (bobby_id, bobby) = add_member(&hub, "bobby").await?;
    let visible = UpstreamId::new();
    let hidden = UpstreamId::new();
    let profile = ProfileId::new();
    let admin = hub.admin_id;
    hub.write(move |conn| {
        for (id, slug) in [(visible, "visible"), (hidden, "hidden")] {
            conn.execute(
                "INSERT INTO upstreams (upstream_id, slug, url, created_at_ms, updated_at_ms)
                 VALUES (?1, ?2, 'https://example.test/mcp', 10000, 10000)",
                params![id.to_string(), slug],
            )?;
        }
        let tool = ToolId::new();
        conn.execute(
            "INSERT INTO tools (tool_id, slug, kind, created_by, current_version, created_at_ms, updated_at_ms)
             VALUES (?1, 'sample', 'command', ?2, 2, 10000, 10000)",
            params![tool.to_string(), admin.to_string()],
        )?;
        let definition = json!({
            "input_schema": {"type": "object"},
            "spec": {
                "kind": "upstream_ref",
                "upstream_id": visible,
                "upstream_tool_name": "sample",
                "account_mode": "caller_bound",
                "runtime_ms": 1000
            }
        }).to_string();
        conn.execute(
            "INSERT INTO tool_revisions (tool_id, version, input_schema_sha256, created_at_ms, definition_json)
             VALUES (?1, 1, 'fixture', 10000, ?2)",
            params![tool.to_string(), definition],
        )?;
        let current = json!({
            "input_schema": {"type": "object"},
            "spec": {
                "kind": "command",
                "program": "/bin/echo",
                "args": [],
                "cwd": "/",
                "env": {},
                "target_selector": {"kind": "tag", "tag": "existing"},
                "runtime_ms": 1000,
                "max_output_bytes": 4096
            }
        });
        conn.execute(
            "INSERT INTO tool_revisions (tool_id, version, input_schema_sha256, created_at_ms, definition_json)
             VALUES (?1, 2, 'fixture', 10000, ?2)",
            params![tool.to_string(), current.to_string()],
        )?;
        let bindings = json!([{"tool_id": tool, "tool_version": 1, "public_name": "sample"}]);
        conn.execute(
            "INSERT INTO profiles (profile_id, slug, discovery_mode, published_version, created_at_ms, updated_at_ms)
             VALUES (?1, 'sample', 'full', 1, 10000, 10000)",
            [profile.to_string()],
        )?;
        conn.execute(
            "INSERT INTO profile_editions (profile_id, version, discovery_mode, published_by, published_at_ms, bindings_json)
             VALUES (?1, 1, 'full', ?2, 10000, ?3)",
            params![profile.to_string(), admin.to_string(), bindings.to_string()],
        )?;
        for member in [alice_id, bobby_id] {
            conn.execute(
                "INSERT INTO grants (grant_id, principal_id, scope_kind, scope_id, capability, created_by, created_at_ms)
                 VALUES (?1, ?2, 'profile', ?3, 'discover', ?4, 10000)",
                params![GrantId::new().to_string(), member.to_string(), profile.to_string(), admin.to_string()],
            )?;
        }
        Ok(())
    }).await?;

    let (status, hidden_result) = hub
        .request(
            Method::PUT,
            "/v1/accounts/hidden",
            &alice,
            Some(http_auth(hidden)),
        )
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{hidden_result}");
    let path = "/v1/accounts/common";
    let (status, alice_account) = hub
        .request(Method::PUT, path, &alice, Some(http_auth(visible)))
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{alice_account}");
    let (status, bobby_account) = hub
        .request(Method::PUT, path, &bobby, Some(http_auth(visible)))
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{bobby_account}");

    let binding = "/v1/account-bindings/me/visible";
    for denied in [
        bobby_account["account"]["account_id"].clone(),
        json!(AccountId::new()),
    ] {
        let (status, problem) = hub
            .request(
                Method::PUT,
                binding,
                &alice,
                Some(json!({"account_id": denied})),
            )
            .await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{problem}");
        assert_eq!(problem["code"], "forbidden");
    }
    for denied in [bobby_id, PrincipalId::new_for_kind(PrincipalKind::Member)] {
        let (status, problem) = hub
            .request(
                Method::PUT,
                &format!("/v1/account-bindings/{denied}/visible"),
                &alice,
                Some(json!({"account_slug": "common"})),
            )
            .await?;
        assert_eq!(status, StatusCode::FORBIDDEN, "{problem}");
        assert_eq!(problem["code"], "forbidden");
    }
    let (status, problem) = hub
        .request(
            Method::PUT,
            "/v1/account-bindings/me/hidden",
            &alice,
            Some(json!({"account_slug": "common"})),
        )
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "{problem}");
    let (status, problem) = hub
        .request_admin(Method::DELETE, "/v1/upstreams/hidden", None)
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{problem}");

    let (status, bound) = hub
        .request(
            Method::PUT,
            binding,
            &alice,
            Some(json!({"account_slug": "common"})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{bound}");
    assert_eq!(
        bound["binding"]["account_id"],
        alice_account["account"]["account_id"]
    );
    let (status, unchanged) = hub
        .request(
            Method::PUT,
            binding,
            &alice,
            Some(json!({"account_slug": "common"})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{unchanged}");
    assert_eq!(unchanged["outcome"], "unchanged");
    let (status, _) = hub.request(Method::DELETE, path, &alice, None).await?;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, shared) = hub
        .request_admin(
            Method::PUT,
            "/v1/accounts/common?visibility=shared",
            Some(http_auth(visible)),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{shared}");
    let (status, overwritten) = hub
        .request_admin(
            Method::PUT,
            &format!("/v1/account-bindings/{alice_id}/visible"),
            Some(json!({"account_id": shared["account"]["account_id"]})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{overwritten}");
    assert_eq!(overwritten["outcome"], "updated");
    let (status, problem) = hub.request(Method::DELETE, binding, &alice, None).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{problem}");
    let (status, _) = hub
        .request(
            Method::PUT,
            binding,
            &bobby,
            Some(json!({"account_slug": "common"})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED);

    let (status, page) = hub
        .request(Method::GET, "/v1/account-bindings?limit=1", &alice, None)
        .await?;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["items"], json!([overwritten["binding"]]));
    assert_eq!(page["next_cursor"], Value::Null);

    let detached = "/v1/accounts/detached";
    let (status, account) = hub
        .request(Method::PUT, detached, &bobby, Some(http_auth(visible)))
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{account}");
    let (status, problem) = hub
        .request_admin(Method::POST, "/v1/upstreams/visible/disable", None)
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{problem}");
    let (status, metadata) = hub.request(Method::GET, detached, &bobby, None).await?;
    assert_eq!(status, StatusCode::OK, "{metadata}");
    assert_eq!(metadata, account["account"]);
    let (status, problem) = hub.request(Method::DELETE, detached, &bobby, None).await?;
    assert_eq!(status, StatusCode::NO_CONTENT, "{problem}");

    hub.shutdown().await;
    Ok(())
}
