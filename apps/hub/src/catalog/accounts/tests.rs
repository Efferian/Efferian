use std::sync::{Mutex, PoisonError};

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
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(invalidation);
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
    let secret = token["token"]
        .as_str()
        .ok_or("token creation did not return a token")?;
    Ok((principal_id, secret.to_owned()))
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
        *invalidations
            .0
            .lock()
            .map_err(|_| "mock invalidations lock poisoned")?,
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
    let (status, problem) = hub
        .request(
            Method::PUT,
            binding,
            &alice,
            Some(json!({"account_slug": "common"})),
        )
        .await?;
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

    let (status, _) = hub.request(Method::DELETE, binding, &bobby, None).await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, problem) = hub.request(Method::DELETE, path, &bobby, None).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{problem}");
    assert_eq!(problem["code"], "resource_in_use");
    let (status, _) = hub
        .request_admin(
            Method::DELETE,
            &format!("/v1/account-bindings/{bobby_id}/visible"),
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = hub.request(Method::DELETE, path, &bobby, None).await?;
    assert_eq!(status, StatusCode::NO_CONTENT);

    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn account_put_validates_payload_and_upstream_kind_before_conflicts_and_filters_queries()
-> TestResult {
    let hub = TestHub::start("account-validation", Config::default(), 10_000).await?;
    let (status, upstream) = hub
        .request_admin(
            Method::PUT,
            "/v1/upstreams/primary",
            Some(json!({"url": "https://example.com/mcp"})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{upstream}");
    let upstream_id: UpstreamId =
        serde_json::from_value(upstream["upstream"]["upstream_id"].clone())?;

    // upstream_id with non-http_auth fails 400 on create.
    let (status, problem) = hub
        .request_admin(
            Method::PUT,
            "/v1/accounts/bad-bind",
            Some(json!({
                "upstream_id": upstream_id,
                "secret": {"kind": "secret_kv", "entries": {"K": "v"}}
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{problem}");

    // NUL byte inside SecretKv value fails 400.
    let (status, problem) = hub
        .request_admin(
            Method::PUT,
            "/v1/accounts/nul-secret",
            Some(json!({
                "secret": {"kind": "secret_kv", "entries": {"K": "bad\0value"}}
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{problem}");

    // Create a valid secret_kv account, then verify invalid inputs return 400 before 409/404.
    let (status, created) = hub
        .request_admin(
            Method::PUT,
            "/v1/accounts/existing",
            Some(secret_kv("initial")),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let (status, problem) = hub
        .request_admin(
            Method::PUT,
            "/v1/accounts/existing",
            Some(json!({
                "upstream_id": UpstreamId::new(),
                "secret": {"kind": "secret_kv", "entries": {"K": "v"}}
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{problem}");
    let (status, problem) = hub
        .request_admin(
            Method::PUT,
            "/v1/accounts/existing",
            Some(json!({
                "secret": {"kind": "http_auth", "auth": {"kind": "bearer", "token": ""}}
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{problem}");

    // visibility=shared combined with owner is always rejected with 400.
    for (method, body) in [
        (Method::GET, None),
        (Method::PUT, Some(secret_kv("x"))),
        (Method::DELETE, None),
    ] {
        let (status, problem) = hub
            .request_admin(
                method,
                &format!(
                    "/v1/accounts/existing?visibility=shared&owner={}",
                    hub.admin_id
                ),
                body,
            )
            .await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{problem}");
    }

    // Owner matching gc_purging_principal_id is hidden (404).
    let purging = PrincipalId::new_agent();
    let admin = hub.admin_id;
    hub.write(move |conn| {
        conn.execute(
            "INSERT INTO principals(principal_id, kind, name, managed_by_principal_id, disabled_at_ms, created_at_ms, updated_at_ms)
             VALUES (?1, 'agent', '~purging:acct', ?2, -1, 10000, 10000)",
            params![purging.to_string(), admin.to_string()],
        )?;
        conn.execute(
            "UPDATE hub_meta SET gc_purging_principal_id = ?1 WHERE id = 1",
            [purging.to_string()],
        )?;
        Ok(())
    })
    .await?;
    let (status, _) = hub
        .request_admin(Method::GET, &format!("/v1/accounts?owner={purging}"), None)
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Second admin rotating a shared account preserves original owner_principal_id.
    let (delegate_id, delegate) = add_human(&hub, "rotator", PrincipalKind::Admin).await?;
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
    let shared_uri = "/v1/accounts/shared-rot?visibility=shared";
    let (status, _) = hub
        .request_admin(Method::PUT, shared_uri, Some(secret_kv("v1")))
        .await?;
    assert_eq!(status, StatusCode::CREATED);
    let (status, rotated) = hub
        .request(Method::PUT, shared_uri, &delegate, Some(secret_kv("v2")))
        .await?;
    assert_eq!(status, StatusCode::OK, "{rotated}");
    assert_eq!(rotated["outcome"], "updated");
    assert_eq!(rotated["account"]["secret_version"], 2);
    assert_eq!(
        rotated["account"]["owner_principal_id"],
        json!(hub.admin_id)
    );

    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn binding_changes_owner_disable_and_inheritance_toggle_invalidate_child_agents() -> TestResult
{
    let invalidations = Arc::new(Invalidations::default());
    let hub = TestHub::start_with_dispatchers(
        "binding-invalidations",
        Config::default(),
        10_000,
        None,
        invalidations.clone(),
    )
    .await?;
    let (owner_id, owner_token) = add_member(&hub, "owner").await?;
    let (status, agent_res) = hub
        .request_admin(
            Method::PUT,
            "/v1/principals/child-agent",
            Some(json!({
                "kind": "agent",
                "owner_principal_id": owner_id,
                "managed_by_principal_id": owner_id,
                "inherit_owner_bindings": true,
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED, "{agent_res}");
    let agent_id: PrincipalId =
        serde_json::from_value(agent_res["principal"]["principal_id"].clone())?;

    let mut upstream_ids = Vec::new();
    for slug in ["alpha", "beta"] {
        let (status, upstream) = hub
            .request_admin(
                Method::PUT,
                &format!("/v1/upstreams/{slug}"),
                Some(json!({"url": "https://example.com/mcp"})),
            )
            .await?;
        assert_eq!(status, StatusCode::CREATED, "{upstream}");
        let id: UpstreamId = serde_json::from_value(upstream["upstream"]["upstream_id"].clone())?;
        upstream_ids.push(id);
    }
    let profile_id = ProfileId::new();
    let admin = hub.admin_id;
    let u0 = upstream_ids[0];
    let u1 = upstream_ids[1];
    hub.write(move |conn| {
        let mut bindings = Vec::new();
        for (idx, uid) in [u0, u1].into_iter().enumerate() {
            let tid = ToolId::new();
            conn.execute(
                "INSERT INTO tools (tool_id, slug, kind, created_by, current_version, created_at_ms, updated_at_ms)
                 VALUES (?1, ?2, 'upstream_ref', ?3, 1, 10000, 10000)",
                params![tid.to_string(), format!("t{idx}"), admin.to_string()],
            )?;
            let def = json!({
                "input_schema": {"type": "object"},
                "spec": {
                    "kind": "upstream_ref", "upstream_id": uid,
                    "upstream_tool_name": "echo", "account_mode": "caller_bound", "runtime_ms": 1000
                }
            });
            conn.execute(
                "INSERT INTO tool_revisions (tool_id, version, input_schema_sha256, created_at_ms, definition_json)
                 VALUES (?1, 1, 'fixture', 10000, ?2)",
                params![tid.to_string(), def.to_string()],
            )?;
            bindings.push(json!({"tool_id": tid, "tool_version": 1, "public_name": format!("tool_{idx}")}));
        }
        conn.execute(
            "INSERT INTO profiles (profile_id, slug, discovery_mode, published_version, created_at_ms, updated_at_ms)
             VALUES (?1, 'p', 'full', 1, 10000, 10000)",
            [profile_id.to_string()],
        )?;
        conn.execute(
            "INSERT INTO profile_editions (profile_id, version, discovery_mode, published_by, published_at_ms, bindings_json)
             VALUES (?1, 1, 'full', ?2, 10000, ?3)",
            params![profile_id.to_string(), admin.to_string(), Value::Array(bindings).to_string()],
        )?;
        conn.execute(
            "INSERT INTO grants (grant_id, principal_id, scope_kind, scope_id, capability, created_by, created_at_ms)
             VALUES (?1, ?2, 'profile', ?3, 'discover', ?4, 10000)",
            params![GrantId::new().to_string(), owner_id.to_string(), profile_id.to_string(), admin.to_string()],
        )?;
        Ok(())
    })
    .await?;

    // Missing own account_slug returns 404 (and invalid slug returns 400).
    let (status, _) = hub
        .request(
            Method::PUT,
            "/v1/account-bindings/me/alpha",
            &owner_token,
            Some(json!({"account_slug": "missing-own"})),
        )
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = hub
        .request(
            Method::PUT,
            "/v1/account-bindings/me/alpha",
            &owner_token,
            Some(json!({"account_slug": "INVALID SLUG"})),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    for (slug, uid) in [("acct-a", u0), ("acct-b", u1)] {
        let (status, acct) = hub
            .request(
                Method::PUT,
                &format!("/v1/accounts/{slug}"),
                &owner_token,
                Some(http_auth(uid)),
            )
            .await?;
        assert_eq!(status, StatusCode::CREATED, "{acct}");
    }
    invalidations
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();

    for (upstream, acct) in [("alpha", "acct-a"), ("beta", "acct-b")] {
        let (status, res) = hub
            .request(
                Method::PUT,
                &format!("/v1/account-bindings/me/{upstream}"),
                &owner_token,
                Some(json!({"account_slug": acct})),
            )
            .await?;
        assert_eq!(status, StatusCode::CREATED, "{res}");
    }
    // Multi-page cursor pagination across the owner's 2 bindings.
    let (status, page1) = hub
        .request(
            Method::GET,
            "/v1/account-bindings?limit=1",
            &owner_token,
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{page1}");
    assert_eq!(page1["items"].as_array().map(Vec::len), Some(1));
    let cursor = page1["next_cursor"]
        .as_str()
        .ok_or("expected binding cursor")?;
    let (status, page2) = hub
        .request(
            Method::GET,
            &format!("/v1/account-bindings?limit=1&cursor={cursor}"),
            &owner_token,
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{page2}");
    assert_eq!(page2["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(page2["next_cursor"], Value::Null);
    assert_ne!(
        page1["items"][0]["upstream_id"],
        page2["items"][0]["upstream_id"]
    );

    // Verify owner binding PUT invalidated both owner and inheriting child agent.
    {
        let mut seen = invalidations
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        assert!(seen.contains(&UpstreamInvalidation::Binding {
            principal_id: owner_id,
            upstream_id: u0,
        }));
        assert!(seen.contains(&UpstreamInvalidation::Binding {
            principal_id: agent_id,
            upstream_id: u0,
        }));
        seen.clear();
    }

    // Disabling owner must invalidate both owner and child agent.
    let (status, _) = hub
        .request_admin(
            Method::POST,
            &format!("/v1/principals/{owner_id}/disable"),
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    {
        let mut seen = invalidations
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        assert!(seen.contains(&UpstreamInvalidation::Principal(owner_id)));
        assert!(seen.contains(&UpstreamInvalidation::Principal(agent_id)));
        seen.clear();
    }

    // Re-enable owner, verify DELETE binding cascades invalidation to child agent,
    // then toggle inherit_owner_bindings: true -> false on child agent.
    let (status, _) = hub
        .request_admin(
            Method::POST,
            &format!("/v1/principals/{owner_id}/enable"),
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    invalidations
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();
    let (status, _) = hub
        .request(
            Method::DELETE,
            "/v1/account-bindings/me/beta",
            &owner_token,
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    {
        let mut seen = invalidations
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        assert!(seen.contains(&UpstreamInvalidation::Binding {
            principal_id: owner_id,
            upstream_id: u1,
        }));
        assert!(seen.contains(&UpstreamInvalidation::Binding {
            principal_id: agent_id,
            upstream_id: u1,
        }));
        seen.clear();
    }
    let (status, updated) = hub
        .request_admin(
            Method::PUT,
            "/v1/principals/child-agent",
            Some(json!({
                "kind": "agent",
                "owner_principal_id": owner_id,
                "managed_by_principal_id": owner_id,
                "inherit_owner_bindings": false,
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::OK, "{updated}");
    {
        let seen = invalidations
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        assert!(seen.contains(&UpstreamInvalidation::Principal(agent_id)));
    }

    hub.shutdown().await;
    Ok(())
}
