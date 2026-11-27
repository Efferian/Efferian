use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use efferian_protocol::PrincipalKind::{Admin, Agent, Member, Service};
use efferian_protocol::{
    GrantId, HubId, PrincipalKind, ProfileId, SecretString, TokenId, ToolDefinition, ToolId,
    ToolSpec, UpstreamAccountMode, UpstreamId,
};
use http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use tower_service::Service as _;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::egress::EgressClient;
use crate::http::{AppState, router};
use crate::node_bridge::OfflineNodeBridge;
use crate::storage::{
    OpenMode, ShutdownReport, StorageClock, StorageConfig, StorageError, StorageRuntime,
    acquire_state_lock, create_staged, open_existing,
};
use crate::vault::VaultKeys;

use super::data::principal_kind_name;
use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct TestDir(PathBuf);

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct TestPrincipal {
    id: PrincipalId,
    token: SecretString,
}

struct TestClock(AtomicI64);

impl StorageClock for TestClock {
    fn wall_now_ms(&self) -> i64 {
        self.0.load(Ordering::Acquire)
    }

    fn monotonic_now(&self) -> Result<Duration, StorageError> {
        Ok(Duration::ZERO)
    }
}

struct Fixture {
    api: Router,
    state: AppState,
    runtime: StorageRuntime,
    principals: Vec<TestPrincipal>,
    clock: Arc<TestClock>,
    _directory: TestDir,
}

impl Fixture {
    fn start(
        config: Config,
        principals: &[(&str, PrincipalKind, bool)],
        seed: impl FnOnce(&Connection, &[TestPrincipal]) -> TestResult,
    ) -> TestResult<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let hub_id = HubId::new();
        let directory = TestDir(std::env::temp_dir().join(format!("efferian-principals-{hub_id}")));
        let keys = VaultKeys::derive(Zeroizing::new([3; 32]))?;
        let mut lock = acquire_state_lock(&directory.0)?;
        let schema = StorageConfig {
            gc_interval: Duration::from_secs(60 * 60),
            ..config.storage_config()
        };
        let clock = Arc::new(TestClock(AtomicI64::new(1_000)));
        let principals = create_staged(
            &mut lock,
            keys.new_hub_identity(hub_id),
            &schema,
            clock.as_ref(),
            |tx| -> TestResult<_> {
                let mut subjects = Vec::new();
                for &(name, kind, narrowed) in principals {
                    let id = PrincipalId::new_for_kind(kind);
                    tx.execute(
                        "INSERT INTO principals (principal_id, name, kind, created_at_ms, updated_at_ms)
                         VALUES (?1, ?2, ?3, 1000, 1000)",
                        params![id.to_string(), name, principal_kind_name(kind)],
                    )?;
                    if kind == Admin {
                        tx.execute(
                            "INSERT INTO grants (grant_id, principal_id, scope_kind, capability,
                                                 created_by, created_at_ms)
                             VALUES (?1, ?2, 'global', 'admin', ?2, 1000)",
                            params![GrantId::new().to_string(), id.to_string()],
                        )?;
                    }
                    let token = TokenId::new_for_kind(kind);
                    let issued = keys.issue_token(token)?;
                    tx.execute(
                        "INSERT INTO auth_tokens (token_id, principal_id, created_by, label, key_id,
                                                  verifier_hmac, withhold_sensitive, created_at_ms)
                         VALUES (?1, ?2, ?2, 'fixture', ?3, ?4, ?5, 1000)",
                        params![
                            token.to_string(),
                            id.to_string(),
                            issued.key_id,
                            issued.verifier,
                            narrowed,
                        ],
                    )?;
                    subjects.push(TestPrincipal { id, token: issued.secret });
                }
                seed(tx, &subjects)?;
                Ok(subjects)
            },
        )
        .map_err(|error| std::io::Error::other(error.to_string()))?;
        let opened = open_existing(
            lock,
            OpenMode::ServeAutoMigrate,
            keys.expected_hub_identity(),
            &schema,
            clock.clone(),
        )?;
        let (storage, runtime) = opened.migrate_and_start_runtime()?;
        let state = AppState {
            storage,
            vault: Arc::new(keys.bind_hub(hub_id)),
            clock: clock.clone(),
            egress: EgressClient::new(config.egress_policy()?)?,
            config: Arc::new(config),
            bridge: Arc::new(OfflineNodeBridge),
        };
        let api = router(state.clone(), 8080)?;
        Ok(Self {
            api,
            state,
            runtime,
            principals,
            clock,
            _directory: directory,
        })
    }

    async fn call(
        &self,
        subject: usize,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> TestResult<(StatusCode, Value)> {
        let builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost:8080")
            .header(
                "authorization",
                format!("Bearer {}", self.principals[subject].token.expose_secret()),
            );
        let request = if let Some(body) = body {
            builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))?
        } else {
            builder.body(Body::empty())?
        };
        let response = self.api.clone().call(request).await?;
        let status = response.status();
        let bytes = response.into_body().collect().await?.to_bytes();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)?
        };
        Ok((status, body))
    }

    async fn stop(self) -> TestResult {
        assert!(matches!(
            self.runtime.shutdown().await,
            ShutdownReport::Complete
        ));
        Ok(())
    }

    async fn mark_gc_purging(&self, id: PrincipalId) -> TestResult {
        let id = id.to_string();
        self.state
            .storage
            .execute_work(0, move |tx| {
                tx.conn().execute(
                "UPDATE principals SET name = '~purging:' || principal_id, disabled_at_ms = 1000
                 WHERE principal_id = ?1",
                [&id],
            )?;
                tx.conn().execute(
                    "UPDATE hub_meta SET gc_purging_principal_id = ?1 WHERE id = 1",
                    [id],
                )?;
                Ok::<(), crate::storage::WriteTxError<ApiError>>(())
            })
            .await?;
        Ok(())
    }
}

#[tokio::test]
async fn delegated_replacement_quota_and_purging_visibility() -> TestResult {
    let mut config = Config::default();
    config.max_managed_agents_per_member = 1;
    let fixture = Fixture::start(
        config,
        &[
            ("operator", Admin, false),
            ("member", Member, false),
            ("narrow", Member, true),
        ],
        |_, _| Ok(()),
    )?;
    let (_, response) = fixture
        .call(
            1,
            Method::PUT,
            "/v1/principals/first",
            Some(json!({"owner_principal_id": null})),
        )
        .await?;
    assert_eq!(response["code"], "forbidden");

    let (first, second) = tokio::join!(
        fixture.call(
            1,
            Method::PUT,
            "/v1/principals/first",
            Some(json!({"inherit_owner_bindings": true}))
        ),
        fixture.call(
            1,
            Method::PUT,
            "/v1/principals/second",
            Some(json!({"inherit_owner_bindings": true}))
        ),
    );
    let (first, second) = (first?, second?);
    let (created, rejected) = if first.0 == StatusCode::CREATED {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(created.0, StatusCode::CREATED);
    assert_eq!(created.1["outcome"], "created");
    assert!(
        created.1["principal"]["inherit_owner_bindings"]
            .as_bool()
            .is_some_and(|flag| flag)
    );
    assert_eq!(rejected.0, StatusCode::CONFLICT);
    assert_eq!(rejected.1["code"], "quota_exceeded");
    let winner_id: PrincipalId =
        serde_json::from_value(created.1["principal"]["principal_id"].clone())?;
    let winner_name = serde_json::from_value::<String>(created.1["principal"]["name"].clone())?;
    let winner_path = format!("/v1/principals/{winner_name}");

    fixture.clock.0.store(2_000, Ordering::Release);
    let (status, updated) = fixture
        .call(1, Method::PUT, &winner_path, Some(json!({})))
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["outcome"], "updated");
    assert_eq!(updated["principal"]["inherit_owner_bindings"], false);
    assert_eq!(updated["principal"]["updated_at_ms"], 2_000);

    fixture.clock.0.store(3_000, Ordering::Release);
    let (status, unchanged) = fixture
        .call(1, Method::PUT, &winner_path, Some(json!({})))
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(unchanged["outcome"], "unchanged");
    assert_eq!(unchanged["principal"]["updated_at_ms"], 2_000);

    for path in [&winner_path, "/v1/principals/unused"] {
        let (status, error) = fixture.call(2, Method::PUT, path, Some(json!({}))).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(error["code"], "token_narrowed");
    }
    let (_, identity) = fixture.call(1, Method::GET, "/v1/me", None).await?;
    assert_eq!(identity["token_scope"]["label"], "fixture");
    assert_eq!(
        identity["owned_agents"][0]["principal_id"],
        winner_id.to_string()
    );

    fixture.mark_gc_purging(winner_id).await?;

    let (_, identity) = fixture.call(1, Method::GET, "/v1/me", None).await?;
    assert_eq!(identity["owned_agents"], json!([]));
    let (status, error) = fixture
        .call(
            0,
            Method::POST,
            &format!("/v1/principals/{winner_id}/enable"),
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(error["code"], "not_found");
    let (status, created) = fixture
        .call(1, Method::PUT, &winner_path, Some(json!({})))
        .await?;
    assert_eq!(status, StatusCode::CREATED);
    assert_ne!(created["principal"]["principal_id"], winner_id.to_string());
    fixture.stop().await
}

#[tokio::test]
async fn promotion_checks_the_current_managed_agent_quota() -> TestResult {
    let mut config = Config::default();
    config.max_managed_agents_per_orchestrator = 1;
    let fixture = Fixture::start(
        config,
        &[
            ("operator", Admin, false),
            ("owner", Member, false),
            ("manager", Service, false),
        ],
        |_, _| Ok(()),
    )?;
    let owner = fixture.principals[1].id;
    let manager = fixture.principals[2].id;
    let create_agent = |name: &'static str| {
        fixture.call(
            0,
            Method::PUT,
            name,
            Some(json!({
                "kind": "agent",
                "owner_principal_id": owner,
                "managed_by_principal_id": manager,
            })),
        )
    };
    let (status, _) = create_agent("/v1/principals/first").await?;
    assert_eq!(status, StatusCode::CREATED);
    let (status, second) = create_agent("/v1/principals/second").await?;
    assert_eq!(status, StatusCode::CREATED);
    let second: PrincipalId = serde_json::from_value(second["principal"]["principal_id"].clone())?;
    let (status, _) = fixture
        .call(
            0,
            Method::POST,
            &format!("/v1/principals/{second}/disable"),
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);

    fixture.clock.0.store(2_000, Ordering::Release);
    let promote = || {
        fixture.call(
            0,
            Method::PUT,
            "/v1/principals/manager",
            Some(json!({
                "kind": "service", "is_orchestrator": true,
            })),
        )
    };
    let (status, problem) = promote().await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["code"], "quota_exceeded");
    let (status, read_back) = fixture
        .call(0, Method::GET, "/v1/principals/manager", None)
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(read_back["is_orchestrator"], false);
    assert_eq!(read_back["updated_at_ms"], 1_000);

    fixture.mark_gc_purging(second).await?;
    let (status, promoted) = promote().await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(promoted["principal"]["is_orchestrator"], true);
    fixture.stop().await
}

#[tokio::test]
async fn me_uses_visible_published_profiles_and_the_pinned_tool_version() -> TestResult {
    let visible_profile = ProfileId::new();
    let hidden_profile = ProfileId::new();
    let visible_upstream = UpstreamId::new();
    let hidden_upstream = UpstreamId::new();
    let fixture = Fixture::start(
        Config::default(),
        &[("operator", Admin, false), ("member", Member, false)],
        |tx, subjects| {
            let admin = subjects[0].id.to_string();
            let member = subjects[1].id.to_string();
            for (upstream, slug) in [(visible_upstream, "visible"), (hidden_upstream, "hidden")] {
                tx.execute(
                    "INSERT INTO upstreams (upstream_id, slug, url, created_at_ms, updated_at_ms)
                     VALUES (?1, ?2, 'https://example.test/mcp', 1000, 1000)",
                    params![upstream.to_string(), slug],
                )?;
            }
            let tool = ToolId::new().to_string();
            tx.execute(
                "INSERT INTO tools (tool_id, slug, kind, created_by, current_version,
                                    created_at_ms, updated_at_ms)
                 VALUES (?1, 'sample', 'upstream_ref', ?2, 2, 1000, 1000)",
                params![tool, admin],
            )?;
            for (version, upstream_id) in [(1, visible_upstream), (2, hidden_upstream)] {
                let definition = ToolDefinition {
                    description: None,
                    input_schema: Some(json!({"type": "object"})),
                    annotations: None,
                    spec: ToolSpec::UpstreamRef {
                        upstream_id,
                        upstream_tool_name: "tool".to_owned(),
                        account_mode: UpstreamAccountMode::CallerBound,
                        shared_account_id: None,
                        runtime_ms: 500,
                    },
                };
                tx.execute(
                    "INSERT INTO tool_revisions (tool_id, version, input_schema_sha256,
                                                 created_at_ms, definition_json)
                     VALUES (?1, ?2, 'fixture', 1000, ?3)",
                    params![tool, version, serde_json::to_string(&definition)?],
                )?;
            }
            for (profile, slug, version) in [
                (visible_profile, "visible", 1),
                (hidden_profile, "hidden", 2),
            ] {
                tx.execute(
                    "INSERT INTO profiles (profile_id, slug, discovery_mode, published_version,
                                           created_at_ms, updated_at_ms)
                     VALUES (?1, ?2, 'full', 1, 1000, 1000)",
                    params![profile.to_string(), slug],
                )?;
                let bindings = json!([
                    {"public_name": "tool", "tool_id": tool, "tool_version": version},
                    {"public_name": "alias", "tool_id": tool, "tool_version": version}
                ]);
                tx.execute(
                    "INSERT INTO profile_editions (profile_id, version, discovery_mode, published_by,
                                                    published_at_ms, bindings_json)
                     VALUES (?1, 1, 'full', ?2, 1000, ?3)",
                    params![profile.to_string(), admin, bindings.to_string()],
                )?;
            }
            tx.execute(
                "INSERT INTO grants (grant_id, principal_id, scope_kind, capability,
                                     created_by, created_at_ms)
                 VALUES (?1, ?2, 'global', 'discover', ?3, 1000)",
                params![GrantId::new().to_string(), member, admin],
            )?;
            tx.execute(
                "UPDATE auth_tokens SET allowed_profiles_json = ?1 WHERE principal_id = ?2",
                params![serde_json::to_string(&[visible_profile])?, member],
            )?;
            Ok(())
        },
    )?;
    let (status, body) = fixture.call(1, Method::GET, "/v1/me", None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["caller_bound_upstreams"],
        json!([
            {"upstream_id": visible_upstream, "slug": "visible"}
        ])
    );
    assert_eq!(
        body["token_scope"]["allowed_profiles"],
        json!([visible_profile])
    );
    fixture.stop().await
}

#[tokio::test]
async fn simultaneous_disables_leave_a_global_administrator_and_one_committed_event() -> TestResult
{
    let fixture = Fixture::start(
        Config::default(),
        &[("first", Admin, false), ("second", Admin, false)],
        |_, _| Ok(()),
    )?;
    let first_path = format!("/v1/principals/{}/disable", fixture.principals[0].id);
    let second_path = format!("/v1/principals/{}/disable", fixture.principals[1].id);
    let (first, second) = tokio::join!(
        fixture.call(0, Method::POST, &first_path, None),
        fixture.call(1, Method::POST, &second_path, None),
    );
    let (first, second) = (first?, second?);
    let (active, rejected) = if first.0 == StatusCode::NO_CONTENT {
        (1, second)
    } else {
        (0, first)
    };
    assert_eq!(rejected.0, StatusCode::CONFLICT);
    assert_eq!(rejected.1["code"], "last_admin");
    let (status, body) = fixture
        .call(active, Method::GET, "/v1/admin/status", None)
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["events_head_seq"], 1);
    assert_eq!(body["active_waiters_count"], 0);
    assert_eq!(body["online_nodes_count"], 0);
    assert_eq!(body["upstream_pool_connections"], 0);
    fixture.stop().await
}

#[tokio::test]
async fn keyset_tracks_binary_id_order_and_visibility() -> TestResult {
    let fixture = Fixture::start(
        Config::default(),
        &[
            ("operator", Admin, false),
            ("member", Member, false),
            ("agent-one", Agent, false),
            ("service", Service, false),
        ],
        |tx, ids| {
            tx.execute(
                "UPDATE principals SET owner_principal_id = ?1, managed_by_principal_id = ?1
                 WHERE principal_id = ?2",
                [ids[1].id.to_string(), ids[2].id.to_string()],
            )?;
            Ok(())
        },
    )?;
    let mut expected = fixture
        .principals
        .iter()
        .map(|subject| subject.id.to_string())
        .collect::<Vec<_>>();
    expected.sort();
    let mut path = "/v1/principals?limit=1".to_owned();
    for (offset, expected_id) in expected.iter().enumerate() {
        let (status, actual) = fixture.call(0, Method::GET, &path, None).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(actual["items"][0]["principal_id"], expected_id.as_str());
        if offset + 1 == expected.len() {
            assert!(actual["next_cursor"].is_null());
        } else {
            assert_eq!(actual["next_cursor"], expected_id.as_str());
            path = format!("/v1/principals?limit=1&cursor={expected_id}");
        }
    }

    let (status, visible) = fixture
        .call(1, Method::GET, "/v1/principals?limit=2", None)
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(visible["items"][0]["name"], "agent-one");
    assert_eq!(visible["items"][1]["name"], "member");
    assert!(visible["next_cursor"].is_null());
    for path in ["/v1/principals/operator", "/v1/principals/unknown"] {
        let (status, error) = fixture.call(1, Method::GET, path, None).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(error["code"], "forbidden");
    }
    let (status, error) = fixture
        .call(1, Method::GET, "/v1/principals?limit=0", None)
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error["code"], "invalid_input");
    fixture.stop().await
}

#[tokio::test]
async fn demotion_invalidates_managed_agent_authentication_and_retains_admin_control() -> TestResult
{
    let fixture = Fixture::start(
        Config::default(),
        &[
            ("operator", Admin, false),
            ("orchestrator", Service, false),
            ("managed", Agent, false),
        ],
        |tx, subjects| {
            let manager = subjects[1].id.to_string();
            let agent = subjects[2].id.to_string();
            tx.execute(
                "UPDATE principals SET is_orchestrator = 1, allowed_node_tags_json = '[\"tag\"]'
                 WHERE principal_id = ?1",
                [&manager],
            )?;
            tx.execute(
                "UPDATE principals SET managed_by_principal_id = ?1 WHERE principal_id = ?2",
                [&manager, &agent],
            )?;
            // The agent may not mint its own token through REST.
            tx.execute(
                "UPDATE auth_tokens SET created_by = ?1 WHERE principal_id = ?2",
                [subjects[0].id.to_string(), agent],
            )?;
            Ok(())
        },
    )?;
    let agent_id = fixture.principals[2].id;
    let orchestrator_id = fixture.principals[1].id;
    let subject_path = format!("/v1/principals/{agent_id}");
    let (status, _) = fixture.call(2, Method::GET, "/v1/me", None).await?;
    assert_eq!(status, StatusCode::OK);

    let (status, invalid) = fixture
        .call(
            0,
            Method::PUT,
            "/v1/principals/orchestrator",
            Some(json!({"kind":"service", "allowed_node_tags":["tag"]})),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid["code"], "invalid_input");
    let (status, updated) = fixture
        .call(
            0,
            Method::PUT,
            "/v1/principals/orchestrator",
            Some(json!({"kind":"service"})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["principal"]["allowed_node_tags"], json!([]));

    let (status, rejected) = fixture.call(2, Method::GET, "/v1/me", None).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(rejected["code"], "forbidden");
    let (status, forbidden) = fixture
        .call(
            0,
            Method::PUT,
            "/v1/principals/managed",
            Some(json!({"kind":"agent", "managed_by_principal_id":orchestrator_id})),
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(forbidden["code"], "forbidden");

    let (status, result) = fixture.call(0, Method::DELETE, &subject_path, None).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(result["code"], "resource_in_use");
    let (status, _) = fixture
        .call(0, Method::POST, &format!("{subject_path}/disable"), None)
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = fixture.call(0, Method::DELETE, &subject_path, None).await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = fixture
        .call(0, Method::GET, "/v1/principals/managed", None)
        .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);
    fixture.stop().await
}
