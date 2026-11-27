use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use efferian_protocol::PrincipalKind::{Admin, Agent, Member, Service};
use efferian_protocol::{
    GrantId, HubId, NodeId, PrincipalKind, ProfileId, SecretString, TokenId, ToolDefinition,
    ToolId, ToolSpec, UpstreamAccountMode, UpstreamId,
};
use http::{Method, StatusCode};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::config::Config;
use crate::egress::EgressClient;
use crate::http::{AppState, router};
use crate::node_bridge::{BridgeCloseReason, NodeBridgeControl};
use crate::storage::{
    OpenMode, RevocationReason, ShutdownReport, StorageClock, StorageConfig, StorageRuntime,
    acquire_state_lock, create_staged, open_existing,
};
use crate::test_support::{ManualClock, RecordingBridge, TestDir, TestResult, send_json};
use crate::vault::VaultKeys;

use super::data::principal_kind_name;
use super::*;

struct TestPrincipal {
    id: PrincipalId,
    token: SecretString,
}

struct Fixture {
    api: Router,
    state: AppState,
    runtime: StorageRuntime,
    principals: Vec<TestPrincipal>,
    bridge: Arc<RecordingBridge>,
    clock: Arc<ManualClock>,
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
        let directory = TestDir::new("principals")?;
        let keys = VaultKeys::derive(Zeroizing::new([3; 32]))?;
        let mut lock = acquire_state_lock(&directory.0)?;
        let schema = StorageConfig {
            gc_interval: Duration::from_secs(60 * 60),
            ..config.storage_config()
        };
        let clock = Arc::new(ManualClock::new(1_000));
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
                            issued.verifier.as_str(),
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
            Arc::clone(&clock) as Arc<dyn StorageClock>,
        )?;
        let (storage, runtime) = opened.migrate_and_start_runtime()?;
        let bridge = Arc::new(RecordingBridge::new(directory.join("hub.sqlite3")));
        let state = AppState {
            storage,
            vault: Arc::new(keys.bind_hub(hub_id)),
            clock: Arc::clone(&clock) as Arc<dyn StorageClock>,
            egress: EgressClient::new(config.egress_policy()?)?,
            config: Arc::new(config),
            bridge: Arc::clone(&bridge) as Arc<dyn NodeBridgeControl>,
        };
        let api = router(state.clone(), 8080)?;
        Ok(Self {
            api,
            state,
            runtime,
            principals,
            bridge,
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
        send_json(
            &self.api,
            method,
            path,
            self.principals[subject].token.expose_secret(),
            body,
        )
        .await
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

    fixture.clock.set(2_000);
    let (status, updated) = fixture
        .call(1, Method::PUT, &winner_path, Some(json!({})))
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["outcome"], "updated");
    assert_eq!(updated["principal"]["inherit_owner_bindings"], false);
    assert_eq!(updated["principal"]["updated_at_ms"], 2_000);

    fixture.clock.set(3_000);
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

    fixture.clock.set(2_000);
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
        &[
            ("operator", Admin, false),
            ("member", Member, false),
            ("delegate", Member, false),
        ],
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
            tx.execute(
                "INSERT INTO grants (grant_id, principal_id, scope_kind, scope_id, capability, created_by, created_at_ms)
                 VALUES (?1, ?2, 'profile', ?3, 'discover', ?4, 1000)",
                params![GrantId::new().to_string(), subjects[2].id.to_string(), visible_profile.to_string(), admin],
            )?;
            // Make SQLite fail if a query evaluates bindings_json for the hidden profile.
            tx.execute(
                "UPDATE profile_editions SET bindings_json = 'unreadable' WHERE profile_id = ?1",
                [hidden_profile.to_string()],
            )?;
            tx.execute_batch(
                "ALTER TABLE profile_editions RENAME TO stored_editions;
                 CREATE VIEW profile_editions AS SELECT profile_id, version, disabled_at_ms,
                    json(bindings_json) AS bindings_json FROM stored_editions;",
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
    let (status, delegate) = fixture.call(2, Method::GET, "/v1/me", None).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        delegate["caller_bound_upstreams"],
        body["caller_bound_upstreams"]
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

#[tokio::test]
async fn narrowed_and_non_global_anti_oracle_and_me_owned_agents() -> TestResult {
    let fixture = Fixture::start(
        Config::default(),
        &[
            ("global-admin", Admin, false),
            ("narrow-admin", Admin, true),
            ("plain-admin", Admin, false),
            ("member", Member, false),
            ("narrow-member", Member, true),
            ("narrow-orch", Service, true),
            ("agent", Agent, false),
        ],
        |tx, subjects| {
            let global_admin = subjects[0].id.to_string();
            let narrow_admin = subjects[1].id.to_string();
            let plain_admin = subjects[2].id.to_string();
            let member = subjects[3].id.to_string();
            let narrow_member = subjects[4].id.to_string();
            let narrow_orch = subjects[5].id.to_string();
            // Remove global admin grant from plain-admin so it is an Admin without global admin grant.
            tx.execute("DELETE FROM grants WHERE principal_id = ?1", [&plain_admin])?;
            tx.execute(
                "UPDATE principals SET is_orchestrator = 1 WHERE principal_id = ?1",
                [&narrow_orch],
            )?;
            // Seed one owned/managed agent for each principal role (orchestrator agents have NULL owner).
            for (owner, manager, name) in [
                (Some(global_admin.as_str()), &global_admin, "ga-agent"),
                (Some(narrow_admin.as_str()), &narrow_admin, "na-agent"),
                (Some(plain_admin.as_str()), &plain_admin, "pa-agent"),
                (Some(member.as_str()), &member, "m-agent"),
                (Some(narrow_member.as_str()), &narrow_member, "nm-agent"),
                (None, &narrow_orch, "orch-agent"),
            ] {
                tx.execute(
                    "INSERT INTO principals (principal_id, name, kind, owner_principal_id,
                                             managed_by_principal_id, created_at_ms, updated_at_ms)
                     VALUES (?1, ?2, 'agent', ?3, ?4, 1000, 1000)",
                    params![PrincipalId::new_agent().to_string(), name, owner, manager],
                )?;
            }
            // Seed a non-upstream command tool bound to a profile visible to member to verify /v1/me skips it.
            let profile = ProfileId::new();
            let cmd_tool = ToolId::new();
            tx.execute(
                "INSERT INTO tools (tool_id, slug, kind, created_by, current_version, created_at_ms, updated_at_ms)
                 VALUES (?1, 'cmd', 'command', ?2, 1, 1000, 1000)",
                params![cmd_tool.to_string(), global_admin],
            )?;
            tx.execute(
                "INSERT INTO tool_revisions (tool_id, version, input_schema_sha256, created_at_ms, definition_json)
                 VALUES (?1, 1, 'x', 1000, '{\"spec\":{\"kind\":\"command\"}}')",
                [cmd_tool.to_string()],
            )?;
            tx.execute(
                "INSERT INTO profiles (profile_id, slug, discovery_mode, published_version, created_at_ms, updated_at_ms)
                 VALUES (?1, 'cmd-prof', 'full', 1, 1000, 1000)",
                [profile.to_string()],
            )?;
            tx.execute(
                "INSERT INTO profile_editions (profile_id, version, discovery_mode, published_by, published_at_ms, bindings_json)
                 VALUES (?1, 1, 'full', ?2, 1000, ?3)",
                params![
                    profile.to_string(),
                    global_admin,
                    json!([{"public_name": "run", "tool_id": cmd_tool, "tool_version": 1}]).to_string()
                ],
            )?;
            tx.execute(
                "INSERT INTO grants (grant_id, principal_id, scope_kind, scope_id, capability, created_by, created_at_ms)
                 VALUES (?1, ?2, 'profile', ?3, 'discover', ?4, 1000)",
                params![GrantId::new().to_string(), member, profile.to_string(), global_admin],
            )?;
            // Give agent an allowed_nodes restriction to check /v1/me early return.
            tx.execute(
                "UPDATE auth_tokens SET allowed_nodes_json = '[]' WHERE principal_id = ?1",
                [subjects[6].id.to_string()],
            )?;
            Ok(())
        },
    )?;

    // 1. /v1/me owned_agents matches authorize_principal_manage(Read).
    let (_, me_ga) = fixture.call(0, Method::GET, "/v1/me", None).await?;
    assert_eq!(me_ga["owned_agents"].as_array().map(Vec::len), Some(1));
    let (_, me_na) = fixture.call(1, Method::GET, "/v1/me", None).await?;
    assert_eq!(me_na["owned_agents"], json!([]));
    let (_, me_pa) = fixture.call(2, Method::GET, "/v1/me", None).await?;
    assert_eq!(me_pa["owned_agents"], json!([]));
    let (_, me_m) = fixture.call(3, Method::GET, "/v1/me", None).await?;
    assert_eq!(me_m["owned_agents"].as_array().map(Vec::len), Some(1));
    assert_eq!(me_m["caller_bound_upstreams"], json!([]));
    let (_, me_nm) = fixture.call(4, Method::GET, "/v1/me", None).await?;
    assert_eq!(me_nm["owned_agents"].as_array().map(Vec::len), Some(1));
    let (_, me_no) = fixture.call(5, Method::GET, "/v1/me", None).await?;
    assert_eq!(me_no["owned_agents"], json!([]));
    let (_, me_ag) = fixture.call(6, Method::GET, "/v1/me", None).await?;
    assert_eq!(me_ag["owned_agents"], json!([]));
    assert_eq!(me_ag["caller_bound_upstreams"], json!([]));

    // 2. Anti-oracle: narrowed callers get identical 403 token_narrowed across owned/foreign/missing targets.
    let id_by_name = |name: &'static str| {
        let storage = fixture.state.storage.clone();
        async move {
            storage
                .read_snapshot(move |conn| {
                    conn.query_row(
                        "SELECT principal_id FROM principals WHERE name = ?1",
                        [name],
                        |row| crate::storage::id::<PrincipalId>(row, 0),
                    )
                    .map_err(crate::storage::StorageError::from)
                })
                .await
        }
    };
    let na_agent_id = id_by_name("na-agent").await?;
    let m_agent_id = id_by_name("m-agent").await?;
    let nm_agent_id = id_by_name("nm-agent").await?;
    let orch_agent_id = id_by_name("orch-agent").await?;
    let missing_id = PrincipalId::new_agent();

    for (subject, owned_name, foreign_name, owned_id, foreign_id) in [
        (1, "na-agent", "m-agent", na_agent_id, m_agent_id),
        (4, "nm-agent", "m-agent", nm_agent_id, m_agent_id),
        (5, "orch-agent", "m-agent", orch_agent_id, m_agent_id),
    ] {
        for name in [owned_name, foreign_name, "nonexistent-name"] {
            let (status, err) = fixture
                .call(
                    subject,
                    Method::PUT,
                    &format!("/v1/principals/{name}"),
                    Some(json!({})),
                )
                .await?;
            assert_eq!(status, StatusCode::FORBIDDEN, "{subject} PUT {name}");
            assert_eq!(err["code"], "token_narrowed", "{subject} PUT {name}");
        }
        for id in [owned_id, foreign_id, missing_id] {
            for (method, suffix) in [
                (Method::POST, "/disable"),
                (Method::POST, "/enable"),
                (Method::DELETE, ""),
            ] {
                let (status, err) = fixture
                    .call(
                        subject,
                        method,
                        &format!("/v1/principals/{id}{suffix}"),
                        None,
                    )
                    .await?;
                assert_eq!(status, StatusCode::FORBIDDEN, "{subject} {id}{suffix}");
                assert_eq!(err["code"], "token_narrowed", "{subject} {id}{suffix}");
            }
        }
    }
    // Narrowed admin GET returns 403 forbidden uniformly for existing and missing (matches authorize_principal_manage(Read)).
    for target in ["na-agent", "nonexistent-name"] {
        let (status, err) = fixture
            .call(1, Method::GET, &format!("/v1/principals/{target}"), None)
            .await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(err["code"], "forbidden");
    }
    // Plain admin (without global admin grant) gets uniform 403 forbidden for foreign and missing.
    for target in ["m-agent", "nonexistent-name"] {
        let (status, err) = fixture
            .call(2, Method::GET, &format!("/v1/principals/{target}"), None)
            .await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(err["code"], "forbidden");
    }

    fixture.stop().await
}

#[tokio::test]
async fn disable_closes_managed_nodes_demotion_emits_signal_delete_restrict_and_tags_cap()
-> TestResult {
    let fixture = Fixture::start(
        Config::default(),
        &[("operator", Admin, false), ("orch", Service, false)],
        |tx, subjects| {
            tx.execute(
                "UPDATE principals SET is_orchestrator = 1 WHERE principal_id = ?1",
                [subjects[1].id.to_string()],
            )?;
            Ok(())
        },
    )?;
    let orch = fixture.principals[1].id;

    // 1. allowed_node_tags cardinality cap: 65 rejected with 400, 64 accepted.
    let tags_65: Vec<String> = (0..65).map(|i| format!("tag-{i}")).collect();
    let (status, err) = fixture
        .call(
            0,
            Method::PUT,
            "/v1/principals/orch",
            Some(json!({"kind": "service", "is_orchestrator": true, "allowed_node_tags": tags_65})),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(err["code"], "invalid_input");
    let tags_64: Vec<String> = (0..64).map(|i| format!("tag-{i}")).collect();
    let (status, _) = fixture
        .call(
            0,
            Method::PUT,
            "/v1/principals/orch",
            Some(json!({"kind": "service", "is_orchestrator": true, "allowed_node_tags": tags_64})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);

    // 2. Demotion emits PrincipalPermissionsReduced; unchanged PUT emits nothing.
    let mut revocations = fixture.state.storage.subscribe_revocations()?;
    let (status, _) = fixture
        .call(
            0,
            Method::PUT,
            "/v1/principals/orch",
            Some(json!({"kind": "service", "is_orchestrator": false})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    let signal = revocations.try_recv()?;
    assert_eq!(
        signal.reason,
        RevocationReason::PrincipalPermissionsReduced(orch)
    );
    let (status, unchanged) = fixture
        .call(
            0,
            Method::PUT,
            "/v1/principals/orch",
            Some(json!({"kind": "service", "is_orchestrator": false})),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(unchanged["outcome"], "unchanged");
    assert!(revocations.try_recv().is_err());

    // 3. Disabling principal closes active managed nodes on the bridge with committed epoch.
    let node = NodeId::new();
    let issued_node = fixture.state.vault.issue_node(node)?;
    let verifier = issued_node.verifier.as_str().to_owned();
    fixture
        .state
        .storage
        .execute_work(0, move |tx| {
            tx.conn().execute(
                "INSERT INTO nodes (node_id, name, key_id, credential_hmac, managed_by_principal_id,
                                    session_epoch, created_at_ms, updated_at_ms)
                 VALUES (?1, 'managed', 1, ?2, ?3, 4, 1000, 1000)",
                params![node.to_string(), verifier, orch.to_string()],
            )?;
            Ok::<_, crate::storage::WriteTxError<std::convert::Infallible>>(())
        })
        .await?;
    fixture.bridge.sessions().insert(node, 4);
    let (status, _) = fixture
        .call(
            0,
            Method::POST,
            &format!("/v1/principals/{orch}/disable"),
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let closes = fixture.bridge.closes().clone();
    assert_eq!(closes.len(), 1);
    assert_eq!(closes[0].node_id, node);
    assert_eq!(closes[0].through_epoch, 4);
    assert_eq!(closes[0].reason, BridgeCloseReason::NodeRevoked);

    // 4. DELETE disabled managed agent blocked by accounts (ON DELETE RESTRICT) or
    //    executions (EXISTS pre-check) returns 409 resource_in_use, then succeeds
    //    with 204 once the blocking row is removed.
    let operator = fixture.principals[0].id;
    let blocked_acc = PrincipalId::new_agent();
    let blocked_exec = PrincipalId::new_agent();
    let tok_exec = TokenId::new_user_or_agent();
    let issued_tok = fixture.state.vault.issue_token(tok_exec)?;
    let tok_verifier = issued_tok.verifier.as_str().to_owned();
    fixture
        .state
        .storage
        .execute_work(0, move |tx| {
            for (pid, name) in [(blocked_acc, "acc-owner"), (blocked_exec, "exec-caller")] {
                tx.conn().execute(
                    "INSERT INTO principals (principal_id, name, kind, managed_by_principal_id,
                                             disabled_at_ms, created_at_ms, updated_at_ms)
                     VALUES (?1, ?2, 'agent', ?3, 1000, 1000, 1000)",
                    params![pid.to_string(), name, operator.to_string()],
                )?;
            }
            tx.conn().execute(
                "INSERT INTO accounts (account_id, slug, owner_principal_id, visibility, kind,
                                       sealed_secret_blob, created_at_ms, updated_at_ms)
                 VALUES ('acc_1', 'acc-1', ?1, 'private', 'secret_kv', X'01', 1000, 1000)",
                [blocked_acc.to_string()],
            )?;
            tx.conn().execute(
                "INSERT INTO auth_tokens (token_id, principal_id, created_by, label, key_id,
                                          verifier_hmac, created_at_ms)
                 VALUES (?1, ?2, ?3, 'x', 1, ?4, 1000)",
                params![
                    tok_exec.to_string(),
                    blocked_exec.to_string(),
                    operator.to_string(),
                    tok_verifier
                ],
            )?;
            tx.conn().execute(
                "INSERT INTO executions (execution_id, invoke_kind, request_id, request_digest,
                    caller_principal_id, caller_token_id, tool_id, tool_version, public_name,
                    executor_kind, node_id, state, deadline_at_ms, created_at_ms,
                    result_expires_at_ms, expires_at_ms)
                 VALUES ('exec_1', 'tool_test', 'req_1', 'd', ?1, ?2, 'tool_1', 1, 't',
                         'node', ?3, 'succeeded', 1000, 1000, 2000, 2000)",
                params![
                    blocked_exec.to_string(),
                    tok_exec.to_string(),
                    node.to_string()
                ],
            )?;
            Ok::<_, crate::storage::WriteTxError<std::convert::Infallible>>(())
        })
        .await?;
    for blocked in [blocked_acc, blocked_exec] {
        let (status, err) = fixture
            .call(
                0,
                Method::DELETE,
                &format!("/v1/principals/{blocked}"),
                None,
            )
            .await?;
        assert_eq!(status, StatusCode::CONFLICT, "{blocked}");
        assert_eq!(err["code"], "resource_in_use", "{blocked}");
    }
    fixture
        .state
        .storage
        .execute_work(0, |tx| {
            tx.conn()
                .execute("DELETE FROM accounts WHERE account_id = 'acc_1'", [])?;
            tx.conn()
                .execute("DELETE FROM executions WHERE execution_id = 'exec_1'", [])?;
            Ok::<_, crate::storage::WriteTxError<std::convert::Infallible>>(())
        })
        .await?;
    for unblocked in [blocked_acc, blocked_exec] {
        let (status, _) = fixture
            .call(
                0,
                Method::DELETE,
                &format!("/v1/principals/{unblocked}"),
                None,
            )
            .await?;
        assert_eq!(status, StatusCode::NO_CONTENT, "{unblocked}");
    }
    fixture.stop().await
}
