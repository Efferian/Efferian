use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use efferian_protocol::{
    HubId, NodeId, PrincipalId, PrincipalKind, ProfileId, TokenId, ToolId, error_codes,
};
use rusqlite::{Connection, OpenFlags, params};
use serde_json::{Value, json};
use tower_service::Service;

use crate::config::Config;
use crate::egress::EgressClient;
use crate::http::{self, AppState};
use crate::node_bridge::{BridgeCloseReason, NodeBridgeControl, NodeLiveStatus};
use crate::operations;
use crate::storage::{
    OpenMode, ShutdownReport, StorageClock, StorageError, StorageRuntime, WriteTxError,
};
use crate::vault::auth::{CredentialError, authenticate_node};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct ManualClock(AtomicI64);

impl StorageClock for ManualClock {
    fn wall_now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    fn monotonic_now(&self) -> Result<Duration, StorageError> {
        Ok(Duration::ZERO)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ClosedSession {
    node_id: NodeId,
    through_epoch: u64,
    reason: BridgeCloseReason,
    committed_epoch: Option<i64>,
    committed_revocation: Option<i64>,
}

struct RecordingBridge {
    database: PathBuf,
    sessions: Mutex<BTreeMap<NodeId, u64>>,
    closes: Mutex<Vec<ClosedSession>>,
}

impl RecordingBridge {
    fn sessions(&self) -> MutexGuard<'_, BTreeMap<NodeId, u64>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn closes(&self) -> MutexGuard<'_, Vec<ClosedSession>> {
        self.closes.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl NodeBridgeControl for RecordingBridge {
    fn live_status(&self, node_id: NodeId) -> NodeLiveStatus {
        if self.sessions().contains_key(&node_id) {
            NodeLiveStatus::Ready
        } else {
            NodeLiveStatus::Offline
        }
    }

    fn online_nodes_count(&self) -> usize {
        self.sessions().len()
    }

    fn close_session(&self, node_id: NodeId, through_epoch: u64, reason: BridgeCloseReason) {
        let observed: rusqlite::Result<(Option<i64>, Option<i64>)> =
            Connection::open_with_flags(&self.database, OpenFlags::SQLITE_OPEN_READ_ONLY).and_then(
                |conn| {
                    conn.query_row(
                        "SELECT session_epoch, revoked_at_ms FROM nodes WHERE node_id = ?1",
                        [node_id.to_string()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                },
            );
        let (committed_epoch, committed_revocation) = observed.unwrap_or_default();
        self.closes().push(ClosedSession {
            node_id,
            through_epoch,
            reason,
            committed_epoch,
            committed_revocation,
        });
        let mut sessions = self.sessions();
        if sessions
            .get(&node_id)
            .is_some_and(|epoch| *epoch <= through_epoch)
        {
            sessions.remove(&node_id);
        }
    }
}

struct TestDir(PathBuf);

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    router: Router,
    state: AppState,
    runtime: StorageRuntime,
    admin: String,
    bridge: Arc<RecordingBridge>,
    clock: Arc<ManualClock>,
    _dir: TestDir,
}

impl Fixture {
    fn new(config: Config) -> TestResult<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = TestDir(std::env::temp_dir().join(format!("efferian-nodes-{}", HubId::new())));
        let output = dir.0.join("admin.token");
        let storage_config = config.storage_config();
        operations::init(&dir.0, "admin", &output, &storage_config)?;
        let token = std::fs::read_to_string(output)?;
        let clock = Arc::new(ManualClock(AtomicI64::new(10_000)));
        let (opened, vault) = operations::open_existing(
            &dir.0,
            OpenMode::ServeAutoMigrate,
            &storage_config,
            clock.clone(),
        )?;
        let (storage, runtime) = opened.migrate_and_start_runtime()?;
        let bridge = Arc::new(RecordingBridge {
            database: dir.0.join("hub.sqlite3"),
            sessions: Mutex::default(),
            closes: Mutex::default(),
        });
        let state = AppState {
            storage,
            vault,
            clock: clock.clone(),
            egress: EgressClient::new(config.egress_policy()?)?,
            config: Arc::new(config),
            bridge: bridge.clone(),
        };
        let router = http::router(state.clone(), 8080)?;
        Ok(Self {
            router,
            state,
            runtime,
            admin: token.trim_end().to_owned(),
            bridge,
            clock,
            _dir: dir,
        })
    }

    async fn request(
        &self,
        method: Method,
        uri: &str,
        token: &str,
        json: Option<Value>,
    ) -> TestResult<(StatusCode, Value)> {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", "localhost:8080")
            .header("authorization", format!("Bearer {token}"));
        let body = if let Some(json) = json {
            req = req.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&json)?)
        } else {
            Body::empty()
        };
        let response = self.router.clone().call(req.body(body)?).await?;
        let status = response.status();
        let body = to_bytes(response.into_body(), 256 * 1024).await?;
        let data = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body)?
        };
        Ok((status, data))
    }

    async fn mint(&self, token: &str, name: &str) -> TestResult<String> {
        let (status, body) = self
            .request(
                Method::POST,
                "/v1/enrollment/tokens",
                token,
                Some(json!({"target_node_name": name, "tags": ["sandbox", "alpha", "sandbox"]})),
            )
            .await?;
        assert_eq!(status, StatusCode::CREATED);
        json_string(&body, "enrollment_token")
    }

    async fn rotate(&self, node_id: NodeId, ttl_ms: i64) -> TestResult<(String, i64)> {
        let (status, body) = self
            .request(
                Method::POST,
                &format!("/v1/nodes/{node_id}/reenroll-tokens"),
                &self.admin,
                Some(json!({"ttl_ms": ttl_ms})),
            )
            .await?;
        assert_eq!(status, StatusCode::CREATED);
        let expires = body["expires_at_ms"].as_i64().ok_or("missing expiration")?;
        Ok((json_string(&body, "enrollment_token")?, expires))
    }

    async fn exchange(&self, token: &str) -> TestResult<(StatusCode, Value)> {
        self.request(
            Method::POST,
            "/v1/enrollment/exchange",
            token,
            Some(json!({})),
        )
        .await
    }

    async fn read(&self, node: NodeId, token: &str) -> TestResult<(StatusCode, Value)> {
        self.request(Method::GET, &format!("/v1/nodes/{node}"), token, None)
            .await
    }

    async fn revoke(&self, node: NodeId, token: &str) -> TestResult<(StatusCode, Value)> {
        self.request(
            Method::POST,
            &format!("/v1/nodes/{node}/revoke"),
            token,
            None,
        )
        .await
    }

    async fn delete(&self, node: NodeId) -> TestResult<(StatusCode, Value)> {
        self.request(
            Method::DELETE,
            &format!("/v1/nodes/{node}"),
            &self.admin,
            None,
        )
        .await
    }

    async fn token_active(&self, token: &str) -> TestResult<bool> {
        let vault = Arc::clone(&self.state.vault);
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}"))?,
        );
        let bearer = crate::vault::auth::ParsedBearer::from_headers(&headers)?;
        self.state
            .storage
            .read_snapshot(move |conn| match authenticate_node(&vault, conn, bearer) {
                Ok(_) => Ok(true),
                Err(CredentialError::Unauthenticated) => Ok(false),
                Err(error) => Err(error),
            })
            .await
            .map_err(Into::into)
    }

    async fn write(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<()> + Send + 'static,
    ) -> TestResult {
        self.state
            .storage
            .execute_work(
                0,
                move |tx| -> Result<_, WriteTxError<std::convert::Infallible>> {
                    Ok(f(tx.conn())?)
                },
            )
            .await?;
        Ok(())
    }

    async fn orchestrator(&self) -> TestResult<(PrincipalId, String)> {
        let kind = PrincipalKind::Service;
        let principal = PrincipalId::new_for_kind(kind);
        let token_id = TokenId::new_for_kind(kind);
        let issued = self.state.vault.issue_token(token_id)?;
        let raw = issued.secret.expose_secret().to_owned();
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO principals
                    (principal_id, kind, name, is_orchestrator, allowed_node_tags_json, created_at_ms, updated_at_ms)
                 VALUES (?1, 'service', 'orchestrator', 1, '[\"alpha\",\"sandbox\"]', 1, 1)",
                [principal.to_string()],
            )?;
            conn.execute(
                "INSERT INTO auth_tokens (token_id, principal_id, created_by, label, key_id, verifier_hmac, created_at_ms)
                 VALUES (?1, ?2, ?2, 'orchestrator', ?3, ?4, 1)",
                params![token_id.to_string(), principal.to_string(), issued.key_id, issued.verifier],
            )?;
            Ok(())
        }).await?;
        Ok((principal, raw))
    }

    async fn shutdown(self) {
        let report = self.runtime.shutdown().await;
        assert!(matches!(report, ShutdownReport::Complete), "{report:?}");
    }
}

fn json_string(value: &Value, name: &str) -> TestResult<String> {
    Ok(value[name]
        .as_str()
        .ok_or_else(|| format!("missing response field {name}"))?
        .to_owned())
}

fn response_node(value: &Value) -> TestResult<NodeId> {
    Ok(json_string(value, "node_id")?.parse()?)
}

#[tokio::test]
async fn revoke_and_reenroll_preserve_identity_with_a_commit_fenced_session() -> TestResult {
    let hub = Fixture::new(Config::default())?;
    let first_ticket = hub.mint(&hub.admin, "release-node").await?;
    let (status, body) = hub
        .request(
            Method::POST,
            "/v1/enrollment/exchange",
            &first_ticket,
            Some(json!([])),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], error_codes::INVALID_INPUT);

    let (status, first) = hub.exchange(&first_ticket).await?;
    assert_eq!(status, StatusCode::OK);
    let node = response_node(&first)?;
    let old_token = json_string(&first, "node_token")?;
    assert!(hub.token_active(&old_token).await?);
    hub.bridge.sessions().insert(node, 0);

    let (before_revoke, _) = hub.rotate(node, 9).await?;
    assert_eq!(
        hub.revoke(node, &hub.admin).await?.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        hub.exchange(&before_revoke).await?.0,
        StatusCode::UNAUTHORIZED
    );
    assert!(!hub.token_active(&old_token).await?);
    let (status, summary) = hub.read(node, &hub.admin).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(summary["live_status"], "offline");
    let (between_revokes, _) = hub.rotate(node, 9).await?;
    assert_eq!(
        hub.revoke(node, &hub.admin).await?.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        hub.exchange(&between_revokes).await?.0,
        StatusCode::UNAUTHORIZED
    );

    let (ticket, expires) = hub.rotate(node, 1).await?;
    assert_eq!(expires, 10_001);
    let (status, second) = hub.exchange(&ticket).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response_node(&second)?, node);
    assert_eq!(
        hub.read(node, &hub.admin).await?.1["tags"],
        json!(["alpha", "sandbox"])
    );
    assert!(!hub.token_active(&old_token).await?);
    assert!(
        hub.token_active(&json_string(&second, "node_token")?)
            .await?
    );
    assert_eq!(hub.exchange(&ticket).await?.0, StatusCode::UNAUTHORIZED);
    let closes = hub.bridge.closes().clone();
    assert_eq!(
        closes,
        vec![
            ClosedSession {
                node_id: node,
                through_epoch: 0,
                reason: BridgeCloseReason::NodeRevoked,
                committed_epoch: Some(0),
                committed_revocation: Some(10_000)
            },
            ClosedSession {
                node_id: node,
                through_epoch: 0,
                reason: BridgeCloseReason::NodeRevoked,
                committed_epoch: Some(0),
                committed_revocation: Some(10_000)
            },
            ClosedSession {
                node_id: node,
                through_epoch: 0,
                reason: BridgeCloseReason::Superseded,
                committed_epoch: Some(1),
                committed_revocation: None
            },
        ],
    );
    hub.bridge.sessions().insert(node, 1);
    hub.bridge
        .close_session(node, 0, BridgeCloseReason::NodeRevoked);
    assert_eq!(hub.read(node, &hub.admin).await?.1["live_status"], "ready");

    assert_eq!(
        hub.revoke(node, &hub.admin).await?.0,
        StatusCode::NO_CONTENT
    );
    hub.clock.0.store(9000, Ordering::SeqCst);
    let (ticket, expires) = hub.rotate(node, 1).await?;
    assert_eq!(expires, 9001);
    hub.clock.0.store(9001, Ordering::SeqCst);
    assert_eq!(hub.exchange(&ticket).await?.0, StatusCode::UNAUTHORIZED);
    let (ticket, _) = hub.rotate(node, 1).await?;
    let (status, body) = hub.exchange(&ticket).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response_node(&body)?, node);

    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn simultaneous_exchanges_and_active_name_conflict_are_atomic() -> TestResult {
    let hub = Fixture::new(Config::default())?;
    let ticket = hub.mint(&hub.admin, "runner").await?;
    let alternate = hub.mint(&hub.admin, "runner").await?;
    let (first, second) = tokio::join!(hub.exchange(&ticket), hub.exchange(&ticket));
    let (first, second) = (first?, second?);
    let (accepted, rejected) = if first.0 == StatusCode::OK {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(accepted.0, StatusCode::OK);
    assert_eq!(rejected.0, StatusCode::UNAUTHORIZED);
    let node = response_node(&accepted.1)?;
    let (status, response) = hub.exchange(&alternate).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(response["code"], error_codes::NODE_NAME_IN_USE);
    assert_eq!(
        hub.revoke(node, &hub.admin).await?.0,
        StatusCode::NO_CONTENT
    );
    let (reenroll, _) = hub.rotate(node, 15_000).await?;
    let (status, response) = hub.exchange(&alternate).await?;
    assert_eq!(status, StatusCode::OK);
    let replacement = response_node(&response)?;
    assert_ne!(replacement, node);
    let (status, response) = hub.exchange(&reenroll).await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(response["code"], error_codes::NODE_NAME_IN_USE);
    let (status, response) = hub
        .request(
            Method::POST,
            &format!("/v1/nodes/{node}/reenroll-tokens"),
            &hub.admin,
            Some(json!({})),
        )
        .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(response["code"], error_codes::NODE_NAME_IN_USE);
    assert_eq!(
        hub.revoke(replacement, &hub.admin).await?.0,
        StatusCode::NO_CONTENT
    );
    let (status, response) = hub.exchange(&reenroll).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response_node(&response)?, node);
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn node_visibility_and_quota_apply_before_returning_metadata() -> TestResult {
    let mut config = Config::default();
    config.max_active_nodes_per_orchestrator = 1;
    config.max_pending_enrollments_per_issuer = 2;
    let hub = Fixture::new(config)?;
    let (orchestrator, credential) = hub.orchestrator().await?;
    let first = hub.mint(&credential, "orchestrated-one").await?;
    let second = hub.mint(&credential, "orchestrated-two").await?;
    let (status, problem) = hub
        .request(
            Method::POST,
            "/v1/enrollment/tokens",
            &credential,
            Some(json!({"target_node_name":"orchestrated-three"})),
        )
        .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["code"], error_codes::QUOTA_EXCEEDED);

    let (first, second) = tokio::join!(hub.exchange(&first), hub.exchange(&second));
    let (first, second) = (first?, second?);
    let (success, conflict) = if first.0 == StatusCode::OK {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(success.0, StatusCode::OK);
    assert_eq!(conflict.0, StatusCode::CONFLICT);
    assert_eq!(conflict.1["code"], error_codes::QUOTA_EXCEEDED);
    let own = response_node(&success.1)?;
    let foreign = hub.mint(&hub.admin, "admin-node").await?;
    let (status, response) = hub.exchange(&foreign).await?;
    assert_eq!(status, StatusCode::OK);
    let foreign = response_node(&response)?;

    let (status, page) = hub
        .request(Method::GET, "/v1/nodes?limit=1", &credential, None)
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["next_cursor"], Value::Null);
    assert_eq!(page["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(response_node(&page["items"][0])?, own);
    assert_eq!(
        page["items"][0]["managed_by_principal_id"],
        orchestrator.to_string()
    );
    assert_eq!(
        hub.read(foreign, &credential).await?.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        hub.read(NodeId::new(), &credential).await?.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        hub.read(NodeId::new(), &hub.admin).await?.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        hub.revoke(foreign, &credential).await?.0,
        StatusCode::FORBIDDEN
    );

    hub.write(move |conn| {
        conn.execute(
            "UPDATE principals SET allowed_node_tags_json = '[]' WHERE principal_id = ?1",
            [orchestrator.to_string()],
        )?;
        Ok(())
    })
    .await?;
    let (status, problem) = hub
        .request(
            Method::POST,
            "/v1/enrollment/tokens",
            &credential,
            Some(json!({"target_node_name":"unapproved","tags":["sandbox"]})),
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem["code"], error_codes::NODE_TAG_NOT_ALLOWED);
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn deleting_a_revoked_node_respects_reversible_catalog_references() -> TestResult {
    let hub = Fixture::new(Config::default())?;
    let ticket = hub.mint(&hub.admin, "fixed-node").await?;
    let (_, result) = hub.exchange(&ticket).await?;
    let node = response_node(&result)?;
    assert_eq!(hub.delete(node).await?.0, StatusCode::CONFLICT);
    assert_eq!(
        hub.revoke(node, &hub.admin).await?.0,
        StatusCode::NO_CONTENT
    );

    let tool = ToolId::new();
    let profile = ProfileId::new();
    let pinned_definition =
        command_definition(json!({"kind": "fixed", "node_ids": [node]})).to_string();
    let other_definition = command_definition(json!({"kind": "tag", "tag": "alpha"})).to_string();
    // Both aliases pin the same revision. The second has a binding-level node reference.
    let mut draft = binding(tool, 2, None);
    let mut alias = binding(tool, 2, Some(node))[0].clone();
    alias["public_name"] = json!("fixed-alias");
    draft
        .as_array_mut()
        .ok_or("expected binding array")?
        .push(alias);
    let direct_draft = draft.to_string();
    let pinned = binding(tool, 1, None).to_string();
    let direct_published = direct_draft.clone();

    hub.write(move |conn| {
        conn.execute(
            "INSERT INTO tools (tool_id, slug, kind, created_by, current_version, disabled_at_ms,
                                created_at_ms, updated_at_ms)
             SELECT ?1, 'fixed-tool', 'command', principal_id, 1, 1, 1, 1
             FROM principals WHERE name = 'admin'",
            [tool.to_string()],
        )?;
        conn.execute(
            "INSERT INTO tool_revisions (tool_id, version, input_schema_sha256, created_at_ms, definition_json)
             VALUES (?1, 1, 'test', 1, ?2), (?1, 2, 'test', 1, ?3)",
            params![tool.to_string(), pinned_definition, other_definition],
        )?;
        Ok(())
    }).await?;
    assert_resource_in_use(hub.delete(node).await?);

    hub.write(move |conn| {
        conn.execute("UPDATE tools SET current_version = 2 WHERE tool_id = ?1", [tool.to_string()])?;
        conn.execute(
            "INSERT INTO profiles (profile_id, slug, discovery_mode, disabled_at_ms, created_at_ms, updated_at_ms, draft_bindings_json)
             VALUES (?1, 'test-profile', 'full', 1, 1, 1, ?2)",
            params![profile.to_string(), direct_draft],
        )?;
        Ok(())
    }).await?;
    assert_resource_in_use(hub.delete(node).await?);

    let pinned_draft = pinned.clone();
    hub.write(move |conn| {
        conn.execute(
            "UPDATE profiles SET draft_bindings_json = ?1 WHERE profile_id = ?2",
            params![pinned_draft, profile.to_string()],
        )?;
        Ok(())
    })
    .await?;
    assert_resource_in_use(hub.delete(node).await?);

    hub.write(move |conn| {
        conn.execute(
            "UPDATE profiles SET draft_bindings_json = '[]', published_version = 1 WHERE profile_id = ?1",
            [profile.to_string()],
        )?;
        conn.execute(
            "INSERT INTO profile_editions (profile_id, version, discovery_mode, published_by, published_at_ms, bindings_json)
             SELECT ?1, 1, 'full', principal_id, 1, ?2 FROM principals WHERE name = 'admin'
             UNION ALL
             SELECT ?1, 2, 'full', principal_id, 1, ?3 FROM principals WHERE name = 'admin'
             UNION ALL
             SELECT ?1, 3, 'full', principal_id, 1, '[]' FROM principals WHERE name = 'admin'",
            params![profile.to_string(), pinned, direct_published],
        )?;
        Ok(())
    }).await?;
    assert_resource_in_use(hub.delete(node).await?);

    hub.write(move |conn| {
        conn.execute(
            "UPDATE profiles SET published_version = 2 WHERE profile_id = ?1",
            [profile.to_string()],
        )?;
        Ok(())
    })
    .await?;
    assert_resource_in_use(hub.delete(node).await?);

    hub.write(move |conn| {
        conn.execute(
            "UPDATE profiles SET published_version = 3 WHERE profile_id = ?1",
            [profile.to_string()],
        )?;
        conn.execute(
            "UPDATE tool_revisions SET definition_json = '{' WHERE tool_id = ?1 AND version = 2",
            [tool.to_string()],
        )?;
        Ok(())
    })
    .await?;
    assert_eq!(hub.delete(node).await?.0, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(hub.read(node, &hub.admin).await?.0, StatusCode::OK);

    let other_definition = command_definition(json!({"kind": "tag", "tag": "alpha"})).to_string();
    hub.write(move |conn| {
        conn.execute(
            "UPDATE tool_revisions SET definition_json = ?1 WHERE tool_id = ?2 AND version = 2",
            params![other_definition, tool.to_string()],
        )?;
        Ok(())
    })
    .await?;
    assert_eq!(hub.delete(node).await?.0, StatusCode::NO_CONTENT);
    assert_eq!(hub.read(node, &hub.admin).await?.0, StatusCode::NOT_FOUND);
    hub.shutdown().await;
    Ok(())
}

fn command_definition(target_selector: Value) -> Value {
    json!({
        "spec": {
            "kind": "command",
            "program": "/bin/true",
            "args": [],
            "cwd": "/tmp",
            "env": {},
            "runtime_ms": 1_000,
            "max_output_bytes": 1_024,
            "target_selector": target_selector,
        }
    })
}

fn binding(tool_id: ToolId, tool_version: u64, fixed_node_id: Option<NodeId>) -> Value {
    json!([{
        "tool_id": tool_id,
        "tool_version": tool_version,
        "public_name": "fixed",
        "fixed_node_id": fixed_node_id,
    }])
}

fn assert_resource_in_use((status, problem): (StatusCode, Value)) {
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["code"], error_codes::RESOURCE_IN_USE);
}
