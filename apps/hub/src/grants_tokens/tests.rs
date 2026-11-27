use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use efferian_protocol::HubId;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower_service::Service;

use super::*;
use crate::config::Config;
use crate::egress::EgressClient;
use crate::http::router;
use crate::node_bridge::OfflineNodeBridge;
use crate::operations;
use crate::storage::{OpenMode, ShutdownReport, StorageClock, StorageRuntime, SystemStorageClock};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct TestDirectory(PathBuf);

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    app: AppState,
    http: Router,
    runtime: StorageRuntime,
    admin: PrincipalId,
    admin_token: String,
    _dir: TestDirectory,
}

impl Fixture {
    async fn start(max_active_tokens: usize) -> TestResult<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = TestDirectory(std::env::temp_dir().join(format!("hub-access-{}", HubId::new())));
        let state_dir = dir.0.join("state");
        fs::create_dir(&dir.0)?;
        let output = dir.0.join("initial-token");
        let mut config = Config::default();
        config.max_active_tokens_per_principal = max_active_tokens;
        let storage_config = config.storage_config();
        operations::init(&state_dir, "admin", &output, &storage_config)?;
        let admin_token = fs::read_to_string(output)?.trim_end().to_owned();
        let clock: Arc<dyn StorageClock> = Arc::new(SystemStorageClock::new()?);
        let (opened, vault) = operations::open_existing(
            &state_dir,
            OpenMode::ServeAutoMigrate,
            &storage_config,
            Arc::clone(&clock),
        )?;
        let (storage, runtime) = opened.migrate_and_start_runtime()?;
        let admin = storage
            .read_snapshot(|conn| {
                conn.query_row(
                    "SELECT principal_id FROM principals WHERE name = 'admin'",
                    [],
                    |row| id(row, 0),
                )
                .map_err(crate::storage::StorageError::from)
            })
            .await?;
        let app = AppState {
            storage,
            vault,
            clock,
            egress: EgressClient::new(config.egress_policy()?)?,
            config: Arc::new(config),
            bridge: Arc::new(OfflineNodeBridge),
        };
        let http = router(app.clone(), 8080)?;
        Ok(Self {
            app,
            http,
            runtime,
            admin,
            admin_token,
            _dir: dir,
        })
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        token: &str,
        json: Option<Value>,
    ) -> TestResult<(StatusCode, Value)> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost:8080")
            .header("authorization", format!("Bearer {token}"));
        let body = if let Some(json) = json {
            request = request.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&json)?)
        } else {
            Body::empty()
        };
        let response = self.http.clone().call(request.body(body)?).await?;
        let status = response.status();
        let data = response.into_body().collect().await?.to_bytes();
        let json = if data.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&data)?
        };
        Ok((status, json))
    }

    async fn request_admin(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> TestResult<(StatusCode, Value)> {
        self.request(method, path, &self.admin_token, body).await
    }

    async fn seed_principal(
        &self,
        name: &'static str,
        kind: PrincipalKind,
        owner: Option<PrincipalId>,
        manager: Option<PrincipalId>,
        is_orchestrator: bool,
    ) -> TestResult<SeededPrincipal> {
        use std::convert::Infallible;
        let principal_id = PrincipalId::new_for_kind(kind);
        let token_id = TokenId::new_for_kind(kind);
        let IssuedCredential {
            key_id,
            verifier,
            secret,
        } = self.app.vault.issue_token(token_id)?;
        let admin = self.admin;
        self.app.storage.execute_work::<_, Infallible, _>(name.len(), move |tx| {
            tx.conn().execute(
                "INSERT INTO principals (principal_id, kind, name, owner_principal_id, managed_by_principal_id,
                 is_orchestrator, created_at_ms, updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
                params![principal_id.to_string(), scalar_text(kind)?, name,
                    owner.map(|id| id.to_string()), manager.map(|id| id.to_string()), is_orchestrator, tx.now_ms()],
            )?;
            tx.conn().execute(
                "INSERT INTO auth_tokens (token_id, principal_id, created_by, label, key_id, verifier_hmac, created_at_ms)
                 VALUES (?1, ?2, ?3, 'fixture', ?4, ?5, ?6)",
                params![token_id.to_string(), principal_id.to_string(), admin.to_string(), key_id, verifier, tx.now_ms()],
            )?;
            Ok(())
        }).await?;
        Ok(SeededPrincipal {
            principal_id,
            token_id,
            secret,
        })
    }

    async fn finish(self) {
        assert!(matches!(
            self.runtime.shutdown().await,
            ShutdownReport::Complete
        ));
    }
}

struct SeededPrincipal {
    principal_id: PrincipalId,
    token_id: TokenId,
    secret: SecretString,
}

fn field<'a>(value: &'a Value, name: &str) -> TestResult<&'a str> {
    value[name]
        .as_str()
        .ok_or_else(|| format!("response lacks string field {name}").into())
}

#[tokio::test]
async fn quota_and_idempotent_token_revocation_through_router() -> TestResult {
    let fixture = Fixture::start(2).await?;
    let mint = || {
        fixture.request_admin(
            Method::POST,
            "/v1/tokens",
            Some(json!({
                "principal_id": fixture.admin, "label": "cli"
            })),
        )
    };
    let (first, second) = tokio::join!(mint(), mint());
    let mut results = [first?, second?];
    results.sort_by_key(|(status, _)| *status);
    let [(status, created), (rejection, reason)] = results;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(rejection, StatusCode::CONFLICT);
    assert_eq!(reason["code"], error_codes::QUOTA_EXCEEDED);
    let token_id = field(&created, "token_id")?;
    let bearer = field(&created, "token")?;

    let (status, page) = fixture
        .request(Method::GET, "/v1/tokens", bearer, None)
        .await?;
    assert_eq!(status, StatusCode::OK);
    let items = page["items"].as_array().ok_or("expected a token page")?;
    assert_eq!(items.len(), 2);
    assert!(
        items
            .iter()
            .all(|item| item.get("token").is_none() && item.get("verifier_hmac").is_none())
    );

    let head = || {
        fixture.app.storage.read_snapshot(|conn| {
            conn.query_row(
                "SELECT events_head_seq FROM hub_meta WHERE id = 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(crate::storage::StorageError::from)
        })
    };
    let before = head().await?;
    let revoke_path = format!("/v1/tokens/{token_id}/revoke");
    for _ in 0..2 {
        assert_eq!(
            fixture
                .request_admin(Method::POST, &revoke_path, None)
                .await?
                .0,
            StatusCode::NO_CONTENT,
        );
    }
    assert_eq!(head().await?, before + 1);
    assert_eq!(
        fixture
            .request(Method::GET, "/v1/tokens", bearer, None)
            .await?
            .0,
        StatusCode::UNAUTHORIZED,
    );
    let (status, reason) = fixture
        .request_admin(
            Method::POST,
            "/v1/tokens",
            Some(json!({
                "principal_id": fixture.admin, "label": "bad\nlabel",
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(reason["code"], error_codes::INVALID_INPUT);
    fixture.finish().await;
    Ok(())
}

#[tokio::test]
async fn token_pages_filter_before_binary_cursor_and_treat_purging_as_missing() -> TestResult {
    use std::convert::Infallible;

    let fixture = Fixture::start(64).await?;
    let service = fixture
        .seed_principal("svc", PrincipalKind::Service, None, None, false)
        .await?;
    let member = fixture
        .seed_principal("member", PrincipalKind::Member, None, None, false)
        .await?;
    let agent = fixture
        .seed_principal(
            "owned",
            PrincipalKind::Agent,
            Some(member.principal_id),
            Some(member.principal_id),
            false,
        )
        .await?;
    let purging = fixture
        .seed_principal(
            "retired",
            PrincipalKind::Agent,
            Some(member.principal_id),
            Some(member.principal_id),
            false,
        )
        .await?;
    let purging_id = purging.principal_id;
    fixture
        .app
        .storage
        .execute_work::<_, Infallible, _>(0, move |tx| {
            tx.conn().execute(
                "UPDATE principals SET name = ?1, disabled_at_ms = ?2 WHERE principal_id = ?3",
                params![
                    format!("~purging:{purging_id}"),
                    tx.now_ms(),
                    purging_id.to_string()
                ],
            )?;
            tx.conn().execute(
                "UPDATE hub_meta SET gc_purging_principal_id = ?1 WHERE id = 1",
                [purging_id.to_string()],
            )?;
            Ok(())
        })
        .await?;

    let mut ids = Vec::new();
    let mut path = "/v1/tokens?limit=1".to_owned();
    for index in 0..4 {
        let (status, page) = fixture.request_admin(Method::GET, &path, None).await?;
        assert_eq!(status, StatusCode::OK);
        ids.push(field(&page["items"][0], "token_id")?.to_owned());
        if index < 3 {
            let cursor = field(&page, "next_cursor")?;
            path = format!("/v1/tokens?limit=1&cursor={cursor}");
        } else {
            assert!(page["next_cursor"].is_null());
        }
    }
    assert_eq!(ids[0], service.token_id.to_string());
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));

    let (status, page) = fixture
        .request(
            Method::GET,
            "/v1/tokens?limit=1",
            member.secret.expose_secret(),
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    let mut expected = [agent.token_id.to_string(), member.token_id.to_string()];
    expected.sort();
    assert_eq!(page["items"][0]["token_id"], expected[0]);
    assert_eq!(page["next_cursor"], expected[0]);
    for hidden in [purging_id, service.principal_id, PrincipalId::new_service()] {
        let (status, problem) = fixture
            .request(
                Method::GET,
                &format!("/v1/tokens?principal_id={hidden}"),
                member.secret.expose_secret(),
                None,
            )
            .await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(problem["code"], error_codes::FORBIDDEN);
    }
    assert_eq!(
        fixture
            .request_admin(
                Method::GET,
                &format!("/v1/tokens?principal_id={purging_id}"),
                None
            )
            .await?
            .0,
        StatusCode::NOT_FOUND,
    );
    fixture.finish().await;
    Ok(())
}

#[tokio::test]
async fn grant_upsert_orders_authorization_and_preserves_identity() -> TestResult {
    use std::convert::Infallible;

    let fixture = Fixture::start(64).await?;
    let member = fixture
        .seed_principal("member", PrincipalKind::Member, None, None, false)
        .await?;
    let agent = fixture
        .seed_principal(
            "agent",
            PrincipalKind::Agent,
            Some(member.principal_id),
            Some(member.principal_id),
            false,
        )
        .await?;
    let profile = ProfileId::new();
    fixture.app.storage.execute_work::<_, Infallible, _>(0, move |tx| {
        tx.conn().execute(
            "INSERT INTO profiles (profile_id, slug, discovery_mode, disabled_at_ms, created_at_ms, updated_at_ms)
             VALUES (?1, 'draft', 'full', ?2, ?2, ?2)",
            params![profile.to_string(), tx.now_ms()],
        )?;
        Ok(())
    }).await?;

    for target in [
        member.principal_id,
        agent.principal_id,
        PrincipalId::new_user(),
    ] {
        let (status, problem) = fixture.request(Method::PUT, "/v1/grants", member.secret.expose_secret(), Some(json!({
            "principal_id": target, "scope": GrantScope::Global, "capability": Capability::Admin
        }))).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(problem["code"], error_codes::ADMIN_HUMAN_REQUIRED);
    }
    for target_profile in [profile, ProfileId::new()] {
        let (status, problem) = fixture.request(Method::PUT, "/v1/grants", member.secret.expose_secret(), Some(json!({
            "principal_id": agent.principal_id, "scope": GrantScope::Profile(target_profile),
            "capability": Capability::Invoke,
        }))).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(problem["code"], error_codes::FORBIDDEN);
    }

    let scope = GrantScope::Profile(profile);
    let (status, parent) = fixture.request_admin(Method::PUT, "/v1/grants", Some(json!({
        "principal_id": member.principal_id, "scope": scope, "capability": Capability::Invoke
    }))).await?;
    assert_eq!(status, StatusCode::CREATED);
    let delegated = json!({ "principal_id": agent.principal_id, "scope": scope, "capability": Capability::Invoke });
    let (status, created) = fixture
        .request(
            Method::PUT,
            "/v1/grants",
            member.secret.expose_secret(),
            Some(delegated.clone()),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["outcome"], "created");
    let (status, unchanged) = fixture
        .request(
            Method::PUT,
            "/v1/grants",
            member.secret.expose_secret(),
            Some(delegated),
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(unchanged["outcome"], "unchanged");
    assert_eq!(unchanged["grant"], created["grant"]);

    let path = format!("/v1/grants/{}", field(&parent["grant"], "grant_id")?);
    assert_eq!(
        fixture.request_admin(Method::DELETE, &path, None).await?.0,
        StatusCode::NO_CONTENT
    );
    let path = format!("/v1/grants/{}", field(&created["grant"], "grant_id")?);
    assert_eq!(
        fixture
            .request(Method::DELETE, &path, member.secret.expose_secret(), None)
            .await?
            .0,
        StatusCode::NO_CONTENT,
    );
    fixture.finish().await;
    Ok(())
}

#[tokio::test]
async fn concurrent_grant_deletes_preserve_a_global_admin() -> TestResult {
    let fixture = Fixture::start(64).await?;
    let second = fixture
        .seed_principal("second-admin", PrincipalKind::Admin, None, None, false)
        .await?;
    let (status, grant) = fixture.request_admin(Method::PUT, "/v1/grants", Some(json!({
        "principal_id": second.principal_id, "scope": GrantScope::Global, "capability": Capability::Admin,
    }))).await?;
    assert_eq!(status, StatusCode::CREATED);
    let second_grant = format!("/v1/grants/{}", field(&grant["grant"], "grant_id")?);
    let path = format!("/v1/grants?principal_id={}", fixture.admin);
    let (_, first_page) = fixture.request_admin(Method::GET, &path, None).await?;
    let first_grant = format!("/v1/grants/{}", field(&first_page["items"][0], "grant_id")?);
    let (first, second) = tokio::join!(
        fixture.request_admin(Method::DELETE, &first_grant, None),
        fixture.request(
            Method::DELETE,
            &second_grant,
            second.secret.expose_secret(),
            None
        ),
    );
    let mut results = [first?, second?];
    results.sort_by_key(|(status, _)| *status);
    assert_eq!(results[0].0, StatusCode::NO_CONTENT);
    assert_eq!(results[1].0, StatusCode::CONFLICT);
    assert_eq!(results[1].1["code"], error_codes::LAST_ADMIN);
    fixture.finish().await;
    Ok(())
}

#[tokio::test]
async fn orchestrator_can_only_attenuate_into_active_managed_nodes() -> TestResult {
    use std::convert::Infallible;

    let fixture = Fixture::start(64).await?;
    let orchestrator = fixture
        .seed_principal("manager", PrincipalKind::Service, None, None, true)
        .await?;
    let agent = fixture
        .seed_principal(
            "worker",
            PrincipalKind::Agent,
            None,
            Some(orchestrator.principal_id),
            false,
        )
        .await?;
    let unknown_agent = PrincipalId::new_agent();
    let node = NodeId::new();
    let manager_id = orchestrator.principal_id;
    let IssuedCredential {
        key_id, verifier, ..
    } = fixture.app.vault.issue_node(node)?;
    fixture
        .app
        .storage
        .execute_work::<_, Infallible, _>(0, move |tx| {
            tx.conn().execute(
                "INSERT INTO nodes (node_id, name, key_id, credential_hmac,
                                managed_by_principal_id, created_at_ms, updated_at_ms)
             VALUES (?1, 'managed', ?2, ?3, ?4, ?5, ?5)",
                params![
                    node.to_string(),
                    key_id,
                    verifier,
                    manager_id.to_string(),
                    tx.now_ms()
                ],
            )?;
            Ok(())
        })
        .await?;

    let mint_body = |target| {
        json!({
            "principal_id": target,
            "label": "delegated",
            "max_capability": "invoke",
            "allowed_nodes": [node],
            "expires_at_ms": fixture.app.clock.wall_now_ms() + 60_000,
        })
    };
    let mint = |target| {
        fixture.request(
            Method::POST,
            "/v1/tokens",
            orchestrator.secret.expose_secret(),
            Some(mint_body(target)),
        )
    };
    assert_eq!(mint(agent.principal_id).await?.0, StatusCode::CREATED);
    fixture
        .app
        .storage
        .execute_work::<_, Infallible, _>(0, move |tx| {
            tx.conn().execute(
                "UPDATE nodes SET revoked_at_ms = ?1 WHERE node_id = ?2",
                params![tx.now_ms(), node.to_string()],
            )?;
            Ok(())
        })
        .await?;
    let (status, problem) = mint(agent.principal_id).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem["code"], error_codes::TOKEN_AMPLIFICATION);
    let (status, problem) = mint(unknown_agent).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem["code"], error_codes::FORBIDDEN);

    let disabled_agent = agent.principal_id;
    fixture
        .app
        .storage
        .execute_work::<_, Infallible, _>(0, move |tx| {
            tx.conn().execute(
                "UPDATE principals SET disabled_at_ms = ?1 WHERE principal_id = ?2",
                params![tx.now_ms(), disabled_agent.to_string()],
            )?;
            Ok(())
        })
        .await?;
    let mut request = mint_body(agent.principal_id);
    request["allowed_nodes"] = json!([]);
    let (status, problem) = fixture
        .request(
            Method::POST,
            "/v1/tokens",
            orchestrator.secret.expose_secret(),
            Some(request),
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem["code"], error_codes::PRINCIPAL_DISABLED);
    fixture.finish().await;
    Ok(())
}

#[tokio::test]
async fn a_token_revoked_while_the_request_body_is_pending_cannot_mint() -> TestResult {
    use std::convert::Infallible;
    use std::time::Duration;

    use bytes::Bytes;
    use futures_util::stream;
    use tokio::sync::Notify;

    let fixture = Fixture::start(8).await?;
    let (status, issued) = fixture
        .request_admin(
            Method::POST,
            "/v1/tokens",
            Some(json!({"principal_id": fixture.admin, "label": "pending-caller"})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED);
    let token_id = field(&issued, "token_id")?;
    let bearer = field(&issued, "token")?;
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let payload = Bytes::from(serde_json::to_vec(&json!({
        "principal_id": fixture.admin,
        "label": "after-revoke",
    }))?);
    let body = Body::from_stream(stream::once({
        let started = Arc::clone(&started);
        let release = Arc::clone(&release);
        async move {
            started.notify_one();
            release.notified().await;
            Ok::<_, Infallible>(payload)
        }
    }));
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/tokens")
        .header("host", "localhost:8080")
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .body(body)?;
    let mut router = fixture.http.clone();
    let pending = tokio::spawn(async move { router.call(request).await });

    tokio::time::timeout(Duration::from_secs(5), started.notified()).await?;
    let (status, _) = fixture
        .request_admin(Method::POST, &format!("/v1/tokens/{token_id}/revoke"), None)
        .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    release.notify_one();
    let response = tokio::time::timeout(Duration::from_secs(5), pending).await???;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let (_, tokens) = fixture
        .request_admin(Method::GET, "/v1/tokens", None)
        .await?;
    assert_eq!(tokens["items"].as_array().map(Vec::len), Some(2));
    fixture.finish().await;
    Ok(())
}
