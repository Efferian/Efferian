use std::sync::Arc;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use serde_json::{Value, json};
use tower_service::Service;

use super::*;
use crate::config::Config;
use crate::test_support::{TestHub, TestResult};

struct Fixture {
    hub: TestHub,
}

impl Fixture {
    async fn start(max_active_tokens: usize) -> TestResult<Self> {
        let mut config = Config::default();
        config.max_active_tokens_per_principal = max_active_tokens;
        let hub = TestHub::start("access", config, 10_000).await?;
        Ok(Self { hub })
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        token: &str,
        json: Option<Value>,
    ) -> TestResult<(StatusCode, Value)> {
        self.hub.request(method, path, token, json).await
    }

    async fn request_admin(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> TestResult<(StatusCode, Value)> {
        self.hub.request_admin(method, path, body).await
    }

    async fn seed_principal(
        &self,
        name: &'static str,
        kind: PrincipalKind,
        owner: Option<PrincipalId>,
        manager: Option<PrincipalId>,
        is_orchestrator: bool,
    ) -> TestResult<SeededPrincipal> {
        self.seed_principal_with(name, kind, owner, manager, is_orchestrator, false)
            .await
    }

    async fn seed_principal_with(
        &self,
        name: &'static str,
        kind: PrincipalKind,
        owner: Option<PrincipalId>,
        manager: Option<PrincipalId>,
        is_orchestrator: bool,
        narrowed: bool,
    ) -> TestResult<SeededPrincipal> {
        use std::convert::Infallible;
        let principal_id = PrincipalId::new_for_kind(kind);
        let token_id = TokenId::new_for_kind(kind);
        let IssuedCredential {
            key_id,
            verifier,
            secret,
        } = self.hub.state.vault.issue_token(token_id)?;
        let verifier = verifier.as_str().to_owned();
        let admin = self.hub.admin_id;
        self.hub.state.storage.execute_work::<_, Infallible, _>(name.len(), move |tx| {
            tx.conn().execute(
                "INSERT INTO principals (principal_id, kind, name, owner_principal_id, managed_by_principal_id,
                 is_orchestrator, created_at_ms, updated_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
                params![principal_id.to_string(), scalar_text(kind)?, name,
                    owner.map(|id| id.to_string()), manager.map(|id| id.to_string()), is_orchestrator, tx.now_ms()],
            )?;
            tx.conn().execute(
                "INSERT INTO auth_tokens (token_id, principal_id, created_by, label, key_id,
                 verifier_hmac, withhold_sensitive, created_at_ms)
                 VALUES (?1, ?2, ?3, 'fixture', ?4, ?5, ?6, ?7)",
                params![token_id.to_string(), principal_id.to_string(), admin.to_string(), key_id, verifier, narrowed, tx.now_ms()],
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
        self.hub.shutdown().await;
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
                "principal_id": fixture.hub.admin_id, "label": "cli"
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
        fixture.hub.state.storage.read_snapshot(|conn| {
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
                "principal_id": fixture.hub.admin_id, "label": "bad\nlabel",
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
        .hub
        .state
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
    let (status, page) = fixture
        .request(
            Method::GET,
            &format!("/v1/tokens?principal_id={}", agent.principal_id),
            member.secret.expose_secret(),
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["items"].as_array().ok_or("expected items")?.len(), 1);
    assert_eq!(page["items"][0]["token_id"], agent.token_id.to_string());
    assert!(page["next_cursor"].is_null());
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
    fixture.hub.state.storage.execute_work::<_, Infallible, _>(0, move |tx| {
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
    let path = format!("/v1/grants?principal_id={}", fixture.hub.admin_id);
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
    } = fixture.hub.state.vault.issue_node(node)?;
    let verifier = verifier.as_str().to_owned();
    fixture
        .hub
        .state
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
            "expires_at_ms": fixture.hub.state.clock.wall_now_ms() + 60_000,
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
        .hub
        .state
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
        .hub
        .state
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
            Some(json!({"principal_id": fixture.hub.admin_id, "label": "pending-caller"})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED);
    let token_id = field(&issued, "token_id")?;
    let bearer = field(&issued, "token")?;
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let payload = Bytes::from(serde_json::to_vec(&json!({
        "principal_id": fixture.hub.admin_id,
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
    let mut router = fixture.hub.router.clone();
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

#[tokio::test]
async fn narrowed_anti_oracle_grants_pagination_labels_and_scope_caps() -> TestResult {
    let fixture = Fixture::start(64).await?;
    let narrow_admin = fixture
        .seed_principal_with(
            "narrow-admin",
            PrincipalKind::Admin,
            None,
            None,
            false,
            true,
        )
        .await?;
    let plain_admin = fixture
        .seed_principal_with(
            "plain-admin",
            PrincipalKind::Admin,
            None,
            None,
            false,
            false,
        )
        .await?;
    let narrow_member = fixture
        .seed_principal_with(
            "narrow-member",
            PrincipalKind::Member,
            None,
            None,
            false,
            true,
        )
        .await?;
    let narrow_orch = fixture
        .seed_principal_with(
            "narrow-orch",
            PrincipalKind::Service,
            None,
            None,
            true,
            true,
        )
        .await?;
    let owned_agent = fixture
        .seed_principal(
            "owned-agent",
            PrincipalKind::Agent,
            Some(narrow_member.principal_id),
            Some(narrow_orch.principal_id),
            false,
        )
        .await?;
    let profile = ProfileId::new();
    let admin_id = fixture.hub.admin_id;
    let na_id = narrow_admin.principal_id;
    fixture
        .hub
        .write(move |conn| {
            conn.execute(
                "INSERT INTO grants (grant_id, principal_id, scope_kind, capability, created_by, created_at_ms)
                 VALUES (?1, ?2, 'global', 'admin', ?3, 1000)",
                params![GrantId::new().to_string(), na_id.to_string(), admin_id.to_string()],
            )?;
            conn.execute(
                "INSERT INTO profiles (profile_id, slug, discovery_mode, created_at_ms, updated_at_ms)
                 VALUES (?1, 'p', 'full', 1000, 1000)",
                [profile.to_string()],
            )?;
            Ok(())
        })
        .await?;
    let (_, agent_grant) = fixture
        .request_admin(
            Method::PUT,
            "/v1/grants",
            Some(json!({
                "principal_id": owned_agent.principal_id,
                "scope": GrantScope::Profile(profile),
                "capability": Capability::Discover,
            })),
        )
        .await?;
    let owned_grant_id: GrantId = serde_json::from_value(agent_grant["grant"]["grant_id"].clone())?;

    // 1. Narrowed admin, member, and orchestrator get uniform token_narrowed on mutations.
    for (caller_secret, target_token, target_grant) in [
        (
            narrow_admin.secret.expose_secret(),
            owned_agent.token_id,
            owned_grant_id,
        ),
        (
            narrow_member.secret.expose_secret(),
            owned_agent.token_id,
            owned_grant_id,
        ),
        (
            narrow_orch.secret.expose_secret(),
            owned_agent.token_id,
            owned_grant_id,
        ),
    ] {
        for tok in [target_token, TokenId::new_user_or_agent()] {
            let (status, err) = fixture
                .request(
                    Method::POST,
                    &format!("/v1/tokens/{tok}/revoke"),
                    caller_secret,
                    None,
                )
                .await?;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(err["code"], error_codes::TOKEN_NARROWED);
        }
        for grant in [target_grant, GrantId::new()] {
            let (status, err) = fixture
                .request(
                    Method::DELETE,
                    &format!("/v1/grants/{grant}"),
                    caller_secret,
                    None,
                )
                .await?;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(err["code"], error_codes::TOKEN_NARROWED);
        }
        for target_principal in [owned_agent.principal_id, PrincipalId::new_agent()] {
            let (status, err) = fixture
                .request(
                    Method::PUT,
                    "/v1/grants",
                    caller_secret,
                    Some(json!({
                        "principal_id": target_principal,
                        "scope": GrantScope::Profile(profile),
                        "capability": Capability::Discover,
                    })),
                )
                .await?;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(err["code"], error_codes::TOKEN_NARROWED);
        }
    }
    // Plain admin (no global grant) gets uniform forbidden on foreign/missing revocations.
    for tok in [owned_agent.token_id, TokenId::new_user_or_agent()] {
        let (status, err) = fixture
            .request(
                Method::POST,
                &format!("/v1/tokens/{tok}/revoke"),
                plain_admin.secret.expose_secret(),
                None,
            )
            .await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(err["code"], error_codes::FORBIDDEN);
    }

    // 2. Invalid grant combinations & GET /v1/grants pagination/visibility.
    let (status, err) = fixture
        .request_admin(
            Method::PUT,
            "/v1/grants",
            Some(json!({
                "principal_id": owned_agent.principal_id,
                "scope": GrantScope::Profile(profile),
                "capability": Capability::Admin,
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(err["code"], error_codes::INVALID_INPUT);

    let (status, err) = fixture
        .request(
            Method::PUT,
            "/v1/grants",
            narrow_member.secret.expose_secret(),
            Some(json!({
                "principal_id": owned_agent.principal_id,
                "scope": GrantScope::Global,
                "capability": Capability::Invoke,
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err["code"], error_codes::FORBIDDEN);

    let (status, page1) = fixture
        .request_admin(Method::GET, "/v1/grants?limit=1", None)
        .await?;
    assert_eq!(status, StatusCode::OK);
    let cursor = field(&page1, "next_cursor")?;
    let (status, page2) = fixture
        .request_admin(
            Method::GET,
            &format!("/v1/grants?limit=1&cursor={cursor}"),
            None,
        )
        .await?;
    assert_eq!(status, StatusCode::OK);
    assert!(field(&page1["items"][0], "grant_id")? < field(&page2["items"][0], "grant_id")?);

    // 3. Label trimming and cardinality caps (256 profiles/nodes).
    let (status, err) = fixture
        .request_admin(
            Method::POST,
            "/v1/tokens",
            Some(json!({"principal_id": fixture.hub.admin_id, "label": "   "})),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(err["code"], error_codes::INVALID_INPUT);
    let exact_128 = "x".repeat(128);
    let (status, minted) = fixture
        .request_admin(
            Method::POST,
            "/v1/tokens",
            Some(
                json!({"principal_id": fixture.hub.admin_id, "label": format!("  {exact_128}  ")}),
            ),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED);
    let minted_id = field(&minted, "token_id")?;
    let (_, listed) = fixture
        .request_admin(
            Method::GET,
            &format!("/v1/tokens?principal_id={}", fixture.hub.admin_id),
            None,
        )
        .await?;
    let stored = listed["items"]
        .as_array()
        .ok_or("expected items")?
        .iter()
        .find(|item| item["token_id"] == minted_id)
        .ok_or("missing minted token in listing")?;
    assert_eq!(stored["label"], exact_128);
    let (status, err) = fixture
        .request_admin(
            Method::POST,
            "/v1/tokens",
            Some(json!({"principal_id": fixture.hub.admin_id, "label": "x".repeat(129)})),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(err["code"], error_codes::INVALID_INPUT);

    let profiles_257: Vec<ProfileId> = (0..257).map(|_| ProfileId::new()).collect();
    let (status, err) = fixture
        .request_admin(
            Method::POST,
            "/v1/tokens",
            Some(json!({
                "principal_id": fixture.hub.admin_id,
                "label": "too-many-profiles",
                "allowed_profiles": profiles_257,
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(err["code"], error_codes::INVALID_INPUT);
    let nodes_257: Vec<NodeId> = (0..257).map(|_| NodeId::new()).collect();
    let (status, err) = fixture
        .request_admin(
            Method::POST,
            "/v1/tokens",
            Some(json!({
                "principal_id": fixture.hub.admin_id,
                "label": "too-many-nodes",
                "allowed_nodes": nodes_257,
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(err["code"], error_codes::INVALID_INPUT);
    let profiles_256: Vec<ProfileId> = (0..256).map(|_| ProfileId::new()).collect();
    let (status, _) = fixture
        .request_admin(
            Method::POST,
            "/v1/tokens",
            Some(json!({
                "principal_id": fixture.hub.admin_id,
                "label": "max-profiles",
                "allowed_profiles": profiles_256,
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED);
    fixture.finish().await;
    Ok(())
}
