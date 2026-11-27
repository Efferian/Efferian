use std::sync::Arc;

use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use efferian_protocol::{
    NodeId, PrincipalId, PrincipalKind, ProfileId, TokenId, ToolId, error_codes,
};
use rusqlite::{Connection, params};
use serde_json::{Value, json};

use crate::config::Config;
use crate::node_bridge::{BridgeCloseReason, NodeBridgeControl};
use crate::test_support::{ClosedSession, TestHub, TestResult};
use crate::vault::auth::{CredentialError, authenticate_node};

struct Fixture {
    hub: TestHub,
}

impl Fixture {
    async fn new(config: Config) -> TestResult<Self> {
        Ok(Self {
            hub: TestHub::start("nodes", config, 10_000).await?,
        })
    }

    async fn request(
        &self,
        method: Method,
        uri: &str,
        token: &str,
        json: Option<Value>,
    ) -> TestResult<(StatusCode, Value)> {
        self.hub.request(method, uri, token, json).await
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
                &self.hub.admin_token,
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
            &self.hub.admin_token,
            None,
        )
        .await
    }

    async fn token_active(&self, token: &str) -> TestResult<bool> {
        let vault = Arc::clone(&self.hub.state.vault);
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}"))?,
        );
        let bearer = crate::vault::auth::ParsedBearer::from_headers(&headers)?;
        self.hub
            .state
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
        self.hub.write(f).await
    }

    async fn orchestrator(&self) -> TestResult<(PrincipalId, String)> {
        self.orchestrator_with("orchestrator", false).await
    }

    async fn orchestrator_with(
        &self,
        name: &'static str,
        narrowed: bool,
    ) -> TestResult<(PrincipalId, String)> {
        let kind = PrincipalKind::Service;
        let principal = PrincipalId::new_for_kind(kind);
        let token_id = TokenId::new_for_kind(kind);
        let issued = self.hub.state.vault.issue_token(token_id)?;
        let verifier = issued.verifier.as_str().to_owned();
        let raw = issued.secret.expose_secret().to_owned();
        self.write(move |conn| {
            conn.execute(
                "INSERT INTO principals
                    (principal_id, kind, name, is_orchestrator, allowed_node_tags_json, created_at_ms, updated_at_ms)
                 VALUES (?1, 'service', ?2, 1, '[\"alpha\",\"sandbox\"]', 1, 1)",
                params![principal.to_string(), name],
            )?;
            conn.execute(
                "INSERT INTO auth_tokens (token_id, principal_id, created_by, label, key_id,
                                          verifier_hmac, withhold_sensitive, created_at_ms)
                 VALUES (?1, ?2, ?2, 'orchestrator', ?3, ?4, ?5, 1)",
                params![token_id.to_string(), principal.to_string(), issued.key_id, verifier, narrowed],
            )?;
            Ok(())
        }).await?;
        Ok((principal, raw))
    }

    async fn shutdown(self) {
        self.hub.shutdown().await;
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
    let hub = Fixture::new(Config::default()).await?;
    let first_ticket = hub.mint(&hub.hub.admin_token, "release-node").await?;
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
    hub.hub.bridge.sessions().insert(node, 0);

    let (before_revoke, _) = hub.rotate(node, 9).await?;
    assert_eq!(
        hub.revoke(node, &hub.hub.admin_token).await?.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        hub.exchange(&before_revoke).await?.0,
        StatusCode::UNAUTHORIZED
    );
    assert!(!hub.token_active(&old_token).await?);
    let (status, summary) = hub.read(node, &hub.hub.admin_token).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(summary["live_status"], "offline");
    let (between_revokes, _) = hub.rotate(node, 9).await?;
    assert_eq!(
        hub.revoke(node, &hub.hub.admin_token).await?.0,
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
        hub.read(node, &hub.hub.admin_token).await?.1["tags"],
        json!(["alpha", "sandbox"])
    );
    assert!(!hub.token_active(&old_token).await?);
    assert!(
        hub.token_active(&json_string(&second, "node_token")?)
            .await?
    );
    assert_eq!(hub.exchange(&ticket).await?.0, StatusCode::UNAUTHORIZED);
    let closes = hub.hub.bridge.closes().clone();
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
    hub.hub.bridge.sessions().insert(node, 1);
    hub.hub
        .bridge
        .close_session(node, 0, BridgeCloseReason::NodeRevoked);
    assert_eq!(
        hub.read(node, &hub.hub.admin_token).await?.1["live_status"],
        "ready"
    );

    assert_eq!(
        hub.revoke(node, &hub.hub.admin_token).await?.0,
        StatusCode::NO_CONTENT
    );
    hub.hub.clock.set(9000);
    let (ticket, expires) = hub.rotate(node, 1).await?;
    assert_eq!(expires, 9001);
    hub.hub.clock.set(9001);
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
    let hub = Fixture::new(Config::default()).await?;
    let ticket = hub.mint(&hub.hub.admin_token, "runner").await?;
    let alternate = hub.mint(&hub.hub.admin_token, "runner").await?;
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
        hub.revoke(node, &hub.hub.admin_token).await?.0,
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
            &hub.hub.admin_token,
            Some(json!({})),
        )
        .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(response["code"], error_codes::NODE_NAME_IN_USE);
    assert_eq!(
        hub.revoke(replacement, &hub.hub.admin_token).await?.0,
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
    let hub = Fixture::new(config).await?;
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
    let foreign = hub.mint(&hub.hub.admin_token, "admin-node").await?;
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
        hub.read(NodeId::new(), &hub.hub.admin_token).await?.0,
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
    let hub = Fixture::new(Config::default()).await?;
    let ticket = hub.mint(&hub.hub.admin_token, "fixed-node").await?;
    let (_, result) = hub.exchange(&ticket).await?;
    let node = response_node(&result)?;
    assert_eq!(hub.delete(node).await?.0, StatusCode::CONFLICT);
    assert_eq!(
        hub.revoke(node, &hub.hub.admin_token).await?.0,
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
    assert_eq!(
        hub.read(node, &hub.hub.admin_token).await?.0,
        StatusCode::OK
    );

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
    assert_eq!(
        hub.read(node, &hub.hub.admin_token).await?.0,
        StatusCode::NOT_FOUND
    );
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn narrowed_anti_oracle_live_rotation_at_quota_and_tags_cap() -> TestResult {
    let mut config = Config::default();
    config.max_active_nodes_per_orchestrator = 1;
    let hub = Fixture::new(config).await?;
    let (orch_id, orch_token) = hub.orchestrator_with("orch", false).await?;
    let (_, narrow_orch_token) = hub.orchestrator_with("narrow-orch", true).await?;

    // Mint a narrowed admin token.
    let (status, narrowed_admin) = hub
        .request(
            Method::POST,
            "/v1/tokens",
            &hub.hub.admin_token,
            Some(json!({
                "principal_id": hub.hub.admin_id,
                "label": "narrow-admin",
                "withhold_sensitive": true,
            })),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED);
    let narrow_admin_token = json_string(&narrowed_admin, "token")?;

    // 1. Tags cap: 65 tags rejected with 400, 64 tags accepted.
    let tags_65: Vec<String> = (0..65).map(|i| format!("t-{i}")).collect();
    let (status, err) = hub
        .request(
            Method::POST,
            "/v1/enrollment/tokens",
            &hub.hub.admin_token,
            Some(json!({"target_node_name": "too-many", "tags": tags_65})),
        )
        .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(err["code"], error_codes::INVALID_INPUT);
    let tags_64: Vec<String> = (0..64).map(|i| format!("t-{i}")).collect();
    let (status, _) = hub
        .request(
            Method::POST,
            "/v1/enrollment/tokens",
            &hub.hub.admin_token,
            Some(json!({"target_node_name": "exact-64", "tags": tags_64})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED);

    // 2. Live rotation of active orchestrator node at full quota preserves identity & bumps epoch.
    let ticket = hub.mint(&orch_token, "managed-one").await?;
    let (status, enrolled) = hub.exchange(&ticket).await?;
    assert_eq!(status, StatusCode::OK);
    let node = response_node(&enrolled)?;
    hub.hub.bridge.sessions().insert(node, 0);

    let (rotate_ticket, _) = hub.rotate(node, 15_000).await?;
    let (status, rotated) = hub.exchange(&rotate_ticket).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response_node(&rotated)?, node);
    let (_, summary) = hub.read(node, &hub.hub.admin_token).await?;
    assert_eq!(summary["name"], "managed-one");
    assert_eq!(summary["tags"], json!(["alpha", "sandbox"]));
    assert_eq!(summary["managed_by_principal_id"], orch_id.to_string());
    let closes = hub.hub.bridge.closes().clone();
    assert_eq!(closes.len(), 1);
    assert_eq!(closes[0].reason, BridgeCloseReason::Superseded);
    assert_eq!(closes[0].through_epoch, 0);
    assert_eq!(closes[0].committed_epoch, Some(1));

    // 3. Anti-oracle: narrowed admin & narrowed orchestrator get uniform token_narrowed on node ops.
    for token in [&narrow_admin_token, &narrow_orch_token] {
        for target in [node, NodeId::new()] {
            let (status, err) = hub.revoke(target, token).await?;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(err["code"], error_codes::TOKEN_NARROWED);
            let (status, err) = hub
                .request(Method::DELETE, &format!("/v1/nodes/{target}"), token, None)
                .await?;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(err["code"], error_codes::TOKEN_NARROWED);
        }
    }
    for target in [node, NodeId::new()] {
        let (status, err) = hub.read(target, &narrow_admin_token).await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(err["code"], error_codes::FORBIDDEN);
        let (status, err) = hub
            .request(
                Method::POST,
                &format!("/v1/nodes/{target}/reenroll-tokens"),
                &narrow_admin_token,
                Some(json!({})),
            )
            .await?;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(err["code"], error_codes::TOKEN_NARROWED);
    }

    // 4. mint_reenrollment with active demoted service succeeds (201), disabled manager fails (403 managed_by_disabled).
    hub.write(move |conn| {
        conn.execute(
            "UPDATE principals SET is_orchestrator = 0, allowed_node_tags_json = '[]' WHERE principal_id = ?1",
            [orch_id.to_string()],
        )?;
        Ok(())
    })
    .await?;
    let (status, _) = hub
        .request(
            Method::POST,
            &format!("/v1/nodes/{node}/reenroll-tokens"),
            &hub.hub.admin_token,
            Some(json!({})),
        )
        .await?;
    assert_eq!(status, StatusCode::CREATED);
    hub.write(move |conn| {
        conn.execute(
            "UPDATE principals SET disabled_at_ms = 1000 WHERE principal_id = ?1",
            [orch_id.to_string()],
        )?;
        Ok(())
    })
    .await?;
    let (status, err) = hub
        .request(
            Method::POST,
            &format!("/v1/nodes/{node}/reenroll-tokens"),
            &hub.hub.admin_token,
            Some(json!({})),
        )
        .await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err["code"], error_codes::MANAGED_BY_DISABLED);
    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn delete_node_handles_active_execution_disabled_edition_and_corrupt_profile() -> TestResult {
    let hub = Fixture::new(Config::default()).await?;
    let ticket = hub.mint(&hub.hub.admin_token, "ref-node").await?;
    let (_, enrolled) = hub.exchange(&ticket).await?;
    let node = response_node(&enrolled)?;
    assert_eq!(
        hub.revoke(node, &hub.hub.admin_token).await?.0,
        StatusCode::NO_CONTENT
    );

    // 1. Active execution blocks DELETE with 409 resource_in_use.
    let admin = hub.hub.admin_id;
    let tool = ToolId::new();
    let profile = ProfileId::new();
    let binding_json = binding(tool, 1, Some(node)).to_string();
    let other_def = command_definition(json!({"kind": "tag", "tag": "alpha"})).to_string();
    hub.write(move |conn| {
        conn.execute(
            "INSERT INTO executions (execution_id, invoke_kind, request_id, request_digest,
                caller_principal_id, caller_token_id, tool_id, tool_version, public_name,
                executor_kind, node_id, state, deadline_at_ms, created_at_ms,
                result_expires_at_ms, expires_at_ms)
             SELECT 'exec_active', 'tool_test', 'req_1', 'd', principal_id, token_id, ?1, 1, 't',
                    'node', ?2, 'running', 1000, 1000, 2000, 2000
             FROM auth_tokens WHERE label = 'bootstrap'",
            params![tool.to_string(), node.to_string()],
        )?;
        Ok(())
    })
    .await?;
    assert_resource_in_use(hub.delete(node).await?);

    // 2. Finish execution; add a disabled current profile edition referencing the node -> DELETE allowed!
    // First test fail-closed on missing edition (published_version = 99 with no matching edition row).
    hub.write(move |conn| {
        conn.execute("UPDATE executions SET state = 'succeeded'", [])?;
        conn.execute(
            "INSERT INTO tools (tool_id, slug, kind, created_by, current_version, created_at_ms, updated_at_ms)
             VALUES (?1, 't', 'command', ?2, 1, 1, 1)",
            params![tool.to_string(), admin.to_string()],
        )?;
        conn.execute(
            "INSERT INTO tool_revisions (tool_id, version, input_schema_sha256, created_at_ms, definition_json)
             VALUES (?1, 1, 'x', 1, ?2)",
            params![tool.to_string(), other_def],
        )?;
        conn.execute(
            "INSERT INTO profiles (profile_id, slug, discovery_mode, published_version, created_at_ms, updated_at_ms)
             VALUES (?1, 'prof', 'full', 99, 1, 1)",
            [profile.to_string()],
        )?;
        Ok(())
    })
    .await?;
    assert_eq!(hub.delete(node).await?.0, StatusCode::INTERNAL_SERVER_ERROR);

    // Now point published_version to a disabled edition referencing `node`: must allow deletion.
    hub.write(move |conn| {
        conn.execute(
            "INSERT INTO profile_editions (profile_id, version, discovery_mode, published_by,
                                           published_at_ms, disabled_at_ms, bindings_json)
             VALUES (?1, 1, 'full', ?2, 1, 1000, ?3)",
            params![profile.to_string(), admin.to_string(), binding_json],
        )?;
        conn.execute(
            "UPDATE profiles SET published_version = 1 WHERE profile_id = ?1",
            [profile.to_string()],
        )?;
        Ok(())
    })
    .await?;
    assert_eq!(hub.delete(node).await?.0, StatusCode::NO_CONTENT);
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
