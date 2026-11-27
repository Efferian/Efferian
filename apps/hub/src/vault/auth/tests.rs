#![allow(clippy::unwrap_used)]

use efferian_protocol::{HubId, SecretString};
use http::HeaderValue;
use rusqlite::params;

use super::*;
use crate::vault::{IssuedCredential, VaultKeys};

const NOW: i64 = 1800;

fn test_vault() -> Vault {
    VaultKeys::derive(Zeroizing::new([36; 32]))
        .unwrap()
        .bind_hub(HubId::new())
}

fn database(vault: &Vault) -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(include_str!("../../storage/v1.sql"))
        .unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    conn.execute(
        "INSERT INTO hub_meta (id, hub_id, master_key_fingerprint, created_at_ms, updated_at_ms)
         VALUES (1, ?1, ?2, ?3, ?3)",
        params![
            vault.hub_id.to_string(),
            vault.keys.expected_hub_identity().master_key_fingerprint,
            NOW
        ],
    )
    .unwrap();
    conn
}

fn api_from_headers(
    vault: &Vault,
    conn: &Connection,
    headers: &HeaderMap,
    now: i64,
) -> Result<AuthenticatedApi, CredentialError> {
    authenticate_api(
        vault,
        conn,
        ParsedBearer::<TokenId>::from_headers(headers)?,
        now,
    )
}

fn enrollment_from_headers(
    vault: &Vault,
    conn: &Connection,
    headers: &HeaderMap,
    now: i64,
) -> Result<AuthenticatedEnrollment, CredentialError> {
    authenticate_enrollment(
        vault,
        conn,
        ParsedBearer::<EnrollmentId>::from_headers(headers)?,
        now,
    )
}

fn node_from_headers(
    vault: &Vault,
    conn: &Connection,
    headers: &HeaderMap,
) -> Result<VerifiedCredential<NodeId>, CredentialError> {
    authenticate_node(vault, conn, ParsedBearer::<NodeId>::from_headers(headers)?)
}

fn headers(token: &SecretString) -> HeaderMap {
    let mut header = HeaderValue::from_str(&format!("Bearer {}", token.expose_secret())).unwrap();
    header.set_sensitive(true);
    HeaderMap::from_iter([(AUTHORIZATION, header)])
}

fn principal(conn: &Connection, name: &str, kind: PrincipalKind) -> PrincipalId {
    let principal = PrincipalId::new_for_kind(kind);
    conn.execute(
        "INSERT INTO principals (principal_id, name, kind, created_at_ms, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?4)",
        params![
            principal.to_string(),
            name,
            crate::storage::scalar_text(kind).unwrap(),
            NOW
        ],
    )
    .unwrap();
    principal
}

fn global_admin(conn: &Connection) -> PrincipalId {
    let admin = principal(conn, "admin", PrincipalKind::Admin);
    conn.execute(
        "INSERT INTO grants (grant_id, principal_id, scope_kind, capability, created_by, created_at_ms)
         VALUES (?1, ?2, 'global', 'admin', ?2, ?3)",
        params![efferian_protocol::GrantId::new().to_string(), admin.to_string(), NOW],
    ).unwrap();
    admin
}

fn token(
    vault: &Vault,
    conn: &Connection,
    principal_id: PrincipalId,
    kind: PrincipalKind,
) -> (TokenId, IssuedCredential) {
    let id = TokenId::new_for_kind(kind);
    let issued = vault.issue_token(id).unwrap();
    conn.execute(
        "INSERT INTO auth_tokens (token_id, principal_id, created_by, label, key_id,
                                  verifier_hmac, created_at_ms)
         VALUES (?1, ?2, ?2, 'fixture', ?3, ?4, ?5)",
        params![
            id.to_string(),
            principal_id.to_string(),
            issued.key_id,
            issued.verifier.as_str(),
            NOW
        ],
    )
    .unwrap();
    (id, issued)
}

fn assert_unauthenticated<T>(result: Result<T, CredentialError>) {
    assert!(matches!(result, Err(CredentialError::Unauthenticated)));
}

#[test]
fn strict_bearer_parser_and_family_selection() {
    let vault = test_vault();
    let conn = database(&vault);
    let admin = global_admin(&conn);
    let (id, issued) = token(&vault, &conn, admin, PrincipalKind::Admin);
    let raw = issued.secret.expose_secret();
    let request_headers = |value: &str| {
        HeaderMap::from_iter([(AUTHORIZATION, HeaderValue::from_str(value).unwrap())])
    };

    assert_eq!(
        api_from_headers(
            &vault,
            &conn,
            &request_headers(&format!("bEaReR {raw}")),
            NOW
        )
        .unwrap()
        .credential
        .id(),
        id,
    );
    let mut duplicate = headers(&issued.secret);
    duplicate.append(AUTHORIZATION, duplicate[AUTHORIZATION].clone());
    assert_unauthenticated(api_from_headers(&vault, &conn, &duplicate, NOW));
    let mut uppercase_hex = format!("Bearer {raw}");
    uppercase_hex.pop();
    uppercase_hex.push('A');
    for invalid in [
        format!("Bearer  {raw}"),
        format!("Bearer {raw} "),
        format!("Bearer\t{raw}"),
        format!("Basic {raw}"),
        format!("Bearer eff_{id}"),
        format!("Bearer eff_{id}.{}", "0".repeat(63)),
        format!("Bearer eff_{id}.{}", "0".repeat(65)),
        format!("Bearer{}", " ".repeat(507)),
        uppercase_hex,
    ] {
        assert_unauthenticated(api_from_headers(
            &vault,
            &conn,
            &request_headers(&invalid),
            NOW,
        ));
    }
    let enrollment = vault.issue_enrollment(EnrollmentId::new()).unwrap();
    let node = vault.issue_node(NodeId::new()).unwrap();
    for secret in [&enrollment.secret, &node.secret] {
        assert_unauthenticated(api_from_headers(&vault, &conn, &headers(secret), NOW));
    }
    assert_unauthenticated(enrollment_from_headers(
        &vault,
        &conn,
        &headers(&issued.secret),
        NOW,
    ));
    assert_unauthenticated(node_from_headers(&vault, &conn, &headers(&issued.secret)));
}

#[test]
fn dummy_verifier_runs_for_missing_purging_and_unknown_key_rows() {
    let vault = test_vault();
    let conn = database(&vault);
    let user = principal(&conn, "agent", PrincipalKind::Agent);
    let (id, issued) = token(&vault, &conn, user, PrincipalKind::Agent);
    let missing = vault.issue_token(TokenId::new_user_or_agent()).unwrap();
    let check_dummy = |secret| {
        MAC_CHECKS.with(|checks| checks.set(0));
        assert_unauthenticated(api_from_headers(&vault, &conn, &headers(secret), NOW));
        MAC_CHECKS.with(|checks| assert_eq!(checks.get(), 1));
    };
    check_dummy(&missing.secret);

    for bad_key in [-1, 0, 2, 65537_i64] {
        conn.execute(
            "UPDATE auth_tokens SET key_id = ?1 WHERE token_id = ?2",
            params![bad_key, id.to_string()],
        )
        .unwrap();
        check_dummy(&issued.secret);
    }
    conn.execute(
        "UPDATE auth_tokens SET key_id = 1 WHERE token_id = ?1",
        [id.to_string()],
    )
    .unwrap();
    assert!(api_from_headers(&vault, &conn, &headers(&issued.secret), NOW).is_ok());
    conn.execute(
        "UPDATE hub_meta SET gc_purging_principal_id = ?1 WHERE id = 1",
        [user.to_string()],
    )
    .unwrap();
    check_dummy(&issued.secret);
}

#[test]
fn api_auth_reads_only_and_checks_mac_before_disabled_or_expired_status() {
    let vault = test_vault();
    let conn = database(&vault);
    let admin = global_admin(&conn);
    let (id, issued) = token(&vault, &conn, admin, PrincipalKind::Admin);
    conn.execute_batch("PRAGMA query_only = ON;").unwrap();
    let changes = conn.total_changes();
    let accepted = api_from_headers(&vault, &conn, &headers(&issued.secret), NOW).unwrap();
    assert_eq!(accepted.credential.id(), id);
    assert_eq!(accepted.principal_id, admin);
    assert_eq!(
        refresh_api(&conn, &accepted.credential, NOW)
            .unwrap()
            .caller_grants,
        [GrantView {
            scope: GrantScope::Global,
            capability: Capability::Admin
        }]
    );
    assert_eq!(conn.total_changes(), changes);
    assert!(!format!("{:?}", accepted.credential).contains(issued.verifier.as_str()));

    conn.execute_batch("PRAGMA query_only = OFF;").unwrap();
    conn.execute(
        "UPDATE principals SET disabled_at_ms = ?1 WHERE principal_id = ?2",
        params![NOW, admin.to_string()],
    )
    .unwrap();
    let wrong_secret = vault.issue_token(id).unwrap();
    assert_unauthenticated(api_from_headers(
        &vault,
        &conn,
        &headers(&wrong_secret.secret),
        NOW,
    ));
    assert!(matches!(
        api_from_headers(&vault, &conn, &headers(&issued.secret), NOW),
        Err(CredentialError::Authz(AuthzError::PrincipalDisabled)),
    ));
    conn.execute(
        "UPDATE auth_tokens SET expires_at_ms = ?1 WHERE token_id = ?2",
        params![NOW, id.to_string()],
    )
    .unwrap();
    assert_unauthenticated(api_from_headers(
        &vault,
        &conn,
        &headers(&issued.secret),
        NOW,
    ));
    assert_unauthenticated(refresh_api(&conn, &accepted.credential, NOW));

    conn.execute("UPDATE principals SET disabled_at_ms = NULL", [])
        .unwrap();
    conn.execute(
        "UPDATE auth_tokens SET expires_at_ms = NULL, verifier_hmac = ?1",
        [wrong_secret.verifier.as_str()],
    )
    .unwrap();
    assert_unauthenticated(refresh_api(&conn, &accepted.credential, NOW));
    assert!(api_from_headers(&vault, &conn, &headers(&wrong_secret.secret), NOW).is_ok());
}

#[test]
fn service_tokens_and_managed_agents_use_current_principal_projection() {
    let vault = test_vault();
    let conn = database(&vault);
    let manager = principal(&conn, "manager", PrincipalKind::Service);
    let agent = principal(&conn, "agent", PrincipalKind::Agent);
    conn.execute(
        "UPDATE principals SET is_orchestrator = 1 WHERE principal_id = ?1",
        [manager.to_string()],
    )
    .unwrap();
    conn.execute(
        "UPDATE principals SET managed_by_principal_id = ?1 WHERE principal_id = ?2",
        params![manager.to_string(), agent.to_string()],
    )
    .unwrap();
    let (_, manager_token) = token(&vault, &conn, manager, PrincipalKind::Service);
    let (_, agent_token) = token(&vault, &conn, agent, PrincipalKind::Agent);
    let manager_headers = headers(&manager_token.secret);
    let agent_headers = headers(&agent_token.secret);

    let manager_auth = api_from_headers(&vault, &conn, &manager_headers, NOW).unwrap();
    let manager_context = refresh_api(&conn, &manager_auth.credential, NOW).unwrap();
    assert_eq!(manager_context.caller.kind, PrincipalKind::Service);
    assert!(manager_context.caller.is_orchestrator);
    let agent_auth = api_from_headers(&vault, &conn, &agent_headers, NOW).unwrap();
    let agent_context = refresh_api(&conn, &agent_auth.credential, NOW).unwrap();
    assert_eq!(agent_context.managed_by.unwrap().principal_id, manager);
    conn.execute(
        "UPDATE principals SET is_orchestrator = 0 WHERE principal_id = ?1",
        [manager.to_string()],
    )
    .unwrap();
    assert!(matches!(
        refresh_api(&conn, &agent_auth.credential, NOW),
        Err(CredentialError::Authz(AuthzError::InvalidAuthContext)),
    ));
    assert!(matches!(
        api_from_headers(&vault, &conn, &agent_headers, NOW),
        Err(CredentialError::Authz(AuthzError::InvalidAuthContext)),
    ));
}

#[test]
fn new_managed_enrollment_requires_the_issuers_current_tag_allowlist() {
    let vault = test_vault();
    let conn = database(&vault);
    let manager = principal(&conn, "manager", PrincipalKind::Service);
    conn.execute(
        "UPDATE principals SET is_orchestrator = 1, allowed_node_tags_json = '[\"private\"]'
         WHERE principal_id = ?1",
        [manager.to_string()],
    )
    .unwrap();
    let id = EnrollmentId::new();
    let issued = vault.issue_enrollment(id).unwrap();
    conn.execute(
        "INSERT INTO node_enrollments (enrollment_id, verifier_hmac, target_node_name,
                                      created_by, managed_by_principal_id, tags_json,
                                      expires_at_ms, created_at_ms)
         VALUES (?1, ?2, 'node', ?3, ?3, '[\"private\"]', ?4, ?5)",
        params![
            id.to_string(),
            issued.verifier.as_str(),
            manager.to_string(),
            NOW + 100,
            NOW
        ],
    )
    .unwrap();
    let request = headers(&issued.secret);
    let authenticated = enrollment_from_headers(&vault, &conn, &request, NOW).unwrap();
    assert!(matches!(
        authenticated.record,
        EnrollmentRecord::New { managed_by: Some(id), ref tags, .. }
            if id == manager && tags.contains("private")
    ));
    conn.execute(
        "UPDATE principals SET allowed_node_tags_json = '[]' WHERE principal_id = ?1",
        [manager.to_string()],
    )
    .unwrap();
    assert_unauthenticated(enrollment_from_headers(&vault, &conn, &request, NOW));
    assert_unauthenticated(recheck_enrollment(&conn, &authenticated.credential, NOW));
}

#[test]
fn enrollment_and_node_auth_recheck_current_rows_and_active_managers() {
    let vault = test_vault();
    let conn = database(&vault);
    let admin = global_admin(&conn);
    let manager = principal(&conn, "manager", PrincipalKind::Service);
    let node_id = NodeId::new();
    let node = vault.issue_node(node_id).unwrap();
    conn.execute(
        "INSERT INTO nodes (node_id, name, key_id, credential_hmac, managed_by_principal_id,
                            revoked_at_ms, created_at_ms, updated_at_ms)
         VALUES (?1, 'node', 1, ?2, ?3, ?4, ?4, ?4)",
        params![
            node_id.to_string(),
            node.verifier.as_str(),
            manager.to_string(),
            NOW
        ],
    )
    .unwrap();
    let enrollment_id = EnrollmentId::new();
    let issued = vault.issue_enrollment(enrollment_id).unwrap();
    conn.execute(
        "INSERT INTO node_enrollments (enrollment_id, key_id, verifier_hmac, target_node_id,
                                      created_by, expires_at_ms, created_at_ms)
         VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6)",
        params![
            enrollment_id.to_string(),
            issued.verifier.as_str(),
            node_id.to_string(),
            admin.to_string(),
            NOW + 100,
            NOW
        ],
    )
    .unwrap();

    assert_unauthenticated(node_from_headers(&vault, &conn, &headers(&node.secret)));
    assert_unauthenticated(enrollment_from_headers(
        &vault,
        &conn,
        &headers(&issued.secret),
        NOW,
    ));
    conn.execute("UPDATE node_enrollments SET created_at_ms = ?1", [NOW + 1])
        .unwrap();
    // A demoted, active service can still manage a previously enrolled node.
    let enrollment = enrollment_from_headers(&vault, &conn, &headers(&issued.secret), NOW).unwrap();
    assert_eq!(enrollment.credential.id(), enrollment_id);
    assert!(
        matches!(enrollment.record, EnrollmentRecord::Reenroll { node_id: id } if id == node_id)
    );
    assert_unauthenticated(node_from_headers(&vault, &conn, &headers(&issued.secret)));
    assert_unauthenticated(enrollment_from_headers(
        &vault,
        &conn,
        &headers(&node.secret),
        NOW,
    ));
    assert_unauthenticated(recheck_enrollment(&conn, &enrollment.credential, NOW + 100));

    conn.execute("UPDATE nodes SET revoked_at_ms = NULL", [])
        .unwrap();
    let authenticated_node = node_from_headers(&vault, &conn, &headers(&node.secret)).unwrap();
    recheck_node(&conn, &authenticated_node).unwrap();
    conn.execute(
        "UPDATE principals SET disabled_at_ms = ?1 WHERE principal_id = ?2",
        params![NOW, manager.to_string()],
    )
    .unwrap();
    assert!(matches!(
        recheck_node(&conn, &authenticated_node),
        Err(CredentialError::Authz(AuthzError::ManagedByDisabled))
    ));
    assert_unauthenticated(recheck_enrollment(&conn, &enrollment.credential, NOW));
    conn.execute("UPDATE principals SET disabled_at_ms = NULL", [])
        .unwrap();
    conn.execute("UPDATE node_enrollments SET consumed_at_ms = ?1", [NOW])
        .unwrap();
    assert_unauthenticated(recheck_enrollment(&conn, &enrollment.credential, NOW));

    let rotated = vault.issue_node(node_id).unwrap();
    conn.execute(
        "UPDATE nodes SET credential_hmac = ?1",
        [rotated.verifier.as_str()],
    )
    .unwrap();
    assert_unauthenticated(recheck_node(&conn, &authenticated_node));
    node_from_headers(&vault, &conn, &headers(&rotated.secret)).unwrap();
}

#[test]
fn parsed_bearer_debug_edge_headers_corrupt_macs_and_node_manager_order() {
    let vault = test_vault();
    let conn = database(&vault);
    let admin = global_admin(&conn);
    let (id, issued) = token(&vault, &conn, admin, PrincipalKind::Admin);

    let parsed = ParsedBearer::<TokenId>::from_headers(&headers(&issued.secret)).unwrap();
    let debug = format!("{parsed:?}");
    let secret_hex = issued.secret.expose_secret().split_once('.').unwrap().1;
    assert!(debug.starts_with("ParsedBearer { id: ") && debug.ends_with(", .. }"));
    assert!(!debug.contains(secret_hex));
    assert!(!debug.contains(&format!("{:?}", parsed.secret.as_slice())));

    // Non-UTF8, leading space, non-v7 UUID, and uppercase UUID must fail parsing cleanly.
    let mut non_utf8 = HeaderMap::new();
    non_utf8.insert(
        AUTHORIZATION,
        HeaderValue::from_bytes(b"Bearer \xff\xfe").unwrap(),
    );
    assert_unauthenticated(ParsedBearer::<TokenId>::from_headers(&non_utf8));
    let raw = issued.secret.expose_secret();
    for bad in [
        format!(" Bearer {raw}"),
        format!("Bearer eff_tok_00000000000000000000000000000000.{secret_hex}"),
        format!(
            "Bearer eff_{}.{secret_hex}",
            id.to_string().to_ascii_uppercase()
        ),
    ] {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, HeaderValue::from_str(&bad).unwrap());
        assert_unauthenticated(ParsedBearer::<TokenId>::from_headers(&h));
    }

    // Corrupted stored verifier_hmac must still run the dummy MAC path and return Unauthenticated.
    for bad_hmac in ["short", &"g".repeat(64), &"A".repeat(64)] {
        conn.execute(
            "UPDATE auth_tokens SET verifier_hmac = ?1 WHERE token_id = ?2",
            params![bad_hmac, id.to_string()],
        )
        .unwrap();
        MAC_CHECKS.with(|checks| checks.set(0));
        assert_unauthenticated(api_from_headers(
            &vault,
            &conn,
            &headers(&issued.secret),
            NOW,
        ));
        MAC_CHECKS.with(|checks| assert_eq!(checks.get(), 1));
    }

    // Node auth checks MAC before revealing disabled manager status.
    let manager = principal(&conn, "disabled-manager", PrincipalKind::Service);
    conn.execute(
        "UPDATE principals SET disabled_at_ms = ?1 WHERE principal_id = ?2",
        params![NOW, manager.to_string()],
    )
    .unwrap();
    let node_id = NodeId::new();
    let valid_node = vault.issue_node(node_id).unwrap();
    let wrong_node = vault.issue_node(node_id).unwrap();
    conn.execute(
        "INSERT INTO nodes (node_id, name, key_id, credential_hmac, managed_by_principal_id,
                            created_at_ms, updated_at_ms)
         VALUES (?1, 'managed-node', 1, ?2, ?3, ?4, ?4)",
        params![
            node_id.to_string(),
            valid_node.verifier.as_str(),
            manager.to_string(),
            NOW
        ],
    )
    .unwrap();
    assert_unauthenticated(node_from_headers(
        &vault,
        &conn,
        &headers(&wrong_node.secret),
    ));
    assert!(matches!(
        node_from_headers(&vault, &conn, &headers(&valid_node.secret)),
        Err(CredentialError::Authz(AuthzError::ManagedByDisabled))
    ));
}

#[test]
fn corrupt_scope_or_duplicate_token_sets_return_from_sql_conversion_failure() {
    let vault = test_vault();
    let conn = database(&vault);
    let admin = global_admin(&conn);
    let (tok_id, issued) = token(&vault, &conn, admin, PrincipalKind::Admin);
    let auth = api_from_headers(&vault, &conn, &headers(&issued.secret), NOW).unwrap();

    // Duplicate ID in allowed_profiles_json must fail with FromSqlConversionFailure, not InvalidQuery.
    let profile = efferian_protocol::ProfileId::new();
    let dup = serde_json::to_string(&[profile, profile]).unwrap();
    conn.execute(
        "UPDATE auth_tokens SET allowed_profiles_json = ?1 WHERE token_id = ?2",
        params![dup, tok_id.to_string()],
    )
    .unwrap();
    assert!(matches!(
        refresh_api(&conn, &auth.credential, NOW),
        Err(CredentialError::Storage(StorageError::Sqlite(
            rusqlite::Error::FromSqlConversionFailure(..)
        )))
    ));

    // Reset token scope, then inject an invalid grants row by temporarily recreating grants without CHECK.
    conn.execute(
        "UPDATE auth_tokens SET allowed_profiles_json = NULL WHERE token_id = ?1",
        [tok_id.to_string()],
    )
    .unwrap();
    conn.execute_batch(
        "PRAGMA foreign_keys = OFF;
         ALTER TABLE grants RENAME TO grants_checked;
         CREATE TABLE grants (
             grant_id TEXT PRIMARY KEY,
             principal_id TEXT NOT NULL,
             scope_kind TEXT NOT NULL,
             scope_id TEXT NOT NULL DEFAULT '',
             capability TEXT NOT NULL,
             created_by TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL
         );
         INSERT INTO grants SELECT * FROM grants_checked;
         UPDATE grants SET scope_id = 'unexpected' WHERE scope_kind = 'global';
         PRAGMA foreign_keys = ON;",
    )
    .unwrap();
    assert!(matches!(
        refresh_api(&conn, &auth.credential, NOW),
        Err(CredentialError::Storage(StorageError::Sqlite(
            rusqlite::Error::FromSqlConversionFailure(..)
        )))
    ));
}

#[tokio::test]
async fn db_actor_stays_healthy_after_corrupt_token_scope_decode_failure() {
    use crate::config::Config;
    use crate::storage::{WriteError, WriteTxError};
    use crate::test_support::TestHub;

    let hub = TestHub::start("auth-savepoint", Config::default(), NOW)
        .await
        .unwrap();
    let bearer = ParsedBearer::<TokenId>::from_headers(&headers(&SecretString::new(
        hub.admin_token.clone(),
    )))
    .unwrap();
    let vault = std::sync::Arc::clone(&hub.state.vault);
    let authed = hub
        .state
        .storage
        .read_snapshot(move |conn| authenticate_api(&vault, conn, bearer, NOW))
        .await
        .unwrap();
    let tok_id = authed.credential.id();
    let profile = efferian_protocol::ProfileId::new();
    let dup = serde_json::to_string(&[profile, profile]).unwrap();
    hub.write(move |conn| {
        conn.execute(
            "UPDATE auth_tokens SET allowed_profiles_json = ?1 WHERE token_id = ?2",
            params![dup, tok_id.to_string()],
        )?;
        Ok(())
    })
    .await
    .unwrap();

    let cred = authed.credential;
    let err = hub
        .state
        .storage
        .execute_work(0, move |tx| -> Result<(), WriteTxError<CredentialError>> {
            refresh_api(tx.conn(), &cred, NOW).map_err(|error| match error {
                CredentialError::Storage(storage) => WriteTxError::from(storage),
                other => WriteTxError::Domain(other),
            })?;
            Ok(())
        })
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        WriteError::Storage(StorageError::Sqlite(
            rusqlite::Error::FromSqlConversionFailure(..)
        ))
    ));

    // A subsequent write transaction on the same DbActor commits cleanly.
    hub.write(move |conn| {
        conn.execute(
            "UPDATE auth_tokens SET allowed_profiles_json = NULL WHERE token_id = ?1",
            [tok_id.to_string()],
        )?;
        Ok(())
    })
    .await
    .unwrap();
    hub.shutdown().await;
}
