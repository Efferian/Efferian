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
            vault.hub_id().to_string(),
            vault.keys.expected_hub_identity().master_key_fingerprint,
            NOW
        ],
    )
    .unwrap();
    conn
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
            issued.verifier,
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
        authenticate_api(
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
    assert_unauthenticated(authenticate_api(&vault, &conn, &duplicate, NOW));
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
        assert_unauthenticated(authenticate_api(
            &vault,
            &conn,
            &request_headers(&invalid),
            NOW,
        ));
    }
    let enrollment = vault.issue_enrollment(EnrollmentId::new()).unwrap();
    let node = vault.issue_node(NodeId::new()).unwrap();
    for secret in [&enrollment.secret, &node.secret] {
        assert_unauthenticated(authenticate_api(&vault, &conn, &headers(secret), NOW));
    }
    assert_unauthenticated(authenticate_enrollment(
        &vault,
        &conn,
        &headers(&issued.secret),
        NOW,
    ));
    assert_unauthenticated(authenticate_node(&vault, &conn, &headers(&issued.secret)));
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
        assert_unauthenticated(authenticate_api(&vault, &conn, &headers(secret), NOW));
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
    assert!(authenticate_api(&vault, &conn, &headers(&issued.secret), NOW).is_ok());
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
    let accepted = authenticate_api(&vault, &conn, &headers(&issued.secret), NOW).unwrap();
    assert_eq!(accepted.context.token.token_id, id);
    assert_eq!(accepted.context.caller.principal_id, admin);
    assert_eq!(
        accepted.context.caller_grants,
        [GrantView {
            scope: GrantScope::Global,
            capability: Capability::Admin
        }]
    );
    assert_eq!(conn.total_changes(), changes);
    assert!(!format!("{:?}", accepted.credential).contains(&issued.verifier));

    conn.execute_batch("PRAGMA query_only = OFF;").unwrap();
    conn.execute(
        "UPDATE principals SET disabled_at_ms = ?1 WHERE principal_id = ?2",
        params![NOW, admin.to_string()],
    )
    .unwrap();
    let wrong_secret = vault.issue_token(id).unwrap();
    assert_unauthenticated(authenticate_api(
        &vault,
        &conn,
        &headers(&wrong_secret.secret),
        NOW,
    ));
    assert!(matches!(
        authenticate_api(&vault, &conn, &headers(&issued.secret), NOW),
        Err(CredentialError::Authz(AuthzError::PrincipalDisabled)),
    ));
    conn.execute(
        "UPDATE auth_tokens SET expires_at_ms = ?1 WHERE token_id = ?2",
        params![NOW, id.to_string()],
    )
    .unwrap();
    assert_unauthenticated(authenticate_api(
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
        [&wrong_secret.verifier],
    )
    .unwrap();
    assert_unauthenticated(refresh_api(&conn, &accepted.credential, NOW));
    assert!(authenticate_api(&vault, &conn, &headers(&wrong_secret.secret), NOW).is_ok());
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

    let manager_context = authenticate_api(&vault, &conn, &manager_headers, NOW)
        .unwrap()
        .context;
    assert_eq!(manager_context.caller.kind, PrincipalKind::Service);
    assert!(manager_context.caller.is_orchestrator);
    let agent_auth = authenticate_api(&vault, &conn, &agent_headers, NOW).unwrap();
    assert_eq!(agent_auth.context.managed_by.unwrap().principal_id, manager);
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
        authenticate_api(&vault, &conn, &agent_headers, NOW),
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
            issued.verifier,
            manager.to_string(),
            NOW + 100,
            NOW
        ],
    )
    .unwrap();
    let request = headers(&issued.secret);
    let authenticated = authenticate_enrollment(&vault, &conn, &request, NOW).unwrap();
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
    assert_unauthenticated(authenticate_enrollment(&vault, &conn, &request, NOW));
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
        params![node_id.to_string(), node.verifier, manager.to_string(), NOW],
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
            issued.verifier,
            node_id.to_string(),
            admin.to_string(),
            NOW + 100,
            NOW
        ],
    )
    .unwrap();

    assert_unauthenticated(authenticate_node(&vault, &conn, &headers(&node.secret)));
    assert_unauthenticated(authenticate_enrollment(
        &vault,
        &conn,
        &headers(&issued.secret),
        NOW,
    ));
    conn.execute("UPDATE node_enrollments SET created_at_ms = ?1", [NOW + 1])
        .unwrap();
    // A demoted, active service can still manage a previously enrolled node.
    let enrollment = authenticate_enrollment(&vault, &conn, &headers(&issued.secret), NOW).unwrap();
    assert_eq!(enrollment.credential.id(), enrollment_id);
    assert!(
        matches!(enrollment.record, EnrollmentRecord::Reenroll { node_id: id } if id == node_id)
    );
    assert_unauthenticated(authenticate_node(&vault, &conn, &headers(&issued.secret)));
    assert_unauthenticated(authenticate_enrollment(
        &vault,
        &conn,
        &headers(&node.secret),
        NOW,
    ));
    assert_unauthenticated(recheck_enrollment(&conn, &enrollment.credential, NOW + 100));

    conn.execute("UPDATE nodes SET revoked_at_ms = NULL", [])
        .unwrap();
    let authenticated_node = authenticate_node(&vault, &conn, &headers(&node.secret)).unwrap();
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
    conn.execute("UPDATE nodes SET credential_hmac = ?1", [&rotated.verifier])
        .unwrap();
    assert_unauthenticated(recheck_node(&conn, &authenticated_node));
    authenticate_node(&vault, &conn, &headers(&rotated.secret)).unwrap();
}
