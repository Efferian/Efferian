//! Credential authentication for Hub API requests, node enrollments and bridges.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use efferian_authz::{AuthContext, AuthzError, GrantView, TokenScope, check_active};
use efferian_protocol::{
    Capability, EnrollmentId, GrantScope, NodeId, PrincipalId, PrincipalKind, TokenId,
};
use http::{HeaderMap, header::AUTHORIZATION};
use rusqlite::{Connection, OptionalExtension};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

use super::{ACTIVE_KEY_ID, CredentialFamily, SecretBytes, Vault, VaultError};
use crate::storage::{
    PrincipalLiveness, StorageError, id, invalid_text_msg, opt_id, optional_scalar,
    principal_liveness, read_grant_scope, read_principal, scalar,
};

const MAX_AUTHORIZATION_BYTES: usize = 512;
const DUMMY_VERIFIER: [u8; 32] = [0; 32];

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("invalid or inactive credential")]
    Unauthenticated,
    #[error(transparent)]
    Authz(#[from] AuthzError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("credential verification failed")]
    Vault(#[from] VaultError),
}

impl From<rusqlite::Error> for CredentialError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error.into())
    }
}

/// Proof that this credential matched a persisted verifier in an earlier
/// snapshot. The write transaction must still compare it with the current row.
#[derive(Clone)]
pub struct VerifiedCredential<Id> {
    id: Id,
    key_id: u16,
    verifier: Zeroizing<String>,
}

impl<Id: Copy> VerifiedCredential<Id> {
    pub fn id(&self) -> Id {
        self.id
    }

    pub fn key_id(&self) -> u16 {
        self.key_id
    }

    pub fn verifier(&self) -> &str {
        &self.verifier
    }
}

impl<Id: fmt::Debug> fmt::Debug for VerifiedCredential<Id> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedCredential")
            .field("id", &self.id)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct AuthenticatedApi {
    pub principal_id: PrincipalId,
    pub principal_kind: PrincipalKind,
    pub credential: VerifiedCredential<TokenId>,
}

#[derive(Clone)]
pub struct AuthenticatedEnrollment {
    pub credential: VerifiedCredential<EnrollmentId>,
    pub record: EnrollmentRecord,
}

#[derive(Clone)]
pub enum EnrollmentRecord {
    New {
        name: String,
        tags: BTreeSet<String>,
        managed_by: Option<PrincipalId>,
    },
    Reenroll {
        node_id: NodeId,
    },
}

struct StoredApiLiveness {
    key_id: i64,
    verifier: Zeroizing<String>,
    principal_id: PrincipalId,
    expires_at_ms: Option<i64>,
    revoked_at_ms: Option<i64>,
}

/// Authenticate inside one read snapshot. Bearer bytes are never copied into
/// the output or handed to a write transaction.
pub fn authenticate_api(
    vault: &Vault,
    conn: &Connection,
    bearer: ParsedBearer<TokenId>,
    now_ms: i64,
) -> Result<AuthenticatedApi, CredentialError> {
    let ParsedBearer {
        id: token_id,
        secret,
    } = bearer;
    let canonical_id = token_id.to_string();
    let row = conn
        .prepare_cached(
            "SELECT t.key_id, t.verifier_hmac, t.principal_id, t.expires_at_ms, t.revoked_at_ms
             FROM auth_tokens t JOIN hub_meta h ON h.id = 1
             WHERE t.token_id = ?1 AND t.principal_id IS NOT h.gc_purging_principal_id",
        )?
        .query_row([&canonical_id], |row| {
            Ok(StoredApiLiveness {
                key_id: row.get(0)?,
                verifier: Zeroizing::new(row.get(1)?),
                principal_id: id(row, 2)?,
                expires_at_ms: row.get(3)?,
                revoked_at_ms: row.get(4)?,
            })
        })
        .optional()?;
    let row = verify_row(
        vault,
        CredentialFamily::Token,
        &canonical_id,
        &secret,
        row,
        |r| (r.key_id, &r.verifier),
    )?;
    let token = TokenScope {
        token_id,
        principal_id: row.principal_id,
        max_capability: None,
        allowed_profiles: None,
        allowed_nodes: None,
        withhold_sensitive: false,
        expires_at_ms: row.expires_at_ms,
        revoked_at_ms: row.revoked_at_ms,
    };
    if !token.is_active(now_ms) {
        return Err(CredentialError::Unauthenticated);
    }
    let context = active_principal_context(conn, token, now_ms)?;
    Ok(AuthenticatedApi {
        principal_id: context.caller.principal_id,
        principal_kind: context.caller.kind,
        credential: VerifiedCredential {
            id: token_id,
            key_id: ACTIVE_KEY_ID,
            verifier: row.verifier,
        },
    })
}

struct StoredApiFull {
    key_id: i64,
    verifier: Zeroizing<String>,
    principal_id: PrincipalId,
    label: String,
    max_capability: Option<Capability>,
    allowed_profiles_json: Option<String>,
    allowed_nodes_json: Option<String>,
    withhold_sensitive: bool,
    expires_at_ms: Option<i64>,
    revoked_at_ms: Option<i64>,
}

/// Recheck the bearer proof and reload the authorization context in the same
/// snapshot as the resource authorization or write.
pub fn refresh_api(
    conn: &Connection,
    credential: &VerifiedCredential<TokenId>,
    now_ms: i64,
) -> Result<AuthContext, CredentialError> {
    refresh_api_with_label(conn, credential, now_ms).map(|(ctx, _)| ctx)
}

pub(crate) fn refresh_api_with_label(
    conn: &Connection,
    credential: &VerifiedCredential<TokenId>,
    now_ms: i64,
) -> Result<(AuthContext, String), CredentialError> {
    let (context, label) = load_api_context(conn, credential, now_ms, true)?;
    Ok((context, label))
}

/// Invocation policy decides how much an agent with a disabled owner can see.
/// The credential is still rechecked before constructing this context.
pub(crate) fn refresh_invoke(
    conn: &Connection,
    credential: &VerifiedCredential<TokenId>,
    now_ms: i64,
) -> Result<AuthContext, CredentialError> {
    load_api_context(conn, credential, now_ms, false).map(|(ctx, _)| ctx)
}

fn load_api_context(
    conn: &Connection,
    credential: &VerifiedCredential<TokenId>,
    now_ms: i64,
    require_active: bool,
) -> Result<(AuthContext, String), CredentialError> {
    let token_id = credential.id();
    let row = conn
        .prepare_cached(
            "SELECT t.key_id, t.verifier_hmac, t.principal_id, t.label, t.max_capability,
                    t.allowed_profiles_json, t.allowed_nodes_json, t.withhold_sensitive,
                    t.expires_at_ms, t.revoked_at_ms
             FROM auth_tokens t JOIN hub_meta h ON h.id = 1
             WHERE t.token_id = ?1 AND t.principal_id IS NOT h.gc_purging_principal_id",
        )?
        .query_row([token_id.to_string()], |row| {
            Ok(StoredApiFull {
                key_id: row.get(0)?,
                verifier: Zeroizing::new(row.get(1)?),
                principal_id: id(row, 2)?,
                label: row.get(3)?,
                max_capability: optional_scalar(row, 4)?,
                allowed_profiles_json: row.get(5)?,
                allowed_nodes_json: row.get(6)?,
                withhold_sensitive: row.get(7)?,
                expires_at_ms: row.get(8)?,
                revoked_at_ms: row.get(9)?,
            })
        })
        .optional()?;
    let row = recheck_row(credential, row, |r| (r.key_id, &r.verifier))?;
    let token = TokenScope {
        token_id,
        principal_id: row.principal_id,
        max_capability: row.max_capability,
        allowed_profiles: decode_nullable_set(row.allowed_profiles_json.as_deref(), 5)?,
        allowed_nodes: decode_nullable_set(row.allowed_nodes_json.as_deref(), 6)?,
        withhold_sensitive: row.withhold_sensitive,
        expires_at_ms: row.expires_at_ms,
        revoked_at_ms: row.revoked_at_ms,
    };
    if !token.is_active(now_ms) {
        return Err(CredentialError::Unauthenticated);
    }
    let mut context = principal_context(conn, token, now_ms)?;
    if require_active {
        check_active(&context)?;
    }
    context.caller_grants = grant_views(conn, context.caller.principal_id)?;
    if let Some(owner) = &context.owner {
        context.owner_grants = grant_views(conn, owner.principal_id)?;
    }
    if let Some(manager) = &context.managed_by {
        context.managed_by_grants = grant_views(conn, manager.principal_id)?;
    }
    Ok((context, row.label))
}

struct StoredEnrollment {
    key_id: i64,
    verifier: Zeroizing<String>,
    issuer: PrincipalId,
    name: Option<String>,
    managed_by: Option<PrincipalId>,
    tags_json: String,
    node_id: Option<NodeId>,
    node_exists: bool,
    node_revoked_at_ms: Option<i64>,
    node_managed_by: Option<PrincipalId>,
    created_at_ms: i64,
    expires_at_ms: i64,
    revoked_at_ms: Option<i64>,
    consumed_at_ms: Option<i64>,
}

const ENROLLMENT_QUERY: &str = "SELECT e.key_id, e.verifier_hmac, e.created_by,
        e.target_node_name, e.managed_by_principal_id, e.tags_json, e.target_node_id,
        n.node_id IS NOT NULL, n.revoked_at_ms, n.managed_by_principal_id,
        e.created_at_ms, e.expires_at_ms, e.revoked_at_ms, e.consumed_at_ms
     FROM node_enrollments e LEFT JOIN nodes n ON n.node_id = e.target_node_id
     WHERE e.enrollment_id = ?1";

fn read_enrollment(
    conn: &Connection,
    enrollment_id: &str,
) -> Result<Option<StoredEnrollment>, CredentialError> {
    Ok(conn
        .prepare_cached(ENROLLMENT_QUERY)?
        .query_row([enrollment_id], |row| {
            Ok(StoredEnrollment {
                key_id: row.get(0)?,
                verifier: Zeroizing::new(row.get(1)?),
                issuer: id(row, 2)?,
                name: row.get(3)?,
                managed_by: opt_id(row, 4)?,
                tags_json: row.get(5)?,
                node_id: opt_id(row, 6)?,
                node_exists: row.get(7)?,
                node_revoked_at_ms: row.get(8)?,
                node_managed_by: opt_id(row, 9)?,
                created_at_ms: row.get(10)?,
                expires_at_ms: row.get(11)?,
                revoked_at_ms: row.get(12)?,
                consumed_at_ms: row.get(13)?,
            })
        })
        .optional()?)
}

pub fn authenticate_enrollment(
    vault: &Vault,
    conn: &Connection,
    bearer: ParsedBearer<EnrollmentId>,
    now_ms: i64,
) -> Result<AuthenticatedEnrollment, CredentialError> {
    let ParsedBearer {
        id: enrollment_id,
        secret,
    } = bearer;
    let canonical_id = enrollment_id.to_string();
    let row = read_enrollment(conn, &canonical_id)?;
    let mut row = verify_row(
        vault,
        CredentialFamily::Enrollment,
        &canonical_id,
        &secret,
        row,
        |r| (r.key_id, &r.verifier),
    )?;
    let verifier = std::mem::take(&mut row.verifier);
    let record = validate_enrollment_row(conn, row, now_ms)?;
    Ok(AuthenticatedEnrollment {
        credential: VerifiedCredential {
            id: enrollment_id,
            key_id: ACTIVE_KEY_ID,
            verifier,
        },
        record,
    })
}

pub fn recheck_enrollment(
    conn: &Connection,
    credential: &VerifiedCredential<EnrollmentId>,
    now_ms: i64,
) -> Result<EnrollmentRecord, CredentialError> {
    let row = read_enrollment(conn, &credential.id().to_string())?;
    let row = recheck_row(credential, row, |r| (r.key_id, &r.verifier))?;
    validate_enrollment_row(conn, row, now_ms)
}

fn validate_enrollment_row(
    conn: &Connection,
    row: StoredEnrollment,
    now_ms: i64,
) -> Result<EnrollmentRecord, CredentialError> {
    if row.expires_at_ms <= now_ms || row.revoked_at_ms.is_some() || row.consumed_at_ms.is_some() {
        return Err(CredentialError::Unauthenticated);
    }
    if row.node_id.is_some()
        && (!row.node_exists
            || row
                .node_revoked_at_ms
                .is_some_and(|revoked_at| row.created_at_ms <= revoked_at))
    {
        return Err(CredentialError::Unauthenticated);
    }
    let tags: BTreeSet<String> = serde_json::from_str(&row.tags_json)
        .map_err(|_| StorageError::InvalidDatabase("invalid enrollment tags"))?;

    let issuer = read_principal(conn, row.issuer)?
        .filter(|issuer| issuer.disabled_at_ms.is_none())
        .ok_or(CredentialError::Unauthenticated)?;

    let admin = issuer.kind == PrincipalKind::Admin
        && grant_views(conn, issuer.principal_id)?.contains(&GrantView {
            scope: GrantScope::Global,
            capability: Capability::Admin,
        });
    match (row.name, row.node_id) {
        (Some(name), None)
            if (admin && row.managed_by.is_none())
                || (issuer.is_orchestrator
                    && row.managed_by == Some(issuer.principal_id)
                    && tags.is_subset(&issuer.allowed_node_tags)) =>
        {
            Ok(EnrollmentRecord::New {
                name,
                tags,
                managed_by: row.managed_by,
            })
        }
        (None, Some(node_id)) if admin && manager_is_active(conn, row.node_managed_by)? => {
            Ok(EnrollmentRecord::Reenroll { node_id })
        }
        _ => Err(CredentialError::Unauthenticated),
    }
}

struct StoredNodeCredential {
    key_id: i64,
    verifier: Zeroizing<String>,
    revoked_at_ms: Option<i64>,
    managed_by: Option<PrincipalId>,
}

const NODE_QUERY: &str = "SELECT key_id, credential_hmac, revoked_at_ms, managed_by_principal_id
     FROM nodes WHERE node_id = ?1";

fn read_node_credential(
    conn: &Connection,
    node_id: &str,
) -> Result<Option<StoredNodeCredential>, CredentialError> {
    Ok(conn
        .prepare_cached(NODE_QUERY)?
        .query_row([node_id], |row| {
            Ok(StoredNodeCredential {
                key_id: row.get(0)?,
                verifier: Zeroizing::new(row.get(1)?),
                revoked_at_ms: row.get(2)?,
                managed_by: opt_id(row, 3)?,
            })
        })
        .optional()?)
}

pub fn authenticate_node(
    vault: &Vault,
    conn: &Connection,
    bearer: ParsedBearer<NodeId>,
) -> Result<VerifiedCredential<NodeId>, CredentialError> {
    let ParsedBearer {
        id: node_id,
        secret,
    } = bearer;
    let canonical_id = node_id.to_string();
    let row = read_node_credential(conn, &canonical_id)?;
    let row = verify_row(
        vault,
        CredentialFamily::Node,
        &canonical_id,
        &secret,
        row,
        |r| (r.key_id, &r.verifier),
    )?;
    validate_node_row(conn, &row)?;
    Ok(VerifiedCredential {
        id: node_id,
        key_id: ACTIVE_KEY_ID,
        verifier: row.verifier,
    })
}

#[allow(dead_code, reason = "node bridge handshake CAS seam for #7")]
pub fn recheck_node(
    conn: &Connection,
    credential: &VerifiedCredential<NodeId>,
) -> Result<(), CredentialError> {
    let row = read_node_credential(conn, &credential.id().to_string())?;
    let row = recheck_row(credential, row, |r| (r.key_id, &r.verifier))?;
    validate_node_row(conn, &row)
}

fn validate_node_row(conn: &Connection, row: &StoredNodeCredential) -> Result<(), CredentialError> {
    if row.revoked_at_ms.is_some() {
        return Err(CredentialError::Unauthenticated);
    }
    if !manager_is_active(conn, row.managed_by)? {
        return Err(AuthzError::ManagedByDisabled.into());
    }
    Ok(())
}

fn active_principal_context(
    conn: &Connection,
    token: TokenScope,
    now_ms: i64,
) -> Result<AuthContext, CredentialError> {
    let context = principal_context(conn, token, now_ms)?;
    check_active(&context)?;
    Ok(context)
}

fn principal_context(
    conn: &Connection,
    token: TokenScope,
    now_ms: i64,
) -> Result<AuthContext, CredentialError> {
    let caller =
        read_principal(conn, token.principal_id)?.ok_or(CredentialError::Unauthenticated)?;
    Ok(AuthContext {
        owner: load_parent(conn, caller.owner_principal_id)?,
        managed_by: load_parent(conn, caller.managed_by_principal_id)?,
        caller,
        token,
        caller_grants: Vec::new(),
        owner_grants: Vec::new(),
        managed_by_grants: Vec::new(),
        now_ms,
    })
}

fn load_parent(
    conn: &Connection,
    parent: Option<PrincipalId>,
) -> Result<Option<efferian_authz::PrincipalView>, StorageError> {
    parent
        .map(|parent| read_principal(conn, parent))
        .transpose()
        .map(Option::flatten)
}

pub fn grant_views(
    conn: &Connection,
    principal: PrincipalId,
) -> Result<Vec<GrantView>, CredentialError> {
    let mut stmt = conn.prepare_cached(
        "SELECT g.scope_kind, g.scope_id, g.capability FROM grants g
         JOIN hub_meta h ON h.id = 1
         WHERE g.principal_id = ?1 AND g.principal_id IS NOT h.gc_purging_principal_id",
    )?;
    Ok(stmt
        .query_map([principal.to_string()], |row| {
            Ok(GrantView {
                scope: read_grant_scope(row, 0, 1)?,
                capability: scalar::<Capability>(row, 2)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?)
}

fn decode_nullable_set<T>(raw: Option<&str>, column: usize) -> rusqlite::Result<Option<BTreeSet<T>>>
where
    T: Ord + serde::de::DeserializeOwned,
{
    let Some(raw) = raw else {
        return Ok(None);
    };
    let values: Vec<T> = serde_json::from_str(raw)
        .map_err(|_| invalid_text_msg(column, "invalid token scope JSON"))?;
    let count = values.len();
    let set: BTreeSet<_> = values.into_iter().collect();
    if count != set.len() {
        return Err(invalid_text_msg(column, "duplicate token scope entry"));
    }
    Ok(Some(set))
}

fn manager_is_active(
    conn: &Connection,
    manager: Option<PrincipalId>,
) -> Result<bool, StorageError> {
    match manager {
        Some(manager) => Ok(principal_liveness(conn, manager)? == PrincipalLiveness::Enabled),
        None => Ok(true),
    }
}

fn verify_row<T>(
    vault: &Vault,
    family: CredentialFamily,
    canonical_id: &str,
    secret: &SecretBytes,
    row: Option<T>,
    extract: impl FnOnce(&T) -> (i64, &Zeroizing<String>),
) -> Result<T, CredentialError> {
    // With a single active key, real and dummy checks both use that family's
    // key. Keep the MAC and constant-time comparison on every parsed bearer.
    let mut decoded = Zeroizing::new([0; 32]);
    let known = row.as_ref().is_some_and(|row| {
        let (key_id, verifier) = extract(row);
        u16::try_from(key_id) == Ok(ACTIVE_KEY_ID) && decode_hex(verifier, &mut decoded).is_some()
    });
    let expected = if known {
        decoded.as_slice()
    } else {
        &DUMMY_VERIFIER
    };
    let computed = vault.keys.compute_verifier(family, canonical_id, secret)?;
    let matched = Choice::from(u8::from(known)) & computed.as_slice().ct_eq(expected);
    #[cfg(test)]
    MAC_CHECKS.with(|checks| checks.set(checks.get() + 1));
    row.filter(|_| bool::from(matched))
        .ok_or(CredentialError::Unauthenticated)
}

fn recheck_row<Id: Copy, T>(
    credential: &VerifiedCredential<Id>,
    row: Option<T>,
    extract: impl FnOnce(&T) -> (i64, &Zeroizing<String>),
) -> Result<T, CredentialError> {
    let row = row.ok_or(CredentialError::Unauthenticated)?;
    let (key_id, verifier) = extract(&row);
    if u16::try_from(key_id) != Ok(credential.key_id())
        || !bool::from(verifier.as_bytes().ct_eq(credential.verifier().as_bytes()))
    {
        return Err(CredentialError::Unauthenticated);
    }
    Ok(row)
}

pub struct ParsedBearer<Id> {
    id: Id,
    secret: SecretBytes,
}

impl<Id: fmt::Debug> fmt::Debug for ParsedBearer<Id> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedBearer")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl<Id: FromStr> ParsedBearer<Id> {
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, CredentialError> {
        let (id, secret) = parse_bearer(headers).ok_or(CredentialError::Unauthenticated)?;
        Ok(Self { id, secret })
    }
}

fn parse_bearer<Id: FromStr>(headers: &HeaderMap) -> Option<(Id, SecretBytes)> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next()?;
    if value.len() > MAX_AUTHORIZATION_BYTES || values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.to_str().ok()?.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let (id, encoded_secret) = token.strip_prefix("eff_")?.split_once('.')?;
    let id = id.parse().ok()?;
    let mut secret = Zeroizing::new([0; 32]);
    decode_hex(encoded_secret, &mut secret)?;
    Some((id, secret))
}

fn decode_hex(input: &str, output: &mut [u8; 32]) -> Option<()> {
    if input.len() != 64 {
        return None;
    }
    fn digit(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }
    let (pairs, _) = input.as_bytes().as_chunks::<2>();
    for (byte, &[high, low]) in output.iter_mut().zip(pairs) {
        *byte = (digit(high)? << 4) | digit(low)?;
    }
    Some(())
}

#[cfg(test)]
thread_local! {
    static MAC_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
mod tests;
