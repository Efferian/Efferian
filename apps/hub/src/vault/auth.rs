//! Credential authentication for Hub API requests, node enrollments and bridges.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use efferian_authz::{AuthContext, AuthzError, GrantView, TokenScope, check_active};
use efferian_protocol::{
    Capability, EnrollmentId, GrantScope, NodeId, PrincipalId, PrincipalKind, ProfileId, TokenId,
};
use http::{HeaderMap, header::AUTHORIZATION};
use rusqlite::{Connection, OptionalExtension, Row, types::ValueRef};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

use super::{ACTIVE_KEY_ID, CredentialFamily, SecretBytes, Vault, VaultError};
use crate::storage::{
    PrincipalLiveness, StorageError, id, json, opt_id, principal_liveness, read_principal, scalar,
};

const MAX_AUTHORIZATION_BYTES: usize = 512;
const DUMMY_VERIFIER: [u8; 32] = [0; 32];
const API_VERIFIER_QUERY: &str =
    "SELECT t.key_id, t.verifier_hmac FROM auth_tokens t JOIN hub_meta h ON h.id = 1
     WHERE t.token_id = ?1 AND t.principal_id IS NOT h.gc_purging_principal_id";
const ENROLLMENT_VERIFIER_QUERY: &str =
    "SELECT key_id, verifier_hmac FROM node_enrollments WHERE enrollment_id = ?1";
const NODE_VERIFIER_QUERY: &str = "SELECT key_id, credential_hmac FROM nodes WHERE node_id = ?1";

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
    verifier: String,
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

/// Authenticate inside one read snapshot. Bearer bytes are never copied into
/// the output or handed to a write transaction.
pub fn authenticate_api(
    vault: &Vault,
    conn: &Connection,
    bearer: ParsedBearer<TokenId>,
    now_ms: i64,
) -> Result<AuthenticatedApi, CredentialError> {
    let credential = verify(
        vault,
        conn,
        bearer,
        CredentialFamily::Token,
        API_VERIFIER_QUERY,
    )?;
    let context = active_api_context(conn, credential.id(), now_ms)?;
    Ok(AuthenticatedApi {
        principal_id: context.caller.principal_id,
        credential,
    })
}

/// Recheck the bearer proof and reload the authorization context in the same
/// snapshot as the resource authorization or write.
pub fn refresh_api(
    conn: &Connection,
    credential: &VerifiedCredential<TokenId>,
    now_ms: i64,
) -> Result<AuthContext, CredentialError> {
    recheck_verifier(conn, credential, API_VERIFIER_QUERY)?;
    let mut context = active_api_context(conn, credential.id(), now_ms)?;
    context.caller_grants = grant_views(conn, context.caller.principal_id)?;
    if let Some(owner) = &context.owner {
        context.owner_grants = grant_views(conn, owner.principal_id)?;
    }
    if let Some(manager) = &context.managed_by {
        context.managed_by_grants = grant_views(conn, manager.principal_id)?;
    }
    Ok(context)
}

pub fn authenticate_enrollment(
    vault: &Vault,
    conn: &Connection,
    bearer: ParsedBearer<EnrollmentId>,
    now_ms: i64,
) -> Result<AuthenticatedEnrollment, CredentialError> {
    let credential = verify(
        vault,
        conn,
        bearer,
        CredentialFamily::Enrollment,
        ENROLLMENT_VERIFIER_QUERY,
    )?;
    let record = active_enrollment(conn, credential.id(), now_ms)?;
    Ok(AuthenticatedEnrollment { credential, record })
}

pub fn recheck_enrollment(
    conn: &Connection,
    credential: &VerifiedCredential<EnrollmentId>,
    now_ms: i64,
) -> Result<EnrollmentRecord, CredentialError> {
    recheck_verifier(conn, credential, ENROLLMENT_VERIFIER_QUERY)?;
    active_enrollment(conn, credential.id(), now_ms)
}

pub fn authenticate_node(
    vault: &Vault,
    conn: &Connection,
    bearer: ParsedBearer<NodeId>,
) -> Result<VerifiedCredential<NodeId>, CredentialError> {
    let credential = verify(
        vault,
        conn,
        bearer,
        CredentialFamily::Node,
        NODE_VERIFIER_QUERY,
    )?;
    check_active_node(conn, credential.id())?;
    Ok(credential)
}

pub fn recheck_node(
    conn: &Connection,
    credential: &VerifiedCredential<NodeId>,
) -> Result<(), CredentialError> {
    recheck_verifier(conn, credential, NODE_VERIFIER_QUERY)?;
    check_active_node(conn, credential.id())
}

fn active_api_context(
    conn: &Connection,
    token_id: TokenId,
    now_ms: i64,
) -> Result<AuthContext, CredentialError> {
    let mut stmt = conn.prepare_cached(
        "SELECT t.principal_id, t.max_capability, t.allowed_profiles_json,
                t.allowed_nodes_json, t.withhold_sensitive, t.expires_at_ms, t.revoked_at_ms
         FROM auth_tokens t JOIN hub_meta h ON h.id = 1
         WHERE t.token_id = ?1 AND t.principal_id IS NOT h.gc_purging_principal_id",
    )?;
    let token = stmt
        .query_row([token_id.to_string()], |row| {
            Ok(TokenScope {
                token_id,
                principal_id: id(row, 0)?,
                max_capability: optional_scalar(row, 1)?,
                allowed_profiles: nullable_set(row, 2)?,
                allowed_nodes: nullable_set(row, 3)?,
                withhold_sensitive: row.get(4)?,
                expires_at_ms: row.get(5)?,
                revoked_at_ms: row.get(6)?,
            })
        })
        .optional()?
        .filter(|token| token.is_active(now_ms))
        .ok_or(CredentialError::Unauthenticated)?;

    let caller =
        read_principal(conn, token.principal_id)?.ok_or(CredentialError::Unauthenticated)?;
    let context = AuthContext {
        owner: load_parent(conn, caller.owner_principal_id)?,
        managed_by: load_parent(conn, caller.managed_by_principal_id)?,
        caller,
        token,
        caller_grants: Vec::new(),
        owner_grants: Vec::new(),
        managed_by_grants: Vec::new(),
        now_ms,
    };
    check_active(&context)?;
    Ok(context)
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

pub(crate) fn read_grant_scope(
    row: &Row<'_>,
    kind_column: usize,
    id_column: usize,
) -> rusqlite::Result<GrantScope> {
    match row.get_ref(kind_column)?.as_str()? {
        "global" if row.get_ref(id_column)?.as_str()?.is_empty() => Ok(GrantScope::Global),
        "profile" => id::<ProfileId>(row, id_column).map(GrantScope::Profile),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

pub(crate) fn optional_scalar<T: serde::de::DeserializeOwned>(
    row: &Row<'_>,
    column: usize,
) -> rusqlite::Result<Option<T>> {
    if row.get_ref(column)? == ValueRef::Null {
        Ok(None)
    } else {
        scalar(row, column).map(Some)
    }
}

pub(crate) fn optional_json<T: serde::de::DeserializeOwned>(
    row: &Row<'_>,
    column: usize,
) -> rusqlite::Result<Option<T>> {
    if row.get_ref(column)? == ValueRef::Null {
        Ok(None)
    } else {
        json(row, column).map(Some)
    }
}

fn nullable_set<T>(row: &Row<'_>, column: usize) -> rusqlite::Result<Option<BTreeSet<T>>>
where
    T: Ord + serde::de::DeserializeOwned,
{
    let Some(values): Option<Vec<T>> = optional_json(row, column)? else {
        return Ok(None);
    };
    let count = values.len();
    let set: BTreeSet<_> = values.into_iter().collect();
    if count != set.len() {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(Some(set))
}

struct PendingEnrollment {
    issuer: PrincipalId,
    name: Option<String>,
    managed_by: Option<PrincipalId>,
    tags: BTreeSet<String>,
    node_id: Option<NodeId>,
    node_managed_by: Option<PrincipalId>,
}

fn active_enrollment(
    conn: &Connection,
    enrollment_id: EnrollmentId,
    now_ms: i64,
) -> Result<EnrollmentRecord, CredentialError> {
    let row = conn
        .prepare_cached(
            "SELECT e.created_by, e.target_node_name, e.managed_by_principal_id,
                e.tags_json, e.target_node_id, n.managed_by_principal_id
         FROM node_enrollments e LEFT JOIN nodes n ON n.node_id = e.target_node_id
         WHERE e.enrollment_id = ?1 AND e.expires_at_ms > ?2
           AND e.revoked_at_ms IS NULL AND e.consumed_at_ms IS NULL
           AND (e.target_node_id IS NULL OR (n.node_id IS NOT NULL
                AND (n.revoked_at_ms IS NULL OR e.created_at_ms > n.revoked_at_ms)))",
        )?
        .query_row(
            rusqlite::params![enrollment_id.to_string(), now_ms],
            |row| {
                Ok(PendingEnrollment {
                    issuer: id(row, 0)?,
                    name: row.get(1)?,
                    managed_by: opt_id(row, 2)?,
                    tags: json(row, 3)?,
                    node_id: opt_id(row, 4)?,
                    node_managed_by: opt_id(row, 5)?,
                })
            },
        )
        .optional()?
        .ok_or(CredentialError::Unauthenticated)?;

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
                    && row.tags.is_subset(&issuer.allowed_node_tags)) =>
        {
            Ok(EnrollmentRecord::New {
                name,
                tags: row.tags,
                managed_by: row.managed_by,
            })
        }
        (None, Some(node_id)) if admin && manager_is_active(conn, row.node_managed_by)? => {
            Ok(EnrollmentRecord::Reenroll { node_id })
        }
        _ => Err(CredentialError::Unauthenticated),
    }
}

fn check_active_node(conn: &Connection, node_id: NodeId) -> Result<(), CredentialError> {
    let manager = conn.prepare_cached(
        "SELECT managed_by_principal_id FROM nodes WHERE node_id = ?1 AND revoked_at_ms IS NULL",
    )?.query_row([node_id.to_string()], |row| opt_id(row, 0))
      .optional()?.ok_or(CredentialError::Unauthenticated)?;
    if !manager_is_active(conn, manager)? {
        return Err(AuthzError::ManagedByDisabled.into());
    }
    Ok(())
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

struct StoredVerifier {
    key_id: i64,
    text: String,
}

fn read_verifier(
    conn: &Connection,
    query: &str,
    id: &str,
) -> Result<Option<StoredVerifier>, CredentialError> {
    Ok(conn
        .prepare_cached(query)?
        .query_row([id], |row| {
            Ok(StoredVerifier {
                key_id: row.get(0)?,
                text: row.get(1)?,
            })
        })
        .optional()?)
}

fn verify<Id: fmt::Display>(
    vault: &Vault,
    conn: &Connection,
    bearer: ParsedBearer<Id>,
    family: CredentialFamily,
    query: &str,
) -> Result<VerifiedCredential<Id>, CredentialError> {
    let ParsedBearer { id, secret } = bearer;
    let canonical_id = id.to_string();
    let row = read_verifier(conn, query, &canonical_id)?;

    // With a single active key, real and dummy checks both use that family's
    // key. Keep the MAC and constant-time comparison on every parsed bearer.
    let mut decoded = [0; 32];
    let known = row.as_ref().is_some_and(|verifier| {
        u16::try_from(verifier.key_id) == Ok(ACTIVE_KEY_ID)
            && decode_hex(&verifier.text, &mut decoded).is_some()
    });
    let expected = if known { &decoded } else { &DUMMY_VERIFIER };
    let computed = vault
        .keys
        .compute_verifier(family, &canonical_id, &secret)?;
    let matched = Choice::from(u8::from(known)) & computed.as_slice().ct_eq(expected);
    #[cfg(test)]
    MAC_CHECKS.with(|checks| checks.set(checks.get() + 1));
    let row = row
        .filter(|_| bool::from(matched))
        .ok_or(CredentialError::Unauthenticated)?;
    Ok(VerifiedCredential {
        id,
        key_id: ACTIVE_KEY_ID,
        verifier: row.text,
    })
}

fn recheck_verifier<Id: fmt::Display>(
    conn: &Connection,
    credential: &VerifiedCredential<Id>,
    query: &str,
) -> Result<(), CredentialError> {
    let row = read_verifier(conn, query, &credential.id.to_string())?
        .filter(|row| u16::try_from(row.key_id) == Ok(credential.key_id))
        .ok_or(CredentialError::Unauthenticated)?;
    if !bool::from(row.text.as_bytes().ct_eq(credential.verifier.as_bytes())) {
        return Err(CredentialError::Unauthenticated);
    }
    Ok(())
}

pub struct ParsedBearer<Id> {
    id: Id,
    secret: SecretBytes,
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
