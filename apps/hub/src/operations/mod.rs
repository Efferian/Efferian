//! Local initialization, break-glass token issuance, and online backups.

mod output;

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use efferian_authz::{AuthContext, TokenScope, authorize_admin};
use efferian_platform::{PlatformError, PrivateFs};
use efferian_protocol::{
    GrantId, HubId, PrincipalId, PrincipalKind, TokenId, validate_resource_name,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use zeroize::Zeroizing;

use crate::storage::{
    self, OpenMode, OpenedDb, StorageClock, StorageConfig, StorageError, SystemStorageClock,
    WalCheckpointOutcome, WriteError,
};
use crate::vault::auth::{CredentialError, grant_views};
use crate::vault::{IssuedCredential, Vault, VaultError, VaultKeys};

use output::{FileOutput, TokenOutputPlan, absent, publish_private_file};

const DATABASE: &str = "hub.sqlite3";
const MASTER_KEY: &str = "hub.master.key";
const STAGING: &str = ".staging-hub-init";
const SIDECARS: [&str; 3] = ["hub.sqlite3-wal", "hub.sqlite3-shm", "hub.sqlite3-journal"];
const RESERVED: [&str; 7] = [
    DATABASE,
    SIDECARS[0],
    SIDECARS[1],
    SIDECARS[2],
    MASTER_KEY,
    "hub.lock",
    STAGING,
];

#[derive(Debug, thiserror::Error)]
pub enum OperationError {
    #[error("invalid principal name")]
    InvalidPrincipalName,
    #[error("invalid token label")]
    InvalidTokenLabel,
    #[error("max_active_tokens_per_principal must be positive")]
    InvalidTokenLimit,
    #[error("principal does not exist")]
    PrincipalNotFound,
    #[error("principal must be an active human administrator with a global admin grant")]
    PrincipalNotAdmin,
    #[error("principal is at or above the active token limit")]
    TokenQuotaExceeded,
    #[error("state directory must already exist and be a directory")]
    InvalidExistingStateDir,
    #[error("hub.master.key already exists")]
    MasterKeyExists,
    #[error("hub.master.key must contain exactly 32 bytes")]
    MasterKeyLength,
    #[error("could not generate a master key")]
    KeyRandomness,
    #[error("invalid output path {path:?}: {reason}")]
    InvalidOutput { path: PathBuf, reason: &'static str },
    #[error("{action} {path:?}: {source}")]
    PathIo {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not write the token to stdout: {0}")]
    Stdout(#[source] io::Error),
    #[error(
        "the database may have been published, but durability is unknown; inspect the state and use admin create-token if the Hub database is present: {0}"
    )]
    InitDurabilityUnknown(#[source] io::Error),
    #[error(
        "Hub was initialized, but token output failed; recover access with admin create-token: {0}"
    )]
    InitOutput(#[source] Box<Self>),
    #[error(
        "the new token was committed, but token output failed; use admin create-token to recover and revoke the undelivered token: {0}"
    )]
    MintOutput(#[source] Box<Self>),
    #[error("token commit outcome is unknown; check the stored tokens before retrying")]
    TokenCommitUnknown,
    #[error("transaction aborted before commit")]
    TransactionAborted,
    #[error(
        "output {target:?} was published with two links (nlink == 2), but removing temporary file {temporary:?} failed; remove the temporary link: {source}"
    )]
    PublishedWithTemporary {
        target: PathBuf,
        temporary: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "output {target:?} was published and temporary file {temporary:?} was removed, but directory sync failed; crash durability is unknown: {source}"
    )]
    PublishedDurabilityUnknown {
        target: PathBuf,
        temporary: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Platform(#[from] PlatformError),
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error(transparent)]
    CredentialProjection(#[from] CredentialError),
}

impl From<WriteError<Self>> for OperationError {
    fn from(error: WriteError<Self>) -> Self {
        match error {
            WriteError::Storage(StorageError::PublishedDurabilityUnknown(source)) => {
                Self::InitDurabilityUnknown(source)
            }
            WriteError::Storage(error) => Self::Storage(error),
            WriteError::PreCommitAborted => Self::TransactionAborted,
            WriteError::CommitOutcomeUnknown => Self::TokenCommitUnknown,
            WriteError::Domain(error) => error,
        }
    }
}

pub fn init(
    state_dir: &Path,
    admin_name: &str,
    out: &Path,
    storage_config: &StorageConfig,
) -> Result<(), OperationError> {
    validate_resource_name(admin_name).map_err(|_| OperationError::InvalidPrincipalName)?;
    storage_config.validate()?;
    let clock = SystemStorageClock::new()?;
    let mut lock = storage::acquire_state_lock(state_dir)?;
    preflight_init(lock.path())?;
    let output = TokenOutputPlan::preflight(lock.path(), out)?.reserve()?;

    let mut master_key = Zeroizing::new([0; 32]);
    getrandom::fill(master_key.as_mut()).map_err(|_| OperationError::KeyRandomness)?;
    publish_private_file(lock.path(), MASTER_KEY, master_key.as_ref())?;

    let keys = VaultKeys::derive(master_key)?;
    let admin_id = PrincipalId::new_for_kind(PrincipalKind::Admin);
    let token_id = TokenId::new_for_kind(PrincipalKind::Admin);
    let credential = keys.issue_token(token_id)?;
    storage::create_staged(
        &mut lock,
        keys.new_hub_identity(HubId::new()),
        storage_config,
        &clock,
        |tx| -> Result<(), OperationError> {
            let now_ms = tx.query_row(
                "SELECT created_at_ms FROM hub_meta WHERE id = 1",
                [],
                |row| row.get::<_, i64>(0),
            )?;
            tx.execute(
                "INSERT INTO principals(principal_id, kind, name, created_at_ms, updated_at_ms)
                 VALUES (?1, 'admin', ?2, ?3, ?3)",
                params![admin_id.to_string(), admin_name, now_ms],
            )?;
            tx.execute(
                "INSERT INTO grants(grant_id, principal_id, scope_kind, scope_id, capability,
                                    created_by, created_at_ms)
                 VALUES (?1, ?2, 'global', '', 'admin', ?2, ?3)",
                params![GrantId::new().to_string(), admin_id.to_string(), now_ms],
            )?;
            insert_admin_token(tx, admin_id, token_id, &credential, "bootstrap", now_ms)?;
            Ok(())
        },
    )?;

    output
        .write(&credential.secret)
        .map_err(|error| OperationError::InitOutput(Box::new(error)))
}

pub fn open_existing(
    state_dir: &Path,
    mode: OpenMode,
    config: &StorageConfig,
    clock: Arc<dyn StorageClock>,
) -> Result<(OpenedDb, Arc<Vault>), OperationError> {
    config.validate()?;
    existing_state_dir(state_dir)?;
    for name in [DATABASE, MASTER_KEY] {
        let path = state_dir.join(name);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| path_io("inspect first-run state", &path, error))?;
        if !metadata.is_file() {
            return Err(OperationError::InvalidOutput {
                path,
                reason: "expected a regular file",
            });
        }
    }
    let lock = storage::acquire_state_lock(state_dir)?;
    let bytes = Zeroizing::new(PrivateFs::read_private_file(
        &lock.path().join(MASTER_KEY),
        32,
    )?);
    let mut master_key = Zeroizing::new([0; 32]);
    if bytes.len() != master_key.len() {
        return Err(OperationError::MasterKeyLength);
    }
    master_key.copy_from_slice(&bytes);
    drop(bytes);
    let keys = VaultKeys::derive(master_key)?;
    let opened = storage::open_existing(lock, mode, keys.expected_hub_identity(), config, clock)?;
    let vault = Arc::new(keys.bind_hub(*opened.hub_id()));
    Ok((opened, vault))
}

pub fn create_token(
    state_dir: &Path,
    principal: &str,
    out: &Path,
    label: &str,
    storage_config: &StorageConfig,
    max_active_tokens: usize,
) -> Result<(), OperationError> {
    validate_resource_name(principal).map_err(|_| OperationError::InvalidPrincipalName)?;
    let label = normalize_token_label(label).ok_or(OperationError::InvalidTokenLabel)?;
    if max_active_tokens == 0 {
        return Err(OperationError::InvalidTokenLimit);
    }
    existing_state_dir(state_dir)?;
    let output_plan = TokenOutputPlan::preflight(state_dir, out)?;
    let clock: Arc<dyn StorageClock> = Arc::new(SystemStorageClock::new()?);
    let (opened, vault) = open_existing(
        state_dir,
        OpenMode::OfflineExactVersion,
        storage_config,
        Arc::clone(&clock),
    )?;
    let output = output_plan.reserve()?;
    let token_id = TokenId::new_for_kind(PrincipalKind::Admin);
    let credential = vault.issue_token(token_id)?;
    let outcome = opened.run_offline_tx(|tx| -> Result<(), OperationError> {
        let now_ms = clock.wall_now_ms();
        let principal_id = recover_admin(tx, principal, token_id, now_ms)?;
        if active_token_count(tx, principal_id, now_ms)? >= max_active_tokens {
            return Err(OperationError::TokenQuotaExceeded);
        }
        insert_admin_token(tx, principal_id, token_id, &credential, label, now_ms)?;
        Ok(())
    })?;

    let published = output.write(&credential.secret);
    if !matches!(outcome.checkpoint, WalCheckpointOutcome::Truncated) {
        let _ = writeln!(
            io::stderr().lock(),
            "Warning: token committed, but WAL checkpoint did not complete: {:?}",
            outcome.checkpoint,
        );
    }
    published.map_err(|error| OperationError::MintOutput(Box::new(error)))
}

pub fn snapshot(state_dir: &Path, out: &Path) -> Result<(), OperationError> {
    existing_state_dir(state_dir)?;
    let output = FileOutput::preflight(state_dir, out)?;
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let conn = Connection::open_with_flags(state_dir.join(DATABASE), flags)?;
    conn.busy_timeout(Duration::from_secs(5))?;

    let _: HubId = conn.query_row("SELECT hub_id FROM hub_meta WHERE id = 1", [], |row| {
        storage::id(row, 0)
    })?;

    let temporary = output.reserve()?;
    conn.execute("VACUUM INTO ?1", [temporary.utf8_path()?])?;
    conn.close().map_err(|(_, error)| error)?;
    temporary.publish(output)
}

fn preflight_init(state_dir: &Path) -> Result<(), OperationError> {
    if !absent(&state_dir.join(DATABASE))? {
        return Err(StorageError::AlreadyInitialized.into());
    }
    if !absent(&state_dir.join(MASTER_KEY))? {
        return Err(OperationError::MasterKeyExists);
    }
    for name in SIDECARS {
        if !absent(&state_dir.join(name))? {
            return Err(StorageError::SidecarConflict(name).into());
        }
    }
    let path = state_dir.join(STAGING);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(StorageError::SidecarConflict(STAGING).into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(path_io("inspect staging directory", &path, error)),
    }
}

fn existing_state_dir(state_dir: &Path) -> Result<(), OperationError> {
    use std::os::unix::ffi::OsStrExt;
    let raw = state_dir.as_os_str().as_bytes();
    let trimmed = if raw.iter().all(|&b| b == b'/') {
        if raw.is_empty() { raw } else { b"/" }
    } else {
        let end = raw
            .iter()
            .rposition(|&b| b != b'/')
            .map_or(0, |index| index + 1);
        &raw[..end]
    };
    let check_path = Path::new(std::ffi::OsStr::from_bytes(trimmed));
    match fs::symlink_metadata(check_path) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(OperationError::InvalidExistingStateDir),
        Err(error) => Err(path_io(
            "inspect existing state directory",
            state_dir,
            error,
        )),
    }
}

fn recover_admin(
    conn: &Connection,
    name: &str,
    token_id: TokenId,
    now_ms: i64,
) -> Result<PrincipalId, OperationError> {
    let raw_id = conn
        .query_row(
            "SELECT p.principal_id FROM principals p JOIN hub_meta h ON h.id = 1
             WHERE p.name = ?1 AND p.principal_id IS NOT h.gc_purging_principal_id",
            [name],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(OperationError::PrincipalNotFound)?;
    let principal_id = raw_id
        .parse::<PrincipalId>()
        .map_err(|_| StorageError::InvalidDatabase("invalid principal ID"))?;
    let caller =
        storage::read_principal(conn, principal_id)?.ok_or(OperationError::PrincipalNotFound)?;
    if caller.kind != PrincipalKind::Admin || caller.disabled_at_ms.is_some() {
        return Err(OperationError::PrincipalNotAdmin);
    }
    let context = AuthContext {
        caller,
        token: TokenScope {
            token_id,
            principal_id,
            max_capability: None,
            allowed_profiles: None,
            allowed_nodes: None,
            withhold_sensitive: false,
            expires_at_ms: None,
            revoked_at_ms: None,
        },
        caller_grants: grant_views(conn, principal_id)?,
        owner: None,
        owner_grants: Vec::new(),
        managed_by: None,
        managed_by_grants: Vec::new(),
        now_ms,
    };
    authorize_admin(&context).map_err(|_| OperationError::PrincipalNotAdmin)?;
    Ok(principal_id)
}

fn insert_admin_token(
    conn: &Connection,
    principal_id: PrincipalId,
    token_id: TokenId,
    credential: &IssuedCredential,
    label: &str,
    now_ms: i64,
) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO auth_tokens(token_id, principal_id, created_by, label, key_id, verifier_hmac,
                                 created_at_ms)
         VALUES (?1, ?2, ?2, ?3, ?4, ?5, ?6)",
        params![
            token_id.to_string(),
            principal_id.to_string(),
            label,
            credential.key_id,
            credential.verifier.as_str(),
            now_ms
        ],
    )
}

pub(crate) fn normalize_token_label(label: &str) -> Option<&str> {
    if label.bytes().any(|byte| byte.is_ascii_control()) {
        return None;
    }
    let trimmed = label.trim();
    if !(1..=128).contains(&trimmed.len()) {
        return None;
    }
    Some(trimmed)
}

pub(crate) fn active_token_count(
    conn: &Connection,
    principal_id: PrincipalId,
    now_ms: i64,
) -> rusqlite::Result<usize> {
    conn.prepare_cached(
        "SELECT COUNT(*) FROM auth_tokens WHERE principal_id = ?1 AND revoked_at_ms IS NULL
           AND (expires_at_ms IS NULL OR expires_at_ms > ?2)",
    )?
    .query_row(params![principal_id.to_string(), now_ms], |row| row.get(0))
}

fn path_io(action: &'static str, path: &Path, source: io::Error) -> OperationError {
    OperationError::PathIo {
        action,
        path: path.to_owned(),
        source,
    }
}

#[cfg(test)]
mod tests;
