use std::fs::{self, File, Metadata, OpenOptions, Permissions};
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use efferian_platform::{FileLock, PlatformError, PrivateFs};
use efferian_protocol::HubId;
use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags, Transaction, TransactionBehavior, params};

use super::{
    BUSY_TIMEOUT, CURRENT_SCHEMA_VERSION, PAGE_SIZE, SqliteSynchronous, StorageClock,
    StorageConfig, StorageError, WriteError,
};

const DATABASE: &str = "hub.sqlite3";
const SIDECARS: [&str; 3] = ["hub.sqlite3-wal", "hub.sqlite3-shm", "hub.sqlite3-journal"];
const STAGING_DIR: &str = ".staging-hub-init";
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
const SQLITE_HEADER_LEN: usize = 20;
const STATEMENT_CACHE_CAPACITY: usize = 64;
pub(super) const WAL_FILE: &str = SIDECARS[0];
const SHM_FILE: &str = SIDECARS[1];

const NOFOLLOW: OpenFlags = OpenFlags::SQLITE_OPEN_NO_MUTEX.union(OpenFlags::SQLITE_OPEN_NOFOLLOW);
const RW: OpenFlags = NOFOLLOW.union(OpenFlags::SQLITE_OPEN_READ_WRITE);
const RO: OpenFlags = NOFOLLOW.union(OpenFlags::SQLITE_OPEN_READ_ONLY);

#[derive(Debug)]
pub struct LockedStateDir {
    path: PathBuf,
    _lock: FileLock,
}

impl LockedStateDir {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub fn acquire_state_lock(state_dir: &Path) -> Result<LockedStateDir, StorageError> {
    let path = PrivateFs::ensure_private_dir(state_dir)?;
    let lock = FileLock::acquire_exclusive(&path.join("hub.lock"))?;
    Ok(LockedStateDir { path, _lock: lock })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenMode {
    OfflineExactVersion,
    ServeAutoMigrate,
}

pub struct ExpectedHubIdentity {
    pub active_key_id: i64,
    pub master_key_fingerprint: String,
}

pub struct NewHubIdentity {
    pub hub_id: HubId,
    pub active_key_id: i64,
    pub master_key_fingerprint: String,
}

pub struct OpenedDb {
    // Field order keeps the instance lock held until the connection closes.
    pub(super) conn: Connection,
    pub(super) config: StorageConfig,
    pub(super) clock: Arc<dyn StorageClock>,
    pub(super) hub_id: HubId,
    pub(super) mode: OpenMode,
    pub(super) lock: LockedStateDir,
}

impl OpenedDb {
    pub fn hub_id(&self) -> &HubId {
        &self.hub_id
    }

    pub fn run_offline_tx<T, E>(
        mut self,
        op: impl FnOnce(&Transaction<'_>) -> Result<T, E>,
    ) -> Result<OfflineTxOutcome<T>, WriteError<E>> {
        if self.mode != OpenMode::OfflineExactVersion {
            return Err(
                StorageError::InvalidConfig("offline transaction requires offline mode").into(),
            );
        }
        let value = immediate(&mut self.conn, op)?;
        let Self {
            conn, lock, config, ..
        } = self;
        let checkpoint = truncate_checkpoint(&conn, config.shutdown_checkpoint_timeout)
            .unwrap_or_else(WalCheckpointOutcome::Failed);
        let close = close_writer(conn);
        drop(lock);
        Ok(OfflineTxOutcome {
            value,
            checkpoint: close.map_or_else(WalCheckpointOutcome::Failed, |()| checkpoint),
        })
    }
}

#[derive(Debug)]
pub enum WalCheckpointOutcome {
    Truncated,
    Incomplete {
        busy: i32,
        log: i32,
        checkpointed: i32,
    },
    Failed(StorageError),
}

#[derive(Debug)]
pub struct OfflineTxOutcome<T> {
    pub value: T,
    pub checkpoint: WalCheckpointOutcome,
}

pub fn create_staged<T, E>(
    lock: &mut LockedStateDir,
    identity: NewHubIdentity,
    config: &StorageConfig,
    clock: &dyn StorageClock,
    seed: impl FnOnce(&Transaction<'_>) -> Result<T, E>,
) -> Result<T, WriteError<E>> {
    let path = lock.path();
    config.validate()?;
    ensure_unpublished(path)?;
    clean_staging(path)?;
    let staging = PrivateFs::create_ephemeral_dir(path, STAGING_DIR).map_err(StorageError::from)?;
    let source = staging.path().join(DATABASE);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&source)
        .map_err(StorageError::from)?;
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(StorageError::from)?;

    let mut conn = Connection::open_with_flags(&source, RW).map_err(StorageError::from)?;
    conn.pragma_update(None, "page_size", PAGE_SIZE)
        .map_err(StorageError::from)?;
    conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")
        .map_err(StorageError::from)?;
    configure_writer(&conn, config)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(StorageError::from)?;
    tx.execute_batch(include_str!("v1.sql"))
        .map_err(StorageError::from)?;
    tx.execute(
        "INSERT INTO hub_meta(id, hub_id, active_key_id, master_key_fingerprint, created_at_ms, updated_at_ms)
         VALUES (1, ?1, ?2, ?3, ?4, ?4)",
        params![
            identity.hub_id.to_string(),
            identity.active_key_id,
            identity.master_key_fingerprint,
            clock.wall_now_ms(),
        ],
    )
    .map_err(StorageError::from)?;
    tx.pragma_update(None, "user_version", 1u32)
        .map_err(StorageError::from)?;
    let value = if CURRENT_SCHEMA_VERSION == 1 {
        let value = seed(&tx).map_err(WriteError::Domain)?;
        #[cfg(test)]
        super::tests::stage_point("pre-commit");
        // The file is still private inside staging and has never been published.
        tx.commit().map_err(StorageError::from)?;
        value
    } else {
        tx.commit().map_err(StorageError::from)?;
        migrate_to_current(&mut conn, 1)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StorageError::from)?;
        let value = seed(&tx).map_err(WriteError::Domain)?;
        #[cfg(test)]
        super::tests::stage_point("pre-commit");
        tx.commit().map_err(StorageError::from)?;
        value
    };

    if !matches!(
        truncate_checkpoint(&conn, BUSY_TIMEOUT)?,
        WalCheckpointOutcome::Truncated
    ) {
        return Err(StorageError::InvalidDatabase("staged WAL was not truncated").into());
    }
    close_writer(conn)?;
    file.sync_all().map_err(StorageError::from)?;
    ensure_unpublished(path)?;
    let parent = File::open(path).map_err(StorageError::from)?;
    #[cfg(test)]
    super::tests::stage_point("pre-link");
    fs::hard_link(&source, path.join(DATABASE)).map_err(StorageError::from)?;
    #[cfg(test)]
    super::tests::stage_point("post-link");

    // From here on the published name can already be durable.
    fs::remove_file(&source)
        .and_then(|()| parent.sync_all())
        .map_err(StorageError::PublishedDurabilityUnknown)?;
    Ok(value)
}

pub fn open_existing(
    lock: LockedStateDir,
    mode: OpenMode,
    expected: ExpectedHubIdentity,
    config: &StorageConfig,
    clock: Arc<dyn StorageClock>,
) -> Result<OpenedDb, StorageError> {
    config.validate()?;
    let path = lock.path();
    clean_staging(path)?;
    let database = path.join(DATABASE);
    let mut header = [0; SQLITE_HEADER_LEN];
    let db_len = match PrivateFs::read_private_file_header(&database, &mut header) {
        Ok(len) => len,
        Err(PlatformError::Io { source, .. }) if source.kind() == io::ErrorKind::UnexpectedEof => {
            return Err(StorageError::InvalidDatabase(
                "expected a SQLite database file",
            ));
        }
        Err(error) => return Err(error.into()),
    };
    if db_len < 100 {
        return Err(StorageError::InvalidDatabase(
            "expected a SQLite database file",
        ));
    }
    if &header[..SQLITE_MAGIC.len()] != SQLITE_MAGIC {
        return Err(StorageError::InvalidDatabase("invalid SQLite header"));
    }
    let wal_format = header[18..20] == [2, 2];

    let mut wal_existed = false;
    let mut shm_existed = false;
    let mut journal_existed = false;
    for name in SIDECARS {
        let sidecar = path.join(name);
        if let Some(metadata) = entry_metadata(&sidecar)? {
            if !metadata.is_file() {
                return Err(StorageError::SidecarConflict(name));
            }
            PrivateFs::verify_private_file(&sidecar)?;
            wal_existed |= name == WAL_FILE;
            shm_existed |= name == SHM_FILE;
            journal_existed |= name == SIDECARS[2];
        }
    }
    // Reject leftover WAL sidecars beside a non-WAL database (such as a restored
    // VACUUM INTO snapshot) before SQLite can replay mismatched pages into it.
    if !wal_format && (wal_existed || shm_existed) {
        return Err(StorageError::SidecarConflict(if wal_existed {
            WAL_FILE
        } else {
            SHM_FILE
        }));
    }

    if journal_existed {
        preflight_rollback_journal(path, mode, &expected, config, wal_existed)?;
    }

    let conn = Connection::open_with_flags(&database, RW)?;
    if wal_existed {
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    }
    // SQLite can satisfy a read-write open by falling back to read-only.
    // Check before any read so WAL recovery never surfaces as a raw SQLite error.
    if conn.is_readonly("main")? {
        return Err(StorageError::ReadOnlyDatabase);
    }
    let hub_id = validate_identity(&conn, mode, &expected, config, wal_existed)?;
    conn.pragma_update(None, "query_only", false)?;
    configure_writer(&conn, config)?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, false)?;

    Ok(OpenedDb {
        conn,
        config: config.clone(),
        clock,
        hub_id,
        mode,
        lock,
    })
}

// SQLite can roll back a hot journal on the first read of an RW connection,
// even with query_only enabled. Validate the recovered state before giving
// SQLite write access to the original. An ordinary, cold journal needs no copy.
fn preflight_rollback_journal(
    path: &Path,
    mode: OpenMode,
    expected: &ExpectedHubIdentity,
    config: &StorageConfig,
    wal_existed: bool,
) -> Result<(), StorageError> {
    let database = path.join(DATABASE);
    let reader = Connection::open_with_flags(&database, RO)?;
    match validate_identity(&reader, mode, expected, config, wal_existed) {
        Ok(_) => return Ok(()),
        Err(StorageError::Sqlite(rusqlite::Error::SqliteFailure(code, _)))
            if code.extended_code == rusqlite::ffi::SQLITE_READONLY_ROLLBACK => {}
        Err(error) => return Err(error),
    }
    drop(reader);

    // Check write access before paying for a full database copy into staging.
    let probe = Connection::open_with_flags(&database, RW)?;
    if wal_existed {
        probe.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    }
    if probe.is_readonly("main")? {
        return Err(StorageError::ReadOnlyDatabase);
    }
    drop(probe);

    let scratch = PrivateFs::create_ephemeral_dir(path, STAGING_DIR)?;
    for name in [DATABASE, SIDECARS[2]] {
        let dest = scratch.path().join(name);
        fs::copy(path.join(name), &dest)?;
        fs::set_permissions(&dest, Permissions::from_mode(0o600))?;
    }
    if wal_existed {
        let dest = scratch.path().join(WAL_FILE);
        fs::copy(path.join(WAL_FILE), &dest)?;
        fs::set_permissions(&dest, Permissions::from_mode(0o600))?;
    }
    let copy = Connection::open_with_flags(scratch.path().join(DATABASE), RW)?;
    validate_identity(&copy, mode, expected, config, wal_existed)?;
    Ok(())
}

// Runs before forward migrations: hub_meta(id, hub_id, active_key_id,
// master_key_fingerprint) is a permanent cross-version identity contract.
fn validate_identity(
    conn: &Connection,
    mode: OpenMode,
    expected: &ExpectedHubIdentity,
    config: &StorageConfig,
    wal_existed: bool,
) -> Result<HubId, StorageError> {
    if wal_existed {
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    }
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.pragma_update(None, "query_only", true)?;

    let found: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if !(1..=i64::from(CURRENT_SCHEMA_VERSION)).contains(&found) {
        return Err(StorageError::UnsupportedSchemaVersion {
            found,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    if mode == OpenMode::OfflineExactVersion && found != i64::from(CURRENT_SCHEMA_VERSION) {
        return Err(StorageError::SchemaMigrationRequired {
            found,
            required: CURRENT_SCHEMA_VERSION,
        });
    }
    check_pragma(conn, "page_size", i64::from(PAGE_SIZE))?;
    check_pragma(conn, "auto_vacuum", 2)?;
    let actual_page_count: u32 = conn.pragma_query_value(None, "page_count", |row| row.get(0))?;
    if actual_page_count > config.max_page_count {
        return Err(StorageError::QuotaBelowCurrentPages {
            requested: config.max_page_count,
            actual_page_count,
        });
    }
    let mut stmt = conn.prepare(
        "SELECT id, hub_id, active_key_id, master_key_fingerprint FROM hub_meta LIMIT 2",
    )?;
    let mut rows = stmt.query([])?;
    let row = rows
        .next()?
        .ok_or(StorageError::InvalidDatabase("missing Hub identity"))?;
    let (id, hub_id, key_id, fingerprint): (i64, String, i64, String) =
        (row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?);
    if id != 1 || rows.next()?.is_some() {
        return Err(StorageError::InvalidDatabase("invalid Hub identity row"));
    }
    if key_id != expected.active_key_id || fingerprint != expected.master_key_fingerprint {
        return Err(StorageError::IdentityMismatch);
    }
    HubId::parse(&hub_id).map_err(|_| StorageError::InvalidDatabase("invalid Hub ID"))
}

fn check_pragma(conn: &Connection, name: &'static str, expected: i64) -> Result<(), StorageError> {
    let actual = conn.pragma_query_value(None, name, |row| row.get::<_, i64>(0))?;
    if actual != expected {
        return Err(StorageError::InvalidDatabase(name));
    }
    Ok(())
}

fn configure_writer(conn: &Connection, config: &StorageConfig) -> Result<(), StorageError> {
    conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE_CAPACITY);
    conn.busy_timeout(BUSY_TIMEOUT)?;
    let mode: String =
        conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(StorageError::InvalidDatabase("journal_mode"));
    }
    let synchronous = match config.synchronous {
        SqliteSynchronous::Full => 2,
        SqliteSynchronous::Normal => 1,
    };
    for (name, value) in [
        ("foreign_keys", 1),
        ("synchronous", synchronous),
        ("secure_delete", 1),
        ("wal_autocheckpoint", 1000),
        ("journal_size_limit", config.journal_size_limit_bytes),
        ("temp_store", 2),
        ("cache_size", -16_000),
    ] {
        conn.pragma_update(None, name, value)?;
        check_pragma(conn, name, value)?;
    }
    check_pragma(conn, "page_size", i64::from(PAGE_SIZE))?;
    check_pragma(conn, "auto_vacuum", 2)?;
    check_pragma(conn, "busy_timeout", 5000)?;
    let requested = config.max_page_count;
    let actual_page_count =
        conn.pragma_update_and_check(None, "max_page_count", requested, |row| row.get(0))?;
    if actual_page_count != requested {
        return Err(StorageError::QuotaBelowCurrentPages {
            requested,
            actual_page_count,
        });
    }
    Ok(())
}

pub(super) fn open_reader(path: &Path) -> Result<Connection, StorageError> {
    let conn = Connection::open_with_flags(path, RO)?;
    conn.set_prepared_statement_cache_capacity(STATEMENT_CACHE_CAPACITY);
    conn.busy_timeout(BUSY_TIMEOUT)?;
    for (name, value) in [("query_only", 1), ("temp_store", 2), ("cache_size", -2000)] {
        conn.pragma_update(None, name, value)?;
        check_pragma(&conn, name, value)?;
    }
    check_pragma(&conn, "busy_timeout", 5000)?;
    Ok(conn)
}

pub(super) fn database_path(lock: &LockedStateDir) -> PathBuf {
    lock.path().join(DATABASE)
}

fn entry_metadata(path: &Path) -> io::Result<Option<Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn ensure_unpublished(path: &Path) -> Result<(), StorageError> {
    if entry_metadata(&path.join(DATABASE))?.is_some() {
        return Err(StorageError::AlreadyInitialized);
    }
    for name in SIDECARS {
        if entry_metadata(&path.join(name))?.is_some() {
            return Err(StorageError::SidecarConflict(name));
        }
    }
    Ok(())
}

fn clean_staging(path: &Path) -> Result<(), StorageError> {
    let staging = path.join(STAGING_DIR);
    if let Some(metadata) = entry_metadata(&staging)? {
        if !metadata.is_dir() {
            return Err(StorageError::SidecarConflict(STAGING_DIR));
        }
        let staging = PrivateFs::ensure_private_dir(&staging)?;
        PrivateFs::wipe_private_dir_contents(&staging)?;
        fs::remove_dir(staging)?;
    }
    Ok(())
}

pub(super) fn immediate<T, E>(
    conn: &mut Connection,
    op: impl FnOnce(&Transaction<'_>) -> Result<T, E>,
) -> Result<T, WriteError<E>> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(StorageError::from)?;
    let value = op(&tx).map_err(WriteError::Domain)?;
    tx.commit().map_err(|_| WriteError::CommitOutcomeUnknown)?;
    Ok(value)
}

/// Apply forward-only migrations from `found + 1` up to `CURRENT_SCHEMA_VERSION`.
/// Taking `&mut Connection` allows future v2+ migrations to toggle
/// `PRAGMA foreign_keys = OFF` outside a transaction for SQLite table rebuilds
/// and run `PRAGMA foreign_key_check` before re-enabling foreign keys.
pub(super) fn migrate_to_current(conn: &mut Connection, found: u32) -> Result<(), StorageError> {
    for version in found + 1..=CURRENT_SCHEMA_VERSION {
        match version {
            1 => {
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                tx.execute_batch(include_str!("v1.sql"))?;
                tx.pragma_update(None, "user_version", version)?;
                tx.commit()?;
            }
            _ => return Err(StorageError::InvalidDatabase("missing schema migration")),
        }
    }
    Ok(())
}

pub(super) fn truncate_checkpoint(
    conn: &Connection,
    timeout: Duration,
) -> Result<WalCheckpointOutcome, StorageError> {
    conn.busy_timeout(timeout)?;
    let result = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
        Ok(match (row.get(0)?, row.get(1)?, row.get(2)?) {
            (0, 0, 0) => WalCheckpointOutcome::Truncated,
            (busy, log, checkpointed) => WalCheckpointOutcome::Incomplete {
                busy,
                log,
                checkpointed,
            },
        })
    });
    conn.busy_timeout(BUSY_TIMEOUT)?;
    Ok(result?)
}

pub(super) fn close_writer(conn: Connection) -> Result<(), StorageError> {
    // A second, implicit close-time checkpoint could repeat a blocked truncate.
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    conn.close().map_err(|(_, error)| error)?;
    Ok(())
}
