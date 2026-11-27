use std::error::Error;
use std::fs::{self, DirBuilder, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Barrier;
use std::thread;

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> TestResult<Self> {
        let path = std::env::temp_dir().join(format!("efferian-operations-{}", HubId::new()));
        DirBuilder::new().mode(0o700).create(&path)?;
        fs::set_permissions(&path, Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }

    fn join(&self, path: &str) -> PathBuf {
        self.0.join(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn open_test(state: &Path) -> Result<(OpenedDb, Arc<Vault>), OperationError> {
    open_existing(
        state,
        OpenMode::OfflineExactVersion,
        &StorageConfig::default(),
        Arc::new(SystemStorageClock::new()?),
    )
}

#[test]
fn init_preflight_preserves_existing_entries_and_creates_no_key_on_refusal() -> TestResult {
    let root = TestDir::new()?;
    let state = root.join("state");
    let alias = root.join("alias");
    let dangling = root.join("dangling");
    symlink(&state, &alias)?;
    symlink("missing", &dangling)?;

    let config = StorageConfig::default();
    let bad_config = StorageConfig {
        max_page_count: 0,
        ..config.clone()
    };
    assert!(matches!(
        init(&state, "admin", &root.join("bad.token"), &bad_config),
        Err(OperationError::Storage(StorageError::InvalidConfig(_)))
    ));
    assert!(!state.exists());

    for target in [alias.join(DATABASE), dangling.clone()] {
        assert!(matches!(
            init(&state, "admin", &target, &config),
            Err(OperationError::InvalidOutput { .. })
        ));
        assert!(!state.join(MASTER_KEY).exists());
        assert!(!state.join(DATABASE).exists());
    }
    assert_eq!(fs::read_link(&dangling)?, Path::new("missing"));

    let staged = state.join(STAGING);
    symlink("missing", &staged)?;
    let token = root.join("admin.token");
    assert!(matches!(
        init(&state, "admin", &token, &config),
        Err(OperationError::Storage(StorageError::SidecarConflict(name))) if name == STAGING
    ));
    assert_eq!(fs::read_link(&staged)?, Path::new("missing"));
    assert!(!state.join(MASTER_KEY).exists());
    fs::remove_file(staged)?;

    let staging_output = alias.join(STAGING).join("nested");
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&staging_output)?;
    assert!(matches!(
        init(&state, "admin", &staging_output.join("key"), &config),
        Err(OperationError::InvalidOutput { .. })
    ));
    assert!(!state.join(MASTER_KEY).exists());

    init(&state, "admin", &token, &config)?;
    assert_eq!(fs::metadata(&state)?.mode() & 0o777, 0o700);
    for file in [state.join(MASTER_KEY), state.join(DATABASE), token.clone()] {
        let metadata = fs::metadata(file)?;
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }
    let bootstrap = Zeroizing::new(fs::read_to_string(&token)?);
    assert!(bootstrap.starts_with("eff_tok_"));
    assert_eq!(bootstrap.lines().count(), 1);
    assert!(bootstrap.ends_with('\n'));
    assert!(matches!(
        init(&state, "other", &token, &config),
        Err(OperationError::Storage(StorageError::AlreadyInitialized))
    ));
    let existing = Zeroizing::new(fs::read_to_string(&token)?);
    assert!(bootstrap.as_str() == existing.as_str());

    let db = Connection::open_with_flags(state.join(DATABASE), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let seed = db.query_row(
        "SELECT p.name, p.kind, g.capability, g.scope_kind, t.label, t.verifier_hmac
         FROM principals p JOIN grants g USING (principal_id) JOIN auth_tokens t USING (principal_id)
         WHERE g.created_by = p.principal_id AND t.created_by = p.principal_id",
        [],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        },
    )?;
    assert_eq!(
        (&*seed.0, &*seed.1, &*seed.2, &*seed.3, &*seed.4),
        ("admin", "admin", "admin", "global", "bootstrap")
    );
    assert_eq!(seed.5.len(), 64);
    assert!(!bootstrap.contains(&seed.5));
    Ok(())
}

#[test]
fn preflight_reserves_private_output_and_cleans_up_on_abort() -> TestResult {
    let root = TestDir::new()?;
    let target = root.join("token");
    let pending = TokenOutput::preflight(&root.0, &target)?;
    let files = fs::read_dir(&root.0)?.collect::<io::Result<Vec<_>>>()?;
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].metadata()?.len(), 0);
    assert_eq!(files[0].metadata()?.mode() & 0o777, 0o600);
    assert!(!target.exists());
    drop(pending);
    assert!(fs::read_dir(&root.0)?.next().is_none());
    Ok(())
}

#[test]
fn snapshot_requires_an_existing_hub_identity() -> TestResult {
    let root = TestDir::new()?;
    let source = root.join(DATABASE);
    let backup = root.join("backup");
    fs::File::create(&source)?;
    assert!(snapshot(&root.0, &backup).is_err());
    assert!(!backup.exists());
    let db = Connection::open(source)?;
    db.execute_batch(
        "CREATE TABLE hub_meta(id, hub_id); INSERT INTO hub_meta VALUES (1, 'invalid');",
    )?;
    assert!(snapshot(&root.0, &backup).is_err());
    assert!(!backup.exists());
    Ok(())
}

#[test]
fn offline_mint_obeys_the_lock_quota_and_current_admin_grant() -> TestResult {
    let root = TestDir::new()?;
    let state = root.join("state");
    let config = StorageConfig::default();
    let out = root.join("new.token");

    assert!(create_token(&state, "admin", &out, "recovery", &config, 1).is_err());
    assert!(!state.exists());
    init(&state, "admin", &root.join("initial.token"), &config)?;
    let (lock, _) = open_test(&state)?;
    assert!(matches!(
        create_token(&state, "admin", &out, "recovery", &config, 2),
        Err(OperationError::Storage(StorageError::Platform(
            PlatformError::LockContended { .. }
        )))
    ));
    drop(lock);

    assert!(matches!(
        create_token(&state, "admin", &out, "recovery", &config, 1),
        Err(OperationError::TokenQuotaExceeded)
    ));
    assert!(!out.exists());
    assert!(matches!(
        create_token(&state, "admin", &out, "\tinvalid", &config, 2),
        Err(OperationError::InvalidTokenLabel)
    ));
    create_token(&state, "admin", &out, "recovery", &config, 2)?;
    assert!(fs::read_to_string(&out)?.starts_with("eff_tok_"));
    assert_eq!(fs::metadata(&out)?.mode() & 0o777, 0o600);

    let db = Connection::open(state.join(DATABASE))?;
    db.execute(
        "UPDATE auth_tokens SET revoked_at_ms = 1 WHERE label = 'bootstrap'",
        [],
    )?;
    let replacement = root.join("replacement.token");
    create_token(&state, "admin", &replacement, "replacement", &config, 2)?;
    db.execute("DELETE FROM grants", [])?;
    let rejected = root.join("rejected.token");
    assert!(matches!(
        create_token(&state, "admin", &rejected, "recovery", &config, 3),
        Err(OperationError::PrincipalNotAdmin)
    ));
    assert!(!rejected.exists());
    Ok(())
}

#[test]
fn an_incomplete_checkpoint_does_not_hide_the_committed_token() -> TestResult {
    let root = TestDir::new()?;
    let state = root.join("state");
    let database = state.join(DATABASE);
    let config = StorageConfig {
        shutdown_checkpoint_timeout: Duration::ZERO,
        ..StorageConfig::default()
    };
    init(&state, "admin", &root.join("initial.token"), &config)?;

    let mut reader = Connection::open(&database)?;
    let snapshot = reader.transaction()?;
    let count = |conn: &Connection| {
        conn.query_row("SELECT count(*) FROM auth_tokens", [], |row| {
            row.get::<_, u32>(0)
        })
    };
    assert_eq!(count(&snapshot)?, 1);

    let out = root.join("recovery.token");
    create_token(&state, "admin", &out, "recovery", &config, 2)?;
    assert!(fs::read_to_string(out)?.starts_with("eff_tok_"));
    assert_eq!(count(&snapshot)?, 1);
    let observer = Connection::open(&database)?;
    assert_eq!(count(&observer)?, 2);
    Ok(())
}

#[test]
fn online_snapshot_has_one_publisher_and_restores_only_with_its_key() -> TestResult {
    let root = TestDir::new()?;
    let state = root.join("state");
    let backup = root.join("backup.sqlite3");
    init(
        &state,
        "admin",
        &root.join("initial.token"),
        &StorageConfig::default(),
    )?;
    let (live_writer, _) = open_test(&state)?;
    let mut db = Connection::open(state.join(DATABASE))?;
    // Keep a writer transaction open while both snapshots read the last committed state.
    let pending = db.transaction()?;
    pending.execute("UPDATE auth_tokens SET label = 'during-snapshot'", [])?;

    let barrier = Barrier::new(2);
    let (first, second) = thread::scope(|scope| -> TestResult<_> {
        let run = || {
            barrier.wait();
            snapshot(&state, &backup)
        };
        let first = scope.spawn(run);
        let second = scope.spawn(run);
        Ok((
            first
                .join()
                .map_err(|_| io::Error::other("first snapshot thread panicked"))?,
            second
                .join()
                .map_err(|_| io::Error::other("second snapshot thread panicked"))?,
        ))
    })?;
    assert_ne!(first.is_ok(), second.is_ok());
    assert!(!fs::read_dir(&root.0)?.any(|entry| {
        entry.is_ok_and(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".efferian-output-")
        })
    }));

    let metadata = fs::metadata(&backup)?;
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    let backing = Connection::open_with_flags(&backup, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let quick_check = backing.query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))?;
    assert_eq!(quick_check, "ok");
    let hub_id = backing.query_row("SELECT hub_id FROM hub_meta", [], |row| {
        row.get::<_, String>(0)
    })?;
    assert_eq!(hub_id, live_writer.hub_id().to_string());
    let copied_label = backing.query_row("SELECT label FROM auth_tokens", [], |row| {
        row.get::<_, String>(0)
    })?;
    assert_eq!(copied_label, "bootstrap");
    pending.commit()?;

    let restore = root.join("restore");
    DirBuilder::new().mode(0o700).create(&restore)?;
    fs::set_permissions(&restore, Permissions::from_mode(0o700))?;
    let restored_db = restore.join(DATABASE);
    fs::copy(&backup, &restored_db)?;
    let restored_key = restore.join(MASTER_KEY);
    fs::copy(state.join(MASTER_KEY), &restored_key)?;
    fs::set_permissions(&restored_key, Permissions::from_mode(0o400))?;
    let (opened, _) = open_test(&restore)?;
    assert_eq!(opened.hub_id().to_string(), hub_id);
    drop(opened);

    // A foreign but well-formed master key must fail the stored identity check.
    let foreign = root.join("foreign");
    init(
        &foreign,
        "admin",
        &root.join("foreign.token"),
        &StorageConfig::default(),
    )?;
    fs::remove_file(&restored_key)?;
    fs::copy(foreign.join(MASTER_KEY), &restored_key)?;
    assert!(matches!(
        open_test(&restore),
        Err(OperationError::Storage(StorageError::IdentityMismatch))
    ));

    assert!(matches!(
        snapshot(&state, &state.join(SIDECARS[0])),
        Err(OperationError::InvalidOutput { .. })
    ));
    Ok(())
}
