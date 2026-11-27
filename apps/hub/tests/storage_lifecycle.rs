mod support;

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::Arc;
use std::time::Duration;

use efferian_hub::storage::{
    OpenMode, SqliteSynchronous, StorageConfig, StorageError, WalCheckpointOutcome, WriteError,
    acquire_state_lock, create_staged, open_existing,
};
use rusqlite::{Connection, OpenFlags, config::DbConfig};

use support::{TestDb, TestResult};

#[test]
fn staging_refuses_all_final_names_and_preserves_a_domain_failure() -> TestResult {
    let db = TestDb::new(StorageConfig::default())?;
    let mut lock = acquire_state_lock(&db.dir)?;
    for name in [
        "hub.sqlite3",
        "hub.sqlite3-wal",
        "hub.sqlite3-shm",
        "hub.sqlite3-journal",
    ] {
        let entry = db.dir.join(name);
        symlink("absent", &entry)?;
        let result = create_staged(
            &mut lock,
            db.identity(),
            &db.config,
            db.clock.as_ref(),
            |_| Ok::<_, ()>(()),
        );
        if name == "hub.sqlite3" {
            assert!(matches!(
                result,
                Err(WriteError::Storage(StorageError::AlreadyInitialized))
            ));
        } else {
            assert!(
                matches!(result, Err(WriteError::Storage(StorageError::SidecarConflict(actual))) if actual == name)
            );
        }
        assert_eq!(fs::read_link(&entry)?, std::path::Path::new("absent"));
        assert!(!db.dir.join(".staging-hub-init").exists());
        fs::remove_file(entry)?;
    }
    let result = create_staged(
        &mut lock,
        db.identity(),
        &db.config,
        db.clock.as_ref(),
        |_| Err::<(), _>("seed rejected"),
    );
    assert!(matches!(result, Err(WriteError::Domain("seed rejected"))));
    assert!(!db.path().exists());
    assert!(!db.dir.join(".staging-hub-init").exists());
    drop(lock);
    db.create(|_| Ok(()))?;
    assert_eq!(db.open(OpenMode::OfflineExactVersion)?.hub_id(), &db.id);
    Ok(())
}

#[test]
fn invalid_identity_or_version_leaves_existing_wal_bytes_intact() -> TestResult {
    let db = TestDb::new(StorageConfig::default())?;
    let lock = acquire_state_lock(&db.dir)?;
    fs::write(db.path(), b"")?;
    let uninitialized = open_existing(
        lock,
        OpenMode::ServeAutoMigrate,
        db.expected(),
        &db.config,
        Arc::clone(&db.clock),
    );
    assert!(matches!(
        uninitialized,
        Err(StorageError::InvalidDatabase(_))
    ));
    assert!(fs::read(db.path())?.is_empty());
    fs::remove_file(db.path())?;
    db.create(|_| Ok(()))?;

    let wal = db.dir.join("hub.sqlite3-wal");
    for version in [1, 0, 99] {
        let conn = Connection::open(db.path())?;
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
        conn.pragma_update(None, "wal_autocheckpoint", 0)?;
        conn.pragma_update(None, "user_version", version)?;
        conn.execute("UPDATE hub_meta SET updated_at_ms = updated_at_ms + 1", [])?;
        conn.close().map_err(|(_, e)| e)?;
        let before = (fs::read(db.path())?, fs::read(&wal)?);
        assert!(!before.1.is_empty());
        for bad_key_id in [false, true] {
            let mut expected = db.expected();
            if bad_key_id {
                expected.active_key_id += 1;
            } else {
                expected.master_key_fingerprint.clear();
            }
            let result = open_existing(
                acquire_state_lock(&db.dir)?,
                OpenMode::ServeAutoMigrate,
                expected,
                &db.config,
                Arc::clone(&db.clock),
            );
            if version == 1 {
                assert!(matches!(result, Err(StorageError::IdentityMismatch)));
            } else {
                assert!(
                    matches!(result, Err(StorageError::UnsupportedSchemaVersion { found, supported: 1 })
                    if found == version)
                );
            }
            assert_eq!((fs::read(db.path())?, fs::read(&wal)?), before);
        }
    }
    Ok(())
}

#[test]
fn writer_open_rejects_sqlites_read_only_fallback() -> TestResult {
    let db = TestDb::new(StorageConfig::default())?;
    db.create(|_| Ok(()))?;
    fs::set_permissions(db.path(), fs::Permissions::from_mode(0o400))?;
    // A privileged process can still open this file for writing.
    let writable = fs::OpenOptions::new().write(true).open(db.path()).is_ok();
    for mode in [OpenMode::ServeAutoMigrate, OpenMode::OfflineExactVersion] {
        let result = open_existing(
            acquire_state_lock(&db.dir)?,
            mode,
            db.expected(),
            &db.config,
            Arc::clone(&db.clock),
        );
        if writable {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(StorageError::ReadOnlyDatabase)));
        }
    }
    Ok(())
}

#[test]
fn a_restored_snapshot_is_validated_before_switching_to_wal() -> TestResult {
    let db = TestDb::new(StorageConfig::default())?;
    db.create(|conn| {
        conn.execute("INSERT INTO upstreams(upstream_id, slug, url, discovered_tools_json, created_at_ms, updated_at_ms)
            VALUES ('a', 'a', 'https://example.test', hex(zeroblob(300000)), 0, 0)", [])?;
        Ok(())
    })?;
    let backup = TestDb::new(StorageConfig {
        synchronous: SqliteSynchronous::Normal,
        ..db.config.clone()
    })?;
    let lock = acquire_state_lock(&backup.dir)?;
    let output = backup.path();
    let output = output.to_str().ok_or("non-UTF-8 test path")?;
    let source = Connection::open_with_flags(db.path(), OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    source.execute("VACUUM INTO ?1", [output])?;
    let original = fs::read(output)?;
    let mut wrong = backup.expected();
    wrong.active_key_id = 2;
    let bad = open_existing(
        lock,
        OpenMode::OfflineExactVersion,
        wrong,
        &backup.config,
        Arc::clone(&backup.clock),
    );
    assert!(matches!(bad, Err(StorageError::IdentityMismatch)));
    assert_eq!(fs::read(output)?, original);
    assert!(!backup.dir.join("hub.sqlite3-wal").exists());

    let small = StorageConfig {
        max_page_count: 64,
        ..backup.config.clone()
    };
    let quota_failure = open_existing(
        acquire_state_lock(&backup.dir)?,
        OpenMode::OfflineExactVersion,
        db.expected(),
        &small,
        Arc::clone(&backup.clock),
    );
    assert!(matches!(
        quota_failure,
        Err(StorageError::QuotaBelowCurrentPages { requested: 64, .. })
    ));
    assert_eq!(fs::read(output)?, original);

    let opened = open_existing(
        acquire_state_lock(&backup.dir)?,
        OpenMode::OfflineExactVersion,
        db.expected(),
        &backup.config,
        Arc::clone(&backup.clock),
    )?;
    assert_eq!(opened.hub_id(), &db.id);
    let outcome = opened.run_offline_tx(|conn| {
        let sync = conn.pragma_query_value(None, "synchronous", |row| row.get::<_, i64>(0))?;
        let journal =
            conn.pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))?;
        assert_eq!((sync, journal.as_str()), (1, "wal"));
        Ok::<_, rusqlite::Error>(())
    })?;
    assert!(matches!(
        outcome.checkpoint,
        WalCheckpointOutcome::Truncated
    ));
    Ok(())
}

#[test]
fn an_offline_commit_reports_incomplete_checkpoint_without_losing_its_value() -> TestResult {
    let db = TestDb::new(StorageConfig {
        shutdown_checkpoint_timeout: Duration::from_millis(20),
        ..StorageConfig::default()
    })?;
    db.create(|_| Ok(()))?;
    let opened = db.open(OpenMode::OfflineExactVersion)?;
    let reader = Connection::open_with_flags(db.path(), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    reader.execute_batch("BEGIN")?;
    let before: i64 =
        reader.query_row("SELECT updated_at_ms FROM hub_meta", [], |row| row.get(0))?;
    let outcome = opened.run_offline_tx(|conn| {
        conn.execute("UPDATE hub_meta SET updated_at_ms = -1", [])?;
        Ok::<_, rusqlite::Error>(42)
    })?;
    assert_eq!(outcome.value, 42);
    assert!(matches!(
        outcome.checkpoint,
        WalCheckpointOutcome::Incomplete { busy: 1, .. }
    ));
    assert_eq!(
        reader.query_row("SELECT updated_at_ms FROM hub_meta", [], |row| row
            .get::<_, i64>(0))?,
        before
    );
    reader.execute_batch("ROLLBACK")?;
    assert_eq!(
        reader.query_row("SELECT updated_at_ms FROM hub_meta", [], |row| row
            .get::<_, i64>(0))?,
        -1
    );
    Ok(())
}

#[test]
fn quota_preflight_preserves_larger_uncheckpointed_wal_without_a_wal_index() -> TestResult {
    let db = TestDb::new(StorageConfig::default())?;
    db.create(|_| Ok(()))?;
    let conn = Connection::open(db.path())?;
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    conn.pragma_update(None, "wal_autocheckpoint", 0)?;
    conn.execute("INSERT INTO upstreams(upstream_id, slug, url, discovered_tools_json, created_at_ms, updated_at_ms)
        VALUES ('a', 'a', 'https://example.test', hex(zeroblob(300000)), 0, 0)", [])?;
    conn.close().map_err(|(_, e)| e)?;
    fs::remove_file(db.dir.join("hub.sqlite3-shm"))?;
    let wal = db.dir.join("hub.sqlite3-wal");
    let before = (fs::read(db.path())?, fs::read(&wal)?);
    let small = StorageConfig {
        max_page_count: 64,
        ..db.config.clone()
    };
    let result = open_existing(
        acquire_state_lock(&db.dir)?,
        OpenMode::ServeAutoMigrate,
        db.expected(),
        &small,
        Arc::clone(&db.clock),
    );
    assert!(matches!(
        result,
        Err(StorageError::QuotaBelowCurrentPages { requested: 64, .. })
    ));
    assert_eq!((fs::read(db.path())?, fs::read(&wal)?), before);
    assert_eq!(db.open(OpenMode::ServeAutoMigrate)?.hub_id(), &db.id);
    Ok(())
}
