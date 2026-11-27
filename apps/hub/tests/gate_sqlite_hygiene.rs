mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;

use efferian_hub::storage::{
    OpenMode, ShutdownReport, StorageConfig, StorageError, WalCheckpointOutcome,
};
use rusqlite::{Connection, ErrorCode};

use support::{TestDb, TestResult};

const TABLES: [&str; 15] = [
    "account_bindings",
    "accounts",
    "auth_tokens",
    "events",
    "executions",
    "grants",
    "hub_meta",
    "node_enrollments",
    "nodes",
    "principals",
    "profile_editions",
    "profiles",
    "tool_revisions",
    "tools",
    "upstreams",
];

const INDEXES: [&str; 16] = [
    "idx_accounts_private_owner_slug",
    "idx_accounts_shared_slug",
    "idx_auth_tokens_created_by",
    "idx_auth_tokens_expires",
    "idx_auth_tokens_principal",
    "idx_auth_tokens_revoked",
    "idx_executions_active_deadline",
    "idx_executions_active_node",
    "idx_executions_active_upstream",
    "idx_executions_caller_created",
    "idx_executions_created",
    "idx_executions_expires",
    "idx_executions_result_expires",
    "idx_grants_principal",
    "idx_node_enrollments_expires",
    "idx_nodes_active_name",
];

#[tokio::test]
async fn gate_sqlite_hygiene() -> TestResult {
    let db = TestDb::new(StorageConfig::default())?;
    db.create(|_| Ok(()))?;
    let opened = db.open(OpenMode::OfflineExactVersion)?;
    let result = opened.run_offline_tx(|conn| {
        for (pragma, value) in [
            ("user_version", 1),
            ("page_size", 4096),
            ("auto_vacuum", 2),
            ("foreign_keys", 1),
            ("synchronous", 2),
            ("secure_delete", 1),
            ("busy_timeout", 5000),
            ("wal_autocheckpoint", 1000),
            ("journal_size_limit", 64 * 1024 * 1024),
            ("max_page_count", 1_048_576),
            ("temp_store", 2),
            ("cache_size", -16_000),
        ] {
            assert_eq!(integer_pragma(conn, pragma)?, value, "{pragma}");
        }
        let mode: String = conn.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
        assert_eq!(mode, "wal");
        let mut stmt = conn.prepare(
            "SELECT name FROM sqlite_schema
            WHERE type = ?1 AND name NOT GLOB 'sqlite_*' ORDER BY name",
        )?;
        for (kind, expected) in [
            ("table", TABLES.as_slice()),
            ("index", INDEXES.as_slice()),
            ("trigger", &[]),
            ("view", &[]),
        ] {
            let names = stmt
                .query_map([kind], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            assert_eq!(names, expected, "{kind}");
        }
        let mut check = conn.prepare("PRAGMA foreign_key_check")?;
        assert!(check.query([])?.next()?.is_none());
        for (table, column) in [("auth_tokens", "last_used_at_ms"), ("tools", "draft_json")] {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2",
                [table, column],
                |row| row.get(0),
            )?;
            assert_eq!(count, 0);
        }
        let mut stmt = conn.prepare(
            "SELECT name FROM pragma_index_info('idx_executions_result_expires') ORDER BY seqno",
        )?;
        let columns = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(columns, ["result_expires_at_ms", "execution_id"]);
        Ok::<_, StorageError>(())
    })?;
    assert!(matches!(result.checkpoint, WalCheckpointOutcome::Truncated));

    let (handle, runtime) = db
        .open(OpenMode::ServeAutoMigrate)?
        .migrate_and_start_runtime()?;
    assert_eq!(handle.hub_id(), &db.id);
    handle.read_snapshot(|conn| {
        assert!(conn.is_readonly("main")?);
        for (pragma, value) in [("query_only", 1), ("temp_store", 2), ("busy_timeout", 5000), ("cache_size", -2000)] {
            assert_eq!(integer_pragma(conn, pragma)?, value, "{pragma}");
        }
        let write = conn.execute("UPDATE hub_meta SET updated_at_ms = -1", []);
        assert!(matches!(write, Err(error) if error.sqlite_error_code() == Some(ErrorCode::ReadOnly)));
        Ok::<_, StorageError>(())
    }).await?;
    assert_eq!(
        fs::metadata(&db.dir)?.permissions().mode() & 0o7777,
        0o700,
        "{}",
        db.dir.display()
    );
    for path in [
        db.dir.join("hub.lock"),
        db.path(),
        db.dir.join("hub.sqlite3-wal"),
        db.dir.join("hub.sqlite3-shm"),
    ] {
        assert_eq!(
            fs::metadata(&path)?.permissions().mode() & 0o7777,
            0o600,
            "{}",
            path.display()
        );
    }
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

fn integer_pragma(conn: &Connection, pragma: &str) -> rusqlite::Result<i64> {
    conn.pragma_query_value(None, pragma, |row| row.get(0))
}

#[test]
fn v1_constraints_enforce_identity_scopes_and_execution_shape() -> TestResult {
    use efferian_hub::storage::read_principal;
    use efferian_protocol::PrincipalId;
    use rusqlite::params;

    let db = TestDb::new(StorageConfig::default())?;
    db.create(|conn| {
        for name in ["alice", "bob"] {
            conn.execute("INSERT INTO principals(principal_id, kind, name, created_at_ms, updated_at_ms)
                VALUES (?1, 'member', ?1, 0, 0)", [name])?;
        }
        for statement in [
            "UPDATE principals SET allowed_node_tags_json = '[\"a\"]' WHERE principal_id = 'alice'",
            "UPDATE principals SET managed_by_principal_id = 'bob' WHERE principal_id = 'alice'",
            "INSERT INTO grants(grant_id, principal_id, scope_kind, scope_id, capability, created_by, created_at_ms)
             VALUES ('g1', 'alice', 'profile', 'p1', 'admin', 'alice', 0)",
            "INSERT INTO nodes(node_id, name, credential_hmac, platform_os, created_at_ms, updated_at_ms)
             VALUES ('n0', 'node', 'h0', 'windows', 0, 0)",
        ] {
            assert!(constraint(conn.execute(statement, [])), "{statement}");
        }
        conn.execute("INSERT INTO nodes(node_id, name, credential_hmac, created_at_ms, updated_at_ms)
            VALUES ('n1', 'node', 'h1', 0, 0)", [])?;
        let second_node = "INSERT INTO nodes(node_id, name, credential_hmac, created_at_ms, updated_at_ms)
                           VALUES ('n2', 'node', 'h2', 0, 0)";
        assert!(constraint(conn.execute(second_node, [])));
        conn.execute("UPDATE nodes SET revoked_at_ms = 1 WHERE node_id = 'n1'", [])?;
        conn.execute(second_node, [])?;

        let insert_account = "INSERT INTO accounts(account_id, slug, owner_principal_id, visibility, kind,
                              sealed_secret_blob, created_at_ms, updated_at_ms)
                              VALUES (?1, 'account', ?2, ?3, 'secret_kv', X'01', 0, 0)";
        conn.execute(insert_account, ["a1", "alice", "private"])?;
        assert!(constraint(conn.execute(insert_account, ["a2", "alice", "private"])));
        conn.execute(insert_account, ["a2", "bob", "private"])?;
        conn.execute(insert_account, ["a3", "alice", "shared"])?;
        assert!(constraint(conn.execute(insert_account, ["a4", "bob", "shared"])));

        let insert_execution = "INSERT INTO executions(execution_id, invoke_kind, request_id, request_digest,
             caller_principal_id, caller_token_id, tool_id, tool_version, public_name, executor_kind,
             node_id, upstream_id, state, deadline_at_ms, created_at_ms, result_expires_at_ms, expires_at_ms)
             VALUES (?1, 'tool_test', 'request1', 'digest', ?2, 'token', 'tool', 1, 'public', ?3,
             ?4, ?5, 'accepted', 0, 0, 0, 0)";
        conn.execute(insert_execution, params!["e1", "alice", "node", "n1", None::<&str>])?;
        assert!(constraint(conn.execute(insert_execution, params!["e2", "alice", "node", "n1", None::<&str>])));
        conn.execute(insert_execution, params!["e2", "bob", "node", "n1", None::<&str>])?;
        for statement in [
            "UPDATE executions SET upstream_id = 'u' WHERE execution_id = 'e1'",
            "UPDATE executions SET executor_kind = 'upstream' WHERE execution_id = 'e1'",
            "UPDATE executions SET sealed_result_blob = X'' WHERE execution_id = 'e1'",
            "UPDATE executions SET sealed_result_blob = X'01', result_bytes = 2 WHERE execution_id = 'e1'",
        ] {
            assert!(constraint(conn.execute(statement, [])), "{statement}");
        }

        let orchestrator = PrincipalId::new_service();
        conn.execute(
            "INSERT INTO principals(principal_id, kind, name, is_orchestrator, allowed_node_tags_json, created_at_ms, updated_at_ms)
             VALUES (?1, 'service', 'orchestrator', 1, '[\"allowed\"]', 0, 0)",
            [orchestrator.to_string()],
        )?;
        let view = read_principal(conn, orchestrator)?.ok_or("missing orchestrator")?;
        assert!(view.allowed_node_tags.contains("allowed"));
        for malformed in ["{", "[42]", "[\"INVALID TAG\"]", "[\"allowed\",\"allowed\"]"] {
            conn.execute("UPDATE principals SET allowed_node_tags_json = ?1 WHERE principal_id = ?2",
                params![malformed, orchestrator.to_string()])?;
            assert!(read_principal(conn, orchestrator).is_err(), "{malformed}");
        }
        Ok(())
    })?;
    Ok(())
}

fn constraint(result: rusqlite::Result<usize>) -> bool {
    matches!(result, Err(error) if error.sqlite_error_code() == Some(ErrorCode::ConstraintViolation))
}
