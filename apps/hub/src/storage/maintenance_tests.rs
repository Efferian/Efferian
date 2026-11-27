use efferian_protocol::{ExecutionId, GrantId, PrincipalId, TokenId, ToolId};

use super::super::tests::{Fixture, TestResult, seed_token};
use super::*;
use crate::storage::{
    OpenMode, PrincipalLiveness, ShutdownReport, StorageConfig, principal_liveness,
};

fn seed_execution(
    conn: &Connection,
    fixture: &Fixture,
    caller: PrincipalId,
    state: &str,
    result_expiry: i64,
    metadata_expiry: i64,
    bytes: usize,
) -> rusqlite::Result<ExecutionId> {
    let execution_id = ExecutionId::new();
    conn.execute(
        "INSERT INTO executions(execution_id, invoke_kind, request_id, request_digest, caller_principal_id,
            caller_token_id, tool_id, tool_version, public_name, executor_kind, node_id, state,
            deadline_at_ms, created_at_ms, result_expires_at_ms, expires_at_ms, sealed_result_blob, result_bytes)
         VALUES (?1, 'tool_test', ?1, 'digest', ?2, ?3, ?4, 1, 'tool', 'node', ?5, ?6,
            0, 0, ?7, ?8, CASE WHEN ?9 = 0 THEN NULL ELSE zeroblob(?9) END, ?9)",
        params![execution_id.to_string(), caller.to_string(), fixture.token.to_string(), fixture.tool.to_string(),
            fixture.node.to_string(), state, result_expiry, metadata_expiry, bytes],
    )?;
    Ok(execution_id)
}

#[test]
fn ttl_work_is_row_and_byte_bounded_and_vacuum_drains_multiple_pages() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let db = f.open(OpenMode::OfflineExactVersion)?;
    let conn = &db.conn;
    for _ in 0..33 {
        seed_execution(conn, &f, f.principal, "succeeded", 1, 9, 1)?;
    }
    assert_eq!(gc_transaction(conn, |tx| expire_results(tx, 1))?, 32);
    assert_eq!(gc_transaction(conn, |tx| expire_results(tx, 1))?, 1);

    let first = seed_execution(conn, &f, f.principal, "succeeded", 2, 9, 2_500_000)?;
    let second = seed_execution(conn, &f, f.principal, "succeeded", 2, 9, 2_500_000)?;
    seed_execution(conn, &f, f.principal, "succeeded", 3, 9, MAX_WORK_BYTES)?;
    seed_execution(conn, &f, f.principal, "succeeded", 4, 9, MAX_WORK_BYTES + 1)?;
    for cutoff in [2, 2, 3, 4] {
        assert_eq!(gc_transaction(conn, |tx| expire_results(tx, cutoff))?, 1);
        if cutoff == 2 && conn.query_row("SELECT count(*) FROM executions WHERE sealed_result_blob IS NOT NULL AND result_expires_at_ms = 2",
            [], |row| row.get::<_, i64>(0))? == 1
        {
            let remaining: String = conn.query_row(
                "SELECT execution_id FROM executions WHERE sealed_result_blob IS NOT NULL AND result_expires_at_ms = 2",
                [], |row| row.get(0),
            )?;
            assert_eq!(remaining, first.max(second).to_string());
        }
    }
    let mut stmt = conn.prepare(&format!(
        "EXPLAIN QUERY PLAN SELECT result_bytes {RESULT_CANDIDATES}"
    ))?;
    let plan = stmt
        .query_map(params![i64::MAX, 32], |row| row.get::<_, String>(3))?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .join(" ");
    assert!(plan.contains("idx_executions_result_expires"), "{plan}");
    assert!(!plan.contains("TEMP B-TREE"), "{plan}");

    let active = seed_execution(conn, &f, f.principal, "running", 100, 5, 0)?;
    let active2 = seed_execution(conn, &f, f.principal, "accepted", 100, 5, 0)?;
    for _ in 0..2 {
        seed_execution(conn, &f, f.principal, "failed", 100, 5, 2_500_000)?;
    }
    assert_eq!(gc_transaction(conn, |tx| expire_executions(tx, 5))?, 1);
    assert_eq!(gc_transaction(conn, |tx| expire_executions(tx, 5))?, 1);
    assert_eq!(gc_transaction(conn, |tx| expire_executions(tx, 5))?, 0);
    for active in [active, active2] {
        assert!(
            conn.query_row(
                "SELECT 1 FROM executions WHERE execution_id = ?1",
                [active.to_string()],
                |row| row.get::<_, i64>(0)
            )
            .is_ok()
        );
    }
    let before = Pages::read(conn)?;
    assert!(before.free >= 10);
    incremental_vacuum(conn)?;
    let after = Pages::read(conn)?;
    assert!(before.count - after.count > 1);
    assert!((2..=64).contains(&(before.free - after.free)));
    Ok(())
}

#[test]
fn event_pruning_is_contiguous_bounded_and_atomic() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let db = f.open(OpenMode::OfflineExactVersion)?;
    let conn = &db.conn;
    for seq in 1..=39 {
        conn.execute(
            "INSERT INTO events(seq, event_id, kind, aggregate_type, aggregate_id, actor_id, created_at_ms, expires_at_ms)
             VALUES (?1, ?1, 'auth.revoked', 'principal', ?1, ?1, 0, ?2)",
            params![seq, if seq == 2 { 11 } else { 10 }],
        )?;
    }
    conn.execute("UPDATE hub_meta SET events_head_seq = 39", [])?;
    let failed = gc_transaction(conn, |tx| {
        assert_eq!(prune_events(tx, 10, 0)?, 1);
        Err::<(), _>(rusqlite::Error::InvalidQuery)
    });
    assert!(failed.is_err());
    let watermark = || {
        conn.query_row(
            "SELECT events_pruned_through_seq FROM hub_meta",
            [],
            |row| row.get::<_, i64>(0),
        )
    };
    assert_eq!(watermark()?, 0);
    assert_eq!(gc_transaction(conn, |tx| prune_events(tx, 10, 0))?, 1);
    assert_eq!(watermark()?, 1);
    assert_eq!(gc_transaction(conn, |tx| prune_events(tx, 10, 0))?, 0);
    let before = conn.total_changes();
    assert_eq!(gc_transaction(conn, |tx| prune_events(tx, 10, 37))?, 31);
    assert_eq!(conn.total_changes() - before, 32);
    assert_eq!(watermark()?, 32);
    assert_eq!(gc_transaction(conn, |tx| prune_events(tx, 10, 0))?, 7);
    assert_eq!(watermark()?, 39);
    assert_eq!(
        conn.query_row("SELECT events_head_seq FROM hub_meta", [], |row| row
            .get::<_, i64>(0))?,
        39
    );
    Ok(())
}

#[test]
fn soft_pressure_uses_result_order_hysteresis_and_preserves_events() -> TestResult {
    let f = Fixture::create(StorageConfig {
        max_page_count: 256,
        ..StorageConfig::default()
    })?;
    let db = f.open(OpenMode::OfflineExactVersion)?;
    let conn = &db.conn;
    let old = seed_execution(conn, &f, f.principal, "succeeded", 100, 200, 350_000)?;
    let recent = seed_execution(conn, &f, f.principal, "succeeded", 200, 300, 350_000)?;
    conn.execute(
        "INSERT INTO events(event_id, kind, aggregate_type, aggregate_id, actor_id, created_at_ms, expires_at_ms)
         VALUES ('one', 'auth.revoked', 'principal', 'a', 'a', 0, 0)",
        [],
    )?;
    let mut maintenance = Maintenance::new(&db)?;
    assert!(maintenance.soft_active);
    assert!(maintenance.used_percent >= 75);
    maintenance.gc_step(&db)?;
    let has_blob = |id: ExecutionId| {
        conn.query_row(
            "SELECT sealed_result_blob IS NOT NULL FROM executions WHERE execution_id = ?1",
            [id.to_string()],
            |row| row.get::<_, bool>(0),
        )
    };
    assert!(!has_blob(old)?);
    assert!(!has_blob(recent)?);
    assert!(!maintenance.soft_active);
    assert!(maintenance.used_percent < 65);
    assert_eq!(
        conn.query_row("SELECT count(*) FROM events", [], |row| row
            .get::<_, i64>(0))?,
        1
    );
    Ok(())
}

#[tokio::test]
async fn agent_purge_checks_all_restrict_edges_and_resumes_after_reopen() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let db = f.open(OpenMode::OfflineExactVersion)?;
    let conn = &db.conn;
    let admin = f.principal.to_string();
    let agents: [PrincipalId; 12] = std::array::from_fn(|_| PrincipalId::new_agent());
    let [
        account,
        token,
        grant,
        enrollment_creator,
        enrollment_manager,
        node_manager,
        owner,
        manager,
        publisher,
        tool_creator,
        caller,
        eligible,
    ] = agents.map(|id| id.to_string());
    for id in &agents {
        let id = id.to_string();
        conn.execute(
            "INSERT INTO principals(principal_id, kind, name, managed_by_principal_id, disabled_at_ms, created_at_ms, updated_at_ms)
             VALUES (?1, 'agent', ?1, ?2, -1, 0, 0)",
            params![id, admin],
        )?;
    }
    conn.execute(
        "INSERT INTO accounts(account_id, slug, owner_principal_id, visibility, kind, sealed_secret_blob, created_at_ms, updated_at_ms)
         VALUES ('shared', 'shared', ?1, 'shared', 'secret_kv', X'01', 0, 0)",
        [&account],
    )?;
    seed_token(
        conn,
        TokenId::new_user_or_agent(),
        f.principal,
        PrincipalId::parse(&token)?,
    )?;
    conn.execute(
        "INSERT INTO grants(grant_id, principal_id, scope_kind, capability, created_by, created_at_ms)
         VALUES ('global', ?1, 'global', 'admin', ?2, 0)",
        params![admin, grant],
    )?;
    conn.execute(
        "INSERT INTO node_enrollments(enrollment_id, verifier_hmac, target_node_name, managed_by_principal_id, created_by, expires_at_ms, created_at_ms)
         VALUES ('enrollment', 'hmac', 'node', ?1, ?2, 300, 0)",
        params![enrollment_manager, enrollment_creator],
    )?;
    conn.execute(
        "UPDATE nodes SET managed_by_principal_id = ?1",
        [&node_manager],
    )?;
    conn.execute(
        "INSERT INTO principals(principal_id, kind, name, owner_principal_id, managed_by_principal_id, created_at_ms, updated_at_ms)
         VALUES (?1, 'agent', 'dependent', ?2, ?3, 0, 0)",
        params![PrincipalId::new_agent().to_string(), owner, manager],
    )?;
    conn.execute(
        "INSERT INTO profiles(profile_id, slug, discovery_mode, created_at_ms, updated_at_ms)
         VALUES ('profile', 'profile', 'full', 0, 0)",
        [],
    )?;
    conn.execute(
        "INSERT INTO profile_editions(profile_id, version, discovery_mode, bindings_json, published_by, published_at_ms)
         VALUES ('profile', 1, 'full', '[]', ?1, 0)",
        [&publisher],
    )?;
    conn.execute(
        "INSERT INTO tools(tool_id, slug, kind, created_by, created_at_ms, updated_at_ms)
         VALUES (?1, 'tool', 'http', ?2, 0, 0)",
        params![ToolId::new().to_string(), tool_creator],
    )?;
    seed_execution(
        conn,
        &f,
        PrincipalId::parse(&caller)?,
        "running",
        100,
        100,
        0,
    )?;

    let renamed = PrincipalId::parse(&eligible)?;
    for n in 0..41 {
        seed_token(conn, TokenId::new_user_or_agent(), renamed, renamed)?;
        let scope = format!("scope-{n}");
        conn.execute(
            "INSERT INTO grants(grant_id, principal_id, scope_kind, scope_id, capability, created_by, created_at_ms)
             VALUES (?1, ?2, 'profile', ?3, 'invoke', ?2, 0)",
            params![GrantId::new().to_string(), eligible, scope],
        )?;
        let upstream = format!("upstream-{n}");
        conn.execute(
            "INSERT INTO upstreams(upstream_id, slug, url, created_at_ms, updated_at_ms)
             VALUES (?1, ?1, 'https://example.test', 0, 0)",
            [&upstream],
        )?;
        conn.execute(
            "INSERT INTO account_bindings(principal_id, upstream_id, account_id, created_at_ms)
             VALUES (?1, ?2, 'shared', 0)",
            params![eligible, upstream],
        )?;
    }
    conn.execute(
        "UPDATE principals SET disabled_at_ms = NULL WHERE principal_id = ?1",
        [&eligible],
    )?;
    assert!(!gc_transaction(conn, |tx| claim_agent(tx, 0))?);
    conn.execute(
        "UPDATE principals SET disabled_at_ms = -1 WHERE principal_id = ?1",
        [&eligible],
    )?;
    let before = conn.total_changes();
    assert!(gc_transaction(conn, |tx| claim_agent(tx, 0))?);
    assert_eq!(conn.total_changes() - before, 2);
    assert_eq!(purging_principal(conn)?.as_deref(), Some(eligible.as_str()));
    assert_eq!(
        principal_liveness(conn, renamed)?,
        PrincipalLiveness::Missing
    );
    conn.execute(
        "INSERT INTO principals(principal_id, kind, name, created_at_ms, updated_at_ms)
         VALUES (?1, 'member', ?2, 0, 0)",
        params![PrincipalId::new_user().to_string(), eligible],
    )?;
    let before = conn.total_changes();
    assert!(gc_transaction(conn, purge_agent_children)?);
    assert_eq!(conn.total_changes() - before, 32);
    drop(db);

    let (handle, runtime) = f.start()?;
    let count = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let name = eligible.clone();
            let count = handle
                .read_snapshot(move |conn| {
                    let purging = purging_principal(conn)?;
                    let n = conn.query_row(
                        "SELECT count(*) FROM principals WHERE name = '~purging:' || ?1",
                        [name],
                        |r| r.get::<_, i64>(0),
                    )?;
                    Ok::<_, StorageError>((purging, n))
                })
                .await?;
            if count.0.is_none() {
                break Ok::<_, StorageError>(count.1);
            }
        }
    })
    .await??;
    assert_eq!(count, 0);
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    let db = f.open(OpenMode::OfflineExactVersion)?;
    for &id in &agents[..11] {
        assert_eq!(
            principal_liveness(&db.conn, id)?,
            PrincipalLiveness::Disabled
        );
    }
    Ok(())
}
