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
    let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {SELECT_RESULT_BYTES}"))?;
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
        max_page_count: 5_600,
        ..StorageConfig::default()
    })?;
    let db = f.open(OpenMode::OfflineExactVersion)?;
    let conn = &db.conn;
    conn.execute(
        "INSERT INTO accounts(account_id, slug, owner_principal_id, visibility, kind, sealed_secret_blob, created_at_ms, updated_at_ms)
         VALUES ('base', 'base', ?1, 'private', 'secret_kv', zeroblob(13400000), 0, 0)",
        [f.principal.to_string()],
    )?;
    // Each blob exceeds MAX_WORK_BYTES / 2 so one soft pass evicts only the
    // oldest result, proving both ordering and 75%->65% hysteresis.
    let old = seed_execution(conn, &f, f.principal, "succeeded", 100, 200, 2_500_000)?;
    let recent = seed_execution(conn, &f, f.principal, "succeeded", 200, 300, 2_500_000)?;
    conn.execute(
        "INSERT INTO events(event_id, kind, aggregate_type, aggregate_id, actor_id, created_at_ms, expires_at_ms)
         VALUES ('one', 'auth.revoked', 'principal', 'a', 'a', 0, 0)",
        [],
    )?;
    let mut maintenance = Maintenance::new(&db, Arc::new(AtomicU64::new(0)))?;
    assert!(matches!(maintenance.soft, SoftState::Active { .. }));
    assert!(
        (75..85).contains(&maintenance.used_percent),
        "{}",
        maintenance.used_percent
    );
    let has_blob = |id: ExecutionId| {
        conn.query_row(
            "SELECT sealed_result_blob IS NOT NULL FROM executions WHERE execution_id = ?1",
            [id.to_string()],
            |row| row.get::<_, bool>(0),
        )
    };
    maintenance.run_lane(&db, GcLane::Soft)?;
    assert!(!has_blob(old)?);
    assert!(has_blob(recent)?);
    assert!(
        (65..75).contains(&maintenance.used_percent),
        "{}",
        maintenance.used_percent
    );
    assert!(matches!(maintenance.soft, SoftState::Active { .. }));

    maintenance.run_lane(&db, GcLane::Soft)?;
    assert!(!has_blob(recent)?);
    assert!(
        maintenance.used_percent < 65,
        "{}",
        maintenance.used_percent
    );
    assert_eq!(maintenance.soft, SoftState::Idle);
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
    let steps = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {CLAIM_AGENT}"))?
        .query_map([0], |row| row.get::<_, String>(3))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let joined = steps.join(" | ");
    assert!(
        joined.contains("idx_principals_disabled_agents"),
        "{joined}"
    );
    assert!(!joined.contains("TEMP B-TREE"), "{joined}");
    assert!(!joined.contains("COMPOUND"), "{joined}");
    for idx in [
        "idx_accounts_owner",
        "idx_auth_tokens_created_by",
        "idx_grants_created_by",
        "idx_node_enrollments_created_by",
        "idx_node_enrollments_managed_by",
        "idx_nodes_managed_by",
        "idx_principals_owner",
        "idx_principals_managed_by",
        "idx_profile_editions_published_by",
        "idx_tools_created_by",
        "idx_executions_caller",
    ] {
        assert!(joined.contains(idx), "missing {idx} in {joined}");
    }

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

#[test]
fn later_ttl_passes_vacuum_an_existing_freelist_without_new_deletions() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let db = f.open(OpenMode::OfflineExactVersion)?;
    let conn = &db.conn;
    seed_execution(conn, &f, f.principal, "succeeded", 0, 9, 2_500_000)?;
    assert_eq!(gc_transaction(conn, |tx| expire_results(tx, 0))?, 1);
    incremental_vacuum(conn)?;
    let before = Pages::read(conn)?;
    assert!(before.free > 128);
    drop(db);

    let db = f.open(OpenMode::OfflineExactVersion)?;
    let mut maintenance = Maintenance::new(&db, Arc::new(AtomicU64::new(0)))?;
    for turn in 1..=2 {
        let now = turn * db.config.gc_interval;
        maintenance.tick(&db, now, false)?;
        for _ in 0..16 {
            if !maintenance.wait_for(&db, now).is_zero() {
                break;
            }
            maintenance.tick(&db, now, false)?;
        }
        assert!(
            !maintenance.wait_for(&db, now).is_zero(),
            "GC did not finish its bounded pass"
        );
        assert_eq!(before.free - Pages::read(&db.conn)?.free, turn * 64);
    }
    Ok(())
}

#[test]
fn periodic_token_gc_makes_progress_while_soft_pressure_remains_active() -> TestResult {
    let f = Fixture::create(StorageConfig {
        max_page_count: 256,
        ..StorageConfig::default()
    })?;
    let db = f.open(OpenMode::OfflineExactVersion)?;
    let conn = &db.conn;
    conn.execute(
        "INSERT INTO upstreams(upstream_id, slug, url, discovered_tools_json, created_at_ms, updated_at_ms)
         VALUES ('large', 'large', 'https://example.test', zeroblob(680000), 0, 0)",
        [],
    )?;
    conn.execute(
        "UPDATE auth_tokens SET revoked_at_ms = ?1",
        [-db.config.token_gc_grace_ms],
    )?;
    let mut maintenance = Maintenance::new(&db, Arc::new(AtomicU64::new(0)))?;
    assert!(matches!(maintenance.soft, SoftState::Active { .. }));
    for _ in 0..20 {
        seed_execution(conn, &f, f.principal, "succeeded", 100, 200, 1024)?;
        maintenance.after_write(&db, true, 1024, true, 0, false)?;
        maintenance.tick(&db, db.config.gc_interval, false)?;
        assert!(
            !matches!(maintenance.soft, SoftState::Idle),
            "fixture must stay under soft pressure"
        );
    }
    let revoked = conn.query_row("SELECT count(*) FROM auth_tokens", [], |row| {
        row.get::<_, u32>(0)
    })?;
    assert_eq!(
        revoked, 0,
        "periodic revocation cleanup was starved by soft result GC"
    );
    Ok(())
}

#[test]
fn failing_purge_lane_does_not_starve_other_gc_lanes() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let db = f.open(OpenMode::OfflineExactVersion)?;
    let conn = &db.conn;
    let stuck = PrincipalId::new_agent();
    conn.execute(
        "INSERT INTO principals(principal_id, kind, name, managed_by_principal_id, disabled_at_ms, created_at_ms, updated_at_ms)
         VALUES (?1, 'agent', '~purging:stuck', ?2, -1, 0, 0)",
        params![stuck.to_string(), f.principal.to_string()],
    )?;
    // An unexpected RESTRICT reference causes purge_agent_children's final DELETE to fail.
    conn.execute(
        "INSERT INTO accounts(account_id, slug, owner_principal_id, visibility, kind, sealed_secret_blob, created_at_ms, updated_at_ms)
         VALUES ('blocker', 'blocker', ?1, 'shared', 'secret_kv', X'01', 0, 0)",
        [stuck.to_string()],
    )?;
    conn.execute(
        "UPDATE hub_meta SET gc_purging_principal_id = ?1 WHERE id = 1",
        [stuck.to_string()],
    )?;
    let expired_token = TokenId::new_user_or_agent();
    seed_token(conn, expired_token, f.principal, f.principal)?;
    conn.execute(
        "UPDATE auth_tokens SET expires_at_ms = ?1 WHERE token_id = ?2",
        params![-db.config.token_gc_grace_ms, expired_token.to_string()],
    )?;

    let gc_errors = Arc::new(AtomicU64::new(0));
    let mut maintenance = Maintenance::new(&db, Arc::clone(&gc_errors))?;
    let now = db.config.gc_interval;
    for _ in 0..16 {
        maintenance.tick(&db, now, false)?;
    }
    assert_eq!(gc_errors.load(Ordering::Relaxed), 1);
    assert!(maintenance.held_lanes[GcLane::Purge as usize]);
    assert!(!maintenance.held_lanes[GcLane::Scheduled as usize]);
    let remaining: i64 = conn.query_row(
        "SELECT COUNT(*) FROM auth_tokens WHERE token_id = ?1",
        [expired_token.to_string()],
        |row| row.get(0),
    )?;
    assert_eq!(
        remaining, 0,
        "expired token GC was blocked by failing Purge lane"
    );
    Ok(())
}

#[test]
fn soft_pressure_clears_latch_in_normal_band_and_respects_recency_grace_until_hard() -> TestResult {
    // Part 1: Normal-band latch clearing (65..74% permanent data must not wipe later results).
    let f = Fixture::create(StorageConfig {
        max_page_count: 300,
        ..StorageConfig::default()
    })?;
    let db = f.open(OpenMode::OfflineExactVersion)?;
    let conn = &db.conn;
    conn.execute(
        "INSERT INTO accounts(account_id, slug, owner_principal_id, visibility, kind, sealed_secret_blob, created_at_ms, updated_at_ms)
         VALUES ('perm', 'perm', ?1, 'private', 'secret_kv', zeroblob(600000), 0, 0)",
        [f.principal.to_string()],
    )?;
    let old = seed_execution(conn, &f, f.principal, "succeeded", 100, 200, 140_000)?;
    let mut maintenance = Maintenance::new(&db, Arc::new(AtomicU64::new(0)))?;
    assert!(
        maintenance.used_percent >= 75,
        "{}",
        maintenance.used_percent
    );
    assert!(matches!(maintenance.soft, SoftState::Active { .. }));
    // First soft pass reclaims `old`, dropping usage into 65..74%.
    maintenance.run_lane(&db, GcLane::Soft)?;
    assert!(
        (65..75).contains(&maintenance.used_percent),
        "{}",
        maintenance.used_percent
    );
    assert!(!conn.query_row(
        "SELECT sealed_result_blob IS NOT NULL FROM executions WHERE execution_id = ?1",
        [old.to_string()],
        |row| row.get::<_, bool>(0),
    )?);
    // Second soft pass finds nothing else reclaimable while < 75% and clears to Idle.
    maintenance.run_lane(&db, GcLane::Soft)?;
    assert_eq!(maintenance.soft, SoftState::Idle);
    // A subsequent normal-pressure result write must NOT reactivate soft eviction.
    let newer = seed_execution(conn, &f, f.principal, "succeeded", 500, 600, 8_192)?;
    maintenance.after_write(&db, true, 8_192, true, 0, false)?;
    assert!(
        maintenance.used_percent < 75,
        "{}",
        maintenance.used_percent
    );
    assert_eq!(maintenance.soft, SoftState::Idle);
    assert!(conn.query_row(
        "SELECT sealed_result_blob IS NOT NULL FROM executions WHERE execution_id = ?1",
        [newer.to_string()],
        |row| row.get::<_, bool>(0),
    )?);

    // Part 2: 60s recency grace protects fresh receipts at 75..84% and is bypassed at >= 85%.
    let f2 = Fixture::create(StorageConfig {
        max_page_count: 300,
        soft_pressure_grace_ms: 60_000,
        ..StorageConfig::default()
    })?;
    f2.set_wall_ms(100_000);
    let db2 = f2.open(OpenMode::OfflineExactVersion)?;
    let conn2 = &db2.conn;
    conn2.execute(
        "INSERT INTO accounts(account_id, slug, owner_principal_id, visibility, kind, sealed_secret_blob, created_at_ms, updated_at_ms)
         VALUES ('perm', 'perm', ?1, 'private', 'secret_kv', zeroblob(550000), 0, 0)",
        [f2.principal.to_string()],
    )?;
    let aged = seed_execution(
        conn2,
        &f2,
        f2.principal,
        "succeeded",
        500_000,
        600_000,
        60_000,
    )?;
    conn2.execute(
        "UPDATE executions SET finished_at_ms = 10000 WHERE execution_id = ?1",
        [aged.to_string()],
    )?;
    let fresh = seed_execution(
        conn2,
        &f2,
        f2.principal,
        "succeeded",
        500_000,
        600_000,
        100_000,
    )?;
    conn2.execute(
        "UPDATE executions SET finished_at_ms = 90000 WHERE execution_id = ?1",
        [fresh.to_string()],
    )?;
    let has_blob2 = |id: ExecutionId| {
        conn2.query_row(
            "SELECT sealed_result_blob IS NOT NULL FROM executions WHERE execution_id = ?1",
            [id.to_string()],
            |row| row.get::<_, bool>(0),
        )
    };
    let mut m2 = Maintenance::new(&db2, Arc::new(AtomicU64::new(0)))?;
    assert!((75..85).contains(&m2.used_percent), "{}", m2.used_percent);
    m2.run_lane(&db2, GcLane::Soft)?;
    assert!(
        !has_blob2(aged)?,
        "aged result should be evicted under soft pressure"
    );
    assert!(
        has_blob2(fresh)?,
        "fresh result within 60s grace must be preserved at 75..84%"
    );
    assert!((75..85).contains(&m2.used_percent), "{}", m2.used_percent);
    m2.run_lane(&db2, GcLane::Soft)?;
    assert!(
        has_blob2(fresh)?,
        "second soft pass must still respect 60s grace"
    );
    assert_eq!(m2.soft, SoftState::Exhausted { at_hard: false });

    // Writing another small result blob while still in 75..84% must NOT re-arm
    // SoftState::Exhausted { at_hard: false } (it waits for periodic GC or >= 85% hard crossing).
    let fresh_two = seed_execution(
        conn2,
        &f2,
        f2.principal,
        "succeeded",
        500_000,
        600_000,
        4_096,
    )?;
    conn2.execute(
        "UPDATE executions SET finished_at_ms = 95000 WHERE execution_id = ?1",
        [fresh_two.to_string()],
    )?;
    m2.after_write(&db2, true, 4_096, true, 0, false)?;
    assert!((75..85).contains(&m2.used_percent), "{}", m2.used_percent);
    assert_eq!(m2.soft, SoftState::Exhausted { at_hard: false });

    // Crossing >= 85% Hard pressure wakes Soft and bypasses recency grace immediately.
    conn2.execute(
        "INSERT INTO accounts(account_id, slug, owner_principal_id, visibility, kind, sealed_secret_blob, created_at_ms, updated_at_ms)
         VALUES ('push', 'push', ?1, 'private', 'secret_kv', zeroblob(180000), 0, 0)",
        [f2.principal.to_string()],
    )?;
    m2.after_write(&db2, true, 180_000, false, 0, false)?;
    assert!(m2.used_percent >= 85, "{}", m2.used_percent);
    assert!(matches!(
        m2.soft,
        SoftState::Active {
            defer_next_work: true
        }
    ));
    m2.run_lane(&db2, GcLane::Soft)?;
    assert!(
        !has_blob2(fresh)?,
        "hard pressure (>= 85%) must bypass 60s recency grace"
    );
    Ok(())
}

#[test]
fn reactive_vacuum_batches_small_freelists_and_wal_truncate_clears_cooldown() -> TestResult {
    let f = Fixture::create(StorageConfig {
        journal_size_limit_bytes: 4096,
        ..StorageConfig::default()
    })?;
    let db = f.open(OpenMode::OfflineExactVersion)?;
    let conn = &db.conn;
    // Free ~10 pages (< 64): reactive vacuum skips, periodic vacuum drains.
    seed_execution(conn, &f, f.principal, "succeeded", 0, 9, 40_960)?;
    assert_eq!(gc_transaction(conn, |tx| expire_results(tx, 0))?, 1);
    let free_small = Pages::read(conn)?.free;
    assert!(
        (1..REACTIVE_VACUUM_MIN_FREE_PAGES).contains(&free_small),
        "{free_small}"
    );

    let mut maintenance = Maintenance::new(&db, Arc::new(AtomicU64::new(0)))?;
    maintenance.reactive_vacuum_pending = true;
    maintenance.run_lane(&db, GcLane::Vacuum)?;
    assert_eq!(
        Pages::read(conn)?.free,
        free_small,
        "reactive vacuum should skip < 64 free pages"
    );

    maintenance.periodic_vacuum_pending = true;
    maintenance.run_lane(&db, GcLane::Vacuum)?;
    assert_eq!(
        Pages::read(conn)?.free,
        0,
        "periodic vacuum should drain small freelist"
    );

    // WAL cooldown is cleared immediately when a TRUNCATE succeeds.
    maintenance.next_wal_truncate = Some(Duration::from_secs(10));
    for i in 1..=6 {
        conn.execute("UPDATE hub_meta SET updated_at_ms = ?1", [i])?;
    }
    assert!(wal_bytes(&maintenance.wal_path)? > 8192);
    maintenance.checkpoint_wal(&db, Duration::from_secs(10))?;
    assert_eq!(maintenance.next_wal_truncate, None);
    assert_eq!(wal_bytes(&maintenance.wal_path)?, 0);
    Ok(())
}

#[test]
fn all_gc_and_waiter_queries_use_indexes_without_temp_btree() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let db = f.open(OpenMode::OfflineExactVersion)?;
    let conn = &db.conn;

    let explain = |sql: &str, expected_index: &str| -> TestResult {
        let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(3))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .join(" | ");
        assert!(rows.contains(expected_index), "{sql} -> {rows}");
        assert!(!rows.contains("TEMP B-TREE"), "{sql} -> {rows}");
        Ok(())
    };

    explain(
        "SELECT execution_id, state, finished_at_ms FROM executions WHERE state IN ('accepted', 'running')",
        "idx_executions_active_deadline",
    )?;
    explain(
        "SELECT result_bytes FROM executions WHERE sealed_result_blob IS NOT NULL AND result_expires_at_ms <= 0 ORDER BY result_expires_at_ms, execution_id LIMIT 32",
        "idx_executions_result_expires",
    )?;
    explain(
        "SELECT result_bytes FROM executions WHERE sealed_result_blob IS NOT NULL AND (result_expires_at_ms <= 0 OR finished_at_ms IS NULL OR finished_at_ms <= 0) ORDER BY result_expires_at_ms, execution_id LIMIT 32",
        "idx_executions_result_expires",
    )?;
    explain(
        "SELECT result_bytes FROM executions WHERE expires_at_ms <= 0 AND state NOT IN ('accepted', 'running') ORDER BY expires_at_ms, rowid LIMIT 32",
        "idx_executions_expires",
    )?;
    explain(
        "SELECT token_id FROM auth_tokens WHERE expires_at_ms <= 0 ORDER BY expires_at_ms LIMIT 32",
        "idx_auth_tokens_expires",
    )?;
    explain(
        "SELECT token_id FROM auth_tokens WHERE revoked_at_ms <= 0 ORDER BY revoked_at_ms LIMIT 32",
        "idx_auth_tokens_revoked",
    )?;
    explain(
        "SELECT enrollment_id FROM node_enrollments WHERE expires_at_ms <= 0 ORDER BY expires_at_ms LIMIT 32",
        "idx_node_enrollments_expires",
    )?;
    // Keyset pagination queries use composite indexes without TEMP B-TREE.
    explain(
        "SELECT principal_id FROM principals WHERE owner_principal_id = 'usr_1' AND principal_id > '' ORDER BY principal_id LIMIT 51",
        "idx_principals_owner",
    )?;
    explain(
        "SELECT principal_id FROM principals WHERE managed_by_principal_id = 'svc_1' AND principal_id > '' ORDER BY principal_id LIMIT 51",
        "idx_principals_managed_by",
    )?;
    explain(
        "SELECT token_id FROM auth_tokens WHERE principal_id = 'usr_1' AND token_id > '' ORDER BY token_id LIMIT 51",
        "idx_auth_tokens_principal",
    )?;
    explain(
        "SELECT grant_id FROM grants WHERE principal_id = 'usr_1' AND grant_id > '' ORDER BY grant_id LIMIT 51",
        "idx_grants_principal",
    )?;
    explain(
        "SELECT node_id FROM nodes WHERE managed_by_principal_id = 'svc_1' AND node_id > '' ORDER BY node_id LIMIT 51",
        "idx_nodes_managed_by",
    )?;
    Ok(())
}

#[test]
fn soft_state_handles_stale_hard_crossing_external_drop_and_held_scheduled_vacuum() -> TestResult {
    // 1. Stale used_percent = 84% when actual DB already crossed >= 85% must NOT
    // latch Exhausted { at_hard: false }; it must stay Active so the next pass
    // bypasses the 60s grace and evicts fresh blobs.
    let f = Fixture::create(StorageConfig {
        max_page_count: 300,
        soft_pressure_grace_ms: 60_000,
        ..StorageConfig::default()
    })?;
    f.set_wall_ms(100_000);
    let db = f.open(OpenMode::OfflineExactVersion)?;
    let conn = &db.conn;
    conn.execute(
        "INSERT INTO accounts(account_id, slug, owner_principal_id, visibility, kind, sealed_secret_blob, created_at_ms, updated_at_ms)
         VALUES ('perm', 'perm', ?1, 'private', 'secret_kv', zeroblob(680000), 0, 0)",
        [f.principal.to_string()],
    )?;
    let fresh = seed_execution(
        conn,
        &f,
        f.principal,
        "succeeded",
        500_000,
        600_000,
        100_000,
    )?;
    conn.execute(
        "UPDATE executions SET finished_at_ms = 90000 WHERE execution_id = ?1",
        [fresh.to_string()],
    )?;
    let mut m = Maintenance::new(&db, Arc::new(AtomicU64::new(0)))?;
    assert!(m.used_percent >= 85, "{}", m.used_percent);
    // Simulate a cached 84% reading before an unsampled write pushed into >= 85%.
    m.used_percent = 84;
    m.soft = SoftState::Active {
        defer_next_work: false,
    };
    m.run_lane(&db, GcLane::Soft)?;
    assert!(m.used_percent >= 85, "{}", m.used_percent);
    assert_eq!(
        m.soft,
        SoftState::Active {
            defer_next_work: true
        },
        "crossing >= 85% during graced soft pass must stay Active for immediate hard retry"
    );
    m.run_lane(&db, GcLane::Soft)?;
    assert!(!conn.query_row(
        "SELECT sealed_result_blob IS NOT NULL FROM executions WHERE execution_id = ?1",
        [fresh.to_string()],
        |row| row.get::<_, bool>(0),
    )?);

    // 2. Non-Soft deletion dropping usage from Exhausted (>= 75%) into Normal (65..74%)
    // must clear SoftState::Exhausted -> Idle both on sample() and on periodic_due.
    let f2 = Fixture::create(StorageConfig {
        max_page_count: 300,
        soft_pressure_grace_ms: 60_000,
        ..StorageConfig::default()
    })?;
    f2.set_wall_ms(100_000);
    let db2 = f2.open(OpenMode::OfflineExactVersion)?;
    let conn2 = &db2.conn;
    conn2.execute(
        "INSERT INTO accounts(account_id, slug, owner_principal_id, visibility, kind, sealed_secret_blob, created_at_ms, updated_at_ms)
         VALUES ('base', 'base', ?1, 'private', 'secret_kv', zeroblob(550000), 0, 0)",
        [f2.principal.to_string()],
    )?;
    conn2.execute(
        "INSERT INTO accounts(account_id, slug, owner_principal_id, visibility, kind, sealed_secret_blob, created_at_ms, updated_at_ms)
         VALUES ('temp', 'temp', ?1, 'private', 'secret_kv', zeroblob(140000), 0, 0)",
        [f2.principal.to_string()],
    )?;
    let mut m2 = Maintenance::new(&db2, Arc::new(AtomicU64::new(0)))?;
    assert!((75..85).contains(&m2.used_percent), "{}", m2.used_percent);
    m2.run_lane(&db2, GcLane::Soft)?;
    assert_eq!(m2.soft, SoftState::Exhausted { at_hard: false });
    // External delete returns usage to Normal 65..74%: an intervening
    // wrote_result_blob commit before periodic_due must sample first, clear
    // Exhausted -> Idle, and leave the new result untouched.
    conn2.execute("DELETE FROM accounts WHERE account_id = 'temp'", [])?;
    let normal_result = seed_execution(
        conn2,
        &f2,
        f2.principal,
        "succeeded",
        500_000,
        600_000,
        1024,
    )?;
    m2.after_write(&db2, true, 1024, true, 0, false)?;
    assert!((65..75).contains(&m2.used_percent), "{}", m2.used_percent);
    assert_eq!(m2.soft, SoftState::Idle);
    assert!(conn2.query_row(
        "SELECT sealed_result_blob IS NOT NULL FROM executions WHERE execution_id = ?1",
        [normal_result.to_string()],
        |row| row.get::<_, bool>(0),
    )?);

    // Same drop into Normal 65..74% before periodic_due must also sample first
    // and clear Exhausted -> Idle rather than waking Soft in Normal.
    m2.soft = SoftState::Exhausted { at_hard: false };
    let due = m2.next_gc;
    m2.tick(&db2, due, false)?;
    assert!((65..75).contains(&m2.used_percent), "{}", m2.used_percent);
    assert_eq!(m2.soft, SoftState::Idle);

    // 3. A held Scheduled lane with remaining steps must NOT block Vacuum.
    m2.held_lanes[GcLane::Scheduled as usize] = true;
    m2.scheduled_steps.push_back(GcStep::Results);
    m2.periodic_vacuum_pending = true;
    assert!(Pages::read(conn2)?.free > 0);
    let ready = m2.ready_lane(&db2);
    assert!(matches!(ready, Some((_, GcLane::Vacuum))), "{ready:?}");
    m2.run_lane(&db2, GcLane::Vacuum)?;
    assert_eq!(Pages::read(conn2)?.free, 0);
    Ok(())
}
