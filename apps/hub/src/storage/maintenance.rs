use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;

use super::actor::{MAX_WORK_BYTES, WriteTx, WriteTxError};
use super::lifecycle::{OpenedDb, WAL_FILE, WalCheckpointOutcome, truncate_checkpoint};
use super::{PAGE_SIZE, StorageError, StorageHandle};

const GC_ROWS: usize = 32;
const PRUNE_EVENTS_LIMIT: usize = GC_ROWS - 1;
const REACTIVE_VACUUM_MIN_FREE_PAGES: u32 = 64;
const SAMPLE_COMMITS: usize = 100;
const SHORT_CHECKPOINT: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoragePressure {
    Normal,
    Soft,
    Hard,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct StorageStatus {
    pub page_count: u32,
    pub freelist_count: u32,
    pub max_page_count: u32,
    pub used_percent: u32,
    pub storage_pressure: StoragePressure,
    pub events_head_seq: i64,
    pub events_pruned_through_seq: i64,
    pub active_waiters_count: usize,
}

#[derive(Clone, Copy)]
struct Pages {
    count: u32,
    free: u32,
}

impl Pages {
    fn read(conn: &Connection) -> rusqlite::Result<Self> {
        let mut stmt = conn.prepare_cached(
            "SELECT (SELECT * FROM pragma_page_count), (SELECT * FROM pragma_freelist_count)",
        )?;
        stmt.query_row([], |row| {
            Ok(Self {
                count: row.get(0)?,
                free: row.get(1)?,
            })
        })
    }

    fn percent(self, cap: u32) -> u32 {
        // A validated writer budget always covers at most u32::MAX pages.
        let ratio = u64::from(self.count.saturating_sub(self.free)) * 100 / u64::from(cap);
        u32::try_from(ratio).unwrap_or(u32::MAX)
    }
}

fn pressure(percent: u32) -> StoragePressure {
    match percent {
        85.. => StoragePressure::Hard,
        75..=84 => StoragePressure::Soft,
        _ => StoragePressure::Normal,
    }
}

impl StorageHandle {
    pub async fn status_snapshot(&self) -> Result<StorageStatus, StorageError> {
        let cap = self.max_page_count();
        let waiters = Arc::clone(&self.active_waiters);
        self.read_snapshot(move |conn| {
            let pages = Pages::read(conn)?;
            let mut meta = conn.prepare_cached(
                "SELECT events_head_seq, events_pruned_through_seq FROM hub_meta WHERE id = 1",
            )?;
            let (events_head_seq, events_pruned_through_seq) =
                meta.query_row([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            let used_percent = pages.percent(cap);
            Ok(StorageStatus {
                page_count: pages.count,
                freelist_count: pages.free,
                max_page_count: cap,
                used_percent,
                storage_pressure: pressure(used_percent),
                events_head_seq,
                events_pruned_through_seq,
                active_waiters_count: waiters.load(Ordering::Acquire),
            })
        })
        .await
    }
}

impl WriteTx<'_> {
    /// Read the current transaction's page usage after the replay lookup.
    pub(crate) fn check_hard_storage_pressure<E>(&mut self) -> Result<(), WriteTxError<E>> {
        let current = pressure(Pages::read(self.conn())?.percent(self.config.max_page_count));
        self.note_pressure_observation(current);
        if current == StoragePressure::Hard {
            return Err(WriteTxError::StoragePressure);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SoftState {
    Idle,
    Active { defer_next_work: bool },
    Exhausted { at_hard: bool },
}

pub(super) struct Maintenance {
    wal_path: PathBuf,
    next_wal_truncate: Option<Duration>,
    next_gc: Duration,
    scheduled_steps: VecDeque<GcStep>,
    held_lanes: [bool; GcLane::COUNT],
    purge_pending: bool,
    reactive_vacuum_pending: bool,
    periodic_vacuum_pending: bool,
    soft: SoftState,
    used_percent: u32,
    live_events_count: usize,
    event_write_debt: usize,
    next_lane: usize,
    unsampled_commits: usize,
    gc_errors: Arc<AtomicU64>,
}

impl Maintenance {
    pub(super) fn new(db: &OpenedDb, gc_errors: Arc<AtomicU64>) -> Result<Self, StorageError> {
        let live_events_count = db
            .conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
        let used_percent = Pages::read(&db.conn)?.percent(db.config.max_page_count);
        let purge_pending = purging_principal(&db.conn)?.is_some();
        let soft = if used_percent >= 75 {
            SoftState::Active {
                defer_next_work: true,
            }
        } else {
            SoftState::Idle
        };
        Ok(Self {
            wal_path: db.lock.path().join(WAL_FILE),
            next_wal_truncate: None,
            next_gc: db
                .clock
                .monotonic_now()?
                .saturating_add(db.config.gc_interval),
            scheduled_steps: VecDeque::new(),
            held_lanes: [false; GcLane::COUNT],
            purge_pending,
            reactive_vacuum_pending: false,
            periodic_vacuum_pending: false,
            soft,
            used_percent,
            live_events_count,
            event_write_debt: 0,
            next_lane: 0,
            unsampled_commits: 0,
            gc_errors,
        })
    }

    pub(super) fn level(&self) -> StoragePressure {
        pressure(self.used_percent)
    }

    /// Give retention and soft reclamation time to recover capacity between
    /// work batches. Priority and shutdown drain stay available.
    pub(super) fn defer_work(&self) -> bool {
        let defer_retention =
            !self.held_lanes[GcLane::Retention as usize] && self.event_write_debt != 0;
        let defer_soft = !self.held_lanes[GcLane::Soft as usize]
            && matches!(
                self.soft,
                SoftState::Active {
                    defer_next_work: true
                }
            );
        defer_retention || defer_soft
    }

    pub(super) fn after_write(
        &mut self,
        db: &OpenedDb,
        committed: bool,
        bytes: usize,
        wrote_result_blob: bool,
        appended_events: usize,
        resample: bool,
    ) -> Result<(), StorageError> {
        if committed {
            self.live_events_count += appended_events;
            let excess = self
                .live_events_count
                .saturating_sub(db.config.max_events_rows);
            if appended_events != 0 && excess != 0 {
                // Charge actual committed outbox rows. An extra slot when
                // already over cap lets a sustained stream pay down old rows.
                self.event_write_debt = self
                    .event_write_debt
                    .saturating_add(appended_events.min(excess).saturating_add(1));
            }
            self.unsampled_commits += 1;
            if wrote_result_blob && !matches!(self.soft, SoftState::Idle) {
                self.soft = SoftState::Active {
                    defer_next_work: true,
                };
            }
        }
        // Sample after result blobs or multi-page writes so even small databases
        // detect a soft/hard transition before the next large batch arrives.
        if !committed
            || resample
            || wrote_result_blob
            || bytes >= PAGE_SIZE as usize
            || self.unsampled_commits >= SAMPLE_COMMITS
        {
            self.sample(db)?;
        }
        Ok(())
    }

    fn sample(&mut self, db: &OpenedDb) -> rusqlite::Result<()> {
        self.used_percent = Pages::read(&db.conn)?.percent(db.config.max_page_count);
        if self.used_percent < 65 {
            self.soft = SoftState::Idle;
        } else if self.used_percent >= 85 {
            match self.soft {
                SoftState::Idle | SoftState::Exhausted { at_hard: false } => {
                    self.soft = SoftState::Active {
                        defer_next_work: true,
                    };
                }
                SoftState::Active { .. } | SoftState::Exhausted { at_hard: true } => {}
            }
        } else if self.used_percent >= 75 && matches!(self.soft, SoftState::Idle) {
            self.soft = SoftState::Active {
                defer_next_work: true,
            };
        }
        self.unsampled_commits = 0;
        Ok(())
    }

    pub(super) fn wait_for(&self, db: &OpenedDb, now: Duration) -> Duration {
        if self.ready_lane(db).is_some() {
            return Duration::ZERO;
        }
        self.next_gc
            .min(self.next_wal_truncate.unwrap_or(Duration::MAX))
            .saturating_sub(now)
    }

    /// Run one mini-transaction between mailbox turns.
    pub(super) fn tick(
        &mut self,
        db: &OpenedDb,
        now: Duration,
        wrote_wal: bool,
    ) -> Result<(), StorageError> {
        let periodic_due = now >= self.next_gc;
        if periodic_due {
            self.next_gc = now.saturating_add(db.config.gc_interval);
            self.held_lanes = [false; GcLane::COUNT];
            self.purge_pending = purging_principal(&db.conn)?.is_some();
            for step in GcStep::SCHEDULED {
                if step == GcStep::Agent && self.purge_pending {
                    continue;
                }
                if !self.scheduled_steps.contains(&step) {
                    self.scheduled_steps.push_back(step);
                }
            }
            self.periodic_vacuum_pending = true;
            if matches!(self.soft, SoftState::Exhausted { .. }) {
                self.soft = SoftState::Active {
                    defer_next_work: false,
                };
            }
            self.sample(db)?;
        }
        if let Some((index, lane)) = self.ready_lane(db) {
            self.next_lane = (index + 1) % GcLane::COUNT;
            if let Err(error) = self.run_lane(db, lane) {
                // FULL and failed FK checks must leave priority admission and
                // unrelated GC lanes intact.
                if !db.conn.is_autocommit() {
                    return Err(error.into());
                }
                self.gc_errors.fetch_add(1, Ordering::Relaxed);
                self.held_lanes[index] = true;
            }
        }
        if wrote_wal || periodic_due || self.next_wal_truncate.is_some_and(|retry| now >= retry) {
            self.checkpoint_wal(db, now)?;
        }
        Ok(())
    }

    fn ready_lane(&self, db: &OpenedDb) -> Option<(usize, GcLane)> {
        let lanes = GcLane::ORDER;
        (0..lanes.len()).find_map(|offset| {
            let index = (self.next_lane + offset) % lanes.len();
            if self.held_lanes[index] {
                return None;
            }
            let lane = lanes[index];
            let ready = match lane {
                GcLane::Purge => self.purge_pending,
                GcLane::Retention => self.live_events_count > db.config.max_events_rows,
                GcLane::Soft => matches!(self.soft, SoftState::Active { .. }),
                GcLane::Scheduled => !self.scheduled_steps.is_empty(),
                GcLane::Vacuum => {
                    (self.reactive_vacuum_pending || self.periodic_vacuum_pending)
                        && self.scheduled_steps.is_empty()
                }
            };
            ready.then_some((index, lane))
        })
    }

    fn run_lane(&mut self, db: &OpenedDb, lane: GcLane) -> rusqlite::Result<()> {
        let conn = &db.conn;
        let now = db.clock.wall_now_ms();
        match lane {
            GcLane::Purge => {
                self.purge_pending = gc_transaction(conn, purge_agent_children)?;
                self.reactive_vacuum_pending = true;
                self.sample(db)?;
            }
            GcLane::Retention => {
                let excess = self
                    .live_events_count
                    .saturating_sub(db.config.max_events_rows);
                let deleted = gc_transaction(conn, |tx| prune_events(tx, now, excess))?;
                if deleted == 0 {
                    self.live_events_count = 0;
                    self.event_write_debt = 0;
                } else {
                    self.record_prune(db, deleted);
                    self.sample(db)?;
                }
            }
            GcLane::Soft => {
                let at_hard = self.used_percent >= 85;
                let grace_ms = db.config.soft_pressure_grace_ms;
                let changed = gc_transaction(conn, |tx| {
                    if at_hard || grace_ms == 0 {
                        expire_results(tx, i64::MAX)
                    } else {
                        expire_results_with_grace(tx, now, now.saturating_sub(grace_ms))
                    }
                })?;
                if changed != 0 {
                    self.reactive_vacuum_pending = true;
                }
                self.sample(db)?;
                if changed == 0 {
                    // If usage has already returned to Normal (< 75%) and no
                    // reclaimable results remain, clear the hysteresis latch so
                    // future normal-pressure results are never evicted on commit.
                    self.soft = if self.used_percent < 75 {
                        SoftState::Idle
                    } else {
                        SoftState::Exhausted { at_hard }
                    };
                } else if matches!(self.soft, SoftState::Active { .. }) {
                    self.soft = SoftState::Active {
                        defer_next_work: false,
                    };
                }
            }
            GcLane::Scheduled => self.periodic_step(db, now)?,
            GcLane::Vacuum => self.vacuum(db)?,
        }
        Ok(())
    }

    fn periodic_step(&mut self, db: &OpenedDb, now: i64) -> rusqlite::Result<()> {
        let Some(step) = self.scheduled_steps.pop_front() else {
            return Ok(());
        };
        if step == GcStep::Agent && self.purge_pending {
            return Ok(());
        }
        let grace_cutoff = now.saturating_sub(db.config.token_gc_grace_ms);
        let changed = gc_transaction(&db.conn, |tx| match step {
            GcStep::Results => expire_results(tx, now),
            GcStep::Executions => expire_executions(tx, now),
            GcStep::Events => prune_events(tx, now, 0),
            GcStep::Tokens => {
                let mut stmt = tx.prepare_cached(
                    "DELETE FROM auth_tokens WHERE token_id IN (
                        SELECT token_id FROM auth_tokens WHERE expires_at_ms <= ?1 ORDER BY expires_at_ms LIMIT 32)",
                )?;
                stmt.execute([grace_cutoff])
            }
            GcStep::RevokedTokens => {
                let mut stmt = tx.prepare_cached(
                    "DELETE FROM auth_tokens WHERE token_id IN (
                        SELECT token_id FROM auth_tokens WHERE revoked_at_ms <= ?1 ORDER BY revoked_at_ms LIMIT 32)",
                )?;
                stmt.execute([grace_cutoff])
            }
            GcStep::Enrollments => {
                let mut stmt = tx.prepare_cached(
                    "DELETE FROM node_enrollments WHERE enrollment_id IN (
                        SELECT enrollment_id FROM node_enrollments WHERE expires_at_ms <= ?1 ORDER BY expires_at_ms LIMIT 32)",
                )?;
                stmt.execute([grace_cutoff])
            }
            GcStep::Agent => {
                claim_agent(tx, now.saturating_sub(db.config.agent_gc_age_ms)).map(usize::from)
            }
        })?;
        if step == GcStep::Events {
            self.record_prune(db, changed);
        }
        if step == GcStep::Agent {
            self.purge_pending = changed != 0;
        }
        if changed != 0 {
            if step != GcStep::Agent {
                self.scheduled_steps.push_back(step);
            }
            self.reactive_vacuum_pending = true;
            self.sample(db)?;
        }
        Ok(())
    }

    fn vacuum(&mut self, db: &OpenedDb) -> rusqlite::Result<()> {
        let periodic = self.periodic_vacuum_pending;
        self.periodic_vacuum_pending = false;
        self.reactive_vacuum_pending = false;
        let free = Pages::read(&db.conn)?.free;
        if free != 0 && (periodic || free >= REACTIVE_VACUUM_MIN_FREE_PAGES) {
            incremental_vacuum(&db.conn)?;
            self.sample(db)?;
        }
        Ok(())
    }

    fn record_prune(&mut self, db: &OpenedDb, deleted: usize) {
        self.live_events_count = self.live_events_count.saturating_sub(deleted);
        self.event_write_debt = if self.live_events_count <= db.config.max_events_rows {
            0
        } else {
            self.event_write_debt.saturating_sub(deleted)
        };
        self.reactive_vacuum_pending |= deleted != 0;
    }

    fn checkpoint_wal(&mut self, db: &OpenedDb, now: Duration) -> Result<(), StorageError> {
        let threshold = u64::try_from(db.config.journal_size_limit_bytes)
            .unwrap_or(u64::MAX)
            .saturating_mul(2);
        if wal_bytes(&self.wal_path)? <= threshold {
            self.next_wal_truncate = None;
            return Ok(());
        }

        db.conn
            .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |_| Ok(()))?;
        if wal_bytes(&self.wal_path)? <= threshold {
            self.next_wal_truncate = None;
            return Ok(());
        }
        if self.next_wal_truncate.is_some_and(|retry| now < retry) {
            return Ok(());
        }
        match truncate_checkpoint(&db.conn, SHORT_CHECKPOINT)? {
            WalCheckpointOutcome::Truncated => {
                self.next_wal_truncate = None;
            }
            WalCheckpointOutcome::Incomplete { .. } | WalCheckpointOutcome::Failed(_) => {
                self.next_wal_truncate = Some(now.saturating_add(db.config.wal_escalate_cooldown));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
#[repr(usize)]
enum GcLane {
    Purge = 0,
    Retention = 1,
    Soft = 2,
    Scheduled = 3,
    Vacuum = 4,
}

impl GcLane {
    const COUNT: usize = 5;
    const ORDER: [Self; Self::COUNT] = [
        Self::Purge,
        Self::Retention,
        Self::Soft,
        Self::Scheduled,
        Self::Vacuum,
    ];
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GcStep {
    Results,
    Executions,
    Events,
    Tokens,
    RevokedTokens,
    Enrollments,
    Agent,
}

impl GcStep {
    const SCHEDULED: [Self; 7] = [
        Self::Results,
        Self::Executions,
        Self::Events,
        Self::Tokens,
        Self::RevokedTokens,
        Self::Enrollments,
        Self::Agent,
    ];
}

fn gc_transaction<T>(
    conn: &Connection,
    op: impl FnOnce(&Connection) -> rusqlite::Result<T>,
) -> rusqlite::Result<T> {
    let tx = rusqlite::Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let value = op(&tx)?;
    tx.commit()?;
    Ok(value)
}

fn accumulate_rows(mut rows: rusqlite::Rows<'_>) -> rusqlite::Result<usize> {
    let mut count = 0;
    let mut remaining = MAX_WORK_BYTES as u64;
    while let Some(row) = rows.next()? {
        let bytes: u64 = row.get(0)?;
        // Always process one legacy or anomalously large row to make progress.
        if count != 0 && bytes > remaining {
            break;
        }
        count += 1;
        remaining = remaining.saturating_sub(bytes);
    }
    Ok(count)
}

const SELECT_RESULT_BYTES: &str = "SELECT result_bytes FROM executions
    WHERE sealed_result_blob IS NOT NULL AND result_expires_at_ms <= ?1
    ORDER BY result_expires_at_ms, execution_id LIMIT ?2";

const UPDATE_EXPIRED_RESULTS: &str = "UPDATE executions
    SET sealed_result_blob = NULL, result_bytes = 0, result_expired = 1
    WHERE execution_id IN (
        SELECT execution_id FROM executions
        WHERE sealed_result_blob IS NOT NULL AND result_expires_at_ms <= ?1
        ORDER BY result_expires_at_ms, execution_id LIMIT ?2
    )";

const SELECT_RESULT_BYTES_GRACE: &str = "SELECT result_bytes FROM executions
    WHERE sealed_result_blob IS NOT NULL
      AND (result_expires_at_ms <= ?1 OR finished_at_ms IS NULL OR finished_at_ms <= ?2)
    ORDER BY result_expires_at_ms, execution_id LIMIT ?3";

const UPDATE_EXPIRED_RESULTS_GRACE: &str = "UPDATE executions
    SET sealed_result_blob = NULL, result_bytes = 0, result_expired = 1
    WHERE execution_id IN (
        SELECT execution_id FROM executions
        WHERE sealed_result_blob IS NOT NULL
          AND (result_expires_at_ms <= ?1 OR finished_at_ms IS NULL OR finished_at_ms <= ?2)
        ORDER BY result_expires_at_ms, execution_id LIMIT ?3
    )";

const SELECT_EXECUTION_BYTES: &str = "SELECT result_bytes FROM executions
    WHERE expires_at_ms <= ?1 AND state NOT IN ('accepted', 'running')
    ORDER BY expires_at_ms, rowid LIMIT ?2";

const DELETE_EXPIRED_EXECUTIONS: &str = "DELETE FROM executions
    WHERE execution_id IN (
        SELECT execution_id FROM executions
        WHERE expires_at_ms <= ?1 AND state NOT IN ('accepted', 'running')
        ORDER BY expires_at_ms, rowid LIMIT ?2
    )";

fn expire_results(conn: &Connection, cutoff: i64) -> rusqlite::Result<usize> {
    let count = {
        let mut stmt = conn.prepare_cached(SELECT_RESULT_BYTES)?;
        accumulate_rows(stmt.query(params![cutoff, GC_ROWS])?)?
    };
    if count == 0 {
        return Ok(0);
    }
    let mut update = conn.prepare_cached(UPDATE_EXPIRED_RESULTS)?;
    update.execute(params![cutoff, count])
}

fn expire_results_with_grace(
    conn: &Connection,
    now: i64,
    finished_before: i64,
) -> rusqlite::Result<usize> {
    let count = {
        let mut stmt = conn.prepare_cached(SELECT_RESULT_BYTES_GRACE)?;
        accumulate_rows(stmt.query(params![now, finished_before, GC_ROWS])?)?
    };
    if count == 0 {
        return Ok(0);
    }
    let mut update = conn.prepare_cached(UPDATE_EXPIRED_RESULTS_GRACE)?;
    update.execute(params![now, finished_before, count])
}

fn expire_executions(conn: &Connection, cutoff: i64) -> rusqlite::Result<usize> {
    let count = {
        let mut stmt = conn.prepare_cached(SELECT_EXECUTION_BYTES)?;
        accumulate_rows(stmt.query(params![cutoff, GC_ROWS])?)?
    };
    if count == 0 {
        return Ok(0);
    }
    let mut delete = conn.prepare_cached(DELETE_EXPIRED_EXECUTIONS)?;
    delete.execute(params![cutoff, count])
}

fn prune_events(conn: &Connection, now: i64, excess: usize) -> rusqlite::Result<usize> {
    let last = {
        let mut stmt =
            conn.prepare_cached("SELECT seq, expires_at_ms FROM events ORDER BY seq LIMIT ?1")?;
        let mut rows = stmt.query([PRUNE_EVENTS_LIMIT])?;
        let mut count = 0;
        let mut last = None;
        while let Some(row) = rows.next()? {
            if count >= excess && row.get::<_, i64>(1)? > now {
                break;
            }
            last = Some(row.get::<_, i64>(0)?);
            count += 1;
        }
        last
    };
    let Some(last) = last else { return Ok(0) };
    let deleted = {
        let mut stmt = conn.prepare_cached("DELETE FROM events WHERE seq <= ?1")?;
        stmt.execute([last])?
    };
    let mut update =
        conn.prepare_cached("UPDATE hub_meta SET events_pruned_through_seq = ?1 WHERE id = 1")?;
    update.execute([last])?;
    Ok(deleted)
}

fn purging_principal(conn: &Connection) -> rusqlite::Result<Option<String>> {
    let mut stmt =
        conn.prepare_cached("SELECT gc_purging_principal_id FROM hub_meta WHERE id = 1")?;
    stmt.query_row([], |row| row.get(0))
}

const CLAIM_AGENT: &str = "SELECT p.principal_id FROM principals p
    WHERE p.kind = 'agent' AND p.managed_by_principal_id IS NOT NULL AND p.disabled_at_ms <= ?1
      AND NOT EXISTS (SELECT 1 FROM executions e WHERE e.caller_principal_id = p.principal_id)
      AND NOT EXISTS (SELECT 1 FROM auth_tokens t
                      WHERE t.created_by = p.principal_id AND t.principal_id != p.principal_id)
      AND p.principal_id NOT IN (
         SELECT owner_principal_id FROM accounts
         UNION SELECT created_by FROM grants WHERE created_by != principal_id
         UNION SELECT created_by FROM node_enrollments
         UNION SELECT managed_by_principal_id FROM node_enrollments WHERE managed_by_principal_id IS NOT NULL
         UNION SELECT managed_by_principal_id FROM nodes WHERE managed_by_principal_id IS NOT NULL
         UNION SELECT owner_principal_id FROM principals WHERE owner_principal_id IS NOT NULL
         UNION SELECT managed_by_principal_id FROM principals WHERE managed_by_principal_id IS NOT NULL
         UNION SELECT published_by FROM profile_editions
         UNION SELECT created_by FROM tools
      )
    ORDER BY p.disabled_at_ms, p.principal_id LIMIT 1";

fn claim_agent(conn: &Connection, cutoff: i64) -> rusqlite::Result<bool> {
    let candidate = {
        let mut stmt = conn.prepare_cached(CLAIM_AGENT)?;
        stmt.query_row([cutoff], |row| row.get::<_, String>(0))
            .optional()?
    };
    let Some(principal) = candidate else {
        return Ok(false);
    };
    let claimed = {
        let mut stmt = conn.prepare_cached(
            "UPDATE hub_meta SET gc_purging_principal_id = ?1 WHERE id = 1 AND gc_purging_principal_id IS NULL",
        )?;
        stmt.execute([&principal])?
    };
    if claimed == 0 {
        return Ok(false);
    }
    let mut rename = conn.prepare_cached(
        "UPDATE principals SET name = '~purging:' || principal_id WHERE principal_id = ?1",
    )?;
    rename.execute([&principal])?;
    Ok(true)
}

fn purge_agent_children(conn: &Connection) -> rusqlite::Result<bool> {
    let Some(principal) = purging_principal(conn)? else {
        return Ok(false);
    };
    for query in [
        "DELETE FROM auth_tokens WHERE token_id IN (
             SELECT token_id FROM auth_tokens WHERE principal_id = ?1 LIMIT 32)",
        "DELETE FROM grants WHERE grant_id IN (
             SELECT grant_id FROM grants WHERE principal_id = ?1 LIMIT 32)",
        "DELETE FROM account_bindings WHERE rowid IN (
             SELECT rowid FROM account_bindings WHERE principal_id = ?1 LIMIT 32)",
    ] {
        let mut stmt = conn.prepare_cached(query)?;
        if stmt.execute([&principal])? != 0 {
            return Ok(true);
        }
    }
    let mut delete = conn.prepare_cached("DELETE FROM principals WHERE principal_id = ?1")?;
    delete.execute([&principal])?;
    Ok(false)
}

fn incremental_vacuum(conn: &Connection) -> rusqlite::Result<()> {
    conn.pragma(None, "incremental_vacuum", 64, |_| Ok(()))
}

fn wal_bytes(path: &Path) -> io::Result<u64> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[path = "maintenance_tests.rs"]
mod tests;
