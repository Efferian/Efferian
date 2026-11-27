use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;

use super::actor::{MAX_WORK_BYTES, WriteTx, WriteTxError};
use super::lifecycle::{OpenedDb, WAL_FILE, truncate_checkpoint};
use super::{StorageError, StorageHandle};

const GC_ROWS: usize = 32;
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
        Ok(Self {
            count: conn.pragma_query_value(None, "page_count", |row| row.get(0))?,
            free: conn.pragma_query_value(None, "freelist_count", |row| row.get(0))?,
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
        let waiters = self.waiter_count();
        self.read_snapshot(move |conn| {
            let pages = Pages::read(conn)?;
            let (events_head_seq, events_pruned_through_seq) = conn.query_row(
                "SELECT events_head_seq, events_pruned_through_seq FROM hub_meta WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let used_percent = pages.percent(cap);
            Ok(StorageStatus {
                page_count: pages.count,
                freelist_count: pages.free,
                max_page_count: cap,
                used_percent,
                storage_pressure: pressure(used_percent),
                events_head_seq,
                events_pruned_through_seq,
                active_waiters_count: waiters,
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

pub(super) struct Maintenance {
    wal_path: PathBuf,
    next_wal_retry: Option<Duration>,
    next_gc: Duration,
    next_step: Option<GcStep>,
    hold_gc_until_tick: bool,
    purge_pending: bool,
    vacuum_pending: bool,
    soft_active: bool,
    soft_exhausted: bool,
    used_percent: u32,
    pub(super) live_events_count: usize,
    unsampled_bytes: usize,
    unsampled_commits: usize,
}

impl Maintenance {
    pub(super) fn new(db: &OpenedDb) -> Result<Self, StorageError> {
        let live_events_count = db
            .conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
        let used_percent = Pages::read(&db.conn)?.percent(db.config.max_page_count);
        let purge_pending = purging_principal(&db.conn)?.is_some();
        Ok(Self {
            wal_path: db.lock.path().join(WAL_FILE),
            next_wal_retry: None,
            next_gc: db
                .clock
                .monotonic_now()?
                .saturating_add(db.config.gc_interval),
            next_step: None,
            hold_gc_until_tick: false,
            purge_pending,
            vacuum_pending: false,
            soft_active: used_percent >= 75,
            soft_exhausted: false,
            used_percent,
            live_events_count,
            unsampled_bytes: 0,
            unsampled_commits: 0,
        })
    }

    pub(super) fn level(&self) -> StoragePressure {
        pressure(self.used_percent)
    }

    pub(super) fn after_write(
        &mut self,
        db: &OpenedDb,
        committed: bool,
        bytes: usize,
        appended_events: usize,
        resample: bool,
    ) -> Result<(), StorageError> {
        if committed {
            self.live_events_count += appended_events;
            self.unsampled_bytes += bytes;
            self.unsampled_commits += 1;
            if bytes != 0 {
                self.soft_exhausted = false;
            }
        }
        if !committed
            || resample
            || self.unsampled_bytes >= MAX_WORK_BYTES
            || self.unsampled_commits >= SAMPLE_COMMITS
        {
            self.sample(db)?;
        }
        Ok(())
    }

    fn sample(&mut self, db: &OpenedDb) -> rusqlite::Result<()> {
        self.used_percent = Pages::read(&db.conn)?.percent(db.config.max_page_count);
        if self.used_percent < 65 {
            self.soft_active = false;
        } else if self.used_percent >= 75 {
            self.soft_active = true;
        }
        self.unsampled_bytes = 0;
        self.unsampled_commits = 0;
        Ok(())
    }

    pub(super) fn wait_for(&self, db: &OpenedDb, now: Duration) -> Duration {
        if self.next_step.is_some()
            || self.vacuum_pending
            || (!self.hold_gc_until_tick
                && (self.purge_pending
                    || (self.soft_active && !self.soft_exhausted)
                    || self.live_events_count > db.config.max_events_rows))
        {
            return Duration::ZERO;
        }
        self.next_gc
            .min(self.next_wal_retry.unwrap_or(Duration::MAX))
            .saturating_sub(now)
    }

    /// Run one mini-transaction between mailbox turns.
    pub(super) fn tick(&mut self, db: &OpenedDb, now: Duration) -> Result<(), StorageError> {
        if now >= self.next_gc {
            self.next_gc = now.saturating_add(db.config.gc_interval);
            self.next_step.get_or_insert(GcStep::Results);
            self.hold_gc_until_tick = false;
            self.soft_exhausted = false;
            self.purge_pending = purging_principal(&db.conn)?.is_some();
            self.sample(db)?;
        }
        if !self.hold_gc_until_tick {
            if let Err(error) = self.gc_step(db) {
                // FULL and failed FK checks must leave priority admission intact.
                if !db.conn.is_autocommit() {
                    return Err(error.into());
                }
                eprintln!("Hub SQLite garbage collection deferred: {error}");
                self.hold_gc_until_tick = true;
                self.next_step = None;
                self.vacuum_pending = false;
            }
        }
        self.checkpoint_wal(db, now)
    }

    fn gc_step(&mut self, db: &OpenedDb) -> rusqlite::Result<()> {
        let now = db.clock.wall_now_ms();
        let excess = self
            .live_events_count
            .saturating_sub(db.config.max_events_rows);
        let grace_cutoff = now.saturating_sub(db.config.token_gc_grace_ms);
        let conn = &db.conn;

        if self.purge_pending {
            self.purge_pending = gc_transaction(conn, purge_agent_children)?;
            self.vacuum_pending = true;
            return self.sample(db);
        }
        if self.soft_active && !self.soft_exhausted {
            let changed = gc_transaction(conn, |tx| expire_results(tx, i64::MAX))?;
            self.soft_exhausted = changed == 0;
            self.vacuum_pending |= changed != 0;
            return self.sample(db);
        }

        let step = if excess > 0 {
            Some(GcStep::Events)
        } else {
            self.next_step
        };
        if let Some(step) = step {
            let changed = gc_transaction(conn, |tx| {
                match step {
                GcStep::Results => expire_results(tx, now),
                GcStep::Executions => expire_executions(tx, now),
                GcStep::Events => prune_events(tx, now, excess),
                GcStep::Tokens => tx.execute(
                    "DELETE FROM auth_tokens WHERE token_id IN (
                        SELECT token_id FROM auth_tokens WHERE expires_at_ms <= ?1 ORDER BY expires_at_ms LIMIT 32)",
                    [grace_cutoff],
                ),
                GcStep::RevokedTokens => tx.execute(
                    "DELETE FROM auth_tokens WHERE token_id IN (
                        SELECT token_id FROM auth_tokens WHERE revoked_at_ms <= ?1 ORDER BY revoked_at_ms LIMIT 32)",
                    [grace_cutoff],
                ),
                GcStep::Enrollments => tx.execute(
                    "DELETE FROM node_enrollments WHERE enrollment_id IN (
                        SELECT enrollment_id FROM node_enrollments WHERE expires_at_ms <= ?1 ORDER BY expires_at_ms LIMIT 32)",
                    [grace_cutoff],
                ),
                GcStep::Agent => claim_agent(tx, now.saturating_sub(db.config.agent_gc_age_ms)).map(usize::from),
            }
            })?;
            if step == GcStep::Events {
                self.live_events_count = self.live_events_count.saturating_sub(changed);
                if excess > 0 && changed == 0 {
                    self.live_events_count = 0;
                }
            }
            if step == GcStep::Agent {
                self.purge_pending = changed != 0;
            }
            if self.next_step == Some(step) && changed == 0 {
                self.next_step = step.next();
            }
            self.vacuum_pending |= changed != 0;
            if changed != 0 {
                self.sample(db)?;
            }
        } else if self.vacuum_pending {
            self.vacuum_pending = false;
            incremental_vacuum(conn)?;
            self.sample(db)?;
        }
        Ok(())
    }

    fn checkpoint_wal(&mut self, db: &OpenedDb, now: Duration) -> Result<(), StorageError> {
        if self.next_wal_retry.is_some_and(|retry| now < retry) {
            return Ok(());
        }
        self.next_wal_retry = None;
        let threshold = u64::try_from(db.config.journal_size_limit_bytes)
            .unwrap_or(u64::MAX)
            .saturating_mul(2);
        if wal_bytes(&self.wal_path)? <= threshold {
            return Ok(());
        }

        db.conn
            .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |_| Ok(()))?;
        if wal_bytes(&self.wal_path)? > threshold {
            self.next_wal_retry = Some(now.saturating_add(db.config.wal_escalate_cooldown));
            // A held reader leaves the WAL intact for the next scheduled attempt.
            truncate_checkpoint(&db.conn, SHORT_CHECKPOINT)?;
        }
        Ok(())
    }
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
    fn next(self) -> Option<Self> {
        Some(match self {
            Self::Results => Self::Executions,
            Self::Executions => Self::Events,
            Self::Events => Self::Tokens,
            Self::Tokens => Self::RevokedTokens,
            Self::RevokedTokens => Self::Enrollments,
            Self::Enrollments => Self::Agent,
            Self::Agent => return None,
        })
    }
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

fn batched_rows(conn: &Connection, sql: &str, cutoff: i64) -> rusqlite::Result<usize> {
    let mut stmt = conn.prepare_cached(sql)?;
    let mut rows = stmt.query(params![cutoff, GC_ROWS])?;
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

const RESULT_CANDIDATES: &str = "FROM executions WHERE sealed_result_blob IS NOT NULL
    AND result_expires_at_ms <= ?1 ORDER BY result_expires_at_ms, execution_id LIMIT ?2";
const EXECUTION_CANDIDATES: &str = "FROM executions WHERE expires_at_ms <= ?1
    AND state NOT IN ('accepted', 'running') ORDER BY expires_at_ms, rowid LIMIT ?2";

fn expire_results(conn: &Connection, cutoff: i64) -> rusqlite::Result<usize> {
    let count = batched_rows(
        conn,
        &format!("SELECT result_bytes {RESULT_CANDIDATES}"),
        cutoff,
    )?;
    if count == 0 {
        return Ok(0);
    }
    conn.execute(
        &format!(
            "UPDATE executions SET sealed_result_blob = NULL, result_bytes = 0, result_expired = 1
                  WHERE execution_id IN (SELECT execution_id {RESULT_CANDIDATES})"
        ),
        params![cutoff, count],
    )
}

fn expire_executions(conn: &Connection, cutoff: i64) -> rusqlite::Result<usize> {
    let count = batched_rows(
        conn,
        &format!("SELECT COALESCE(length(sealed_result_blob), 0) {EXECUTION_CANDIDATES}"),
        cutoff,
    )?;
    if count == 0 {
        return Ok(0);
    }
    conn.execute(
        &format!("DELETE FROM executions WHERE execution_id IN (SELECT execution_id {EXECUTION_CANDIDATES})"),
        params![cutoff, count],
    )
}

fn prune_events(conn: &Connection, now: i64, excess: usize) -> rusqlite::Result<usize> {
    let last = {
        let mut stmt =
            conn.prepare_cached("SELECT seq, expires_at_ms FROM events ORDER BY seq LIMIT ?1")?;
        let mut rows = stmt.query([GC_ROWS - 1])?;
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
    let deleted = conn.execute("DELETE FROM events WHERE seq <= ?1", [last])?;
    conn.execute(
        "UPDATE hub_meta SET events_pruned_through_seq = ?1 WHERE id = 1",
        [last],
    )?;
    Ok(deleted)
}

fn purging_principal(conn: &Connection) -> rusqlite::Result<Option<String>> {
    conn.query_row(
        "SELECT gc_purging_principal_id FROM hub_meta WHERE id = 1",
        [],
        |row| row.get(0),
    )
}

fn claim_agent(conn: &Connection, cutoff: i64) -> rusqlite::Result<bool> {
    let Some(principal) = conn.query_row(
        "SELECT p.principal_id FROM principals p
           WHERE p.kind = 'agent' AND p.managed_by_principal_id IS NOT NULL AND p.disabled_at_ms <= ?1
             AND NOT EXISTS (SELECT 1 FROM executions e WHERE e.caller_principal_id = p.principal_id)
             AND p.principal_id NOT IN (
                SELECT owner_principal_id FROM accounts
                UNION SELECT created_by FROM auth_tokens WHERE created_by != principal_id
                UNION SELECT created_by FROM grants WHERE created_by != principal_id
                UNION SELECT created_by FROM node_enrollments
                UNION SELECT managed_by_principal_id FROM node_enrollments WHERE managed_by_principal_id IS NOT NULL
                UNION SELECT managed_by_principal_id FROM nodes WHERE managed_by_principal_id IS NOT NULL
                UNION SELECT owner_principal_id FROM principals WHERE owner_principal_id IS NOT NULL
                UNION SELECT managed_by_principal_id FROM principals WHERE managed_by_principal_id IS NOT NULL
                UNION SELECT published_by FROM profile_editions
                UNION SELECT created_by FROM tools
             )
           ORDER BY p.disabled_at_ms, p.principal_id LIMIT 1",
        [cutoff],
        |row| row.get::<_, String>(0),
    ).optional()? else { return Ok(false) };
    conn.execute(
        "UPDATE hub_meta SET gc_purging_principal_id = ?1 WHERE id = 1 AND gc_purging_principal_id IS NULL",
        [&principal],
    )?;
    conn.execute(
        "UPDATE principals SET name = '~purging:' || principal_id WHERE principal_id = ?1",
        [&principal],
    )?;
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
        if conn.execute(query, [&principal])? != 0 {
            return Ok(true);
        }
    }
    conn.execute(
        "DELETE FROM principals WHERE principal_id = ?1",
        [&principal],
    )?;
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
