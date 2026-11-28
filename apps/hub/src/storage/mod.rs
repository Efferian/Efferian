//! SQLite storage for the Hub.

mod access;
mod actor;
mod events;
mod executions;
mod lifecycle;
mod maintenance;
mod readers;

pub use access::{PrincipalLiveness, principal_liveness, read_principal};
pub use actor::{ExecutionSnapshot, ShutdownReport, StorageHandle, StorageRuntime};
pub use events::{
    EventsPageRaw, EventsReadError, RevocationReason, RevocationSignal, RevocationWatch,
    StoredEvent,
};
pub use lifecycle::{
    ExpectedHubIdentity, LockedStateDir, NewHubIdentity, OfflineTxOutcome, OpenMode, OpenedDb,
    WalCheckpointOutcome, acquire_state_lock, create_staged, open_existing,
};
pub use maintenance::{StoragePressure, StorageStatus};

pub(crate) use access::inheriting_agents;
pub(crate) use actor::{FollowUpWrite, MAX_WORK_BYTES, PriorityKind, WriteTx, WriteTxError};
pub(crate) use events::{
    id, invalid_text_msg, json, opt_id, optional_json, optional_scalar, read_grant_scope, scalar,
    scalar_text,
};

#[allow(unused_imports, reason = "storage execution seams for hub modules")]
pub(crate) use executions::{
    CloseExecutions, ExecutionTarget, InvalidReceipt, InvokeOutcome, InvokeReplayInput,
    InvokeResource, InvokeWriteError, NewExecutionWrite, PreparedOutcome, PreparedReceipt,
    ReceiptOutcome, ReceiptWrite, RecordedInvocation, TRANSITION_BATCH, lookup_invocation_replay,
};

use std::io;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use efferian_platform::{MonoInstant, MonotonicClock, PlatformError};
use serde::Deserialize;

pub const CURRENT_SCHEMA_VERSION: u32 = 1;
const PAGE_SIZE: u32 = 4096;
const MIN_PAGES: u32 = 64;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const DAY_MS: i64 = 86_400_000;
const SOFT_PRESSURE_GRACE_MS: i64 = 60_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqliteSynchronous {
    #[default]
    Full,
    Normal,
}

impl FromStr for SqliteSynchronous {
    type Err = ();

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "full" => Ok(Self::Full),
            "normal" => Ok(Self::Normal),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct StorageConfig {
    pub synchronous: SqliteSynchronous,
    pub max_page_count: u32,
    pub max_concurrent_waiters: usize,
    pub journal_size_limit_bytes: i64,
    pub max_events_rows: usize,
    pub gc_interval: Duration,
    pub wal_escalate_cooldown: Duration,
    pub shutdown_checkpoint_timeout: Duration,
    pub soft_pressure_grace_ms: i64,
    pub result_ttl_ms: i64,
    pub execution_ttl_ms: i64,
    pub event_ttl_ms: i64,
    pub token_gc_grace_ms: i64,
    pub agent_gc_age_ms: i64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            synchronous: SqliteSynchronous::Full,
            max_page_count: 1_048_576,
            max_concurrent_waiters: 512,
            journal_size_limit_bytes: 64 * 1024 * 1024,
            max_events_rows: 500_000,
            gc_interval: Duration::from_secs(60),
            wal_escalate_cooldown: Duration::from_secs(30),
            shutdown_checkpoint_timeout: BUSY_TIMEOUT,
            soft_pressure_grace_ms: SOFT_PRESSURE_GRACE_MS,
            result_ttl_ms: 7 * DAY_MS,
            execution_ttl_ms: 30 * DAY_MS,
            event_ttl_ms: 14 * DAY_MS,
            token_gc_grace_ms: 7 * DAY_MS,
            agent_gc_age_ms: 30 * DAY_MS,
        }
    }
}

impl StorageConfig {
    pub(crate) fn validate(&self) -> Result<(), StorageError> {
        if !(MIN_PAGES..=0xffff_fffe).contains(&self.max_page_count) {
            return Err(StorageError::InvalidConfig(
                "max_page_count is out of range",
            ));
        }
        if !(1..=tokio::sync::Semaphore::MAX_PERMITS).contains(&self.max_concurrent_waiters) {
            return Err(StorageError::InvalidConfig(
                "max_concurrent_waiters is out of range",
            ));
        }
        if self.journal_size_limit_bytes <= 0
            || self.max_events_rows == 0
            || self.gc_interval.is_zero()
            || self.wal_escalate_cooldown.is_zero()
            || self.shutdown_checkpoint_timeout.as_millis() > i32::MAX as u128
            || self.soft_pressure_grace_ms < 0
            || self.result_ttl_ms <= 0
            || self.execution_ttl_ms < self.result_ttl_ms
            || self.event_ttl_ms <= 0
            || self.token_gc_grace_ms <= 0
            || self.agent_gc_age_ms <= 0
        {
            return Err(StorageError::InvalidConfig(
                "invalid storage maintenance limits",
            ));
        }
        Ok(())
    }
}

pub trait StorageClock: Send + Sync {
    fn wall_now_ms(&self) -> i64;
    fn monotonic_now(&self) -> Result<Duration, StorageError>;
}

pub struct SystemStorageClock(MonoInstant);

impl SystemStorageClock {
    pub fn new() -> Result<Self, StorageError> {
        Ok(Self(MonotonicClock::now().map_err(StorageError::Clock)?))
    }
}

impl StorageClock for SystemStorageClock {
    fn wall_now_ms(&self) -> i64 {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
    }

    fn monotonic_now(&self) -> Result<Duration, StorageError> {
        self.0.elapsed().map_err(StorageError::Clock)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("invalid storage configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("storage queue is full")]
    Overloaded,
    #[error("storage is shutting down")]
    ShuttingDown,
    #[error("storage actor has stopped")]
    ActorStopped,
    #[error("write payload exceeds the work batch byte limit")]
    PayloadTooLarge,
    #[error("storage has reached its admission watermark")]
    StoragePressure,
    #[error("at least one active global administrator is required")]
    LastAdmin,
    #[error("page limit {requested} is below the SQLite page count {actual_page_count}")]
    QuotaBelowCurrentPages {
        requested: u32,
        actual_page_count: u32,
    },
    #[error("Hub database identity does not match the expected key")]
    IdentityMismatch,
    #[error("unsupported schema version {found} (supported up to {supported})")]
    UnsupportedSchemaVersion { found: i64, supported: u32 },
    #[error("schema version {found} requires migration to {required}")]
    SchemaMigrationRequired { found: i64, required: u32 },
    #[error("Hub database was opened read-only; the writer requires write access")]
    ReadOnlyDatabase,
    #[error("Hub database already exists")]
    AlreadyInitialized,
    #[error("unexpected SQLite sidecar: {0}")]
    SidecarConflict(&'static str),
    #[error("database format is invalid: {0}")]
    InvalidDatabase(&'static str),
    #[error("database was published but its durability could not be confirmed")]
    PublishedDurabilityUnknown(#[source] io::Error),
    #[error("storage I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("storage filesystem check failed: {0}")]
    Platform(#[from] PlatformError),
    #[error("SQLite operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("storage clock failed: {0}")]
    Clock(#[source] PlatformError),
    #[error("storage background task failed: {0}")]
    Background(#[from] tokio::task::JoinError),
}

#[derive(Debug, thiserror::Error)]
pub enum WriteError<E> {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("write transaction was aborted before commit")]
    PreCommitAborted,
    #[error("write commit outcome is unknown")]
    CommitOutcomeUnknown,
    #[error("domain operation failed: {0}")]
    Domain(E),
}

#[cfg(test)]
mod tests;
