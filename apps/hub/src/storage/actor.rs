use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use efferian_protocol::{ExecutionId, ExecutionState, HubId};
use rusqlite::{Connection, ErrorCode, Savepoint, Transaction, TransactionBehavior};
use tokio::sync::{broadcast, oneshot, watch};

use super::events::{RevocationSignal, RevocationWatch, StoredEvent};
use super::lifecycle::{
    LockedStateDir, OpenedDb, WalCheckpointOutcome, close_writer, database_path,
    migrate_to_current, truncate_checkpoint,
};
use super::maintenance::{Maintenance, StoragePressure};
use super::readers::ReadPool;
use super::{OpenMode, StorageConfig, StorageError, WriteError};

const PRIORITY_CAPACITY: usize = 128;
const WORK_CAPACITY: usize = 256;
const MAX_COMMANDS: usize = 32;
const PRIORITY_BURST: usize = 16;
pub(super) const MAX_WORK_BYTES: usize = 4 * 1024 * 1024;
const EVENTS_CAPACITY: usize = 1024;
const REVOCATIONS_CAPACITY: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionSnapshot {
    pub state: ExecutionState,
    pub finished_at_ms: Option<i64>,
}

type Waiters = HashMap<ExecutionId, watch::Sender<ExecutionSnapshot>>;
type SubscribeReply = oneshot::Sender<Option<watch::Receiver<ExecutionSnapshot>>>;

#[derive(Clone)]
pub struct StorageHandle {
    hub_id: HubId,
    max_page_count: u32,
    pub(super) active_waiters: Arc<AtomicUsize>,
    gc_errors: Arc<AtomicU64>,
    mailbox: Arc<Mailbox>,
    readers: Arc<ReadPool>,
    events: broadcast::WeakSender<Arc<StoredEvent>>,
    revocations: broadcast::WeakSender<Arc<RevocationSignal>>,
}

pub struct StorageRuntime {
    mailbox: Arc<Mailbox>,
    readers: Arc<ReadPool>,
    stopped: watch::Receiver<bool>,
    thread: Option<JoinHandle<(ShutdownReport, LockedStateDir)>>,
}

#[derive(Debug)]
pub enum ShutdownReport {
    Complete,
    WalCheckpointIncomplete {
        busy: i32,
        log: i32,
        checkpointed: i32,
    },
    Failed(StorageError),
}

impl StorageRuntime {
    /// Resolves when the background writer thread exits (either gracefully or
    /// after an unrecoverable error). Safe to use in a supervisor `select!`.
    pub async fn wait_stopped(&self) {
        let mut rx = self.stopped.clone();
        let _ = rx.wait_for(|&stopped| stopped).await;
    }

    pub async fn shutdown(mut self) -> ShutdownReport {
        self.begin_shutdown();
        let Some(thread) = self.thread.take() else {
            return ShutdownReport::Failed(StorageError::ActorStopped);
        };
        match tokio::task::spawn_blocking(move || thread.join()).await {
            Ok(Ok((report, lock))) => {
                drop(lock);
                report
            }
            Ok(Err(_)) => ShutdownReport::Failed(StorageError::ActorStopped),
            Err(error) => ShutdownReport::Failed(error.into()),
        }
    }

    fn begin_shutdown(&self) {
        self.mailbox.shutdown();
        self.readers.begin_close();
    }
}

impl Drop for StorageRuntime {
    fn drop(&mut self) {
        // The writer finishes draining and releases `hub.lock` after closing
        // SQLite even when an owner drops the runtime or cancels shutdown.
        self.begin_shutdown();
    }
}

impl StorageHandle {
    pub fn hub_id(&self) -> &HubId {
        &self.hub_id
    }

    pub(super) fn max_page_count(&self) -> u32 {
        self.max_page_count
    }

    pub fn gc_error_count(&self) -> u64 {
        self.gc_errors.load(Ordering::Relaxed)
    }

    pub fn subscribe_events(&self) -> Result<broadcast::Receiver<Arc<StoredEvent>>, StorageError> {
        self.events
            .upgrade()
            .map(|events| events.subscribe())
            .ok_or_else(|| self.mailbox.closed_error())
    }

    /// A lagged or closed revocation receiver must invalidate cached authorization.
    pub fn subscribe_revocations(&self) -> Result<RevocationWatch, StorageError> {
        self.revocations
            .upgrade()
            .map(|revocations| RevocationWatch::new(revocations.subscribe()))
            .ok_or_else(|| self.mailbox.closed_error())
    }

    pub async fn subscribe_waiter(
        &self,
        execution_id: ExecutionId,
    ) -> Result<Option<watch::Receiver<ExecutionSnapshot>>, StorageError> {
        let (send, recv) = oneshot::channel();
        self.mailbox.enqueue(|state| {
            if state.subscriptions.len() == WORK_CAPACITY {
                return Err(StorageError::Overloaded);
            }
            state.subscriptions.push_back((execution_id, send));
            Ok(())
        })?;
        recv.await.map_err(|_| self.mailbox.closed_error())
    }

    pub async fn read_snapshot<T, E>(
        &self,
        read: impl FnOnce(&Connection) -> Result<T, E> + Send + 'static,
    ) -> Result<T, E>
    where
        T: Send + 'static,
        E: From<StorageError> + Send + 'static,
    {
        self.readers.snapshot(read).await
    }

    #[allow(dead_code, reason = "work lane write seam for hub modules")]
    pub(crate) async fn execute_work<T, E, F>(
        &self,
        bytes: usize,
        op: F,
    ) -> Result<T, WriteError<E>>
    where
        T: Send + 'static,
        E: Send + 'static,
        F: FnOnce(&mut WriteTx<'_>) -> Result<T, WriteTxError<E>> + Send + 'static,
    {
        if bytes > MAX_WORK_BYTES {
            return Err(StorageError::PayloadTooLarge.into());
        }
        self.execute(Some(bytes), op).await
    }

    #[allow(dead_code, reason = "priority lane write seam for hub modules")]
    pub(crate) async fn execute_priority<T, E, F>(
        &self,
        _kind: PriorityKind,
        op: F,
    ) -> Result<T, WriteError<E>>
    where
        T: Send + 'static,
        E: Send + 'static,
        F: FnOnce(&mut WriteTx<'_>) -> Result<T, WriteTxError<E>> + Send + 'static,
    {
        self.execute(None, op).await
    }

    async fn execute<T, E, F>(&self, bytes: Option<usize>, op: F) -> Result<T, WriteError<E>>
    where
        T: Send + 'static,
        E: Send + 'static,
        F: FnOnce(&mut WriteTx<'_>) -> Result<T, WriteTxError<E>> + Send + 'static,
    {
        let (reply, response) = oneshot::channel();
        let command = Box::new(Operation {
            op: Some(op),
            reply,
            result: None,
        });
        self.mailbox.enqueue(|state| {
            if let Some(bytes) = bytes {
                if state.work.len() == WORK_CAPACITY {
                    return Err(StorageError::Overloaded);
                }
                state.work.push_back(Work { bytes, command });
            } else {
                if state.priority.len() == PRIORITY_CAPACITY {
                    return Err(StorageError::Overloaded);
                }
                state.priority.push_back(command);
            }
            Ok(())
        })?;
        response.await.map_err(|_| self.mailbox.closed_error())?
    }
}

impl OpenedDb {
    /// Run startup on a blocking worker when calling from an async application.
    pub fn migrate_and_start_runtime(
        mut self,
    ) -> Result<(StorageHandle, StorageRuntime), StorageError> {
        if self.mode != OpenMode::ServeAutoMigrate {
            return Err(StorageError::InvalidConfig("runtime requires serve mode"));
        }
        let found: u32 = self
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        migrate_to_current(&mut self.conn, found)?;

        let readers = ReadPool::open(database_path(&self.lock))?;
        let mailbox = Arc::new(Mailbox::default());
        let (events, _) = broadcast::channel(EVENTS_CAPACITY);
        let (revocations, _) = broadcast::channel(REVOCATIONS_CAPACITY);
        let (stopped_tx, stopped_rx) = watch::channel(false);
        let waiters = restore_waiters(&self.conn)?;
        let active_waiters = Arc::new(AtomicUsize::new(waiters.len()));
        let gc_errors = Arc::new(AtomicU64::new(0));
        let handle = StorageHandle {
            hub_id: self.hub_id,
            max_page_count: self.config.max_page_count,
            active_waiters: Arc::clone(&active_waiters),
            gc_errors: Arc::clone(&gc_errors),
            mailbox: Arc::clone(&mailbox),
            readers: Arc::clone(&readers),
            events: events.downgrade(),
            revocations: revocations.downgrade(),
        };
        let mut actor = DbActor {
            waiters,
            active_waiters,
            maintenance: Maintenance::new(&self, gc_errors)?,
            events,
            revocations,
        };
        let writer_mailbox = Arc::clone(&mailbox);
        let writer_readers = Arc::clone(&readers);
        let thread = thread::Builder::new()
            .name("hub-sqlite".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    actor.run(&self, &writer_mailbox)
                }))
                .unwrap_or(Err(StorageError::ActorStopped));
                let failed = result.is_err();
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    writer_mailbox.stop(failed);
                }));
                // End live streams promptly if the writer can no longer publish.
                drop(actor);
                writer_readers.finish_close(failed);
                let (report, lock) = finish_writer(self, result);
                let _ = stopped_tx.send(true);
                (report, lock)
            })?;
        Ok((
            handle,
            StorageRuntime {
                mailbox,
                readers,
                stopped: stopped_rx,
                thread: Some(thread),
            },
        ))
    }
}

fn finish_writer(
    db: OpenedDb,
    result: Result<(), StorageError>,
) -> (ShutdownReport, LockedStateDir) {
    let checkpoint =
        result.and_then(|()| truncate_checkpoint(&db.conn, db.config.shutdown_checkpoint_timeout));
    let OpenedDb { conn, lock, .. } = db;
    let close = close_writer(conn);
    let report = match checkpoint.and_then(|outcome| close.map(|()| outcome)) {
        Ok(WalCheckpointOutcome::Truncated) => ShutdownReport::Complete,
        Ok(WalCheckpointOutcome::Incomplete {
            busy,
            log,
            checkpointed,
        }) => ShutdownReport::WalCheckpointIncomplete {
            busy,
            log,
            checkpointed,
        },
        Ok(WalCheckpointOutcome::Failed(error)) | Err(error) => ShutdownReport::Failed(error),
    };
    (report, lock)
}

struct DbActor {
    waiters: Waiters,
    active_waiters: Arc<AtomicUsize>,
    maintenance: Maintenance,
    events: broadcast::Sender<Arc<StoredEvent>>,
    revocations: broadcast::Sender<Arc<RevocationSignal>>,
}

impl DbActor {
    fn run(&mut self, db: &OpenedDb, mailbox: &Mailbox) -> Result<(), StorageError> {
        let mut timeout = Duration::ZERO;
        loop {
            let Some(turn) = mailbox.next(timeout, self.maintenance.defer_work()) else {
                return Ok(());
            };
            for (execution_id, reply) in turn.subscriptions {
                let result = self
                    .waiters
                    .get(&execution_id)
                    .map(watch::Sender::subscribe);
                let _ = reply.send(result);
            }
            let wrote_wal = if turn.commands.is_empty() {
                false
            } else {
                self.execute_batch(db, turn.commands, turn.bytes)?
            };
            if !mailbox.is_shutting_down() {
                let now = db.clock.monotonic_now()?;
                if !mailbox.is_shutting_down() {
                    self.maintenance.tick(db, now, wrote_wal)?;
                    timeout = self.maintenance.wait_for(db, now);
                }
            }
        }
    }

    fn execute_batch(
        &mut self,
        db: &OpenedDb,
        mut commands: Vec<Box<dyn Command>>,
        bytes: usize,
    ) -> Result<bool, StorageError> {
        let mut effects = Effects::default();
        let mut probe = PressureProbe {
            cached: self.maintenance.level(),
            changed: false,
        };
        let (outcome, fatal_commit) =
            run_transaction(db, &mut commands, &mut effects, &self.waiters, &mut probe);
        let appended = effects.events.len();
        let wrote_result_blob = effects.wrote_result_blob;
        let committed = matches!(outcome, BatchOutcome::Committed);
        let result = match (outcome, fatal_commit) {
            (BatchOutcome::Committed, _) => self.publish(effects),
            (_, Some(error)) => Err(error),
            _ if db.conn.is_autocommit() => Ok(()),
            _ => db
                .conn
                .execute_batch("ROLLBACK")
                .map_err(StorageError::from),
        };
        for command in commands {
            command.reply(outcome);
        }
        result?;
        if !db.conn.is_autocommit() {
            return Err(StorageError::InvalidDatabase(
                "writer transaction could not be cleared",
            ));
        }
        self.maintenance.after_write(
            db,
            committed,
            bytes,
            wrote_result_blob,
            appended,
            probe.changed,
        )?;
        Ok(committed)
    }

    fn publish(&mut self, effects: Effects) -> Result<(), StorageError> {
        for signal in effects.revocations {
            let _ = self.revocations.send(Arc::new(signal));
        }
        self.waiters.extend(effects.registered);
        for (id, snapshot) in effects.updated {
            if let Some(sender) = self.waiters.get(&id) {
                sender.send_replace(snapshot);
            }
        }
        for (id, snapshot) in effects.finished {
            if let Some(sender) = self.waiters.remove(&id) {
                sender.send_replace(snapshot);
            }
        }
        self.active_waiters
            .store(self.waiters.len(), Ordering::Release);
        for event in effects.events {
            let _ = self.events.send(Arc::new(event));
        }
        let mut failed = false;
        for hook in effects.hooks {
            failed |= std::panic::catch_unwind(std::panic::AssertUnwindSafe(hook)).is_err();
        }
        if failed {
            Err(StorageError::ActorStopped)
        } else {
            Ok(())
        }
    }
}

fn run_transaction(
    db: &OpenedDb,
    commands: &mut [Box<dyn Command>],
    effects: &mut Effects,
    waiters: &Waiters,
    probe: &mut PressureProbe,
) -> (BatchOutcome, Option<StorageError>) {
    let Ok(mut tx) = Transaction::new_unchecked(&db.conn, TransactionBehavior::Immediate) else {
        return (BatchOutcome::Aborted, None);
    };
    for command in commands {
        if tx.is_autocommit()
            || run_command(db, &mut tx, command.as_mut(), effects, waiters, probe).is_err()
        {
            if !tx.is_autocommit() {
                let _ = tx.rollback();
            }
            return (BatchOutcome::Aborted, None);
        }
    }
    match tx.execute_batch("COMMIT") {
        Ok(()) => (BatchOutcome::Committed, None),
        // A connection that has already left the transaction cannot prove it
        // rolled back. Stop publication and require a fresh database snapshot.
        Err(error) if tx.is_autocommit() => (BatchOutcome::Unknown, Some(error.into())),
        Err(_) => (BatchOutcome::Unknown, None),
    }
}

fn run_command(
    db: &OpenedDb,
    tx: &mut Transaction<'_>,
    command: &mut dyn Command,
    effects: &mut Effects,
    waiters: &Waiters,
    probe: &mut PressureProbe,
) -> Result<(), ()> {
    let mut write = WriteTx {
        savepoint: tx.savepoint().map_err(|_| ())?,
        config: &db.config,
        hub_id: db.hub_id,
        now_ms: db.clock.wall_now_ms(),
        effects: Effects::default(),
        batch_waiters: &effects.registered,
        waiters,
        probe,
    };
    let succeeded = command.run(&mut write);
    if write.conn().is_autocommit() {
        return Err(());
    }
    if let Some(staged) = write.finish(succeeded)? {
        effects.extend(staged);
    }
    if tx.is_autocommit() { Err(()) } else { Ok(()) }
}

fn restore_waiters(conn: &Connection) -> Result<Waiters, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT execution_id, state, finished_at_ms
         FROM executions WHERE state IN ('accepted', 'running')",
    )?;
    let rows = stmt.query_map([], |row| {
        let state = if row.get_ref(1)?.as_str()? == "accepted" {
            ExecutionState::Accepted
        } else {
            ExecutionState::Running
        };
        Ok((
            row.get::<_, String>(0)?,
            ExecutionSnapshot {
                state,
                finished_at_ms: row.get(2)?,
            },
        ))
    })?;
    let mut waiters = Waiters::new();
    for row in rows {
        let (id, snapshot) = row?;
        let id = ExecutionId::parse(&id)
            .map_err(|_| StorageError::InvalidDatabase("invalid execution ID"))?;
        waiters.insert(id, watch::Sender::new(snapshot));
    }
    Ok(waiters)
}

#[derive(Default)]
struct Effects {
    events: Vec<StoredEvent>,
    revocations: Vec<RevocationSignal>,
    registered: Waiters,
    updated: Vec<(ExecutionId, ExecutionSnapshot)>,
    finished: Vec<(ExecutionId, ExecutionSnapshot)>,
    hooks: Vec<Box<dyn FnOnce() + Send>>,
    wrote_result_blob: bool,
}

impl Effects {
    fn extend(&mut self, other: Self) {
        self.events.extend(other.events);
        self.revocations.extend(other.revocations);
        self.registered.extend(other.registered);
        self.updated.extend(other.updated);
        self.finished.extend(other.finished);
        self.hooks.extend(other.hooks);
        self.wrote_result_blob |= other.wrote_result_blob;
    }
}

struct PressureProbe {
    cached: StoragePressure,
    changed: bool,
}

pub(crate) struct WriteTx<'a> {
    savepoint: Savepoint<'a>,
    pub(super) config: &'a StorageConfig,
    pub(super) hub_id: HubId,
    now_ms: i64,
    effects: Effects,
    batch_waiters: &'a Waiters,
    waiters: &'a Waiters,
    probe: &'a mut PressureProbe,
}

#[allow(dead_code, reason = "write transaction seams for hub modules")]
impl WriteTx<'_> {
    fn finish(self, result: CommandResult) -> Result<Option<Effects>, ()> {
        match result {
            CommandResult::Success => {
                self.savepoint.commit().map_err(|_| ())?;
                Ok(Some(self.effects))
            }
            CommandResult::LocalError => {
                self.savepoint.finish().map_err(|_| ())?;
                Ok(None)
            }
            CommandResult::FatalError => Err(()),
        }
    }

    pub(crate) fn conn(&self) -> &Connection {
        &self.savepoint
    }

    pub(crate) fn now_ms(&self) -> i64 {
        self.now_ms
    }

    pub(super) fn note_pressure_observation(&mut self, level: StoragePressure) {
        self.probe.changed |= level != self.probe.cached;
    }

    pub(crate) fn note_result_blob_written(&mut self) {
        self.effects.wrote_result_blob = true;
    }

    pub(super) fn stage_event(&mut self, event: StoredEvent) {
        self.effects.events.push(event);
    }

    pub(crate) fn stage_revocation(&mut self, signal: RevocationSignal) {
        self.effects.revocations.push(signal);
    }

    pub(crate) fn stage_waiter_register(
        &mut self,
        execution_id: ExecutionId,
        snapshot: ExecutionSnapshot,
    ) -> watch::Receiver<ExecutionSnapshot> {
        let (send, recv) = watch::channel(snapshot);
        self.effects.registered.insert(execution_id, send);
        recv
    }

    pub(crate) fn waiter(
        &self,
        execution_id: ExecutionId,
    ) -> Option<watch::Receiver<ExecutionSnapshot>> {
        self.effects
            .registered
            .get(&execution_id)
            .or_else(|| self.batch_waiters.get(&execution_id))
            .or_else(|| self.waiters.get(&execution_id))
            .map(watch::Sender::subscribe)
    }

    /// Update an active waiter in place (e.g., `Accepted -> Running`) after commit.
    pub(crate) fn stage_waiter_update(
        &mut self,
        execution_id: ExecutionId,
        snapshot: ExecutionSnapshot,
    ) {
        self.effects.updated.push((execution_id, snapshot));
    }

    pub(crate) fn stage_waiter_finish(
        &mut self,
        execution_id: ExecutionId,
        snapshot: ExecutionSnapshot,
    ) {
        self.effects.finished.push((execution_id, snapshot));
    }

    /// Runs on the writer thread after event publication and must return promptly.
    pub(crate) fn on_commit(&mut self, hook: impl FnOnce() + Send + 'static) {
        self.effects.hooks.push(Box::new(hook));
    }
}

#[derive(Debug)]
#[allow(dead_code, reason = "write transaction error variants for hub modules")]
pub(crate) enum WriteTxError<E> {
    Domain(E),
    StoragePressure,
    InvalidDatabase(&'static str),
    Sqlite(rusqlite::Error),
}

impl<E> From<rusqlite::Error> for WriteTxError<E> {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl<E> From<StorageError> for WriteTxError<E> {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::StoragePressure => Self::StoragePressure,
            StorageError::InvalidDatabase(msg) => Self::InvalidDatabase(msg),
            StorageError::Sqlite(error) => Self::Sqlite(error),
            other => Self::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(other))),
        }
    }
}

fn is_local_sqlite_error(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::QueryReturnedNoRows
            | rusqlite::Error::FromSqlConversionFailure(..)
            | rusqlite::Error::ToSqlConversionFailure(..)
            | rusqlite::Error::InvalidColumnType(..)
            | rusqlite::Error::IntegralValueOutOfRange(..)
    ) || error.sqlite_error_code() == Some(ErrorCode::ConstraintViolation)
}

impl<E> WriteTxError<E> {
    fn into_local_error(self) -> Option<WriteError<E>> {
        match self {
            Self::Domain(error) => Some(WriteError::Domain(error)),
            Self::StoragePressure => Some(StorageError::StoragePressure.into()),
            Self::InvalidDatabase(msg) => Some(StorageError::InvalidDatabase(msg).into()),
            Self::Sqlite(error) if is_local_sqlite_error(&error) => {
                Some(StorageError::from(error).into())
            }
            Self::Sqlite(_) => None,
        }
    }
}

#[derive(Clone, Copy)]
#[allow(dead_code, reason = "priority lane categories for hub modules")]
pub(crate) enum PriorityKind {
    RevokeToken,
    DisablePrincipal,
    RevokeNode,
    RevokeGrant,
    DisableEdition,
    CancelExecution,
}

#[derive(Clone, Copy)]
enum BatchOutcome {
    Committed,
    Aborted,
    Unknown,
}

enum CommandResult {
    Success,
    LocalError,
    FatalError,
}

trait Command: Send {
    fn run(&mut self, tx: &mut WriteTx<'_>) -> CommandResult;
    fn reply(self: Box<Self>, outcome: BatchOutcome);
}

struct Operation<T, E, F> {
    op: Option<F>,
    reply: oneshot::Sender<Result<T, WriteError<E>>>,
    result: Option<Result<T, WriteError<E>>>,
}

impl<T, E, F> Command for Operation<T, E, F>
where
    T: Send,
    E: Send,
    F: FnOnce(&mut WriteTx<'_>) -> Result<T, WriteTxError<E>> + Send,
{
    fn run(&mut self, tx: &mut WriteTx<'_>) -> CommandResult {
        let Some(op) = self.op.take() else {
            return CommandResult::FatalError;
        };
        match op(tx) {
            Ok(value) => {
                self.result = Some(Ok(value));
                CommandResult::Success
            }
            Err(error) => {
                // SQLite can roll back the outer transaction on statement errors.
                if tx.conn().is_autocommit() {
                    return CommandResult::FatalError;
                }
                match error.into_local_error() {
                    Some(error) => {
                        self.result = Some(Err(error));
                        CommandResult::LocalError
                    }
                    None => CommandResult::FatalError,
                }
            }
        }
    }

    fn reply(self: Box<Self>, outcome: BatchOutcome) {
        let response = match outcome {
            BatchOutcome::Committed => self
                .result
                .unwrap_or(Err(StorageError::ActorStopped.into())),
            BatchOutcome::Aborted => Err(WriteError::PreCommitAborted),
            BatchOutcome::Unknown => Err(WriteError::CommitOutcomeUnknown),
        };
        let _ = self.reply.send(response);
    }
}

struct Work {
    bytes: usize,
    command: Box<dyn Command>,
}

#[derive(Default)]
struct Mailbox {
    state: Mutex<MailboxState>,
    wake: Condvar,
}

#[derive(Default)]
struct MailboxState {
    priority: VecDeque<Box<dyn Command>>,
    work: VecDeque<Work>,
    subscriptions: VecDeque<(ExecutionId, SubscribeReply)>,
    shutting_down: bool,
    stopped: bool,
    priority_streak: usize,
}

#[derive(Default)]
struct Turn {
    bytes: usize,
    commands: Vec<Box<dyn Command>>,
    subscriptions: VecDeque<(ExecutionId, SubscribeReply)>,
}

impl Mailbox {
    fn state(&self) -> MutexGuard<'_, MailboxState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn is_shutting_down(&self) -> bool {
        self.state().shutting_down
    }

    fn closed_error(&self) -> StorageError {
        if self.state().shutting_down {
            StorageError::ShuttingDown
        } else {
            StorageError::ActorStopped
        }
    }

    fn enqueue(
        &self,
        push: impl FnOnce(&mut MailboxState) -> Result<(), StorageError>,
    ) -> Result<(), StorageError> {
        let mut state = self.state();
        if state.shutting_down {
            return Err(StorageError::ShuttingDown);
        }
        if state.stopped {
            return Err(StorageError::ActorStopped);
        }
        push(&mut state)?;
        self.wake.notify_one();
        Ok(())
    }

    fn shutdown(&self) {
        self.state().shutting_down = true;
        self.wake.notify_one();
    }

    fn stop(&self, failed: bool) {
        // Move queued closures out of the mutex before running their Drop impls.
        let (priority, work, subscriptions) = {
            let mut state = self.state();
            if failed {
                state.stopped = true;
            } else {
                state.shutting_down = true;
            }
            (
                std::mem::take(&mut state.priority),
                std::mem::take(&mut state.work),
                std::mem::take(&mut state.subscriptions),
            )
        };
        drop((priority, work, subscriptions));
    }

    fn next(&self, timeout: Duration, defer_work: bool) -> Option<Turn> {
        let (mut state, _) = self
            .wake
            .wait_timeout_while(self.state(), timeout, |state| {
                state.priority.is_empty()
                    && (defer_work || state.work.is_empty())
                    && state.subscriptions.is_empty()
                    && !state.shutting_down
                    && !state.stopped
            })
            .unwrap_or_else(PoisonError::into_inner);

        if state.stopped {
            return None;
        }
        let mut turn = Turn {
            subscriptions: std::mem::take(&mut state.subscriptions),
            ..Turn::default()
        };
        let work_waiting = !state.work.is_empty();
        let work_ready = work_waiting && (!defer_work || state.shutting_down);
        if !state.priority.is_empty() && (!work_ready || state.priority_streak < PRIORITY_BURST) {
            state.priority_streak = if work_waiting {
                (state.priority_streak + 1).min(PRIORITY_BURST)
            } else {
                0
            };
            turn.commands.extend(state.priority.pop_front());
        } else if work_ready {
            state.priority_streak = 0;
            let mut remaining = MAX_WORK_BYTES;
            while turn.commands.len() < MAX_COMMANDS
                && state
                    .work
                    .front()
                    .is_some_and(|next| next.bytes <= remaining)
            {
                let next = state.work.pop_front()?;
                remaining -= next.bytes;
                turn.bytes += next.bytes;
                turn.commands.push(next.command);
            }
        }
        (!state.shutting_down || !turn.commands.is_empty() || !turn.subscriptions.is_empty())
            .then_some(turn)
    }
}
