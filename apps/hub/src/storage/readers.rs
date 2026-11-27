use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use rusqlite::{Connection, TransactionBehavior};
use tokio::sync::Semaphore;

use super::StorageError;
use super::lifecycle::open_reader;

const READERS: usize = 8;
const CONTROL_READERS: usize = 2;
const GENERAL_READERS: usize = READERS - CONTROL_READERS;

pub(super) struct ReadPool {
    path: PathBuf,
    general: Arc<Semaphore>,
    control: Arc<Semaphore>,
    state: Mutex<PoolState>,
    closed: Condvar,
}

struct PoolState {
    idle: Vec<Connection>,
    in_flight: usize,
    closing: bool,
    stopped: bool,
}

impl ReadPool {
    pub(super) fn open(path: PathBuf) -> Result<Arc<Self>, StorageError> {
        let idle = (0..READERS)
            .map(|_| open_reader(&path))
            .collect::<Result<_, _>>()?;
        Ok(Arc::new(Self {
            path,
            general: Arc::new(Semaphore::new(GENERAL_READERS)),
            control: Arc::new(Semaphore::new(CONTROL_READERS)),
            state: Mutex::new(PoolState {
                idle,
                in_flight: 0,
                closing: false,
                stopped: false,
            }),
            closed: Condvar::new(),
        }))
    }

    fn state(&self) -> MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn closed_error(&self) -> StorageError {
        if self.state().closing {
            StorageError::ShuttingDown
        } else {
            StorageError::ActorStopped
        }
    }

    pub(super) async fn snapshot<T, E>(
        self: &Arc<Self>,
        read: impl FnOnce(&Connection) -> Result<T, E> + Send + 'static,
    ) -> Result<T, E>
    where
        T: Send + 'static,
        E: From<StorageError> + Send + 'static,
    {
        self.snapshot_on(&self.general, read).await
    }

    pub(super) async fn control_snapshot<T, E>(
        self: &Arc<Self>,
        read: impl FnOnce(&Connection) -> Result<T, E> + Send + 'static,
    ) -> Result<T, E>
    where
        T: Send + 'static,
        E: From<StorageError> + Send + 'static,
    {
        self.snapshot_on(&self.control, read).await
    }

    async fn snapshot_on<T, E>(
        self: &Arc<Self>,
        lane: &Arc<Semaphore>,
        read: impl FnOnce(&Connection) -> Result<T, E> + Send + 'static,
    ) -> Result<T, E>
    where
        T: Send + 'static,
        E: From<StorageError> + Send + 'static,
    {
        let permit = Arc::clone(lane)
            .acquire_owned()
            .await
            .map_err(|_| self.closed_error())?;
        let pool = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut reader = pool.checkout()?;
            let conn = reader.conn.as_mut().ok_or(StorageError::ActorStopped)?;
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Deferred)
                .map_err(StorageError::from)?;
            let value = read(&tx)?;
            tx.commit().map_err(StorageError::from)?;
            Ok(value)
        })
        .await
        .map_err(StorageError::from)?
    }

    pub(super) fn begin_close(&self) {
        self.state().closing = true;
        self.general.close();
        self.control.close();
    }

    pub(super) fn finish_close(&self, failed: bool) {
        let idle = {
            let mut state = self.state();
            if failed {
                state.stopped = true;
            } else {
                state.closing = true;
            }
            self.general.close();
            self.control.close();
            std::mem::take(&mut state.idle)
        };
        drop(idle);
        let _state = self
            .closed
            .wait_while(self.state(), |state| state.in_flight != 0)
            .unwrap_or_else(PoisonError::into_inner);
    }

    fn checkout(&self) -> Result<Reader<'_>, StorageError> {
        let conn = {
            let mut state = self.state();
            if state.closing {
                return Err(StorageError::ShuttingDown);
            }
            if state.stopped {
                return Err(StorageError::ActorStopped);
            }
            state.in_flight += 1;
            state.idle.pop()
        };
        let mut reader = Reader { pool: self, conn };
        if reader.conn.is_none() {
            reader.conn = Some(open_reader(&self.path)?);
        }
        Ok(reader)
    }
}

struct Reader<'a> {
    pool: &'a ReadPool,
    conn: Option<Connection>,
}

impl Drop for Reader<'_> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            let clean = conn.is_autocommit()
                || (conn.execute_batch("ROLLBACK").is_ok() && conn.is_autocommit());
            if clean && !std::thread::panicking() {
                let mut state = self.pool.state();
                if !state.closing && !state.stopped {
                    state.idle.push(conn);
                    state.in_flight -= 1;
                    return;
                }
            }
            drop(conn);
        }
        self.pool.state().in_flight -= 1;
        self.pool.closed.notify_all();
    }
}
