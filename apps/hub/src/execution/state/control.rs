use std::collections::{HashMap, hash_map::Entry};
use std::convert::Infallible;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use efferian_protocol::{ExecutionId, PrincipalId, UpstreamId};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

use crate::config::Config;
use crate::http::AppState;
use crate::storage::{CloseExecutions, StorageHandle, WriteError};

/// Shared limits and cancellation handles for active execution I/O and REST waiters.
pub(crate) struct ExecutionControl {
    shutdown: watch::Sender<bool>,
    waiters: Arc<Semaphore>,
    waiters_per_principal: Mutex<HashMap<PrincipalId, usize>>,
    waiter_principal_limit: usize,
    upstreams: Mutex<UpstreamReservations>,
    upstream_limit: usize,
    upstream_resource_limit: usize,
    upstream_principal_limit: usize,
}

#[derive(Default)]
struct UpstreamReservations {
    executions: HashMap<ExecutionId, ReservedUpstream>,
    resources: HashMap<UpstreamId, usize>,
    principals: HashMap<PrincipalId, usize>,
}

struct ReservedUpstream {
    resource: UpstreamId,
    principal: PrincipalId,
    cancel: watch::Sender<bool>,
}

impl ExecutionControl {
    pub(crate) fn new(config: &Config) -> Self {
        Self {
            shutdown: watch::channel(false).0,
            waiters: Arc::new(Semaphore::new(config.max_concurrent_waiters)),
            waiters_per_principal: Mutex::default(),
            waiter_principal_limit: config.max_concurrent_waiters_per_principal,
            upstreams: Mutex::default(),
            upstream_limit: config.max_concurrent_upstream_executions,
            upstream_resource_limit: config.max_concurrent_upstream_executions_per_upstream,
            upstream_principal_limit: config.max_concurrent_upstream_executions_per_principal,
        }
    }

    pub(crate) fn is_accepting(&self) -> bool {
        !*self.shutdown.borrow()
    }

    pub(crate) fn stop(&self) {
        self.shutdown.send_replace(true);
        self.cancel_all_upstreams();
    }

    pub(crate) fn shutdown_receiver(&self) -> watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    pub(super) fn reserve_waiter(self: &Arc<Self>, principal: PrincipalId) -> Option<WaiterPermit> {
        let global = Arc::clone(&self.waiters).try_acquire_owned().ok()?;
        let mut counts = lock(&self.waiters_per_principal);
        if count(&counts, principal) >= self.waiter_principal_limit {
            return None;
        }
        *counts.entry(principal).or_default() += 1;
        Some(WaiterPermit {
            control: Arc::clone(self),
            principal,
            _global: global,
        })
    }

    /// Called only after the writer's replay lookup misses. Rollback drops the
    /// staged guard and releases all three slots before another admission.
    pub(crate) fn reserve_upstream(
        self: &Arc<Self>,
        execution_id: ExecutionId,
        resource: UpstreamId,
        principal: PrincipalId,
    ) -> Option<UpstreamReservation> {
        let mut slots = lock(&self.upstreams);
        if slots.executions.len() >= self.upstream_limit
            || count(&slots.resources, resource) >= self.upstream_resource_limit
            || count(&slots.principals, principal) >= self.upstream_principal_limit
        {
            return None;
        }
        let Entry::Vacant(entry) = slots.executions.entry(execution_id) else {
            return None;
        };
        let (cancel, cancellation) = watch::channel(false);
        entry.insert(ReservedUpstream {
            resource,
            principal,
            cancel,
        });
        *slots.resources.entry(resource).or_default() += 1;
        *slots.principals.entry(principal).or_default() += 1;
        Some(UpstreamReservation {
            control: Arc::clone(self),
            execution_id,
            cancellation,
        })
    }

    pub(crate) fn cancel_upstream(&self, execution_id: ExecutionId) {
        if let Some(slot) = lock(&self.upstreams).executions.get(&execution_id) {
            slot.cancel.send_replace(true);
        }
    }

    pub(crate) fn cancel_all_upstreams(&self) {
        for upstream in lock(&self.upstreams).executions.values() {
            upstream.cancel.send_replace(true);
        }
    }
}

pub(super) struct WaiterPermit {
    control: Arc<ExecutionControl>,
    principal: PrincipalId,
    _global: OwnedSemaphorePermit,
}

impl Drop for WaiterPermit {
    fn drop(&mut self) {
        decrement(
            &mut lock(&self.control.waiters_per_principal),
            self.principal,
        );
    }
}

pub(crate) struct UpstreamReservation {
    control: Arc<ExecutionControl>,
    execution_id: ExecutionId,
    cancellation: watch::Receiver<bool>,
}

impl UpstreamReservation {
    pub(crate) fn cancellation(&self) -> watch::Receiver<bool> {
        self.cancellation.clone()
    }
}

impl Drop for UpstreamReservation {
    fn drop(&mut self) {
        let mut slots = lock(&self.control.upstreams);
        if let Some(record) = slots.executions.remove(&self.execution_id) {
            decrement(&mut slots.resources, record.resource);
            decrement(&mut slots.principals, record.principal);
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn count<K: Eq + std::hash::Hash>(map: &HashMap<K, usize>, key: K) -> usize {
    map.get(&key).copied().unwrap_or_default()
}

fn decrement<K: Eq + std::hash::Hash>(map: &mut HashMap<K, usize>, key: K) {
    if let Entry::Occupied(mut slot) = map.entry(key) {
        if *slot.get() == 1 {
            slot.remove();
        } else {
            *slot.get_mut() -= 1;
        }
    }
}

pub(crate) async fn recover_upstreams(
    storage: &StorageHandle,
) -> Result<(), WriteError<Infallible>> {
    close_executions(storage, None, CloseExecutions::Restart).await
}

pub(crate) async fn finish_upstreams_for_shutdown(
    state: &AppState,
) -> Result<(), WriteError<Infallible>> {
    close_executions(&state.storage, None, CloseExecutions::Shutdown).await
}

pub(crate) async fn sweep_deadlines(state: &AppState) -> Result<(), WriteError<Infallible>> {
    close_executions(&state.storage, Some(state), CloseExecutions::Deadline).await
}

async fn close_executions(
    storage: &StorageHandle,
    sweep_state: Option<&AppState>,
    cause: CloseExecutions,
) -> Result<(), WriteError<Infallible>> {
    loop {
        if sweep_state.is_some_and(|state| !state.execution.is_accepting()) {
            return Ok(());
        }
        let state = sweep_state.cloned();
        let completed = storage
            .execute_work(0, move |tx| {
                let (completed, upstreams) = tx.close_executions(cause)?;
                if let Some(state) = state
                    && !upstreams.is_empty()
                {
                    tx.on_commit(move || {
                        for execution_id in upstreams {
                            state.execution.cancel_upstream(execution_id);
                            state.upstream.cancel(execution_id);
                        }
                    });
                }
                Ok(completed)
            })
            .await;
        match completed {
            Ok(completed) if completed < crate::storage::TRANSITION_BATCH => return Ok(()),
            Ok(_) => {}
            Err(error) => match cause {
                // During shutdown the actor remains available to finish accepted work.
                CloseExecutions::Shutdown
                    if matches!(
                        error,
                        WriteError::Storage(crate::storage::StorageError::Overloaded)
                    ) =>
                {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                _ => return Err(error),
            },
        }
    }
}
