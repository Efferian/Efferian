use std::collections::{HashMap, hash_map::Entry};
use std::convert::Infallible;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use efferian_protocol::{ExecutionId, PrincipalId, UpstreamId};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

use crate::config::Config;
use crate::http::AppState;
use crate::storage::{
    CloseExecutions, StorageError, StorageHandle, TRANSITION_BATCH, WriteError, WriteTx,
};
use crate::upstream_dispatch::UpstreamDispatcher;

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
    cancelled: Arc<watch::Sender<bool>>,
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
        let upstreams = lock(&self.upstreams);
        self.shutdown.send_replace(true);
        for upstream in upstreams.executions.values() {
            upstream.cancelled.send_replace(true);
        }
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

    #[cfg(test)]
    pub(crate) fn active_waiter_permits(&self) -> usize {
        lock(&self.waiters_per_principal).values().sum()
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
        let (cancelled, receiver) = watch::channel(false);
        entry.insert(ReservedUpstream {
            resource,
            principal,
            cancelled: Arc::new(cancelled),
        });
        *slots.resources.entry(resource).or_default() += 1;
        *slots.principals.entry(principal).or_default() += 1;
        Some(UpstreamReservation {
            control: Arc::clone(self),
            execution_id,
            receiver,
        })
    }

    pub(crate) fn mark_upstream_cancelled(&self, execution_id: ExecutionId) {
        let upstreams = lock(&self.upstreams);
        if let Some(slot) = upstreams.executions.get(&execution_id) {
            slot.cancelled.send_replace(true);
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
    receiver: watch::Receiver<bool>,
}

impl UpstreamReservation {
    pub(crate) fn cancellation(&self) -> UpstreamCancellation {
        UpstreamCancellation {
            cancelled: self.receiver.clone(),
            shutdown: self.control.shutdown_receiver(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct UpstreamCancellation {
    cancelled: watch::Receiver<bool>,
    shutdown: watch::Receiver<bool>,
}

impl UpstreamCancellation {
    pub(crate) fn is_cancelled(&self) -> bool {
        *self.shutdown.borrow() || *self.cancelled.borrow()
    }

    /// Resolves for committed cancellation, Hub stop, or a retired reservation.
    #[allow(dead_code, reason = "the live upstream transport observes this signal")]
    pub(crate) async fn cancelled(&mut self) {
        tokio::select! {
            _ = self.shutdown.wait_for(|&stopping| stopping) => {}
            _ = self.cancelled.wait_for(|&cancelled| cancelled) => {}
        }
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

pub(super) fn cancel_upstream(
    tx: &mut WriteTx<'_>,
    control: &Arc<ExecutionControl>,
    dispatcher: Arc<dyn UpstreamDispatcher>,
    id: ExecutionId,
    caller: PrincipalId,
) -> Result<(), StorageError> {
    if tx.cancel_upstream_execution(id, caller)? {
        let control = Arc::clone(control);
        tx.on_commit(move || {
            control.mark_upstream_cancelled(id);
            dispatcher.cancel(id);
        });
    }
    Ok(())
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
    const CLOSE_RETRIES: u8 = 4;
    const CLOSE_RETRY_DELAY: Duration = Duration::from_millis(25);

    let mut retries = 0;
    loop {
        if sweep_state.is_some_and(|state| !state.execution.is_accepting()) {
            return Ok(());
        }
        let state = sweep_state.cloned();
        let completed = storage
            .execute_work(0, move |tx| {
                let mut cancelled_upstreams = Vec::new();
                let completed = tx.close_executions(cause, |id| {
                    cancelled_upstreams.push(id);
                })?;
                if let Some(state) = state
                    && !cancelled_upstreams.is_empty()
                {
                    tx.on_commit(move || {
                        for id in cancelled_upstreams {
                            state.execution.mark_upstream_cancelled(id);
                            state.upstream.cancel(id);
                        }
                    });
                }
                Ok(completed)
            })
            .await;
        match completed {
            Ok(completed) if completed < TRANSITION_BATCH => return Ok(()),
            Ok(_) => retries = 0,
            Err(
                WriteError::PreCommitAborted
                | WriteError::CommitOutcomeUnknown
                | WriteError::Storage(StorageError::Overloaded),
            ) if !matches!(cause, CloseExecutions::Deadline) && retries < CLOSE_RETRIES => {
                retries += 1;
                tokio::time::sleep(CLOSE_RETRY_DELAY).await;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestResult;

    #[tokio::test]
    async fn global_stop_cancels_active_upstream_handles() -> TestResult {
        let control = Arc::new(ExecutionControl::new(&Config::default()));
        let reservation = control
            .reserve_upstream(
                ExecutionId::new(),
                UpstreamId::new(),
                PrincipalId::new_user(),
            )
            .ok_or("upstream reservation missing")?;
        let mut cancellation = reservation.cancellation();
        assert!(!cancellation.is_cancelled());

        control.shutdown.send_replace(true);
        assert!(cancellation.is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), cancellation.cancelled()).await?;
        Ok(())
    }
}
