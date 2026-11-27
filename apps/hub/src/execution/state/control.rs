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
    phase: Arc<watch::Sender<UpstreamPhase>>,
}

#[derive(Clone, Copy)]
enum UpstreamPhase {
    Ready,
    Started,
    CancelStaged { was_started: bool },
    Cancelled,
}

impl UpstreamPhase {
    fn cancellation_staged(self) -> bool {
        matches!(self, Self::CancelStaged { .. })
    }
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
            upstream.phase.send_replace(UpstreamPhase::Cancelled);
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
        let (phase, receiver) = watch::channel(UpstreamPhase::Ready);
        entry.insert(ReservedUpstream {
            resource,
            principal,
            phase: Arc::new(phase),
        });
        *slots.resources.entry(resource).or_default() += 1;
        *slots.principals.entry(principal).or_default() += 1;
        Some(UpstreamReservation {
            control: Arc::clone(self),
            execution_id,
            receiver,
        })
    }

    /// Reserve the cancellation before its write can commit. Dropping the
    /// guard rolls back the fence, including when the actor aborts a batch.
    fn stage_cancel_upstream(
        &self,
        tx: &mut WriteTx<'_>,
        execution_id: ExecutionId,
    ) -> Option<StagedUpstreamCancel> {
        let upstreams = lock(&self.upstreams);
        let slot = upstreams.executions.get(&execution_id)?;
        let staged = slot.phase.send_if_modified(|phase| {
            let was_started = match *phase {
                UpstreamPhase::Ready => false,
                UpstreamPhase::Started => true,
                UpstreamPhase::CancelStaged { .. } | UpstreamPhase::Cancelled => return false,
            };
            *phase = UpstreamPhase::CancelStaged { was_started };
            true
        });
        if !staged {
            return None;
        }
        let phase = Arc::clone(&slot.phase);
        tx.on_indeterminate_commit(move || {
            phase.send_replace(UpstreamPhase::Cancelled);
        });
        Some(StagedUpstreamCancel(Arc::clone(&slot.phase)))
    }

    fn claim_start(&self, execution_id: ExecutionId) -> StartDecision {
        let slots = lock(&self.upstreams);
        if !self.is_accepting() {
            return StartDecision::Finished;
        }
        let Some(slot) = slots.executions.get(&execution_id) else {
            return StartDecision::Finished;
        };
        let mut decision = StartDecision::Finished;
        slot.phase.send_if_modified(|phase| match *phase {
            UpstreamPhase::Ready => {
                *phase = UpstreamPhase::Started;
                decision = StartDecision::Claimed;
                true
            }
            UpstreamPhase::CancelStaged { .. } => {
                decision = StartDecision::Wait;
                false
            }
            UpstreamPhase::Started | UpstreamPhase::Cancelled => false,
        });
        decision
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

enum StartDecision {
    Claimed,
    Wait,
    Finished,
}

/// The guard is held by the writer or its after-commit hook. Its channel is
/// tied to this reservation even after the worker frees its slot.
struct StagedUpstreamCancel(Arc<watch::Sender<UpstreamPhase>>);

impl StagedUpstreamCancel {
    fn commit(self) {
        self.0.send_replace(UpstreamPhase::Cancelled);
    }
}

impl Drop for StagedUpstreamCancel {
    fn drop(&mut self) {
        self.0.send_if_modified(|phase| {
            let UpstreamPhase::CancelStaged { was_started } = *phase else {
                return false;
            };
            *phase = if was_started {
                UpstreamPhase::Started
            } else {
                UpstreamPhase::Ready
            };
            true
        });
    }
}

pub(crate) struct UpstreamReservation {
    control: Arc<ExecutionControl>,
    execution_id: ExecutionId,
    receiver: watch::Receiver<UpstreamPhase>,
}

impl UpstreamReservation {
    pub(crate) async fn claim_start(&mut self) -> Option<UpstreamCancellation> {
        loop {
            match self.control.claim_start(self.execution_id) {
                StartDecision::Claimed => {
                    return Some(UpstreamCancellation {
                        phase: self.receiver.clone(),
                        shutdown: self.control.shutdown_receiver(),
                    });
                }
                StartDecision::Finished => return None,
                StartDecision::Wait => {
                    self.receiver
                        .wait_for(|phase| !phase.cancellation_staged())
                        .await
                        .ok()?;
                }
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct UpstreamCancellation {
    phase: watch::Receiver<UpstreamPhase>,
    shutdown: watch::Receiver<bool>,
}

impl UpstreamCancellation {
    /// Order a nonblocking transport handoff against the cancellation write.
    /// Wait for any staged cancel before calling the handoff under the fence.
    /// The handoff must return promptly and must not reenter cancellation.
    pub(crate) async fn start_io<T>(&mut self, handoff: impl FnOnce() -> T) -> Option<T> {
        let phase = self
            .phase
            .wait_for(|phase| !phase.cancellation_staged())
            .await
            .ok()?;
        // Stop publishes the global signal before visiting each reservation.
        // Hold both reads so either the handoff or the stop wins that order.
        let shutdown = self.shutdown.borrow();
        let result = (!*shutdown && matches!(*phase, UpstreamPhase::Started)).then(handoff);
        drop(shutdown);
        drop(phase);
        result
    }

    /// Resolves for committed cancellation, Hub stop, or a retired reservation.
    #[allow(dead_code, reason = "the live upstream transport observes this signal")]
    pub(crate) async fn cancelled(&mut self) {
        tokio::select! {
            _ = self.shutdown.wait_for(|&stopping| stopping) => {}
            _ = self.phase.wait_for(|phase| matches!(phase, UpstreamPhase::Cancelled)) => {}
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
    control: &ExecutionControl,
    dispatcher: Arc<dyn UpstreamDispatcher>,
    id: ExecutionId,
    caller: PrincipalId,
) -> Result<(), StorageError> {
    let cancellation = control.stage_cancel_upstream(tx, id);
    if tx.cancel_upstream_execution(id, caller)? {
        tx.on_commit(move || {
            if let Some(cancellation) = cancellation {
                cancellation.commit();
            }
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
                let mut cancellations = Vec::new();
                let completed = tx.close_executions(cause, |tx, id| {
                    if let Some(state) = &state {
                        cancellations.push((id, state.execution.stage_cancel_upstream(tx, id)));
                    }
                })?;
                if let Some(state) = state
                    && !cancellations.is_empty()
                {
                    tx.on_commit(move || {
                        for (id, cancellation) in cancellations {
                            if let Some(cancellation) = cancellation {
                                cancellation.commit();
                            }
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
    async fn global_stop_fences_a_slot_before_its_local_cancel_signal() -> TestResult {
        let control = Arc::new(ExecutionControl::new(&Config::default()));
        let mut reservation = control
            .reserve_upstream(
                ExecutionId::new(),
                UpstreamId::new(),
                PrincipalId::new_user(),
            )
            .ok_or("upstream reservation missing")?;
        let mut cancellation = reservation
            .claim_start()
            .await
            .ok_or("start claim missing")?;

        // Simulate the interval after stop publishes its global signal and
        // before it reaches this reservation while walking the slots.
        control.shutdown.send_replace(true);
        assert!(matches!(
            *cancellation.phase.borrow(),
            UpstreamPhase::Started
        ));
        assert!(cancellation.start_io(|| ()).await.is_none());
        tokio::time::timeout(Duration::from_secs(1), cancellation.cancelled()).await?;
        Ok(())
    }
}
