use std::convert::Infallible;
use std::fs;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::time::Duration;

use efferian_protocol::{
    ActorId, Event, ExecutionId, ExecutionState, ExecutionSummary, HubId, NodeId, PrincipalId,
    ProfileId, RequestId, TerminalExecutionState, TokenId, ToolId,
};
use futures_util::poll;
use rusqlite::{Connection, params};
use tokio::sync::oneshot;

use super::actor::{MAX_WORK_BYTES, WriteTxError};
use super::executions::InvokeWrite;
use super::*;

mod revocation;

pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default)]
struct TestClock(AtomicI64);

impl StorageClock for TestClock {
    fn wall_now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    fn monotonic_now(&self) -> Result<Duration, StorageError> {
        Ok(Duration::from_millis(self.wall_now_ms().unsigned_abs()))
    }
}

pub(super) struct Fixture {
    pub(super) dir: PathBuf,
    pub(super) hub_id: HubId,
    pub(super) principal: PrincipalId,
    pub(super) token: TokenId,
    pub(super) node: NodeId,
    pub(super) tool: ToolId,
    config: StorageConfig,
    clock: Arc<TestClock>,
}

impl Fixture {
    pub(super) fn create(config: StorageConfig) -> TestResult<Self> {
        let hub_id = HubId::new();
        let fixture = Self {
            dir: std::env::temp_dir().join(hub_id.to_string()),
            hub_id,
            principal: PrincipalId::new_user(),
            token: TokenId::new_user_or_agent(),
            node: NodeId::new(),
            tool: ToolId::new(),
            config,
            clock: Arc::new(TestClock::default()),
        };
        let mut lock = acquire_state_lock(&fixture.dir)?;
        create_staged(
            &mut lock,
            NewHubIdentity {
                hub_id,
                active_key_id: 1,
                master_key_fingerprint: "test-fingerprint".to_owned(),
            },
            &fixture.config,
            fixture.clock.as_ref(),
            |conn| {
                conn.execute(
                    "INSERT INTO principals(principal_id, kind, name, created_at_ms, updated_at_ms)
                          VALUES (?1, 'admin', 'admin', 0, 0)",
                    [fixture.principal.to_string()],
                )?;
                seed_token(conn, fixture.token, fixture.principal, fixture.principal)?;
                conn.execute("INSERT INTO nodes(node_id, name, credential_hmac, created_at_ms, updated_at_ms)
                          VALUES (?1, 'node', 'verifier', 0, 0)", [fixture.node.to_string()])?;
                Ok::<_, rusqlite::Error>(())
            },
        )?;
        Ok(fixture)
    }

    pub(super) fn open(&self, mode: OpenMode) -> TestResult<OpenedDb> {
        Ok(open_existing(
            acquire_state_lock(&self.dir)?,
            mode,
            ExpectedHubIdentity {
                active_key_id: 1,
                master_key_fingerprint: "test-fingerprint".to_owned(),
            },
            &self.config,
            self.clock.clone(),
        )?)
    }

    pub(super) fn start(&self) -> TestResult<(StorageHandle, StorageRuntime)> {
        Ok(self
            .open(OpenMode::ServeAutoMigrate)?
            .migrate_and_start_runtime()?)
    }

    fn request(&self, request_id: RequestId) -> InvokeWrite {
        InvokeWrite {
            request_id,
            caller: self.principal,
            token: self.token,
            resource: InvokeResource::ToolTest {
                tool_id: self.tool,
                resolved_version: NonZeroU64::MIN,
                requested_version: None,
            },
            public_name: "example".to_owned(),
            requested_target: None,
            arguments: Default::default(),
            executor: ExecutionTarget::Node {
                node_id: self.node,
                session_epoch: 1,
            },
            account_id: None,
            deadline_at_ms: 30_000,
        }
    }

    fn receipt(&self, execution_id: ExecutionId, state: TerminalExecutionState) -> ReceiptWrite {
        ReceiptWrite {
            execution_id,
            node_id: self.node,
            state,
            frame_epoch: 0,
            sealed_result_blob: Some(vec![1, 2, 3]),
            summary: ExecutionSummary {
                exit_code: Some(42),
                duration_ms: Some(5),
                error_code: Some("receipt_code".to_owned()),
                effect_may_have_occurred: Some(true),
                error_message: Some("not for the outbox".to_owned()),
                ..ExecutionSummary::default()
            },
            result_truncated: false,
        }
    }

    pub(super) fn path(&self) -> PathBuf {
        self.dir.join("hub.sqlite3")
    }

    pub(super) fn set_wall_ms(&self, ms: i64) {
        self.clock.0.store(ms, Ordering::SeqCst);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

pub(super) fn seed_token(
    conn: &Connection,
    token: TokenId,
    owner: PrincipalId,
    creator: PrincipalId,
) -> rusqlite::Result<()> {
    conn.execute("INSERT INTO auth_tokens(token_id, principal_id, created_by, label, verifier_hmac, created_at_ms)
        VALUES (?1, ?2, ?3, 'token', ?1, 0)", params![token.to_string(), owner.to_string(), creator.to_string()])?;
    Ok(())
}

async fn pause_writer(
    handle: &StorageHandle,
) -> TestResult<(oneshot::Sender<()>, tokio::task::JoinHandle<()>)> {
    let (ready, started) = oneshot::channel();
    let (release, blocked) = oneshot::channel();
    let handle = handle.clone();
    let task = tokio::spawn(async move {
        let result = handle
            .execute_work(0, move |_| {
                let _ = ready.send(());
                let _ = blocked.blocking_recv();
                Ok::<_, WriteTxError<Infallible>>(())
            })
            .await;
        assert!(result.is_ok(), "{result:?}");
    });
    tokio::time::timeout(TIMEOUT, started).await??;
    Ok((release, task))
}

#[tokio::test]
async fn work_barrier_retries_a_rolled_back_batch() -> TestResult {
    let fixture = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = fixture.start()?;
    let (release, anchor) = pause_writer(&handle).await?;
    let mut aborted = std::pin::pin!(handle.execute_work(0, |tx| {
        tx.conn()
            .execute_batch("INSERT INTO missing_table VALUES (1)")?;
        Ok::<_, WriteTxError<Infallible>>(())
    }));
    let mut barrier = std::pin::pin!(handle.work_barrier());
    assert!(poll!(aborted.as_mut()).is_pending());
    assert!(poll!(barrier.as_mut()).is_pending());
    release.send(()).map_err(|()| "writer dropped the pause")?;
    anchor.await?;
    assert!(matches!(aborted.await, Err(WriteError::PreCommitAborted)));
    tokio::time::timeout(TIMEOUT, barrier).await??;
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn priority_commits_before_the_next_work_batch_and_has_independent_capacity() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let (release, anchor) = pause_writer(&handle).await?;
    let token = f.token;
    let disk = f.path();
    let work_ran = Arc::new(AtomicUsize::new(0));
    let observed = work_ran.clone();
    let mut first = Box::pin(handle.execute_work(MAX_WORK_BYTES, move |tx| {
        let conn = Connection::open(disk)?;
        let revoked: Option<i64> = conn.query_row(
            "SELECT revoked_at_ms FROM auth_tokens WHERE token_id = ?1",
            [token.to_string()],
            |row| row.get(0),
        )?;
        assert_eq!(
            revoked,
            Some(0),
            "priority must already be committed on a separate connection"
        );
        tx.conn()
            .execute("UPDATE hub_meta SET updated_at_ms = 4", [])?;
        observed.fetch_add(1, Ordering::SeqCst);
        Ok::<_, WriteTxError<Infallible>>(())
    }));
    assert!(poll!(&mut first).is_pending());
    let mut queued = Vec::new();
    for _ in 0..255 {
        let mut work = Box::pin(handle.execute_work(0, |_| Ok::<_, WriteTxError<Infallible>>(())));
        assert!(poll!(&mut work).is_pending());
        queued.push(work);
    }
    assert!(matches!(
        handle
            .execute_work(0, |_| Ok::<_, WriteTxError<Infallible>>(()))
            .await,
        Err(WriteError::Storage(StorageError::Overloaded))
    ));
    assert!(matches!(
        handle
            .execute_work(
                MAX_WORK_BYTES + 1,
                |_| Ok::<_, WriteTxError<Infallible>>(())
            )
            .await,
        Err(WriteError::Storage(StorageError::PayloadTooLarge))
    ));
    let mut priority = Box::pin(handle.revoke_token(ActorId::Hub(f.hub_id), f.token));
    assert!(poll!(&mut priority).is_pending());

    release.send(()).map_err(|_| "writer stopped")?;
    anchor.await?;
    assert!(priority.await?);
    first.await?;
    // Dropped callers do not cancel admitted commands. Shutdown drains them.
    drop(queued);
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    assert_eq!(work_ran.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn savepoint_replay_and_hooks_follow_the_proven_commit() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let (release, anchor) = pause_writer(&handle).await?;
    let request = RequestId::new();
    let principal = f.principal;
    let mut events = handle.subscribe_events()?;
    let mut revocations = handle.subscribe_revocations()?;
    let mut first = Box::pin(handle.invoke(f.request(request)));
    let mut duplicate = Box::pin(handle.invoke(f.request(request)));
    let mut conflict_input = f.request(request);
    conflict_input.resource = InvokeResource::Profile {
        profile_id: ProfileId::new(),
        version: NonZeroU64::MIN,
    };
    let mut conflict = Box::pin(handle.invoke(conflict_input));
    let abandoned = Arc::new(AtomicUsize::new(0));
    let callback = abandoned.clone();
    let mut bad = Box::pin(handle.execute_work(0, move |tx| {
        tx.append_event(
            ActorId::Principal(principal),
            Event::PrincipalRevoked(principal),
        )?;
        tx.principal_permissions_reduced(principal)?;
        tx.on_commit(move || {
            callback.fetch_add(1, Ordering::SeqCst);
        });
        tx.conn().execute(
            "INSERT INTO principals(principal_id, kind, name, created_at_ms, updated_at_ms)
            VALUES (?1, 'admin', 'admin', 0, 0)",
            [PrincipalId::new_user().to_string()],
        )?;
        Ok::<_, WriteTxError<Infallible>>(())
    }));
    let mut good = Box::pin(handle.execute_work(0, move |tx| {
        tx.append_event(
            ActorId::Principal(principal),
            Event::PrincipalRevoked(principal),
        )?;
        tx.principal_permissions_reduced(principal)?;
        tx.on_commit(move || {
            assert!(revocations.try_recv().is_ok());
            assert!(events.try_recv().is_ok());
        });
        Ok::<_, WriteTxError<Infallible>>(())
    }));
    assert!(poll!(&mut first).is_pending());
    assert!(poll!(&mut bad).is_pending());
    assert!(poll!(&mut duplicate).is_pending());
    assert!(poll!(&mut conflict).is_pending());
    assert!(poll!(&mut good).is_pending());
    release.send(()).map_err(|_| "writer stopped")?;
    anchor.await?;

    let first = first.await?;
    let replay = duplicate.await?;
    assert!(!first.replayed && replay.replayed);
    assert_eq!(first.execution_id, replay.execution_id);
    let mut waiter = first.waiter.ok_or("missing first waiter")?;
    assert!(waiter.same_channel(&replay.waiter.ok_or("missing replay waiter")?));
    assert!(matches!(
        conflict.await,
        Err(WriteError::Domain(InvokeWriteError::RequestIdConflict))
    ));
    assert!(matches!(
        bad.await,
        Err(WriteError::Storage(StorageError::Sqlite(_)))
    ));
    good.await?;
    assert_eq!(abandoned.load(Ordering::SeqCst), 0);
    assert_eq!(handle.read_events(0, None, 500).await?.items.len(), 1);
    assert!(handle.cancel_execution(first.execution_id).await?);
    assert!(!handle.cancel_execution(first.execution_id).await?);
    assert_eq!(
        handle
            .apply_receipt(f.receipt(first.execution_id, TerminalExecutionState::Cancelled))
            .await?,
        ReceiptOutcome::AppliedTerminal
    );
    waiter.changed().await?;
    assert_eq!(waiter.borrow().state, ExecutionState::Cancelled);
    assert!(handle.subscribe_waiter(first.execution_id).await?.is_none());
    let page = handle.read_events(1, None, 500).await?;
    assert!(matches!(
        page.items[0].envelope.event,
        Event::ExecutionCancelled(_)
    ));
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn full_aborts_the_whole_batch_including_a_speculative_conflict() -> TestResult {
    let f = Fixture::create(StorageConfig {
        max_page_count: 128,
        ..StorageConfig::default()
    })?;
    let (handle, runtime) = f.start()?;
    let (release, anchor) = pause_writer(&handle).await?;
    let request = RequestId::new();
    let mut first = Box::pin(handle.invoke(f.request(request)));
    let mut different = f.request(request);
    different.public_name = "different".to_owned();
    let mut conflict = Box::pin(handle.invoke(different));
    let principal = f.principal;
    let observed = Arc::new(AtomicUsize::new(0));
    let rolled_back = observed.clone();
    let mut full = Box::pin(handle.execute_work(0, move |tx| {
        tx.append_event(
            ActorId::Principal(principal),
            Event::PrincipalRevoked(principal),
        )?;
        tx.on_commit(move || {
            rolled_back.store(1, Ordering::SeqCst);
        });
        let error = tx
            .conn()
            .execute(
                "UPDATE hub_meta SET master_key_fingerprint = zeroblob(524288)",
                [],
            )
            .err()
            .ok_or(rusqlite::Error::InvalidQuery)?;
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DiskFull)
        );
        Err::<(), _>(WriteTxError::<Infallible>::Sqlite(error))
    }));
    assert!(poll!(&mut first).is_pending());
    assert!(poll!(&mut conflict).is_pending());
    assert!(poll!(&mut full).is_pending());
    release.send(()).map_err(|_| "writer stopped")?;
    anchor.await?;
    assert!(matches!(first.await, Err(WriteError::PreCommitAborted)));
    assert!(matches!(conflict.await, Err(WriteError::PreCommitAborted)));
    assert!(matches!(full.await, Err(WriteError::PreCommitAborted)));
    assert_eq!(observed.load(Ordering::SeqCst), 0);
    assert_eq!(handle.status_snapshot().await?.active_waiters_count, 0);
    assert!(handle.read_events(0, None, 500).await?.items.is_empty());
    assert!(!handle.invoke(f.request(request)).await?.replayed);
    assert!(handle.revoke_token(ActorId::Hub(f.hub_id), f.token).await?);
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn a_failed_commit_never_publishes_staged_effects() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let principal = f.principal;
    let mut events = handle.subscribe_events()?;
    let mut revocations = handle.subscribe_revocations()?;
    let result = handle
        .execute_work(0, move |tx| {
            tx.conn().execute_batch("PRAGMA defer_foreign_keys = ON")?;
            seed_token(
                tx.conn(),
                TokenId::new_user_or_agent(),
                PrincipalId::new_user(),
                principal,
            )?;
            tx.append_event(
                ActorId::Principal(principal),
                Event::PrincipalRevoked(principal),
            )?;
            tx.principal_permissions_reduced(principal)?;
            Ok::<_, WriteTxError<Infallible>>(())
        })
        .await;
    assert!(matches!(result, Err(WriteError::CommitOutcomeUnknown)));
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        revocations.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(handle.status_snapshot().await?.events_head_seq, 0);
    assert!(handle.revoke_token(ActorId::Hub(f.hub_id), f.token).await?);
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn late_receipt_is_deduplicated_even_after_event_pruning() -> TestResult {
    let f = Fixture::create(StorageConfig {
        max_events_rows: 1,
        ..StorageConfig::default()
    })?;
    let (handle, runtime) = f.start()?;
    let exec = handle
        .invoke(f.request(RequestId::new()))
        .await?
        .execution_id;
    let principal = f.principal;
    handle.execute_work(0, move |tx| {
        tx.conn().execute(
            "UPDATE executions SET state = 'unknown', summary_json = '{\"effect_may_have_occurred\":true}',
             sealed_result_blob = X'ff', result_bytes = 1, finished_at_ms = 1 WHERE execution_id = ?1",
            [exec.to_string()],
        )?;
        tx.stage_waiter_finish(exec, ExecutionSnapshot { state: ExecutionState::Unknown, finished_at_ms: Some(1) });
        Ok::<_, WriteTxError<Infallible>>(())
    }).await?;
    let mut not_owned = f.receipt(exec, TerminalExecutionState::Failed);
    not_owned.node_id = NodeId::new();
    assert_eq!(
        handle.apply_receipt(not_owned).await?,
        ReceiptOutcome::NotOwnedOrNotFound
    );
    f.set_wall_ms(12);
    assert_eq!(
        handle
            .apply_receipt(f.receipt(exec, TerminalExecutionState::Failed))
            .await?,
        ReceiptOutcome::LateReceiptRecorded
    );
    let page = handle.read_events(0, None, 500).await?;
    let Event::ExecutionLateReceipt(payload) = &page.items[0].envelope.event else {
        return Err("missing late receipt".into());
    };
    assert_eq!(payload.state, ExecutionState::Failed);
    assert_eq!(payload.exit_code, Some(42));
    assert_eq!(payload.error_code.as_deref(), Some("receipt_code"));
    assert_eq!(payload.duration_ms, Some(12));
    let row = handle.read_snapshot(move |conn| {
        let row = conn.query_row("SELECT state, summary_json, sealed_result_blob FROM executions WHERE execution_id = ?1",
            [exec.to_string()], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?)))?;
        Ok::<_, StorageError>(row)
    }).await?;
    assert_eq!(
        row,
        (
            "unknown".to_owned(),
            "{\"effect_may_have_occurred\":true}".to_owned(),
            vec![255]
        )
    );
    for _ in 0..2 {
        handle
            .execute_work(0, move |tx| {
                tx.append_event(
                    ActorId::Principal(principal),
                    Event::PrincipalRevoked(principal),
                )?;
                Ok::<_, WriteTxError<Infallible>>(())
            })
            .await?;
    }
    // The next turn observes the already committed mini-transaction.
    handle.subscribe_waiter(exec).await?;
    assert_eq!(
        handle
            .apply_receipt(f.receipt(exec, TerminalExecutionState::Failed))
            .await?,
        ReceiptOutcome::AlreadyTerminalOwned
    );
    let page = handle.read_events(0, None, 500).await?;
    assert_eq!(
        (
            page.oldest_available_seq,
            page.latest_seq,
            page.scanned_through,
            page.items.len()
        ),
        (3, 3, 3, 1)
    );
    assert!(matches!(
        handle.read_events(1, None, 500).await,
        Err(EventsReadError::ResyncRequired {
            oldest_available_seq: 3,
            latest_seq: 3
        })
    ));
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn hard_admission_uses_current_pages_and_preserves_replay_and_control() -> TestResult {
    const CAP: u32 = 128;
    let f = Fixture::create(StorageConfig {
        max_page_count: CAP,
        ..StorageConfig::default()
    })?;
    let (handle, runtime) = f.start()?;
    let request = RequestId::new();
    let accepted = handle.invoke(f.request(request)).await?;
    assert_eq!(
        handle.status_snapshot().await?.storage_pressure,
        StoragePressure::Normal
    );
    handle.execute_work(0, |tx| {
        let conn = tx.conn();
        for id in 0..CAP {
            let count: u32 = conn.pragma_query_value(None, "page_count", |row| row.get(0))?;
            let free: u32 = conn.pragma_query_value(None, "freelist_count", |row| row.get(0))?;
            if (count - free) * 100 >= 85 * CAP {
                break;
            }
            conn.execute("INSERT INTO upstreams(upstream_id, slug, url, discovered_tools_json, created_at_ms, updated_at_ms)
                VALUES (?1, ?1, 'https://example.test', hex(zeroblob(2048)), 0, 0)", [id])?;
        }
        Ok::<_, WriteTxError<Infallible>>(())
    }).await?;

    let status = handle.status_snapshot().await?;
    assert_eq!(status.storage_pressure, StoragePressure::Hard);
    assert_eq!(
        status.used_percent,
        (status.page_count - status.freelist_count) * 100 / CAP
    );
    assert!(matches!(
        handle.invoke(f.request(RequestId::new())).await,
        Err(WriteError::Storage(StorageError::StoragePressure))
    ));
    let replay = handle.invoke(f.request(request)).await?;
    assert!(replay.replayed);
    assert_eq!(replay.execution_id, accepted.execution_id);
    assert!(handle.revoke_token(ActorId::Hub(f.hub_id), f.token).await?);
    assert_eq!(
        handle
            .apply_receipt(f.receipt(accepted.execution_id, TerminalExecutionState::Succeeded))
            .await?,
        ReceiptOutcome::AppliedTerminal
    );
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));

    let (handle, runtime) = f.start()?;
    assert!(matches!(
        handle.invoke(f.request(RequestId::new())).await,
        Err(WriteError::Storage(StorageError::StoragePressure))
    ));
    handle
        .execute_work(0, |tx| {
            tx.conn().execute("DELETE FROM upstreams", [])?;
            Ok::<_, WriteTxError<Infallible>>(())
        })
        .await?;
    assert!(handle.status_snapshot().await?.freelist_count > 0);
    assert!(!handle.invoke(f.request(RequestId::new())).await?.replayed);
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn profile_replay_uses_the_original_edition_after_publication_and_restart() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let profile = ProfileId::new();
    let caller = f.principal;
    let old_tool = f.tool;
    let new_tool = ToolId::new();
    let node = f.node;
    handle.execute_work(0, move |tx| {
        let conn = tx.conn();
        conn.execute("INSERT INTO profiles(profile_id, slug, discovery_mode, published_version, created_at_ms, updated_at_ms)
            VALUES (?1, 'profile', 'full', 1, 0, 0)", [profile.to_string()])?;
        for (version, tool) in [(1, old_tool), (2, new_tool)] {
            let bindings = serde_json::json!([{
                "public_name": "example", "tool_id": tool, "tool_version": 1,
                "fixed_node_id": if version == 1 { node } else { NodeId::new() },
            }]).to_string();
            conn.execute("INSERT INTO profile_editions(profile_id, version, discovery_mode, bindings_json, published_by, published_at_ms)
                VALUES (?1, ?2, 'full', ?3, ?4, 0)", params![profile.to_string(), version, bindings, caller.to_string()])?;
        }
        Ok::<_, WriteTxError<Infallible>>(())
    }).await?;

    let request = RequestId::new();
    let mut original = f.request(request);
    original.resource = InvokeResource::Profile {
        profile_id: profile,
        version: NonZeroU64::MIN,
    };
    let first = handle.invoke(original).await?;
    handle
        .execute_work(0, move |tx| {
            tx.conn().execute(
                "UPDATE profiles SET published_version = 2 WHERE profile_id = ?1",
                [profile.to_string()],
            )?;
            Ok::<_, WriteTxError<Infallible>>(())
        })
        .await?;
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));

    let (handle, runtime) = f.start()?;
    let mut duplicate = f.request(request);
    duplicate.resource = InvokeResource::Profile {
        profile_id: profile,
        version: NonZeroU64::new(2).ok_or("invalid test version")?,
    };
    let restored = handle
        .subscribe_waiter(first.execution_id)
        .await?
        .ok_or("missing restored waiter")?;
    let replay = handle.invoke(duplicate).await?;
    assert!(replay.replayed);
    assert_eq!(replay.execution_id, first.execution_id);
    assert!(restored.same_channel(&replay.waiter.ok_or("missing replay waiter")?));
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn raw_event_cursor_advances_by_scanned_rows_and_flags_real_gaps() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let empty = handle.read_events(0, None, 500).await?;
    assert_eq!((empty.oldest_available_seq, empty.latest_seq), (1, 0));
    assert!(matches!(
        handle.read_events(-1, None, 1).await,
        Err(EventsReadError::InvalidCursor)
    ));
    let other = PrincipalId::new_user();
    let self_id = f.principal;
    let actor = ActorId::Hub(f.hub_id);
    handle
        .execute_work(0, move |tx| {
            for _ in 0..500 {
                tx.append_event(actor, Event::PrincipalRevoked(other))?;
            }
            tx.append_event(actor, Event::PrincipalRevoked(self_id))?;
            Ok::<_, WriteTxError<Infallible>>(())
        })
        .await?;
    let exact = handle.read_events(0, Some(500), 500).await?;
    assert!(!exact.has_more);
    assert_eq!(exact.scanned_through, 500);
    let page = handle.read_events(0, None, 500).await?;
    assert!(page.has_more);
    assert!(
        page.items
            .iter()
            .all(|item| item.auth.owner_principal_id == Some(other))
    );
    let final_page = handle
        .read_events(page.scanned_through, Some(page.latest_seq), 500)
        .await?;
    assert_eq!(final_page.items.len(), 1);
    assert_eq!(final_page.items[0].auth.owner_principal_id, Some(self_id));
    assert!(!final_page.has_more);

    f.clock
        .0
        .store(StorageConfig::default().event_ttl_ms, Ordering::SeqCst);
    // Release each fairness turn until the actor's TTL pass has committed.
    tokio::time::timeout(TIMEOUT, async {
        loop {
            handle.subscribe_waiter(ExecutionId::new()).await?;
            if handle.status_snapshot().await?.events_pruned_through_seq == 501 {
                break Ok::<_, StorageError>(());
            }
        }
    })
    .await??;
    let empty = handle.read_events(0, None, 500).await?;
    assert_eq!(
        (
            empty.oldest_available_seq,
            empty.latest_seq,
            empty.scanned_through
        ),
        (502, 501, 501)
    );
    assert!(!empty.has_more && empty.items.is_empty());
    assert!(matches!(
        handle.read_events(1, None, 500).await,
        Err(EventsReadError::ResyncRequired {
            oldest_available_seq: 502,
            latest_seq: 501
        })
    ));
    assert!(matches!(
        handle.read_events(502, None, 500).await,
        Err(EventsReadError::ResyncRequired { .. })
    ));
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn revoke_publishes_deduplicated_dependents_and_lag_is_terminal() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let admin = f.principal;
    let node = f.node;
    let both = PrincipalId::new_agent();
    let owner_only = PrincipalId::new_agent();
    let manager_only = PrincipalId::new_agent();
    let other = PrincipalId::new_user();
    let backup_admin = PrincipalId::new_user();
    handle.execute_work(0, move |tx| {
        tx.conn().execute("INSERT INTO principals(principal_id, kind, name, created_at_ms, updated_at_ms)
            VALUES (?1, 'member', 'other', 0, 0)", [other.to_string()])?;
        tx.conn().execute("INSERT INTO principals(principal_id, kind, name, created_at_ms, updated_at_ms)
            VALUES (?1, 'admin', 'backup', 0, 0)", [backup_admin.to_string()])?;
        revocation::seed_admin_grant(tx.conn(), backup_admin)?;
        for (agent, owner, manager) in [(both, admin, admin), (owner_only, admin, other), (manager_only, other, admin)] {
            let agent = agent.to_string();
            tx.conn().execute("INSERT INTO principals(principal_id, kind, name, owner_principal_id, managed_by_principal_id, created_at_ms, updated_at_ms)
                VALUES (?1, 'agent', ?1, ?2, ?3, 0, 0)", params![agent, owner.to_string(), manager.to_string()])?;
        }
        tx.conn().execute("UPDATE nodes SET managed_by_principal_id = ?1 WHERE node_id = ?2",
            params![admin.to_string(), node.to_string()])?;
        Ok::<_, WriteTxError<Infallible>>(())
    }).await?;
    let mut revocations = handle.subscribe_revocations()?;
    assert_eq!(
        handle
            .disable_principal(ActorId::Hub(f.hub_id), admin)
            .await?,
        Some(vec![(node, 0)]),
    );
    assert!(
        handle
            .disable_principal(ActorId::Hub(f.hub_id), admin)
            .await?
            .is_none()
    );
    let signal = revocations.recv().await?;
    assert_eq!(signal.reason, RevocationReason::PrincipalDisabled(admin));
    assert_eq!(signal.affected_principals.len(), 4);
    for id in [admin, both, owner_only, manager_only] {
        assert!(signal.affected_principals.contains(&id));
    }
    assert_eq!(signal.affected_nodes, [node]);
    assert!(matches!(
        revocations.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    let mut events = handle.subscribe_events()?;
    handle
        .execute_work(0, move |tx| {
            tx.principal_permissions_reduced(admin)?;
            Ok::<_, WriteTxError<Infallible>>(())
        })
        .await?;
    let reduced = revocations.try_recv()?;
    assert_eq!(
        reduced.reason,
        RevocationReason::PrincipalPermissionsReduced(admin)
    );
    assert_eq!(reduced.affected_principals, signal.affected_principals);
    assert!(reduced.affected_nodes.is_empty());
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    handle
        .execute_work(0, move |tx| {
            for _ in 0..150 {
                tx.principal_permissions_reduced(admin)?;
            }
            Ok::<_, WriteTxError<Infallible>>(())
        })
        .await?;
    assert!(matches!(
        revocations.recv().await,
        Err(tokio::sync::broadcast::error::RecvError::Lagged(_))
    ));
    assert!(matches!(
        revocations.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Closed)
    ));
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

const STAGE_POINT_ENV: &str = "EFFERIAN_TEST_STAGE_POINT";
const STAGE_DIR_ENV: &str = "EFFERIAN_TEST_STAGE_DIR";
const STAGE_ID_ENV: &str = "EFFERIAN_TEST_STAGE_ID";

pub(super) fn stage_point(point: &str) {
    if std::env::var(STAGE_POINT_ENV).as_deref() == Ok(point) {
        println!("PAUSED {point}");
        loop {
            std::thread::park();
        }
    }
}

#[test]
fn staging_subprocess() -> TestResult {
    let Some(dir) = std::env::var_os(STAGE_DIR_ENV) else {
        return Ok(());
    };
    let dir = PathBuf::from(dir);
    if std::env::var(STAGE_POINT_ENV).as_deref() == Ok("lock") {
        // Prevent an unexpected acquisition from turning into a successful test.
        assert!(matches!(
            acquire_state_lock(&dir),
            Err(StorageError::Platform(
                efferian_platform::PlatformError::LockContended { .. }
            ))
        ));
        return Ok(());
    }
    let mut lock = acquire_state_lock(&dir)?;
    if std::env::var(STAGE_POINT_ENV).as_deref() == Ok("spill") {
        let conn = Connection::open(dir.join("hub.sqlite3"))?;
        conn.pragma_update(None, "cache_size", 2)?;
        conn.execute_batch("BEGIN IMMEDIATE")?;
        conn.execute("UPDATE hub_meta SET active_key_id = 99", [])?;
        for n in 0..12 {
            conn.execute(
                "INSERT INTO upstreams(upstream_id, slug, url, discovered_tools_json, created_at_ms, updated_at_ms)
                 VALUES (?1, ?1, 'https://example.test', hex(zeroblob(10000)), 0, 0)",
                [n],
            )?;
        }
        stage_point("spill");
        return Err("snapshot subprocess ran past its crash boundary".into());
    }
    let hub_id = HubId::parse(&std::env::var(STAGE_ID_ENV)?)?;
    create_staged(
        &mut lock,
        NewHubIdentity {
            hub_id,
            active_key_id: 1,
            master_key_fingerprint: "test-fingerprint".to_owned(),
        },
        &StorageConfig::default(),
        &TestClock::default(),
        |conn| {
            conn.execute("UPDATE hub_meta SET updated_at_ms = 17", [])?;
            Ok::<_, rusqlite::Error>(())
        },
    )?;
    Err("staging subprocess ran past its crash boundary".into())
}

#[test]
fn staged_init_recovers_at_real_process_death_boundaries() -> TestResult {
    use std::process::Command;

    for point in ["pre-commit", "pre-link", "post-link"] {
        let f = Fixture::create(StorageConfig::default())?;
        fs::remove_file(f.path())?;
        let mut subprocess = Command::new(std::env::current_exe()?);
        subprocess
            .args([
                "--exact",
                "storage::tests::staging_subprocess",
                "--nocapture",
            ])
            .env(STAGE_DIR_ENV, &f.dir)
            .env(STAGE_ID_ENV, f.hub_id.to_string());
        let lock = acquire_state_lock(&f.dir)?;
        assert!(subprocess.env(STAGE_POINT_ENV, "lock").status()?.success());
        drop(lock);
        stop_subprocess_at(&mut subprocess, point)?;
        assert_eq!(f.path().exists(), point == "post-link");
        if !f.path().exists() {
            let mut lock = acquire_state_lock(&f.dir)?;
            create_staged(
                &mut lock,
                NewHubIdentity {
                    hub_id: f.hub_id,
                    active_key_id: 1,
                    master_key_fingerprint: "test-fingerprint".into(),
                },
                &f.config,
                f.clock.as_ref(),
                |conn| {
                    conn.execute("UPDATE hub_meta SET updated_at_ms = 17", [])?;
                    Ok::<_, rusqlite::Error>(())
                },
            )?;
        }
        let opened = f.open(OpenMode::OfflineExactVersion)?;
        let read = opened.run_offline_tx(|conn| {
            conn.query_row("SELECT updated_at_ms FROM hub_meta", [], |row| {
                row.get::<_, i64>(0)
            })
        })?;
        assert_eq!(read.value, 17);
        assert!(!f.dir.join(".staging-hub-init").exists());
    }
    Ok(())
}

#[tokio::test]
async fn ro_pool_retains_a_cancelled_workers_slot_and_shutdown_waits_for_readers() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut slots = Vec::new();
    for _ in 0..6 {
        let handle = handle.clone();
        let entered = entered_tx.clone();
        let (release, held) = oneshot::channel();
        let reader = tokio::spawn(async move {
            handle
                .read_snapshot(move |conn| {
                    conn.query_row("SELECT id FROM hub_meta", [], |row| row.get::<_, i64>(0))?;
                    let _ = entered.send(());
                    let _ = held.blocking_recv();
                    Ok::<_, StorageError>(())
                })
                .await
        });
        slots.push((release, reader));
    }
    for _ in 0..6 {
        tokio::time::timeout(TIMEOUT, entered_rx.recv())
            .await?
            .ok_or("reader disconnected")?;
    }
    // Control snapshots stay available while all 6 general readers are saturated.
    let control_id = tokio::time::timeout(
        TIMEOUT,
        handle.read_control_snapshot(|conn| {
            conn.query_row("SELECT id FROM hub_meta", [], |row| row.get::<_, i64>(0))
                .map_err(StorageError::from)
        }),
    )
    .await??;
    assert_eq!(control_id, 1);
    let (cancelled_release, cancelled) = slots.pop().ok_or("missing reader to cancel")?;
    cancelled.abort();
    assert!(cancelled.await.is_err());

    let mut next = Box::pin(handle.status_snapshot());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut next)
            .await
            .is_err()
    );
    handle.invoke(f.request(RequestId::new())).await?;
    cancelled_release
        .send(())
        .map_err(|_| "worker dropped its checkout")?;
    assert_eq!(
        tokio::time::timeout(TIMEOUT, next)
            .await??
            .active_waiters_count,
        1
    );

    let mut stopping = Box::pin(runtime.shutdown());
    assert!(poll!(&mut stopping).is_pending());
    assert!(matches!(
        handle.read_snapshot(|_| Ok::<_, StorageError>(())).await,
        Err(StorageError::ShuttingDown)
    ));
    assert!(matches!(
        acquire_state_lock(&f.dir),
        Err(StorageError::Platform(
            efferian_platform::PlatformError::LockContended { .. }
        ))
    ));
    for (release, reader) in slots {
        release.send(()).map_err(|_| "reader stopped early")?;
        reader.await??;
    }
    assert!(matches!(
        tokio::time::timeout(TIMEOUT, stopping).await?,
        ShutdownReport::Complete
    ));
    drop(acquire_state_lock(&f.dir)?);
    Ok(())
}

#[tokio::test]
async fn dropped_reader_after_panic_does_not_hold_an_old_snapshot() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let result = handle
        .read_snapshot(|conn| {
            let old = conn.query_row("SELECT updated_at_ms FROM hub_meta", [], |row| {
                row.get::<_, i64>(0)
            })?;
            assert_eq!(old, -1, "forced reader panic after entering the snapshot");
            Ok::<_, StorageError>(())
        })
        .await;
    assert!(matches!(result, Err(StorageError::Background(error)) if error.is_panic()));
    handle
        .execute_work(0, |tx| {
            tx.conn()
                .execute("UPDATE hub_meta SET updated_at_ms = 12", [])?;
            Ok::<_, WriteTxError<Infallible>>(())
        })
        .await?;
    let now = handle
        .read_snapshot(|conn| {
            conn.query_row("SELECT updated_at_ms FROM hub_meta", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(StorageError::from)
        })
        .await?;
    assert_eq!(now, 12);
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn wal_checkpoints_back_off_with_an_external_reader_and_resume_after_it_closes() -> TestResult
{
    let f = Fixture::create(StorageConfig {
        journal_size_limit_bytes: 4096,
        shutdown_checkpoint_timeout: Duration::from_millis(20),
        ..StorageConfig::default()
    })?;
    let (handle, runtime) = f.start()?;
    let reader = Connection::open_with_flags(f.path(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    reader.execute_batch("BEGIN")?;
    reader.query_row("SELECT updated_at_ms FROM hub_meta", [], |row| {
        row.get::<_, i64>(0)
    })?;
    for now in 1..=4 {
        handle
            .execute_work(0, move |tx| {
                tx.conn()
                    .execute("UPDATE hub_meta SET updated_at_ms = ?1", [now])?;
                Ok::<_, WriteTxError<Infallible>>(())
            })
            .await?;
    }

    let wal = f.dir.join("hub.sqlite3-wal");
    let busy_timeout = handle
        .execute_work(0, |tx| {
            Ok::<_, WriteTxError<Infallible>>(tx.conn().pragma_query_value(
                None,
                "busy_timeout",
                |row| row.get::<_, i64>(0),
            )?)
        })
        .await?;
    assert_eq!(busy_timeout, 5000);
    assert!(fs::metadata(&wal)?.len() > 8192);
    reader.execute_batch("ROLLBACK")?;
    drop(reader);
    f.clock.0.store(29_999, Ordering::SeqCst);
    handle.subscribe_waiter(ExecutionId::new()).await?;
    handle.subscribe_waiter(ExecutionId::new()).await?;
    assert!(fs::metadata(&wal)?.len() > 8192);
    f.clock.0.store(30_000, Ordering::SeqCst);
    handle.subscribe_waiter(ExecutionId::new()).await?;
    handle.subscribe_waiter(ExecutionId::new()).await?;
    assert_eq!(fs::metadata(&wal)?.len(), 0);

    let reader = Connection::open_with_flags(f.path(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    reader.execute_batch("BEGIN")?;
    reader.query_row("SELECT id FROM hub_meta", [], |row| row.get::<_, i64>(0))?;
    handle
        .execute_work(0, |tx| {
            tx.conn()
                .execute("UPDATE hub_meta SET updated_at_ms = 5", [])?;
            Ok::<_, WriteTxError<Infallible>>(())
        })
        .await?;
    assert!(matches!(
        runtime.shutdown().await,
        ShutdownReport::WalCheckpointIncomplete { busy: 1, .. }
    ));
    assert!(fs::metadata(&wal)?.len() > 0);
    reader.execute_batch("ROLLBACK")?;
    drop(acquire_state_lock(&f.dir)?);
    Ok(())
}

#[tokio::test]
async fn online_vacuum_reads_a_consistent_snapshot_during_a_live_write_transaction() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let (entered, writing) = oneshot::channel();
    let (release, committing) = oneshot::channel();
    let actor = handle.clone();
    let mutation = tokio::spawn(async move {
        actor
            .execute_work(0, move |tx| {
                tx.conn()
                    .execute("UPDATE hub_meta SET updated_at_ms = 44", [])?;
                let _ = entered.send(());
                let _ = committing.blocking_recv();
                Ok::<_, WriteTxError<Infallible>>(())
            })
            .await
    });
    tokio::time::timeout(TIMEOUT, writing).await??;

    let database = f.path();
    let destination = f.dir.join("snapshot.sqlite3");
    let captured = tokio::time::timeout(
        TIMEOUT,
        tokio::task::spawn_blocking(move || {
            let reader =
                Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            reader.execute(
                "VACUUM INTO ?1",
                [destination.to_str().ok_or("non-UTF-8 snapshot path")?],
            )?;
            let snapshot = Connection::open_with_flags(
                destination,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            let health =
                snapshot.pragma_query_value(None, "quick_check", |row| row.get::<_, String>(0))?;
            let captured = snapshot.query_row("SELECT updated_at_ms FROM hub_meta", [], |row| {
                row.get::<_, i64>(0)
            })?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>((health, captured))
        }),
    )
    .await???;
    assert_eq!(captured, ("ok".into(), 0));
    release
        .send(())
        .map_err(|_| "writer released before snapshot")?;
    mutation.await??;
    let persisted = handle
        .read_snapshot(|conn| {
            conn.query_row("SELECT updated_at_ms FROM hub_meta", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(StorageError::from)
        })
        .await?;
    assert_eq!(persisted, 44);
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn priority_burst_yields_and_oversize_combination_keeps_strict_fifo() -> TestResult {
    use super::actor::PriorityKind;
    use std::sync::Mutex;

    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let (release, anchor) = pause_writer(&handle).await?;
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut priority = Vec::new();
    for n in 0..20 {
        let order = order.clone();
        let mut command = Box::pin(handle.execute_priority(
            PriorityKind::CancelExecution,
            move |_| {
                order
                    .lock()
                    .map_err(|_| rusqlite::Error::InvalidQuery)?
                    .push(n);
                Ok::<_, WriteTxError<Infallible>>(())
            },
        ));
        assert!(poll!(&mut command).is_pending());
        priority.push(command);
    }
    let mut work = Vec::new();
    let path = f.path();
    for (n, bytes) in [(20, 3 << 20), (21, 2 << 20), (22, 1 << 20)] {
        let path = path.clone();
        let order = order.clone();
        let mut command = Box::pin(handle.execute_work(bytes, move |tx| {
            let independent = Connection::open(path)?;
            let prev = independent.query_row("SELECT updated_at_ms FROM hub_meta", [], |row| {
                row.get::<_, i64>(0)
            })?;
            // Command 21 spills. Command 22 must follow it and share its next batch.
            assert_eq!(prev, if n == 20 { 0 } else { 20 });
            tx.conn()
                .execute("UPDATE hub_meta SET updated_at_ms = ?1", [n])?;
            order
                .lock()
                .map_err(|_| rusqlite::Error::InvalidQuery)?
                .push(n);
            Ok::<_, WriteTxError<Infallible>>(())
        }));
        assert!(poll!(&mut command).is_pending());
        work.push(command);
    }
    // Cancel the final future before execution and then close admission.
    drop(work.pop());
    let mut draining = Box::pin(runtime.shutdown());
    assert!(poll!(&mut draining).is_pending());
    release.send(()).map_err(|_| "writer stopped")?;
    anchor.await?;
    for command in priority {
        command.await?;
    }
    for command in work {
        command.await?;
    }
    assert!(matches!(
        tokio::time::timeout(TIMEOUT, draining).await?,
        ShutdownReport::Complete
    ));
    let actual = order.lock().map_err(|_| "order mutex poisoned")?.clone();
    assert_eq!(
        actual,
        (0..16)
            .chain([20])
            .chain(16..20)
            .chain([21, 22])
            .collect::<Vec<_>>()
    );
    let opened = f.open(OpenMode::OfflineExactVersion)?;
    let persisted = opened.run_offline_tx(|conn| {
        conn.query_row("SELECT updated_at_ms FROM hub_meta", [], |row| {
            row.get::<_, i64>(0)
        })
    })?;
    assert_eq!(
        persisted.value, 22,
        "cancellation did not cancel the admitted mutation"
    );
    Ok(())
}

#[tokio::test]
async fn receipt_and_control_hooks_can_share_their_transaction() -> TestResult {
    use super::actor::PriorityKind;

    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let exec = handle.invoke(f.request(RequestId::new())).await?;
    let wait = exec.waiter.ok_or("missing waiter")?;
    let observed = Arc::new(AtomicUsize::new(0));
    let hook = observed.clone();
    let outcome = handle
        .execute_priority(PriorityKind::CancelExecution, move |tx| {
            let changed = tx.cancel_execution(exec.execution_id)?;
            tx.on_commit(move || {
                hook.fetch_add(1, Ordering::SeqCst);
            });
            Ok::<_, WriteTxError<Infallible>>(changed)
        })
        .await?;
    assert!(outcome);
    let receipt = f
        .receipt(exec.execution_id, TerminalExecutionState::Cancelled)
        .prepare()?;
    let mut events = handle.subscribe_events()?;
    let hook = observed.clone();
    let outcome = handle
        .execute_work(receipt.payload_bytes(), move |tx| {
            let outcome = tx.apply_receipt(receipt)?;
            tx.on_commit(move || {
                assert!(matches!(
                    events.try_recv().map(|event| event.envelope.kind()),
                    Ok(efferian_protocol::EventKind::ExecutionCancelled)
                ));
                assert_eq!(wait.borrow().state, ExecutionState::Cancelled);
                hook.fetch_add(1, Ordering::SeqCst);
            });
            Ok(outcome)
        })
        .await?;
    assert_eq!(outcome, ReceiptOutcome::AppliedTerminal);
    assert_eq!(observed.load(Ordering::SeqCst), 2);
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn sustained_receipts_leave_capacity_for_retention_and_periodic_gc() -> TestResult {
    use futures_util::StreamExt;
    let f = Fixture::create(StorageConfig {
        max_events_rows: 32,
        ..StorageConfig::default()
    })?;
    let (handle, runtime) = f.start()?;
    let mut executions = Vec::new();
    for _ in 0..768 {
        executions.push(
            handle
                .invoke(f.request(RequestId::new()))
                .await?
                .execution_id,
        );
    }
    let principal = f.principal;
    let token = TokenId::new_user_or_agent();
    handle
        .execute_work(0, move |tx| {
            seed_token(tx.conn(), token, principal, principal)?;
            tx.conn().execute(
                "UPDATE auth_tokens SET revoked_at_ms = 0 WHERE token_id = ?1",
                [token.to_string()],
            )?;
            Ok::<_, WriteTxError<Infallible>>(())
        })
        .await?;
    f.clock
        .0
        .store(f.config.token_gc_grace_ms, Ordering::SeqCst);

    let mut receipts = futures_util::stream::iter(executions)
        .map(|id| handle.apply_receipt(f.receipt(id, TerminalExecutionState::Succeeded)))
        .buffer_unordered(128);
    let mut checked = 0;
    while let Some(receipt) = receipts.next().await {
        assert_eq!(receipt?, ReceiptOutcome::AppliedTerminal);
        checked += 1;
        if checked % 64 == 0 {
            let status = handle.status_snapshot().await?;
            assert!(
                status.events_head_seq - status.events_pruned_through_seq <= 64,
                "{status:?}"
            );
        }
    }
    assert_eq!(checked, 768);
    let old = handle
        .read_snapshot(move |conn| {
            Ok::<_, StorageError>(conn.query_row(
                "SELECT COUNT(*) FROM auth_tokens WHERE token_id = ?1",
                [token.to_string()],
                |row| row.get::<_, i64>(0),
            )?)
        })
        .await?;
    assert_eq!(old, 0);
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn first_maintenance_turn_is_skipped_if_shutdown_has_begun() -> TestResult {
    use std::sync::Mutex;

    struct PausedClock {
        gate: Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
        reads: AtomicUsize,
    }

    impl StorageClock for PausedClock {
        fn wall_now_ms(&self) -> i64 {
            0
        }

        fn monotonic_now(&self) -> Result<Duration, StorageError> {
            if self.reads.fetch_add(1, Ordering::SeqCst) == 1 {
                let gate = self
                    .gate
                    .lock()
                    .map_err(|_| StorageError::ActorStopped)?
                    .take();
                if let Some((ready, release)) = gate {
                    let _ = ready.send(());
                    let _ = release.blocking_recv();
                }
            }
            Ok(Duration::ZERO)
        }
    }

    let f = Fixture::create(StorageConfig::default())?;
    let agent = PrincipalId::new_agent();
    let token = TokenId::new_user_or_agent();
    f.open(OpenMode::OfflineExactVersion)?
        .run_offline_tx(|conn| {
            conn.execute(
                "INSERT INTO principals(principal_id, kind, name, managed_by_principal_id,
            disabled_at_ms, created_at_ms, updated_at_ms)
            VALUES (?1, 'agent', '~purging:agent', ?2, 0, 0, 0)",
                params![agent.to_string(), f.principal.to_string()],
            )?;
            conn.execute(
                "UPDATE hub_meta SET gc_purging_principal_id = ?1",
                [agent.to_string()],
            )?;
            seed_token(conn, token, agent, agent)
        })?;
    let (ready, blocked) = oneshot::channel();
    let (release, park) = oneshot::channel();
    let clock = Arc::new(PausedClock {
        gate: Mutex::new(Some((ready, park))),
        reads: AtomicUsize::new(0),
    });
    let (_, runtime) = open_existing(
        acquire_state_lock(&f.dir)?,
        OpenMode::ServeAutoMigrate,
        ExpectedHubIdentity {
            active_key_id: 1,
            master_key_fingerprint: "test-fingerprint".to_owned(),
        },
        &f.config,
        clock,
    )?
    .migrate_and_start_runtime()?;
    tokio::time::timeout(TIMEOUT, blocked).await??;
    let mut stopping = Box::pin(runtime.shutdown());
    assert!(poll!(&mut stopping).is_pending());
    release
        .send(())
        .map_err(|_| "writer did not reach first maintenance turn")?;
    assert!(matches!(
        tokio::time::timeout(TIMEOUT, stopping).await?,
        ShutdownReport::Complete
    ));

    let retained = f
        .open(OpenMode::OfflineExactVersion)?
        .run_offline_tx(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM auth_tokens WHERE token_id = ?1",
                [token.to_string()],
                |row| row.get::<_, i64>(0),
            )
        })?;
    assert_eq!(retained.value, 1);
    Ok(())
}

fn stop_subprocess_at(subprocess: &mut std::process::Command, point: &'static str) -> TestResult {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let mut child = subprocess
        .env(STAGE_POINT_ENV, point)
        .stdout(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("missing subprocess output")?;
    let (ready, paused) = std::sync::mpsc::channel();
    let watcher = std::thread::spawn(move || {
        if BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
            .any(|line| line == format!("PAUSED {point}"))
        {
            let _ = ready.send(());
        }
    });
    let observed = paused.recv_timeout(TIMEOUT);
    let kill = child.kill();
    let status = child.wait()?;
    watcher
        .join()
        .map_err(|_| "crash output watcher panicked")?;
    observed?;
    kill?;
    assert!(!status.success());
    Ok(())
}

#[test]
fn hot_snapshot_journal_is_recovered_only_after_identity_is_validated() -> TestResult {
    use rusqlite::{OpenFlags, ffi::SQLITE_READONLY_ROLLBACK};

    let f = Fixture::create(StorageConfig::default())?;
    let dir = f.dir.join("restored");
    let lock = acquire_state_lock(&dir)?;
    let snapshot = dir.join("hub.sqlite3");
    let source = Connection::open_with_flags(f.path(), OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    source.execute(
        "VACUUM INTO ?1",
        [snapshot.to_str().ok_or("non-UTF-8 snapshot path")?],
    )?;
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(&snapshot, fs::Permissions::from_mode(0o600))?;
    drop(source);
    drop(lock);
    let mut subprocess = std::process::Command::new(std::env::current_exe()?);
    subprocess
        .args([
            "--exact",
            "storage::tests::staging_subprocess",
            "--nocapture",
        ])
        .env(STAGE_DIR_ENV, &dir);
    stop_subprocess_at(&mut subprocess, "spill")?;

    let rollback = dir.join("hub.sqlite3-journal");
    let original = (fs::read(&snapshot)?, fs::read(&rollback)?);
    let reader = Connection::open_with_flags(&snapshot, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let needs_recovery =
        reader.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0));
    assert!(
        matches!(needs_recovery, Err(rusqlite::Error::SqliteFailure(code, _))
        if code.extended_code == SQLITE_READONLY_ROLLBACK)
    );
    drop(reader);

    let reopen = |key| -> Result<OpenedDb, StorageError> {
        open_existing(
            acquire_state_lock(&dir)?,
            OpenMode::OfflineExactVersion,
            ExpectedHubIdentity {
                active_key_id: key,
                master_key_fingerprint: "test-fingerprint".into(),
            },
            &f.config,
            f.clock.clone(),
        )
    };
    assert!(matches!(reopen(99), Err(StorageError::IdentityMismatch)));
    assert_eq!((fs::read(&snapshot)?, fs::read(&rollback)?), original);
    assert!(!dir.join(".staging-hub-init").exists());

    // A 0400 hot-journal DB must report ReadOnlyDatabase before copying to staging.
    fs::set_permissions(&snapshot, fs::Permissions::from_mode(0o400))?;
    let writable = fs::OpenOptions::new().write(true).open(&snapshot).is_ok();
    if !writable {
        assert!(matches!(reopen(1), Err(StorageError::ReadOnlyDatabase)));
        assert_eq!((fs::read(&snapshot)?, fs::read(&rollback)?), original);
        assert!(!dir.join(".staging-hub-init").exists());
    }
    fs::set_permissions(&snapshot, fs::Permissions::from_mode(0o600))?;

    let opened = reopen(1)?;
    assert_eq!(opened.hub_id(), &f.hub_id);
    let outcome = opened.run_offline_tx(|conn| {
        let row_count = conn.query_row("SELECT count(*) FROM upstreams", [], |row| {
            row.get::<_, i64>(0)
        })?;
        let journal =
            conn.pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))?;
        Ok::<_, rusqlite::Error>((row_count, journal))
    })?;
    assert_eq!(outcome.value, (0, "wal".into()));
    assert!(!rollback.exists());
    assert!(!dir.join(".staging-hub-init").exists());
    Ok(())
}

#[tokio::test]
async fn multiple_events_per_command_do_not_accumulate_across_work_batches() -> TestResult {
    use futures_util::StreamExt;

    let f = Fixture::create(StorageConfig {
        max_events_rows: 32,
        ..StorageConfig::default()
    })?;
    let (handle, runtime) = f.start()?;
    let principal = f.principal;
    let actor = ActorId::Hub(f.hub_id);
    let work = |n: usize| {
        handle.execute_work(0, move |tx| {
            for _ in 0..n {
                tx.append_event(actor, Event::PrincipalRevoked(principal))?;
            }
            Ok::<_, WriteTxError<Infallible>>(())
        })
    };
    // Non-uniform batches also exercise a single command larger than a prune.
    let mut burst =
        futures_util::stream::iter((0..320).map(|index| if index == 128 { 100 } else { 4 }))
            .map(work)
            .buffer_unordered(128);
    let mut committed = 0;
    while let Some(result) = burst.next().await {
        result?;
        committed += 1;
        if committed % 16 == 0 {
            let report = handle.status_snapshot().await?;
            assert!(
                report.events_head_seq - report.events_pruned_through_seq <= 32 + 32 * 4 + 96,
                "{report:?}"
            );
        }
    }
    assert_eq!(committed, 320);
    tokio::time::timeout(TIMEOUT, async {
        loop {
            handle.subscribe_waiter(ExecutionId::new()).await?;
            let report = handle.status_snapshot().await?;
            assert_eq!(report.events_head_seq, 319 * 4 + 100);
            if report.events_head_seq - report.events_pruned_through_seq == 32 {
                break Ok::<_, StorageError>(());
            }
        }
    })
    .await??;
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn event_projections_preserve_committed_recipients_in_live_and_catchup() -> TestResult {
    use efferian_authz::{AuthContext, PrincipalView, TokenScope, can_observe_event};
    use efferian_protocol::PrincipalKind;

    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let manager = PrincipalId::new_service();
    let other = PrincipalId::new_service();
    let revoked_token = TokenId::new_service();
    let node = f.node;
    let actor = ActorId::Hub(f.hub_id);
    let mut live = handle.subscribe_events()?;
    handle.execute_work(0, move |tx| {
        for service in [manager, other] {
            let id = service.to_string();
            tx.conn().execute("INSERT INTO principals(principal_id, kind, name, is_orchestrator, created_at_ms, updated_at_ms)
                VALUES (?1, 'service', ?1, 1, 0, 0)", [id])?;
        }
        seed_token(tx.conn(), revoked_token, manager, manager)?;
        tx.conn().execute("UPDATE nodes SET managed_by_principal_id = ?1", [manager.to_string()])?;
        tx.append_event(actor, Event::NodeConnected(node))?;
        tx.conn().execute("UPDATE nodes SET managed_by_principal_id = ?1", [other.to_string()])?;
        tx.append_event(actor, Event::NodeDisconnected(node))?;
        Ok::<_, WriteTxError<Infallible>>(())
    }).await?;
    assert!(handle.revoke_token(actor, revoked_token).await?);

    let scope = |principal_id| AuthContext {
        caller: PrincipalView {
            principal_id,
            kind: PrincipalKind::Service,
            owner_principal_id: None,
            managed_by_principal_id: None,
            inherit_owner_bindings: false,
            is_orchestrator: true,
            allowed_node_tags: Default::default(),
            observe_executions: false,
            disabled_at_ms: None,
        },
        token: TokenScope {
            token_id: TokenId::new_service(),
            principal_id,
            max_capability: None,
            allowed_profiles: None,
            allowed_nodes: Some([node].into()),
            withhold_sensitive: false,
            expires_at_ms: None,
            revoked_at_ms: None,
        },
        caller_grants: Vec::new(),
        owner: None,
        owner_grants: Vec::new(),
        managed_by: None,
        managed_by_grants: Vec::new(),
        now_ms: 0,
    };
    let contexts = [scope(manager), scope(other)];
    let page = handle.read_events(0, None, 10).await?;
    assert_eq!(page.items.len(), 3);
    for (stored, visible) in page
        .items
        .iter()
        .zip([[true, false], [false, true], [true, false]])
    {
        let published = live.recv().await?;
        assert_eq!(published.auth, stored.auth);
        assert_eq!(published.envelope, stored.envelope);
        for (ctx, allowed) in contexts.iter().zip(visible) {
            assert_eq!(can_observe_event(ctx, &stored.auth), allowed);
        }
    }
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn revocation_is_observable_at_the_instant_the_outbox_wakes_a_subscriber() -> TestResult {
    use std::future::Future;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;
    use std::task::{Context, Wake, Waker};

    struct ObserveRevocation {
        receiver: Mutex<RevocationWatch>,
        received: AtomicBool,
        token: TokenId,
    }
    impl Wake for ObserveRevocation {
        fn wake(self: Arc<Self>) {
            let received = self
                .receiver
                .lock()
                .ok()
                .and_then(|mut watch| watch.try_recv().ok());
            self.received.store(
                received.is_some_and(|signal| {
                    signal.reason == RevocationReason::TokenRevoked(self.token)
                }),
                Ordering::Release,
            );
        }
    }

    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let observe = Arc::new(ObserveRevocation {
        receiver: Mutex::new(handle.subscribe_revocations()?),
        received: AtomicBool::new(false),
        token: f.token,
    });
    let mut live = handle.subscribe_events()?;
    let mut event = Box::pin(live.recv());
    let waker = Waker::from(observe.clone());
    assert!(
        event
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    assert!(handle.revoke_token(ActorId::Hub(f.hub_id), f.token).await?);
    assert!(
        observe.received.load(Ordering::Acquire),
        "outbox woke before revocation was visible"
    );
    let event = tokio::time::timeout(TIMEOUT, event).await??;
    assert!(matches!(event.envelope.event, Event::TokenRevoked(id) if id == f.token));
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn large_receipts_make_progress_at_the_soft_watermark_while_ttl_advances() -> TestResult {
    check_receipt_pressure(4350, 12_000_000, 1, 75..85).await
}

#[tokio::test]
async fn writer_samples_a_payload_batch_crossing_the_soft_watermark() -> TestResult {
    check_receipt_pressure(4096, 9_900_000, 5000, 73..75).await
}

async fn check_receipt_pressure(
    max_page_count: u32,
    permanent_blob_bytes: u32,
    old_result_expiry: i64,
    initial_pressure: std::ops::Range<u32>,
) -> TestResult {
    let f = Fixture::create(StorageConfig {
        max_page_count,
        gc_interval: Duration::from_millis(1),
        token_gc_grace_ms: 1,
        ..StorageConfig::default()
    })?;
    let active: Vec<_> = (0..48).map(|_| ExecutionId::new()).collect();
    f.open(OpenMode::OfflineExactVersion)?.run_offline_tx(|conn| {
        conn.execute(
            "INSERT INTO accounts(account_id, slug, owner_principal_id, visibility, kind, sealed_secret_blob, created_at_ms, updated_at_ms)
             VALUES ('account', 'account', ?1, 'private', 'secret_kv', zeroblob(?2), 0, 0)",
            params![f.principal.to_string(), permanent_blob_bytes],
        )?;
        conn.execute("UPDATE auth_tokens SET revoked_at_ms = 100", [])?;
        let mut insert = conn.prepare(
            "INSERT INTO executions(execution_id, invoke_kind, request_id, request_digest, caller_principal_id,
                caller_token_id, tool_id, tool_version, public_name, executor_kind, node_id, state,
                deadline_at_ms, created_at_ms, result_expires_at_ms, expires_at_ms, sealed_result_blob, result_bytes)
             VALUES (?1, 'tool_test', ?1, 'digest', ?2, ?3, ?4, 1, 'example', 'node', ?5, ?6,
                0, 0, ?7, 100000, CASE WHEN ?8 = 0 THEN NULL ELSE zeroblob(?8) END, ?8)",
        )?;
        for (id, state, expiry, bytes) in active.iter().copied().map(|id| (id, "accepted", 10000, 0))
            .chain([(ExecutionId::new(), "succeeded", old_result_expiry, 2_250_000)])
        {
            insert.execute(params![id.to_string(), f.principal.to_string(), f.token.to_string(),
                f.tool.to_string(), f.node.to_string(), state, expiry, bytes])?;
        }
        Ok::<_, rusqlite::Error>(())
    })?;

    let opened = f.open(OpenMode::ServeAutoMigrate)?;
    let pages: u32 = opened
        .conn
        .pragma_query_value(None, "page_count", |row| row.get(0))?;
    let free: u32 = opened
        .conn
        .pragma_query_value(None, "freelist_count", |row| row.get(0))?;
    assert!(initial_pressure.contains(&((pages - free) * 100 / f.config.max_page_count)));
    let (handle, runtime) = opened.migrate_and_start_runtime()?;
    let (release, anchor) = pause_writer(&handle).await?;
    let mut queue = Vec::new();
    for id in active {
        let mut receipt = f.receipt(id, TerminalExecutionState::Succeeded);
        receipt.sealed_result_blob = Some(vec![7; 2_250_000]);
        let prepared = receipt.prepare()?;
        let mut future = Box::pin(handle.execute_work(prepared.payload_bytes(), move |tx| {
            let result = tx.apply_receipt(prepared)?;
            let token_present =
                tx.conn()
                    .query_row("SELECT EXISTS (SELECT 1 FROM auth_tokens)", [], |row| {
                        row.get::<_, bool>(0)
                    })?;
            Ok((result, token_present))
        }));
        assert!(poll!(&mut future).is_pending());
        queue.push(future);
    }
    f.clock.0.store(200, Ordering::SeqCst);
    release.send(()).map_err(|_| "writer stopped")?;
    anchor.await?;
    let mut observed_ttl_during_work = false;
    for (position, entry) in queue.into_iter().enumerate() {
        let (outcome, token_present) = tokio::time::timeout(TIMEOUT, entry).await??;
        assert_eq!(outcome, ReceiptOutcome::AppliedTerminal);
        observed_ttl_during_work |= position < 47 && !token_present;
    }
    assert!(observed_ttl_during_work);
    assert_eq!(handle.status_snapshot().await?.active_waiters_count, 0);
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn retention_pauses_do_not_reset_the_priority_burst() -> TestResult {
    let f = Fixture::create(StorageConfig {
        max_events_rows: 1,
        ..StorageConfig::default()
    })?;
    let tokens: Vec<_> = (0..40).map(|_| TokenId::new_user_or_agent()).collect();
    f.open(OpenMode::OfflineExactVersion)?
        .run_offline_tx(|conn| {
            for &token in &tokens {
                seed_token(conn, token, f.principal, f.principal)?;
            }
            Ok::<_, rusqlite::Error>(())
        })?;
    let (handle, runtime) = f.start()?;
    let actor_id = ActorId::Hub(f.hub_id);
    let principal = f.principal;
    handle
        .execute_work(0, move |tx| {
            tx.append_event(actor_id, Event::PrincipalRevoked(principal))?;
            Ok::<_, WriteTxError<Infallible>>(())
        })
        .await?;
    let (release, anchor) = pause_writer(&handle).await?;

    let mut queued = Vec::new();
    for token in tokens {
        let mut priority = Box::pin(handle.revoke_token(actor_id, token));
        assert!(poll!(&mut priority).is_pending());
        queued.push(priority);
    }
    let mut work = Box::pin(handle.execute_work(0, |tx| {
        let revoked = tx.conn().query_row(
            "SELECT COUNT(*) FROM auth_tokens WHERE revoked_at_ms IS NOT NULL",
            [],
            |row| row.get::<_, usize>(0),
        )?;
        Ok::<_, WriteTxError<Infallible>>(revoked)
    }));
    assert!(poll!(&mut work).is_pending());
    release.send(()).map_err(|_| "writer stopped")?;
    anchor.await?;

    let revoked_before_work = tokio::time::timeout(TIMEOUT, work).await??;
    assert!(
        (16..=18).contains(&revoked_before_work),
        "{revoked_before_work} revocations ran before work"
    );
    for priority in queued {
        assert!(priority.await?);
    }
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn stage_waiter_update_notifies_without_removing_waiter() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let accepted = handle.invoke(f.request(RequestId::new())).await?;
    let mut waiter = accepted.waiter.ok_or("missing waiter")?;
    assert_eq!(waiter.borrow().state, ExecutionState::Accepted);

    handle
        .execute_work(0, move |tx| {
            tx.conn().execute(
                "UPDATE executions SET state = 'running', started_at_ms = 55 WHERE execution_id = ?1",
                [accepted.execution_id.to_string()],
            )?;
            tx.stage_waiter_update(
                accepted.execution_id,
                ExecutionSnapshot {
                    state: ExecutionState::Running,
                    finished_at_ms: None,
                },
            );
            Ok::<_, WriteTxError<Infallible>>(())
        })
        .await?;
    waiter.changed().await?;
    assert_eq!(
        *waiter.borrow(),
        ExecutionSnapshot {
            state: ExecutionState::Running,
            finished_at_ms: None,
        }
    );
    assert_eq!(handle.status_snapshot().await?.active_waiters_count, 1);
    let subscribed = handle
        .subscribe_waiter(accepted.execution_id)
        .await?
        .ok_or("active waiter must stay registered after update")?;
    assert!(waiter.same_channel(&subscribed));

    assert_eq!(
        handle
            .apply_receipt(f.receipt(accepted.execution_id, TerminalExecutionState::Succeeded))
            .await?,
        ReceiptOutcome::AppliedTerminal
    );
    waiter.changed().await?;
    assert_eq!(waiter.borrow().state, ExecutionState::Succeeded);
    assert_eq!(handle.status_snapshot().await?.active_waiters_count, 0);
    assert!(
        handle
            .subscribe_waiter(accepted.execution_id)
            .await?
            .is_none()
    );
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn composable_execution_primitives_enforce_active_editions_replay_and_upstream_running()
-> TestResult {
    use efferian_protocol::{PreparedArgumentsDigest, UpstreamId};

    let f = Fixture::create(StorageConfig::default())?;
    f.set_wall_ms(1_234);
    let (handle, runtime) = f.start()?;
    let profile = ProfileId::new();
    let upstream = UpstreamId::new();
    let caller = f.principal;
    let tool = f.tool;
    let node = f.node;
    handle
        .execute_work(0, move |tx| {
            tx.conn().execute(
                "INSERT INTO profiles(profile_id, slug, discovery_mode, published_version, created_at_ms, updated_at_ms)
                 VALUES (?1, 'prof', 'full', 1, 0, 0)",
                [profile.to_string()],
            )?;
            let bindings = serde_json::json!([{
                "public_name": "run",
                "tool_id": tool,
                "tool_version": 1,
                "fixed_node_id": node,
            }])
            .to_string();
            tx.conn().execute(
                "INSERT INTO profile_editions(profile_id, version, discovery_mode, bindings_json, published_by, published_at_ms)
                 VALUES (?1, 1, 'full', ?2, ?3, 0)",
                params![profile.to_string(), bindings, caller.to_string()],
            )?;
            Ok::<_, WriteTxError<Infallible>>(())
        })
        .await?;

    // Insert a Profile execution, disable the edition, verify new invokes fail
    // with BindingUnavailable while replay of the existing request still works.
    let req1 = RequestId::new();
    let mut invoke1 = f.request(req1);
    invoke1.resource = InvokeResource::Profile {
        profile_id: profile,
        version: NonZeroU64::MIN,
    };
    invoke1.public_name = "run".to_owned();
    let first = handle.invoke(invoke1).await?;
    assert!(handle.disable_edition(profile, 1).await?);

    let mut invoke_after_disable = f.request(RequestId::new());
    invoke_after_disable.resource = InvokeResource::Profile {
        profile_id: profile,
        version: NonZeroU64::MIN,
    };
    invoke_after_disable.public_name = "run".to_owned();
    assert!(matches!(
        handle.invoke(invoke_after_disable).await,
        Err(WriteError::Domain(InvokeWriteError::BindingUnavailable))
    ));

    let args = PreparedArgumentsDigest::new(&serde_json::Map::new())?;
    let replay_check = handle
        .execute_work(0, move |tx| {
            let recorded = tx
                .lookup_invocation_replay(caller, req1)?
                .ok_or(WriteTxError::InvalidDatabase("missing recorded invocation"))?;
            assert_eq!(recorded.execution_id, first.execution_id);
            assert_eq!(recorded.profile_id, Some(profile));
            assert_eq!(recorded.profile_version, Some(1));
            assert_eq!(recorded.tool_id, tool);
            assert_eq!(recorded.node_id, Some(node));
            assert_eq!(recorded.upstream_id, None);
            tx.verify_invocation_replay(
                &recorded,
                &InvokeReplayInput {
                    resource: InvokeResource::Profile {
                        profile_id: profile,
                        version: NonZeroU64::MIN,
                    },
                    public_name: "run",
                    requested_target: None,
                    arguments: &args,
                },
            )
        })
        .await?;
    assert!(replay_check.replayed);
    assert_eq!(replay_check.execution_id, first.execution_id);

    // Upstream target starts directly in Running with started_at_ms and ExecutionStarted event.
    let mut live_events = handle.subscribe_events()?;
    let mut upstream_req = f.request(RequestId::new());
    upstream_req.executor = ExecutionTarget::Upstream(upstream);
    let upstream_out = handle.invoke(upstream_req).await?;
    assert_eq!(upstream_out.snapshot.state, ExecutionState::Running);
    let waiter = upstream_out.waiter.ok_or("missing upstream waiter")?;
    assert_eq!(waiter.borrow().state, ExecutionState::Running);
    let started_at: Option<i64> = handle
        .read_snapshot(move |conn| {
            conn.query_row(
                "SELECT started_at_ms FROM executions WHERE execution_id = ?1",
                [upstream_out.execution_id.to_string()],
                |row| row.get(0),
            )
            .map_err(StorageError::from)
        })
        .await?;
    assert_eq!(started_at, Some(1_234));
    let started_event = live_events.recv().await?;
    assert!(matches!(
        started_event.envelope.event,
        Event::ExecutionStarted(ref payload)
            if payload.execution_id == upstream_out.execution_id
                && payload.state == ExecutionState::Running
                && payload.node_id.is_none()
    ));
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn local_savepoint_errors_preserve_sibling_commands_in_work_batch() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let profile = ProfileId::new();
    let caller = f.principal;

    // Out-of-range edition version returns Ok(false) rather than truncating.
    assert!(!handle.disable_edition(profile, u64::MAX).await?);

    // Seed a profile edition with corrupt bindings JSON ('not-json').
    handle
        .execute_work(0, move |tx| {
            let principal = read_principal(tx.conn(), caller)?;
            assert!(principal.is_some());
            tx.conn().execute(
                "INSERT INTO profiles(profile_id, slug, discovery_mode, published_version, created_at_ms, updated_at_ms)
                 VALUES (?1, 'corrupt', 'full', 1, 0, 0)",
                [profile.to_string()],
            )?;
            tx.conn().execute(
                "INSERT INTO profile_editions(profile_id, version, discovery_mode, bindings_json, published_by, published_at_ms)
                 VALUES (?1, 1, 'full', 'not-json', ?2, 0)",
                params![profile.to_string(), caller.to_string()],
            )?;
            Ok::<_, WriteTxError<Infallible>>(())
        })
        .await?;

    let (release, anchor) = pause_writer(&handle).await?;
    let mut bad_epoch = f.request(RequestId::new());
    bad_epoch.executor = ExecutionTarget::Node {
        node_id: f.node,
        session_epoch: u64::MAX,
    };
    let mut bad_epoch_fut = Box::pin(handle.invoke(bad_epoch));

    let mut corrupt_edition = f.request(RequestId::new());
    corrupt_edition.resource = InvokeResource::Profile {
        profile_id: profile,
        version: NonZeroU64::MIN,
    };
    let mut corrupt_fut = Box::pin(handle.invoke(corrupt_edition));

    let mut sibling = Box::pin(handle.execute_work(0, |tx| {
        tx.conn()
            .execute("UPDATE hub_meta SET updated_at_ms = 999", [])?;
        Ok::<_, WriteTxError<Infallible>>(())
    }));

    assert!(poll!(&mut bad_epoch_fut).is_pending());
    assert!(poll!(&mut corrupt_fut).is_pending());
    assert!(poll!(&mut sibling).is_pending());
    release.send(()).map_err(|_| "writer stopped")?;
    anchor.await?;

    assert!(matches!(
        bad_epoch_fut.await,
        Err(WriteError::Domain(InvokeWriteError::IntegerOutOfRange))
    ));
    assert!(matches!(
        corrupt_fut.await,
        Err(WriteError::Storage(StorageError::Sqlite(_)))
    ));
    sibling.await?;
    let updated: i64 = handle
        .read_snapshot(|conn| {
            conn.query_row("SELECT updated_at_ms FROM hub_meta WHERE id = 1", [], |r| {
                r.get(0)
            })
            .map_err(StorageError::from)
        })
        .await?;
    assert_eq!(updated, 999);
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[test]
fn receipt_prepare_enforces_error_code_and_summary_invariants() {
    let base = || ReceiptWrite {
        execution_id: ExecutionId::new(),
        node_id: NodeId::new(),
        state: TerminalExecutionState::Failed,
        frame_epoch: 0,
        summary: ExecutionSummary {
            effect_may_have_occurred: Some(true),
            error_code: Some("ok_code".to_owned()),
            ..ExecutionSummary::default()
        },
        sealed_result_blob: None,
        result_truncated: false,
    };
    assert!(base().prepare().is_ok());

    let mut empty_blob = base();
    empty_blob.sealed_result_blob = Some(Vec::new());
    assert!(matches!(
        empty_blob.prepare(),
        Err(WriteError::Domain(InvalidReceipt))
    ));

    let mut huge_code = base();
    huge_code.summary.error_code = Some("x".repeat(65));
    assert!(matches!(
        huge_code.prepare(),
        Err(WriteError::Domain(InvalidReceipt))
    ));

    let mut spaced_code = base();
    spaced_code.summary.error_code = Some("bad code".to_owned());
    assert!(matches!(
        spaced_code.prepare(),
        Err(WriteError::Domain(InvalidReceipt))
    ));

    let mut bad_unknown = base();
    bad_unknown.state = TerminalExecutionState::Unknown;
    bad_unknown.summary.effect_may_have_occurred = Some(false);
    assert!(matches!(
        bad_unknown.prepare(),
        Err(WriteError::Domain(InvalidReceipt))
    ));

    let mut discarded_not_truncated = base();
    discarded_not_truncated.summary.output_discarded_reason =
        Some(efferian_protocol::OutputDiscardedReason::RamCap);
    discarded_not_truncated.result_truncated = false;
    assert!(matches!(
        discarded_not_truncated.prepare(),
        Err(WriteError::Domain(InvalidReceipt))
    ));
}

#[tokio::test]
async fn read_events_rejects_mismatched_auth_projection_columns() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let actor = ActorId::Hub(f.hub_id);
    let node = f.node;
    handle
        .execute_work(0, move |tx| {
            tx.append_event(actor, Event::NodeConnected(node))?;
            Ok::<_, WriteTxError<Infallible>>(())
        })
        .await?;
    assert_eq!(handle.read_events(0, None, 10).await?.items.len(), 1);
    handle
        .execute_work(0, move |tx| {
            tx.conn().execute(
                "UPDATE events SET node_id = ?1 WHERE seq = 1",
                [NodeId::new().to_string()],
            )?;
            Ok::<_, WriteTxError<Infallible>>(())
        })
        .await?;
    assert!(matches!(
        handle.read_events(0, None, 10).await,
        Err(EventsReadError::Storage(StorageError::Sqlite(
            rusqlite::Error::FromSqlConversionFailure(..)
        )))
    ));

    // Empty-payload events must also reject JSON arrays like "[]".
    handle
        .execute_work(0, move |tx| {
            tx.conn().execute(
                "UPDATE events SET node_id = ?1, payload_json = '[]' WHERE seq = 1",
                [node.to_string()],
            )?;
            Ok::<_, WriteTxError<Infallible>>(())
        })
        .await?;
    assert!(matches!(
        handle.read_events(0, None, 10).await,
        Err(EventsReadError::Storage(StorageError::Sqlite(
            rusqlite::Error::FromSqlConversionFailure(..)
        )))
    ));

    // append_event must reject invalid execution error_code before persisting.
    let exec = handle
        .invoke(f.request(RequestId::new()))
        .await?
        .execution_id;
    let tool = f.tool;
    let bad_append = handle
        .execute_work(0, move |tx| {
            tx.append_event(
                actor,
                Event::ExecutionFinished(efferian_protocol::ExecutionEventPayload {
                    execution_id: exec,
                    state: ExecutionState::Failed,
                    profile_id: None,
                    tool_id: tool,
                    public_name: "example".to_owned(),
                    node_id: Some(node),
                    exit_code: Some(1),
                    error_code: Some("bad code".to_owned()),
                    duration_ms: Some(1),
                }),
            )?;
            Ok::<_, WriteTxError<Infallible>>(())
        })
        .await;
    assert!(matches!(
        bad_append,
        Err(WriteError::Storage(StorageError::InvalidDatabase(_)))
    ));
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn unexpected_writer_exit_wakes_wait_stopped_holds_lock_and_reports_actor_stopped()
-> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let exec = handle
        .invoke(f.request(RequestId::new()))
        .await?
        .execution_id;

    let (reader_entered, entered) = tokio::sync::oneshot::channel();
    let (release_reader, released) = std::sync::mpsc::channel();
    let reader_handle = handle.clone();
    let reader = tokio::spawn(async move {
        reader_handle
            .read_snapshot(move |conn| {
                let head: i64 =
                    conn.query_row("SELECT events_head_seq FROM hub_meta", [], |row| row.get(0))?;
                let _ = reader_entered.send(());
                let _ = released.recv();
                Ok::<_, StorageError>(head)
            })
            .await
    });
    entered.await?;

    // Trigger an unexpected writer exit via a panicking post-commit hook.
    handle
        .execute_work(0, |tx| {
            tx.on_commit(|| assert_eq!(1, 0, "simulated writer hook panic"));
            Ok::<_, WriteTxError<Infallible>>(())
        })
        .await?;

    tokio::time::timeout(TIMEOUT, runtime.wait_stopped()).await?;

    // hub.lock must remain held until the runtime is explicitly shut down.
    assert!(matches!(
        acquire_state_lock(&f.dir),
        Err(StorageError::Platform(
            efferian_platform::PlatformError::LockContended { .. }
        ))
    ));

    // All handle entrypoints must report ActorStopped (NOT ShuttingDown).
    assert!(matches!(
        handle
            .execute_work(0, |_| Ok::<_, WriteTxError<Infallible>>(()))
            .await,
        Err(WriteError::Storage(StorageError::ActorStopped))
    ));
    assert!(matches!(
        handle.read_snapshot(|_| Ok::<_, StorageError>(())).await,
        Err(StorageError::ActorStopped)
    ));
    assert!(matches!(
        handle.subscribe_events(),
        Err(StorageError::ActorStopped)
    ));
    assert!(matches!(
        handle.subscribe_revocations(),
        Err(StorageError::ActorStopped)
    ));
    assert!(matches!(
        handle.subscribe_waiter(exec).await,
        Err(StorageError::ActorStopped)
    ));

    let stopping = tokio::spawn(runtime.shutdown());
    assert!(!stopping.is_finished());
    release_reader.send(())?;
    reader.await??;
    let report = tokio::time::timeout(TIMEOUT, stopping).await??;
    assert!(matches!(
        report,
        ShutdownReport::Failed(StorageError::ActorStopped)
    ));

    // After shutdown joins the writer thread, hub.lock is released cleanly.
    drop(acquire_state_lock(&f.dir)?);
    Ok(())
}

#[tokio::test]
async fn revoke_token_and_grant_ignore_principal_being_purged() -> TestResult {
    use efferian_protocol::GrantId;

    let f = Fixture::create(StorageConfig::default())?;
    let agent = PrincipalId::new_agent();
    let token = TokenId::new_user_or_agent();
    let grant = GrantId::new();
    let (handle, runtime) = f.start()?;
    let admin = f.principal;
    handle
        .execute_work(0, move |tx| {
            tx.conn().execute(
                "INSERT INTO principals(principal_id, kind, name, managed_by_principal_id, disabled_at_ms, created_at_ms, updated_at_ms)
                 VALUES (?1, 'agent', '~purging:agent', ?2, -1, 0, 0)",
                params![agent.to_string(), admin.to_string()],
            )?;
            seed_token(tx.conn(), token, agent, agent)?;
            tx.conn().execute(
                "INSERT INTO grants(grant_id, principal_id, scope_kind, scope_id, capability, created_by, created_at_ms)
                 VALUES (?1, ?2, 'profile', 'prof_1', 'invoke', ?2, 0)",
                params![grant.to_string(), agent.to_string()],
            )?;
            tx.conn().execute(
                "UPDATE hub_meta SET gc_purging_principal_id = ?1 WHERE id = 1",
                [agent.to_string()],
            )?;
            Ok::<_, WriteTxError<Infallible>>(())
        })
        .await?;

    let mut events = handle.subscribe_events()?;
    let mut revocations = handle.subscribe_revocations()?;
    let actor = ActorId::Hub(f.hub_id);
    assert!(!handle.revoke_token(actor, token).await?);
    assert!(!handle.revoke_grant(grant).await?);
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        revocations.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(handle.revoke_node(actor, f.node).await?, Some((f.node, 0)));
    assert_eq!(handle.revoke_node(actor, f.node).await?, Some((f.node, 0)));
    assert!(matches!(
        events.try_recv()?.envelope.event,
        Event::NodeRevoked(id) if id == f.node
    ));
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}
