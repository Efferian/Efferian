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
use super::*;

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
        let lock = acquire_state_lock(&fixture.dir)?;
        create_staged(
            &lock,
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
            finished_at_ms: 77,
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
    assert_eq!(payload.duration_ms, Some(5));
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
    handle.execute_work(0, move |tx| {
        tx.conn().execute("INSERT INTO principals(principal_id, kind, name, created_at_ms, updated_at_ms)
            VALUES (?1, 'member', 'other', 0, 0)", [other.to_string()])?;
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
    assert!(
        handle
            .disable_principal(ActorId::Hub(f.hub_id), admin)
            .await?
    );
    assert!(
        !handle
            .disable_principal(ActorId::Hub(f.hub_id), admin)
            .await?
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
    let lock = acquire_state_lock(&dir)?;
    let hub_id = HubId::parse(&std::env::var(STAGE_ID_ENV)?)?;
    create_staged(
        &lock,
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
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

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
        assert_eq!(f.path().exists(), point == "post-link");
        if !f.path().exists() {
            let lock = acquire_state_lock(&f.dir)?;
            create_staged(
                &lock,
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
    for _ in 0..8 {
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
    for _ in 0..8 {
        tokio::time::timeout(TIMEOUT, entered_rx.recv())
            .await?
            .ok_or("reader disconnected")?;
    }
    let (cancelled_release, cancelled) = slots.pop().ok_or("missing reader to cancel")?;
    cancelled.abort();
    assert!(cancelled.await.is_err());

    let mut next = Box::pin(handle.read_snapshot(|conn| {
        conn.query_row("SELECT id FROM hub_meta", [], |row| row.get::<_, i64>(0))
            .map_err(StorageError::from)
    }));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut next)
            .await
            .is_err()
    );
    cancelled_release
        .send(())
        .map_err(|_| "worker dropped its checkout")?;
    assert_eq!(tokio::time::timeout(TIMEOUT, next).await??, 1);

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
