use std::collections::BTreeSet;

use efferian_protocol::{EnrollmentId, GrantId, error_codes, validate_terminal_summary};

use super::super::{actor::PriorityKind, lifecycle::open_reader};
use super::*;

pub(super) fn seed_admin_grant(
    conn: &Connection,
    principal: PrincipalId,
) -> rusqlite::Result<GrantId> {
    let grant = GrantId::new();
    conn.execute(
        "INSERT INTO grants(grant_id, principal_id, scope_kind, scope_id, capability,
                            created_by, created_at_ms)
         VALUES (?1, ?2, 'global', '', 'admin', ?2, 0)",
        params![grant.to_string(), principal.to_string()],
    )?;
    Ok(grant)
}

enum InviteTarget<'a> {
    Name(&'a str),
    Node(NodeId),
}

fn seed_invite(
    conn: &Connection,
    issuer: PrincipalId,
    manager: Option<PrincipalId>,
    target: InviteTarget<'_>,
    consumed: Option<i64>,
) -> rusqlite::Result<EnrollmentId> {
    let enrollment = EnrollmentId::new();
    let (name, node) = match target {
        InviteTarget::Name(name) => (Some(name), None),
        InviteTarget::Node(node) => (None, Some(node.to_string())),
    };
    conn.execute(
        "INSERT INTO node_enrollments(enrollment_id, verifier_hmac, target_node_name, target_node_id,
                                     created_by, managed_by_principal_id, expires_at_ms, consumed_at_ms,
                                     created_at_ms)
         VALUES (?1, ?1, ?2, ?3, ?4, ?5, 99999, ?6, 0)",
        params![
            enrollment.to_string(),
            name,
            node,
            issuer.to_string(),
            manager.map(|manager| manager.to_string()),
            consumed
        ],
    )?;
    Ok(enrollment)
}

fn invite_revoked_at(conn: &Connection, invite: EnrollmentId) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT revoked_at_ms FROM node_enrollments WHERE enrollment_id = ?1",
        [invite.to_string()],
        |row| row.get(0),
    )
}

#[tokio::test]
async fn node_revoke_commits_invites_executions_events_and_waiters_together() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let node = f.node;
    let admin = f.principal;
    let actor = ActorId::Principal(admin);

    f.set_wall_ms(10);
    let accepted = handle.invoke(f.request(RequestId::new())).await?;
    let running = handle.invoke(f.request(RequestId::new())).await?;
    let accepted_id = accepted.execution_id;
    let running_id = running.execution_id;
    let mut accepted_waiter = accepted.waiter.ok_or("missing accepted waiter")?;
    let running_waiter = running.waiter.ok_or("missing running waiter")?;
    let (invite, consumed) = handle
        .execute_work(0, move |tx| {
            let invite = seed_invite(tx.conn(), admin, None, InviteTarget::Node(node), None)?;
            let consumed = seed_invite(tx.conn(), admin, None, InviteTarget::Node(node), Some(5))?;
            tx.conn().execute(
                "UPDATE nodes SET session_epoch = 7 WHERE node_id = ?1",
                [node.to_string()],
            )?;
            tx.conn().execute(
                "UPDATE executions SET state = 'running', started_at_ms = 111
                 WHERE execution_id = ?1",
                [running_id.to_string()],
            )?;
            tx.stage_waiter_update(
                running_id,
                ExecutionSnapshot {
                    state: ExecutionState::Running,
                    finished_at_ms: None,
                },
            );
            Ok::<_, WriteTxError<Infallible>>((invite, consumed))
        })
        .await?;

    f.set_wall_ms(100);
    let mut events = handle.subscribe_events()?;
    let (rollback_hook, mut rollback_observed) = oneshot::channel();
    let rolled_back = handle
        .execute_priority(PriorityKind::RevokeNode, move |tx| {
            assert_eq!(tx.revoke_node(actor, node)?, Some((node, 7)));
            tx.on_commit(move || {
                let _ = rollback_hook.send(());
            });
            Err::<(), _>(WriteTxError::Domain("reject after staging"))
        })
        .await;
    assert!(matches!(
        rolled_back,
        Err(WriteError::Domain("reject after staging"))
    ));
    assert!(matches!(
        rollback_observed.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Closed)
    ));
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert!(!accepted_waiter.has_changed()?);
    assert_eq!(
        handle
            .read_snapshot(move |conn| { Ok::<_, StorageError>(invite_revoked_at(conn, invite)?) })
            .await?,
        None
    );

    let path = f.path();
    let (committed_hook, committed_observed) = oneshot::channel();
    let revoked = handle
        .execute_priority(PriorityKind::RevokeNode, move |tx| {
            let revoked = tx.revoke_node(actor, node)?;
            tx.on_commit(move || {
                let observed = open_reader(&path).and_then(|conn| {
                    Ok(conn.query_row(
                        "SELECT revoked_at_ms FROM nodes WHERE node_id = ?1",
                        [node.to_string()],
                        |row| row.get::<_, Option<i64>>(0),
                    )?)
                });
                let _ = committed_hook.send(observed);
            });
            Ok::<_, WriteTxError<Infallible>>(revoked)
        })
        .await?;
    assert_eq!(revoked, Some((node, 7)));
    assert_eq!(committed_observed.await??, Some(100));

    tokio::time::timeout(TIMEOUT, accepted_waiter.changed()).await??;
    for waiter in [&accepted_waiter, &running_waiter] {
        let snapshot = *waiter.borrow();
        assert_eq!(snapshot.state, ExecutionState::Unknown);
        assert_eq!(snapshot.finished_at_ms, Some(100));
    }
    assert!(handle.subscribe_waiter(accepted_id).await?.is_none());

    assert!(matches!(
        events.try_recv()?.envelope.event,
        Event::NodeRevoked(revoked_node) if revoked_node == node
    ));
    let mut finished_ids = BTreeSet::new();
    for _ in 0..2 {
        let event = events.try_recv()?;
        assert_eq!(event.envelope.actor_id, actor);
        let Event::ExecutionFinished(payload) = &event.envelope.event else {
            return Err("expected execution.finished".into());
        };
        assert_eq!(payload.state, ExecutionState::Unknown);
        assert_eq!(
            payload.error_code.as_deref(),
            Some(error_codes::NODE_REVOKED)
        );
        assert_eq!(payload.node_id, Some(node));
        assert_eq!(
            payload.duration_ms,
            Some(if payload.execution_id == accepted_id {
                90
            } else {
                0
            })
        );
        finished_ids.insert(payload.execution_id);
    }
    assert_eq!(finished_ids, BTreeSet::from([accepted_id, running_id]));
    handle
        .read_snapshot(move |conn| {
            assert_eq!(invite_revoked_at(conn, invite)?, Some(100));
            assert_eq!(invite_revoked_at(conn, consumed)?, None);
            for (execution, duration) in [(accepted_id, 90), (running_id, 0)] {
                let (state, finished_at, late_at, summary, bytes, truncated): (
                    String,
                    i64,
                    Option<i64>,
                    String,
                    usize,
                    bool,
                ) = conn.query_row(
                    "SELECT state, finished_at_ms, late_receipt_at_ms, summary_json,
                            result_bytes, result_truncated FROM executions WHERE execution_id = ?1",
                    [execution.to_string()],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    },
                )?;
                let summary: ExecutionSummary = serde_json::from_str(&summary)
                    .map_err(|_| StorageError::InvalidDatabase("invalid test execution summary"))?;
                assert!(
                    validate_terminal_summary(
                        TerminalExecutionState::Unknown,
                        &summary,
                        bytes != 0,
                        truncated
                    )
                    .is_ok()
                );
                assert_eq!(
                    summary.error_code.as_deref(),
                    Some(error_codes::NODE_REVOKED)
                );
                assert_eq!(summary.duration_ms, Some(duration));
                assert_eq!(
                    (state.as_str(), finished_at, late_at),
                    ("unknown", 100, None)
                );
            }
            Ok::<_, StorageError>(())
        })
        .await?;

    // A ticket issued after the first revoke must still be cleared by a second
    // revoke in the same millisecond, with only one node-revoked event.
    let post_revoke = handle
        .execute_work(0, move |tx| {
            Ok::<_, WriteTxError<Infallible>>(seed_invite(
                tx.conn(),
                admin,
                None,
                InviteTarget::Node(node),
                None,
            )?)
        })
        .await?;
    assert_eq!(handle.revoke_node(actor, node).await?, Some((node, 7)));
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert_eq!(
        handle
            .read_snapshot(move |conn| {
                Ok::<_, StorageError>(invite_revoked_at(conn, post_revoke)?)
            })
            .await?,
        Some(100)
    );
    assert_eq!(
        handle
            .apply_receipt(f.receipt(accepted_id, TerminalExecutionState::Failed))
            .await?,
        ReceiptOutcome::LateReceiptRecorded
    );
    assert_eq!(
        handle
            .apply_receipt(f.receipt(accepted_id, TerminalExecutionState::Failed))
            .await?,
        ReceiptOutcome::AlreadyTerminalOwned
    );
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn disabling_demoted_manager_revokes_all_enrollment_relations_and_keeps_child_flags()
-> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let node = f.node;
    let admin = f.principal;
    let manager = PrincipalId::new_service();
    let active_child = PrincipalId::new_agent();
    let individually_disabled_child = PrincipalId::new_agent();
    let (issued, managed, reenroll, unrelated) = handle
        .execute_work(0, move |tx| {
            seed_admin_grant(tx.conn(), admin)?;
            tx.conn().execute(
                "INSERT INTO principals(principal_id, kind, name, created_at_ms, updated_at_ms)
                 VALUES (?1, 'service', 'former-orchestrator', 0, 0)",
                [manager.to_string()],
            )?;
            for (child, disabled_at) in [(active_child, None), (individually_disabled_child, Some(29))] {
                tx.conn().execute(
                    "INSERT INTO principals(principal_id, kind, name, managed_by_principal_id,
                                           disabled_at_ms, created_at_ms, updated_at_ms)
                     VALUES (?1, 'agent', ?1, ?2, ?3, 0, 0)",
                    params![child.to_string(), manager.to_string(), disabled_at],
                )?;
            }
            tx.conn().execute(
                "UPDATE nodes SET managed_by_principal_id = ?1, session_epoch = 5 WHERE node_id = ?2",
                params![manager.to_string(), node.to_string()],
            )?;
            let issued = seed_invite(tx.conn(), manager, None, InviteTarget::Name("issued"), None)?;
            let managed = seed_invite(tx.conn(), admin, Some(manager), InviteTarget::Name("managed"), None)?;
            let reenroll = seed_invite(tx.conn(), admin, None, InviteTarget::Node(node), None)?;
            let unrelated = seed_invite(tx.conn(), admin, None, InviteTarget::Name("unrelated"), None)?;
            Ok::<_, WriteTxError<Infallible>>((issued, managed, reenroll, unrelated))
        })
        .await?;
    let invocation = handle.invoke(f.request(RequestId::new())).await?;
    let waiter = invocation.waiter.ok_or("missing waiter")?;
    let mut events = handle.subscribe_events()?;
    let mut watch = handle.subscribe_revocations()?;
    f.set_wall_ms(73);
    let close = handle
        .disable_principal(ActorId::Principal(admin), manager)
        .await?;
    assert_eq!(close, Some(vec![(node, 5)]));
    assert_eq!(waiter.borrow().state, ExecutionState::Unknown);
    let signal = watch.try_recv()?;
    assert_eq!(signal.reason, RevocationReason::PrincipalDisabled(manager));
    assert_eq!(signal.affected_nodes, [node]);
    assert_eq!(
        signal
            .affected_principals
            .iter()
            .copied()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([manager, active_child, individually_disabled_child])
    );
    assert!(matches!(
        events.try_recv()?.envelope.event,
        Event::PrincipalRevoked(id) if id == manager
    ));
    assert!(matches!(
        events.try_recv()?.envelope.event,
        Event::NodeRevoked(id) if id == node
    ));
    assert!(matches!(
        &events.try_recv()?.envelope.event,
        Event::ExecutionFinished(payload) if payload.execution_id == invocation.execution_id
    ));
    handle
        .read_snapshot(move |conn| {
            for invite in [issued, managed, reenroll] {
                assert_eq!(invite_revoked_at(conn, invite)?, Some(73));
            }
            assert_eq!(invite_revoked_at(conn, unrelated)?, None);
            for (subject, expected) in [
                (manager, Some(73)),
                (active_child, None),
                (individually_disabled_child, Some(29)),
            ] {
                let disabled_at = conn.query_row(
                    "SELECT disabled_at_ms FROM principals WHERE principal_id = ?1",
                    [subject.to_string()],
                    |row| row.get::<_, Option<i64>>(0),
                )?;
                assert_eq!(disabled_at, expected);
            }
            Ok::<_, StorageError>(())
        })
        .await?;
    assert!(
        handle
            .disable_principal(ActorId::Principal(admin), manager)
            .await?
            .is_none()
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}

#[tokio::test]
async fn concurrent_disable_and_grant_revoke_preserve_one_global_admin() -> TestResult {
    let f = Fixture::create(StorageConfig::default())?;
    let (handle, runtime) = f.start()?;
    let first = f.principal;
    let second = PrincipalId::new_user();
    let second_grant = handle
        .execute_work(0, move |tx| {
            seed_admin_grant(tx.conn(), first)?;
            tx.conn().execute(
                "INSERT INTO principals(principal_id, kind, name, created_at_ms, updated_at_ms)
             VALUES (?1, 'admin', 'backup', 0, 0)",
                [second.to_string()],
            )?;
            Ok::<_, WriteTxError<Infallible>>(seed_admin_grant(tx.conn(), second)?)
        })
        .await?;
    let mut revocations = handle.subscribe_revocations()?;
    let (disabled, revoked) = tokio::join!(
        handle.disable_principal(ActorId::Principal(first), first),
        handle.revoke_grant(second_grant),
    );
    let signal = revocations.try_recv()?;
    assert!(matches!(
        revocations.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    match (disabled, revoked) {
        (Ok(Some(_)), Err(WriteError::Storage(StorageError::LastAdmin))) => {
            assert_eq!(signal.reason, RevocationReason::PrincipalDisabled(first));
            assert!(
                handle
                    .read_snapshot(move |conn| {
                        Ok::<_, StorageError>(conn.query_row(
                            "SELECT EXISTS(SELECT 1 FROM grants WHERE grant_id = ?1)",
                            [second_grant.to_string()],
                            |row| row.get::<_, bool>(0),
                        )?)
                    })
                    .await?
            );
        }
        (Err(WriteError::Storage(StorageError::LastAdmin)), Ok(true)) => {
            assert_eq!(signal.reason, RevocationReason::GrantRevoked(second_grant));
            assert_eq!(
                handle
                    .read_snapshot(move |conn| {
                        Ok::<_, StorageError>(principal_liveness(conn, first)?)
                    })
                    .await?,
                PrincipalLiveness::Enabled
            );
        }
        other => return Err(format!("unexpected concurrent mutation outcome {other:?}").into()),
    }
    let live = handle
        .read_snapshot(|conn| {
            Ok::<_, StorageError>(conn.query_row(
                "SELECT COUNT(*) FROM principals p JOIN grants g USING(principal_id)
             WHERE p.kind = 'admin' AND p.disabled_at_ms IS NULL
               AND g.scope_kind = 'global' AND g.scope_id = '' AND g.capability = 'admin'",
                [],
                |row| row.get::<_, usize>(0),
            )?)
        })
        .await?;
    assert_eq!(live, 1);
    assert!(matches!(runtime.shutdown().await, ShutdownReport::Complete));
    Ok(())
}
