use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;

use efferian_protocol::{ExecutionState, RequestId};
use futures_util::poll;
use http::{Method, StatusCode};
use serde_json::json;
use tokio::sync::oneshot;

use super::super::{Admission, InvokeInput, Resource, admit, preflight};
use super::{NodeSendError, TestResult, admin_caller, managed_fixture, publish};
use crate::storage::{PriorityKind, StorageError, WriteError, WriteTxError};
use crate::test_support::send_json;

const TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn duplicate_admissions_in_one_work_batch_see_staged_execution_and_waiter() -> TestResult {
    let request_id = RequestId::new();
    let (hub, bridge, _, tool) = managed_fixture(request_id.timestamp_ms()).await?;
    publish(&hub, tool, "echo", 1, "async", None).await?;
    let caller = admin_caller(&hub).await?.0;
    let query = Arc::new(InvokeInput::new(
        Resource::Profile {
            slug: "demo".to_owned(),
            edition: None,
        },
        "echo".to_owned(),
        serde_json::from_value(json!({"text": "batched"}))?,
        None,
        Some(request_id),
        Some(0),
    )?);
    let first_preparation = preflight(&hub.state, &caller, Arc::clone(&query)).await?;
    let second_preparation = preflight(&hub.state, &caller, Arc::clone(&query)).await?;
    assert!(first_preparation.is_some() && second_preparation.is_some());

    let storage = &hub.state.storage;
    let (entered, paused) = oneshot::channel();
    let (release, blocked) = oneshot::channel();
    let mut anchor = Box::pin(storage.execute_work(0, move |_| {
        let _ = entered.send(());
        let _ = blocked.blocking_recv();
        Ok::<_, WriteTxError<Infallible>>(())
    }));
    assert!(poll!(&mut anchor).is_pending());
    tokio::time::timeout(TIMEOUT, paused).await??;

    let committed = Arc::new(AtomicBool::new(false));
    let mut first = Box::pin(storage.execute_work(0, {
        let state = hub.state.clone();
        let caller = caller.clone();
        let query = Arc::clone(&query);
        let committed = Arc::clone(&committed);
        let runtime = tokio::runtime::Handle::current();
        move |tx| {
            let admitted = admit(tx, state, &caller, &query, first_preparation, runtime)?;
            tx.on_commit(move || committed.store(true, Ordering::SeqCst));
            Ok(admitted)
        }
    }));
    let mut second = Box::pin(storage.execute_work(0, {
        let state = hub.state.clone();
        let runtime = tokio::runtime::Handle::current();
        let committed = Arc::clone(&committed);
        move |tx| {
            assert!(
                !committed.load(Ordering::SeqCst),
                "first admission committed in another batch"
            );
            admit(tx, state, &caller, &query, second_preparation, runtime)
        }
    }));
    assert!(poll!(&mut first).is_pending());
    assert!(poll!(&mut second).is_pending());
    release
        .send(())
        .map_err(|_| "writer exited during the gate")?;
    let (anchor_result, first, second) =
        tokio::time::timeout(TIMEOUT, async { tokio::join!(anchor, first, second) }).await?;
    anchor_result?;
    let (Admission::Execution(first, 0), Admission::Execution(second, 0)) = (first?, second?)
    else {
        return Err("the writer did not admit both requests".into());
    };
    assert!(!first.replayed);
    assert!(second.replayed);
    assert_eq!(first.execution_id, second.execution_id);
    let first_waiter = first.waiter.unwrap();
    let second_waiter = second.waiter.unwrap();
    assert!(first_waiter.same_channel(&second_waiter));
    assert_eq!(first_waiter.borrow().state, ExecutionState::Accepted);
    assert_eq!(second_waiter.borrow().state, ExecutionState::Accepted);
    assert!(committed.load(Ordering::SeqCst));
    assert_eq!(bridge.sent.lock().unwrap().len(), 1);

    hub.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn dispatch_rejection_commits_before_the_queued_work_when_both_ingresses_are_full()
-> TestResult {
    for (failure, error_code) in [
        (NodeSendError::Full, "node_ws_backpressure"),
        (NodeSendError::Closed, "node_disconnected_before_dispatch"),
    ] {
        let (hub, bridge, _, tool) = managed_fixture(RequestId::new().timestamp_ms()).await?;
        publish(&hub, tool, "echo", 1, "async", None).await?;
        *bridge.fail.lock().unwrap() = Some(failure);
        let (entered, dispatching) = oneshot::channel();
        let (release, blocked) = oneshot::channel();
        *bridge.dispatch_gate.lock().unwrap() = Some((entered, blocked));
        let router = hub.router.clone();
        let token = hub.admin_token.clone();
        let invoke = tokio::spawn(async move {
            send_json(
                &router,
                Method::POST,
                "/v1/profiles/demo/invoke",
                &token,
                Some(
                    json!({"public_name": "echo", "arguments": {"text": "rejected"}, "wait_ms": 0}),
                ),
            )
            .await
        });

        // The writer is inside the post-commit send. Its external queues
        // cannot drain until this test lets the send return its error.
        let execution_id = tokio::time::timeout(TIMEOUT, dispatching).await??;
        let storage = &hub.state.storage;
        let mut first_priority = Box::pin(storage.execute_priority(
            PriorityKind::CancelExecution,
            move |tx| {
                let state: String = tx.conn().query_row(
                    "SELECT state FROM executions WHERE execution_id = ?1",
                    [execution_id.to_string()],
                    |row| row.get(0),
                )?;
                Ok::<_, WriteTxError<Infallible>>(state)
            },
        ));
        assert!(poll!(&mut first_priority).is_pending());

        let mut queued_work = Vec::new();
        for _ in 0..256 {
            let mut queued =
                Box::pin(storage.execute_work(0, |_| Ok::<_, WriteTxError<Infallible>>(())));
            assert!(poll!(&mut queued).is_pending());
            queued_work.push(queued);
        }
        let mut queued_priority = Vec::new();
        for _ in 1..128 {
            let mut queued = Box::pin(
                storage.execute_priority(PriorityKind::CancelExecution, |_| {
                    Ok::<_, WriteTxError<Infallible>>(())
                }),
            );
            assert!(poll!(&mut queued).is_pending());
            queued_priority.push(queued);
        }
        let mut work_overflow =
            Box::pin(storage.execute_work(0, |_| Ok::<_, WriteTxError<Infallible>>(())));
        let mut priority_overflow = Box::pin(
            storage.execute_priority(PriorityKind::CancelExecution, |_| {
                Ok::<_, WriteTxError<Infallible>>(())
            }),
        );
        assert!(matches!(
            poll!(&mut work_overflow),
            Poll::Ready(Err(WriteError::Storage(StorageError::Overloaded)))
        ));
        assert!(matches!(
            poll!(&mut priority_overflow),
            Poll::Ready(Err(WriteError::Storage(StorageError::Overloaded)))
        ));

        release
            .send(())
            .map_err(|_| "writer exited during the dispatch gate")?;
        let (status, execution) = tokio::time::timeout(TIMEOUT, invoke).await???;
        assert_eq!(status, StatusCode::OK, "{execution}");
        assert_eq!(execution["execution_id"], json!(execution_id));
        assert_eq!(execution["state"], "failed");
        assert_eq!(execution["summary"]["error_code"], error_code);
        assert_eq!(execution["summary"]["effect_may_have_occurred"], false);
        assert_eq!(
            tokio::time::timeout(TIMEOUT, first_priority).await??,
            "failed"
        );
        for command in queued_priority {
            command.await?;
        }
        for command in queued_work {
            command.await?;
        }
        drop(work_overflow);
        drop(priority_overflow);
        hub.shutdown().await;
    }
    Ok(())
}
