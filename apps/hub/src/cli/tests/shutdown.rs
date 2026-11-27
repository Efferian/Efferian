use std::convert::Infallible;
use std::fs;
use std::io::{self, BufRead};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use efferian_protocol::{DiscoveredUpstreamTool, ExecuteReqPayload, ExecutionId, NodeId};
use reqwest::{Client, RequestBuilder, StatusCode};
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::mpsc as async_mpsc;
use tokio::time::{Instant, sleep, timeout};

use crate::config::Config;
use crate::egress::EgressClient;
use crate::http::AppState;
use crate::node_bridge::{
    BridgeCloseReason, NodeDispatcher, NodeLiveStatus, NodeSendError, ReadyNode,
};
use crate::operations;
use crate::storage::{
    OpenMode, ShutdownReport, StorageClock, StorageError, SystemStorageClock, WriteTxError,
    acquire_state_lock,
};
use crate::test_support::{TestDir, TestResult};
use crate::upstream_dispatch::{
    DiscoverUpstream, DispatchFuture, InvokeUpstream, UpstreamCancellation, UpstreamDispatchError,
    UpstreamDispatcher,
};

use super::super::serve_running;

const WAIT: Duration = Duration::from_secs(10);
const TICK: Duration = Duration::from_millis(10);
const CHILD_DIRECTORY: &str = "EFFERIAN_HUB_TEST_SHUTDOWN_DIRECTORY";
const CHILD_FAULT: &str = "EFFERIAN_HUB_TEST_SHUTDOWN_FAULT";

struct NodeFixture;

impl NodeDispatcher for NodeFixture {
    fn live_status(&self, _: NodeId) -> NodeLiveStatus {
        NodeLiveStatus::Ready
    }

    fn online_nodes_count(&self) -> usize {
        1
    }

    fn close_session(&self, _: NodeId, _: u64, _: BridgeCloseReason) {}

    fn ready_node(&self, _: NodeId) -> Option<ReadyNode> {
        Some(ReadyNode {
            epoch: 0,
            max_concurrent_executions: 64,
        })
    }

    fn try_send_execute(
        &self,
        _: NodeId,
        epoch: u64,
        request: ExecuteReqPayload,
    ) -> Result<(), NodeSendError> {
        assert_eq!(epoch, 0);
        eprintln!("fixture node started {}", request.execution_id);
        Ok(())
    }

    fn shutdown_graceful(&self, flush_receipts: bool) -> DispatchFuture<'_, ()> {
        Box::pin(async move {
            eprintln!("fixture node shutdown flush={flush_receipts}");
        })
    }
}

struct UpstreamFixture;

impl UpstreamDispatcher for UpstreamFixture {
    fn discover(
        &self,
        request: DiscoverUpstream,
    ) -> DispatchFuture<'_, Result<Vec<DiscoveredUpstreamTool>, UpstreamDispatchError>> {
        Box::pin(async move {
            Ok(vec![DiscoveredUpstreamTool {
                upstream_id: request.upstream_id,
                tool_name: "echo".to_owned(),
                description: Some("Fixture upstream".to_owned()),
                input_schema: json!({"type":"object"}),
                annotations: None,
            }])
        })
    }

    fn invoke(
        &self,
        request: InvokeUpstream,
        mut cancellation: UpstreamCancellation,
    ) -> DispatchFuture<'_, Result<Bytes, UpstreamDispatchError>> {
        Box::pin(async move {
            if cancellation
                .start_io(|| eprintln!("fixture upstream started {}", request.execution_id))
                .await
                .is_none()
            {
                return Err(UpstreamDispatchError::Disconnected);
            }
            cancellation.cancelled().await;
            eprintln!("fixture upstream cancelled {}", request.execution_id);
            Err(UpstreamDispatchError::Disconnected)
        })
    }

    fn shutdown(&self) -> DispatchFuture<'_, ()> {
        Box::pin(async { eprintln!("fixture upstream shutdown") })
    }
}

fn wait_in_storage_thread(path: &Path) -> io::Result<()> {
    let deadline = std::time::Instant::now() + WAIT;
    while !path.try_exists()? {
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "release signal timed out",
            ));
        }
        std::thread::sleep(TICK);
    }
    Ok(())
}

async fn wait_for_file(path: &Path) -> io::Result<()> {
    while !path.try_exists()? {
        sleep(TICK).await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_subprocess() -> TestResult {
    let Some(directory) = std::env::var_os(CHILD_DIRECTORY) else {
        return Ok(());
    };
    let directory = PathBuf::from(directory);
    let fatal = std::env::var_os(CHILD_FAULT).is_some();
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "fixture TLS provider was already installed")?;
    let interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let config: Config = toml::from_str("listen = \"127.0.0.1:0\"")?;
    let clock: Arc<dyn StorageClock> = Arc::new(SystemStorageClock::new()?);
    let (opened, vault) = operations::open_existing(
        &directory.join("state"),
        OpenMode::ServeAutoMigrate,
        &config.storage_config(),
        Arc::clone(&clock),
    )?;
    let (storage, runtime) = opened.migrate_and_start_runtime()?;
    let egress = EgressClient::new(config.egress_policy()?)?;
    let mut app = AppState::new(
        storage,
        vault,
        clock,
        Arc::new(config),
        Arc::new(NodeFixture),
        egress,
    );
    app.upstream = Arc::new(UpstreamFixture);

    // A real captured reader keeps the storage join pending in both branches
    // until the client has observed the supervisor's transport shutdown.
    let storage = app.storage.clone();
    let release = directory.join("release-reader");
    let reader = tokio::spawn(async move {
        storage
            .read_snapshot(move |conn| {
                conn.query_row("SELECT events_head_seq FROM hub_meta", [], |_| Ok(()))?;
                eprintln!("fixture reader held");
                wait_in_storage_thread(&release)?;
                Ok::<_, StorageError>(())
            })
            .await
    });

    let execution = Arc::clone(&app.execution);
    let waiters_ready = tokio::spawn(async move {
        while execution.active_waiter_permits() < 2 {
            sleep(TICK).await;
        }
        eprintln!("fixture two waiters active");
    });

    let storage = app.storage.clone();
    let trigger = directory.join("trigger-writer");
    let release = directory.join("release-writer");
    let writer = tokio::spawn(async move {
        timeout(WAIT, wait_for_file(&trigger)).await??;
        storage
            .execute_work(0, move |tx| {
                if fatal {
                    tx.on_commit(|| assert_eq!(0, 1, "fixture writer failure"));
                } else {
                    // Keep the orderly shutdown barrier queued until both
                    // waiters have returned the still-active durable states.
                    eprintln!("fixture writer held");
                    assert!(
                        wait_in_storage_thread(&release).is_ok(),
                        "writer release timed out"
                    );
                }
                Ok::<_, WriteTxError<Infallible>>(())
            })
            .await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });

    let running = serve_running(app, &runtime, interrupt, terminate).await;
    let report = runtime.shutdown().await;
    reader.await??;
    waiters_ready.await?;
    writer.await??;
    if fatal {
        assert_eq!(
            running.err().map(|error| error.to_string()).as_deref(),
            Some("Hub database writer stopped unexpectedly")
        );
        assert!(matches!(report, ShutdownReport::Failed(_)), "{report:?}");
    } else {
        running.map_err(|error| io::Error::other(error.to_string()))?;
        assert!(matches!(report, ShutdownReport::Complete), "{report:?}");
    }
    Ok(())
}

struct Process {
    child: Child,
    received: async_mpsc::UnboundedReceiver<String>,
    diagnostics: Vec<String>,
}

impl Process {
    fn start(directory: &Path, fatal: bool) -> TestResult<Self> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "cli::tests::shutdown::serve_subprocess",
                "--nocapture",
            ])
            .env(CHILD_DIRECTORY, directory)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if fatal {
            command.env(CHILD_FAULT, "1");
        } else {
            command.env_remove(CHILD_FAULT);
        }
        let mut child = command.spawn()?;
        let stderr = child.stderr.take().ok_or("fixture stderr was not piped")?;
        let (send, received) = async_mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for line in io::BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            received,
            diagnostics: Vec::new(),
        })
    }

    async fn observe(&mut self, prefix: &str) -> TestResult<String> {
        let received = timeout(WAIT, async {
            if let Some(found) = self
                .diagnostics
                .iter()
                .find_map(|line| line.strip_prefix(prefix))
            {
                return Some(found.to_owned());
            }
            while let Some(line) = self.received.recv().await {
                let found = line.strip_prefix(prefix).map(str::to_owned);
                self.diagnostics.push(line);
                if found.is_some() {
                    return found;
                }
            }
            None
        })
        .await;
        let Ok(Some(found)) = received else {
            return Err(format!("missing {prefix:?}: {:?}", self.diagnostics).into());
        };
        Ok(found)
    }

    fn signal(&self, name: &str) -> TestResult {
        // POSIX kill names keep the test portable across Unix signal numbers.
        let status = Command::new("sh")
            .args([
                "-c",
                "kill -s \"$1\" \"$2\"",
                "sh",
                name,
                &self.child.id().to_string(),
            ])
            .status()?;
        assert!(status.success(), "could not signal fixture child");
        Ok(())
    }

    async fn finish(&mut self) -> TestResult {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(status) = self.child.try_wait()? {
                while let Some(line) = timeout(WAIT, self.received.recv()).await? {
                    self.diagnostics.push(line);
                }
                assert!(status.success(), "{status}: {:?}", self.diagnostics);
                return Ok(());
            }
            assert!(
                Instant::now() < deadline,
                "fixture did not stop: {:?}",
                self.diagnostics
            );
            sleep(TICK).await;
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn json_response(request: RequestBuilder, expected: StatusCode) -> TestResult<Value> {
    let response = request.send().await?;
    assert_eq!(response.status(), expected);
    Ok(response.json().await?)
}

async fn launch_jobs(
    client: &Client,
    addr: SocketAddr,
    token: &str,
) -> TestResult<[ExecutionId; 2]> {
    let base = format!("http://{addr}/v1");
    let ticket = json_response(
        client
            .post(format!("{base}/enrollment/tokens"))
            .bearer_auth(token)
            .json(&json!({"target_node_name":"shutdown-worker"})),
        StatusCode::CREATED,
    )
    .await?;
    let enrollment_token = ticket["enrollment_token"]
        .as_str()
        .ok_or("missing enrollment ticket")?;
    let node = json_response(
        client
            .post(format!("{base}/enrollment/exchange"))
            .bearer_auth(enrollment_token)
            .json(&json!({})),
        StatusCode::OK,
    )
    .await?;
    json_response(
        client
            .put(format!("{base}/tools/managed"))
            .bearer_auth(token)
            .json(&json!({
                "description":"Fixture managed command",
                "input_schema":{"type":"object"},
                "spec":{
                    "kind":"command",
                    "program":"/bin/echo", "cwd":"/", "args":[], "env":{},
                    "target_selector":{"kind":"fixed","node_ids":[node["node_id"]]},
                    "runtime_ms":60000, "max_output_bytes":4
                }
            })),
        StatusCode::CREATED,
    )
    .await?;
    let upstream = json_response(
        client
            .put(format!("{base}/upstreams/fixture"))
            .bearer_auth(token)
            .json(&json!({"url":"https://example.com/mcp"})),
        StatusCode::CREATED,
    )
    .await?;
    json_response(
        client
            .post(format!("{base}/upstreams/fixture/discover"))
            .bearer_auth(token)
            .json(&json!({})),
        StatusCode::OK,
    )
    .await?;
    json_response(
        client
            .put(format!("{base}/tools/remote"))
            .bearer_auth(token)
            .json(&json!({
                "spec":{
                    "kind":"upstream_ref", "account_mode":"none",
                    "upstream_id":upstream["upstream"]["upstream_id"], "upstream_tool_name":"echo",
                    "runtime_ms":60000
                }
            })),
        StatusCode::CREATED,
    )
    .await?;

    let launch = |slug: &str| {
        json_response(
            client
                .post(format!("{base}/tools/{slug}/test"))
                .bearer_auth(token)
                .json(&json!({"wait_ms":0})),
            StatusCode::ACCEPTED,
        )
    };
    let managed = launch("managed").await?;
    let remote = launch("remote").await?;
    assert_eq!(managed["state"], "accepted");
    assert_eq!(remote["state"], "running");
    Ok([
        serde_json::from_value(managed["execution_id"].clone())?,
        serde_json::from_value(remote["execution_id"].clone())?,
    ])
}

const BODY: &str = r#"{"wait_ms":0}"#;

async fn hold_admitted_body(addr: SocketAddr, token: &str) -> TestResult<BufReader<TcpStream>> {
    let mut socket = BufReader::new(TcpStream::connect(addr).await?);
    let headers = format!(
        "POST /v1/tools/managed/test HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\n\
         Expect: 100-continue\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        BODY.len()
    );
    socket.get_mut().write_all(headers.as_bytes()).await?;
    let mut acknowledged = String::new();
    timeout(WAIT, socket.read_line(&mut acknowledged)).await??;
    assert_eq!(acknowledged, "HTTP/1.1 100 Continue\r\n");
    acknowledged.clear();
    timeout(WAIT, socket.read_line(&mut acknowledged)).await??;
    assert_eq!(acknowledged, "\r\n");
    Ok(socket)
}

async fn prove_work_rejected(mut pending: BufReader<TcpStream>) -> TestResult {
    pending.get_mut().write_all(BODY.as_bytes()).await?;
    let mut response = String::new();
    timeout(WAIT, pending.read_to_string(&mut response)).await??;
    assert!(response.starts_with("HTTP/1.1 503 "), "{response}");
    assert!(response.contains(r#""code":"overloaded""#), "{response}");
    Ok(())
}

fn check_durable_shutdown(directory: &Path, ids: [ExecutionId; 2], fatal: bool) -> TestResult {
    let _lock = acquire_state_lock(directory)?;
    if !fatal {
        match fs::metadata(directory.join("hub.sqlite3-wal")) {
            Ok(metadata) => assert_eq!(metadata.len(), 0),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let conn = Connection::open_with_flags(
        directory.join("hub.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let record = |id: ExecutionId| {
        conn.query_row(
            "SELECT state, json_extract(summary_json, '$.error_code'),
             json_extract(summary_json, '$.effect_may_have_occurred') FROM executions
             WHERE execution_id = ?1",
            [id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<bool>>(2)?,
                ))
            },
        )
    };
    assert_eq!(record(ids[0])?, ("accepted".to_owned(), None, None));
    if fatal {
        assert_eq!(record(ids[1])?.0, "running");
    } else {
        assert_eq!(
            record(ids[1])?,
            (
                "unknown".to_owned(),
                Some("hub_shutting_down".to_owned()),
                Some(true)
            )
        );
    }
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM executions", [], |row| row
            .get::<_, usize>(0))?,
        2
    );
    let terminal = conn.query_row(
        "SELECT COUNT(*) FROM events WHERE kind = 'execution.finished' AND aggregate_id = ?1",
        [ids[1].to_string()],
        |row| row.get::<_, usize>(0),
    )?;
    assert_eq!(terminal, usize::from(!fatal));
    Ok(())
}

async fn exercise_supervisor(signal: Option<&str>) -> TestResult {
    let fatal = signal.is_none();
    let fixture = TestDir::new("supervisor")?;
    let directory = fixture.join("state");
    let token_path = fixture.join("admin-token");
    operations::init(
        &directory,
        "admin",
        &token_path,
        &Config::default().storage_config(),
    )?;
    let token = fs::read_to_string(token_path)?;
    let token = token.trim_end();
    let mut server = Process::start(&fixture.0, fatal)?;
    let addr: SocketAddr = server.observe("Hub listening on ").await?.parse()?;
    server.observe("fixture reader held").await?;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = Client::builder().no_proxy().timeout(WAIT).build()?;
    let ids = launch_jobs(&client, addr, token).await?;
    assert_eq!(
        server.observe("fixture node started ").await?,
        ids[0].to_string()
    );
    assert_eq!(
        server.observe("fixture upstream started ").await?,
        ids[1].to_string()
    );
    let status = json_response(
        client
            .get(format!("http://{addr}/v1/admin/status"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(status["active_waiters_count"], 2);
    assert_eq!(status["active_upstream_executions"], 1);
    let last_seq = status["events_head_seq"]
        .as_u64()
        .ok_or("missing head sequence")?;
    let stream = client
        .get(format!("http://{addr}/v1/events/stream?after={last_seq}"))
        .bearer_auth(token)
        .send()
        .await?;
    assert_eq!(stream.status(), StatusCode::OK);

    let poll = |id, active_state: &'static str| {
        let request = client
            .get(format!("http://{addr}/v1/executions/{id}?wait_ms=25000"))
            .bearer_auth(token);
        tokio::spawn(async move {
            let response = request.send().await?;
            let status = response.status();
            let view: Value = response.json().await?;
            if fatal && status == StatusCode::SERVICE_UNAVAILABLE {
                assert_eq!(view["code"], "overloaded");
            } else {
                assert_eq!(status, StatusCode::OK);
                assert_eq!(view["state"], active_state);
                assert_eq!(view["result_access"], "not_requested");
            }
            Ok::<_, reqwest::Error>(())
        })
    };
    let node_waiter = poll(ids[0], "accepted");
    let upstream_waiter = poll(ids[1], "running");
    server.observe("fixture two waiters active").await?;
    let pending = hold_admitted_body(addr, token).await?;

    fs::write(fixture.join("trigger-writer"), [])?;
    if let Some(signal) = signal {
        server.observe("fixture writer held").await?;
        server.signal(signal)?;
    }
    node_waiter.await??;
    upstream_waiter.await??;
    if !fatal {
        fs::write(fixture.join("release-writer"), [])?;
    }
    assert!(stream.bytes().await?.is_empty());
    prove_work_rejected(pending).await?;
    assert_eq!(
        server.observe("fixture upstream cancelled ").await?,
        ids[1].to_string()
    );
    server.observe("fixture upstream shutdown").await?;
    assert_eq!(
        server.observe("fixture node shutdown flush=").await?,
        (!fatal).to_string()
    );
    assert!(
        TcpStream::connect(addr).await.is_err(),
        "HTTP accept must already be closed"
    );
    assert!(matches!(
        acquire_state_lock(&directory),
        Err(StorageError::Platform(
            efferian_platform::PlatformError::LockContended { .. }
        ))
    ));

    fs::write(fixture.join("release-reader"), [])?;
    server.finish().await?;
    for prefix in ["fixture node started ", "fixture upstream started "] {
        assert_eq!(
            server
                .diagnostics
                .iter()
                .filter(|line| line.starts_with(prefix))
                .count(),
            1
        );
    }
    check_durable_shutdown(&directory, ids, fatal)
}

#[tokio::test]
async fn term_and_int_drain_accepted_work_before_checkpoint() -> TestResult {
    exercise_supervisor(Some("TERM")).await?;
    exercise_supervisor(Some("INT")).await
}

#[tokio::test]
async fn writer_failure_notifies_the_supervisor_while_readers_drain() -> TestResult {
    exercise_supervisor(None).await
}
