//! Operator checks through the actual Hub binary, HTTP server, and SQLite.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "report failed test setup"
)]

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use efferian_protocol::{ExecutionId, HubId, NodeId, RequestId, ToolId, UpstreamId};
use futures_util::{StreamExt, stream};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde_json::{Value, json};

struct RunDir(PathBuf);

impl RunDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("efferian-cli-{}", HubId::new()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn hub() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_efferian-hub"));
    for (key, _) in std::env::vars_os() {
        if key
            .to_str()
            .is_some_and(|key| key.starts_with("EFFERIAN_HUB_"))
        {
            command.env_remove(key);
        }
    }
    command
}

fn success(output: Output) -> Vec<u8> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn token(stdout: Vec<u8>) -> String {
    let output = String::from_utf8(stdout).unwrap();
    assert_eq!(output.lines().count(), 1);
    assert!(output.starts_with("eff_tok_") && output.ends_with('\n'));
    output.trim_end_matches('\n').to_owned()
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

struct Server {
    child: Child,
    addr: SocketAddr,
    diagnostics: mpsc::Receiver<String>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    fn start(state: &Path, quota: &str, config: Option<&Path>) -> Self {
        let mut command = hub();
        command.args(["serve", "--state-dir"]).arg(state).args([
            "--listen",
            "127.0.0.1:0",
            "--max-active-tokens-per-principal",
            quota,
        ]);
        if let Some(config) = config {
            command.arg("--config").arg(config);
        }
        let mut child = command
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (send, recv) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut diagnostics = Vec::new();
        let addr = loop {
            match recv.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(line) => {
                    if let Some(addr) = line.strip_prefix("Hub listening on ") {
                        break addr.parse().unwrap();
                    }
                    diagnostics.push(line);
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    reader.join().unwrap();
                    panic!("serve failed to start ({error}): {diagnostics:?}");
                }
            }
        };
        Self {
            child,
            addr,
            diagnostics: recv,
            reader: Some(reader),
        }
    }

    fn url(&self, resource: &str) -> String {
        format!("http://{}/v1/{resource}", self.addr)
    }

    fn stop(mut self, signal: &str) {
        assert!(
            Command::new("sh")
                .args([
                    "-c",
                    "kill -s \"$1\" \"$2\"",
                    "sh",
                    signal,
                    &self.child.id().to_string()
                ])
                .status()
                .unwrap()
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                if let Some(reader) = self.reader.take() {
                    reader.join().unwrap();
                }
                let diagnostics = self.diagnostics.try_iter().collect::<Vec<_>>();
                assert!(status.success(), "{status}: {diagnostics:?}");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "serve did not stop after {signal}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

async fn json(request: RequestBuilder, status: StatusCode) -> Value {
    let response = request.send().await.unwrap();
    assert_eq!(response.status(), status);
    response.json().await.unwrap()
}

fn client() -> Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

#[tokio::test]
async fn startup_recovers_upstream_and_preserves_pending_node_execution() {
    let client = client();
    let dir = RunDir::new();
    let state = dir.path("state");
    let credential = token(success(
        hub()
            .args(["init", "--state-dir"])
            .arg(&state)
            .output()
            .unwrap(),
    ));
    let node_execution = ExecutionId::new();
    let upstream_execution = ExecutionId::new();
    let conn = rusqlite::Connection::open(state.join("hub.sqlite3")).unwrap();
    let request_id = RequestId::new();
    for (execution, request, kind, state, node, upstream) in [
        (
            node_execution,
            request_id,
            "node",
            "accepted",
            Some(NodeId::new()),
            None,
        ),
        (
            upstream_execution,
            RequestId::new(),
            "upstream",
            "running",
            None,
            Some(UpstreamId::new()),
        ),
    ] {
        conn.execute(
            "INSERT INTO executions (
                execution_id, invoke_kind, request_id, request_digest, caller_principal_id,
                caller_token_id, tool_id, tool_version, public_name, executor_kind, node_id,
                node_session_epoch, upstream_id, state, deadline_at_ms, created_at_ms,
                result_expires_at_ms, expires_at_ms
             ) SELECT ?1, 'tool_test', ?2, 'fixture', principal_id, token_id, ?3, 1, 'fixture',
                 ?4, ?5, CASE WHEN ?5 IS NOT NULL THEN 1 END, ?6, ?7, ?8 + 300000, ?8,
                 ?8 + 604800000, ?8 + 2592000000 FROM auth_tokens",
            rusqlite::params![
                execution.to_string(),
                request.to_string(),
                ToolId::new().to_string(),
                kind,
                node.map(|id| id.to_string()),
                upstream.map(|id| id.to_string()),
                state,
                request_id.timestamp_ms()
            ],
        )
        .unwrap();
    }
    conn.close().unwrap();

    let server = Server::start(&state, "2", None);
    let recovered = json(
        client
            .get(server.url(&format!("executions/{upstream_execution}")))
            .bearer_auth(&credential),
        StatusCode::OK,
    )
    .await;
    assert_eq!(recovered["state"], "unknown");
    assert_eq!(recovered["summary"]["error_code"], "hub_restarted");
    let status = json(
        client
            .get(server.url("admin/status"))
            .bearer_auth(&credential),
        StatusCode::OK,
    )
    .await;
    assert_eq!(status["active_waiters_count"], 1);
    assert_eq!(status["active_upstream_executions"], 0);
    assert!(status["events_head_seq"].as_u64().unwrap() > 0);
    server.stop("TERM");

    let server = Server::start(&state, "2", None);
    let pending = json(
        client
            .get(server.url(&format!("executions/{node_execution}")))
            .bearer_auth(&credential),
        StatusCode::OK,
    )
    .await;
    assert_eq!(pending["state"], "accepted");
    server.stop("TERM");
}

#[tokio::test]
async fn bootstrap_snapshot_restore_and_offline_recovery() {
    let client = client();
    let dir = RunDir::new();
    let state = dir.path("state");
    let bootstrap_path = dir.path("bootstrap");
    let output = hub()
        .args(["init", "--state-dir"])
        .arg(&state)
        .arg("--admin-token-out")
        .arg(&bootstrap_path)
        .output()
        .unwrap();
    assert!(success(output).is_empty());
    let original = token(fs::read(&bootstrap_path).unwrap());
    assert_eq!(mode(&state), 0o700);
    assert_eq!(mode(&bootstrap_path), 0o600);
    let key = state.join("hub.master.key");
    assert_eq!(mode(&key), 0o600);
    fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).unwrap();

    let server = Server::start(&state, "1", None);
    let health = json(
        client
            .get(server.url("health"))
            .header("Host", "probe.example"),
        StatusCode::OK,
    )
    .await;
    assert_eq!(health["status"], "ok");
    let me = json(
        client.get(server.url("me")).bearer_auth(&original),
        StatusCode::OK,
    )
    .await;
    assert_eq!(me["principal"]["kind"], "admin");
    let token_id = me["token_scope"]["token_id"].as_str().unwrap();
    let info = json(client.get(server.url("info")), StatusCode::OK).await;
    let spec = client.get(server.url("openapi.json")).send().await.unwrap();
    assert_eq!(spec.status(), StatusCode::OK);
    let etag = spec.headers()[reqwest::header::ETAG].clone();
    let bytes = spec.bytes().await.unwrap();
    assert!(bytes.as_ref() == include_bytes!("../../../contracts/openapi-hub.json"));
    let unchanged = client
        .get(server.url("openapi.json"))
        .header(reqwest::header::IF_NONE_MATCH, etag)
        .send()
        .await
        .unwrap();
    assert_eq!(unchanged.status(), StatusCode::NOT_MODIFIED);
    assert!(unchanged.bytes().await.unwrap().is_empty());
    let spec: Value = serde_json::from_slice(&bytes).unwrap();
    for (path, code) in [
        ("/v1/me", "401"),
        ("/v1/tokens", "403"),
        ("/v1/nodes/{id}", "404"),
    ] {
        assert!(
            spec["paths"][path]["get"]["responses"][code]["content"]["application/problem+json"]
                .is_object()
        );
    }
    let status = json(
        client
            .get(server.url("admin/status"))
            .bearer_auth(&original),
        StatusCode::OK,
    )
    .await;
    assert_eq!(status["max_page_count"], 1_048_576);

    let output = hub()
        .args(["admin", "create-token", "--state-dir"])
        .arg(&state)
        .args(["--principal", "admin"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());

    let snapshot = dir.path("backup.sqlite3");
    let make_snapshot = || {
        hub()
            .args(["sqlite-snapshot", "--state-dir"])
            .arg(&state)
            .arg("--out")
            .arg(&snapshot)
            .output()
            .unwrap()
    };
    assert!(success(make_snapshot()).is_empty());
    assert!(!make_snapshot().status.success());
    assert_eq!(mode(&snapshot), 0o600);
    server.stop("TERM");

    let restore = dir.path("restore");
    fs::DirBuilder::new().mode(0o700).create(&restore).unwrap();
    fs::copy(&snapshot, restore.join("hub.sqlite3")).unwrap();
    fs::copy(&key, restore.join("hub.master.key")).unwrap();
    let server = Server::start(&restore, "1", None);
    let restored_info = json(client.get(server.url("info")), StatusCode::OK).await;
    assert_eq!(restored_info["hub_id"], info["hub_id"]);
    json(
        client.get(server.url("me")).bearer_auth(&original),
        StatusCode::OK,
    )
    .await;
    server.stop("INT");

    let mint = |quota: &str| {
        hub()
            .args(["admin", "create-token", "--state-dir"])
            .arg(&restore)
            .args([
                "--principal",
                "admin",
                "--out",
                "-",
                "--max-active-tokens-per-principal",
                quota,
            ])
            .output()
            .unwrap()
    };
    let denied = mint("1");
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    let recovery = token(success(mint("2")));
    let server = Server::start(&restore, "1", None);
    let tokens = json(
        client.get(server.url("tokens")).bearer_auth(&recovery),
        StatusCode::OK,
    )
    .await;
    assert_eq!(tokens["items"].as_array().unwrap().len(), 2);
    let status = || {
        client
            .get(server.url("admin/status"))
            .bearer_auth(&recovery)
    };
    let before = json(status(), StatusCode::OK).await;
    let unexpected_byte = stream::iter([Ok::<_, std::io::Error>("x")]);
    let unfinished = unexpected_byte.chain(stream::pending());
    let invalid = json(
        client
            .post(server.url(&format!("tokens/{token_id}/revoke")))
            .bearer_auth(&recovery)
            .body(reqwest::Body::wrap_stream(unfinished)),
        StatusCode::BAD_REQUEST,
    )
    .await;
    assert_eq!(invalid["code"], "invalid_input");
    let after = json(status(), StatusCode::OK).await;
    assert_eq!(after["events_head_seq"], before["events_head_seq"]);
    json(
        client.get(server.url("me")).bearer_auth(&original),
        StatusCode::OK,
    )
    .await;

    let response = client
        .post(server.url(&format!("tokens/{token_id}/revoke")))
        .bearer_auth(&recovery)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let problem = json(
        client.get(server.url("me")).bearer_auth(&original),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_eq!(problem["code"], "unauthenticated");
    server.stop("TERM");
}

#[tokio::test]
async fn enrollment_and_revocation_preserve_node_identity() {
    let client = client();
    let dir = RunDir::new();
    let state = dir.path("state");
    let admin = token(success(
        hub()
            .args(["init", "--state-dir"])
            .arg(&state)
            .output()
            .unwrap(),
    ));
    let server = Server::start(&state, "64", None);
    let ticket = json(
        client
            .post(server.url("enrollment/tokens"))
            .bearer_auth(&admin)
            .json(&json!({"target_node_name":"runner", "tags":["test"]})),
        StatusCode::CREATED,
    )
    .await;
    let enrollment = ticket["enrollment_token"].as_str().unwrap();
    let exchange = || {
        client
            .post(server.url("enrollment/exchange"))
            .json(&json!({}))
    };
    let denied = json(
        client.get(server.url("me")).bearer_auth(enrollment),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    assert_eq!(denied["code"], "unauthenticated");
    json(exchange().bearer_auth(&admin), StatusCode::UNAUTHORIZED).await;
    let original = json(exchange().bearer_auth(enrollment), StatusCode::OK).await;
    let node_id = original["node_id"].as_str().unwrap();
    let old_node_token = original["node_token"].as_str().unwrap();
    json(exchange().bearer_auth(enrollment), StatusCode::UNAUTHORIZED).await;
    let handshake = |credential: &str, version: &'static str| {
        client
            .get(server.url("bridge/connect"))
            .bearer_auth(credential)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", version)
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
    };
    let unauthorized = json(handshake(&admin, "12"), StatusCode::UNAUTHORIZED).await;
    assert_eq!(unauthorized["code"], "unauthenticated");
    let malformed = json(handshake(old_node_token, "12"), StatusCode::BAD_REQUEST).await;
    assert_eq!(malformed["code"], "invalid_input");
    let unavailable = json(
        handshake(old_node_token, "13"),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    assert_eq!(unavailable["code"], "overloaded");

    let reenroll = || {
        client
            .post(server.url(&format!("nodes/{node_id}/reenroll-tokens")))
            .bearer_auth(&admin)
            .json(&json!({}))
    };
    let pre_revoke = json(reenroll(), StatusCode::CREATED).await;
    let status = client
        .post(server.url(&format!("nodes/{node_id}/revoke")))
        .bearer_auth(&admin)
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::NO_CONTENT);
    json(
        exchange().bearer_auth(pre_revoke["enrollment_token"].as_str().unwrap()),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    let fresh = json(reenroll(), StatusCode::CREATED).await;
    let restored = json(
        exchange().bearer_auth(fresh["enrollment_token"].as_str().unwrap()),
        StatusCode::OK,
    )
    .await;
    assert_eq!(restored["hub_id"], original["hub_id"]);
    assert_eq!(restored["node_id"], node_id);
    assert!(restored["node_token"].as_str().unwrap() != old_node_token);
    let node = json(
        client
            .get(server.url(&format!("nodes/{node_id}")))
            .bearer_auth(&admin),
        StatusCode::OK,
    )
    .await;
    assert_eq!(node["tags"], json!(["test"]));
    assert!(node["revoked_at_ms"].is_null());
    assert_eq!(node["live_status"], "offline");
    server.stop("TERM");
}

#[test]
fn invalid_launch_configuration_leaves_state_untouched() {
    let dir = RunDir::new();
    let missing = dir.path("missing");
    let bad_config = dir.path("hub.toml");
    fs::write(&bad_config, "unknown_key = true\n").unwrap();

    let cases = [
        hub()
            .args(["serve", "--state-dir"])
            .arg(&missing)
            .output()
            .unwrap(),
        hub()
            .args(["serve", "--state-dir"])
            .arg(&missing)
            .args(["--listen", "0.0.0.0:0"])
            .output()
            .unwrap(),
        hub()
            .args(["serve", "--state-dir"])
            .arg(&missing)
            .arg("--config")
            .arg(&bad_config)
            .output()
            .unwrap(),
        hub()
            .args(["admin", "create-token", "--state-dir"])
            .arg(&missing)
            .args(["--principal", "admin"])
            .output()
            .unwrap(),
    ];
    for output in cases {
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!missing.exists());
    }
}

#[test]
fn init_rejects_a_fifo_output_parent_without_waiting() {
    let dir = RunDir::new();
    let state = dir.path("state");
    let fifo = dir.path("fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );

    let mut child = hub()
        .args(["init", "--state-dir"])
        .arg(&state)
        .arg("--admin-token-out")
        .arg(fifo.join("token"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("Hub init waited on a non-directory output parent");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("output parent is not a directory"));
    assert!(!state.join("hub.master.key").exists());
    assert!(!state.join("hub.sqlite3").exists());
}

#[test]
fn failed_stdout_delivery_reports_committed_init_and_mint() {
    fn closed_stdout() -> Stdio {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        Stdio::from(writer)
    }

    let dir = RunDir::new();
    let state = dir.path("state");
    let init = hub()
        .args(["init", "--state-dir"])
        .arg(&state)
        .stdout(closed_stdout())
        .output()
        .unwrap();
    assert!(!init.status.success());
    let stderr = String::from_utf8_lossy(&init.stderr);
    assert!(stderr.contains("Hub was initialized, but token output failed"));
    assert!(stderr.contains("admin create-token"));
    assert!(!stderr.contains("eff_tok_"));

    let mint = || {
        let mut command = hub();
        command
            .args(["admin", "create-token", "--state-dir"])
            .arg(&state)
            .args(["--principal", "admin"]);
        command
    };
    let failed = mint().stdout(closed_stdout()).output().unwrap();
    assert!(!failed.status.success());
    let stderr = String::from_utf8_lossy(&failed.stderr);
    assert!(stderr.contains("new token was committed, but token output failed"));
    assert!(!stderr.contains("eff_tok_"));
    token(success(mint().output().unwrap()));

    let db = rusqlite::Connection::open_with_flags(
        state.join("hub.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let tokens: i64 = db
        .query_row("SELECT count(*) FROM auth_tokens", [], |row| row.get(0))
        .unwrap();
    assert_eq!(tokens, 3);
}

#[tokio::test]
async fn serve_accepts_allowed_hosts_and_allowed_origins_flags() {
    let client = client();
    let dir = RunDir::new();
    let state = dir.path("state");
    success(
        hub()
            .args(["init", "--state-dir"])
            .arg(&state)
            .output()
            .unwrap(),
    );

    let mut command = hub();
    command.args(["serve", "--state-dir"]).arg(&state).args([
        "--listen",
        "127.0.0.1:0",
        "--allowed-hosts",
        "hub.example:443,127.0.0.1:8080",
        "--allowed-origins",
        "https://console.example:443,http://app.example:80",
    ]);
    let mut child = command
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (send, recv) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            if send.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut diagnostics = Vec::new();
    let addr = loop {
        match recv.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) => {
                if let Some(addr) = line.strip_prefix("Hub listening on ") {
                    break addr.parse::<SocketAddr>().unwrap();
                }
                diagnostics.push(line);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                reader.join().unwrap();
                panic!("serve failed to start ({error}): {diagnostics:?}");
            }
        }
    };
    let server = Server {
        child,
        addr,
        diagnostics: recv,
        reader: Some(reader),
    };

    json(
        client
            .get(server.url("info"))
            .header("Host", "hub.example:443")
            .header("Origin", "https://console.example"),
        StatusCode::OK,
    )
    .await;
    json(
        client
            .get(server.url("info"))
            .header("Host", "hub.example:443")
            .header("Origin", "http://app.example"),
        StatusCode::OK,
    )
    .await;
    json(
        client
            .get(server.url("info"))
            .header("Host", "other.example:443"),
        StatusCode::FORBIDDEN,
    )
    .await;
    json(
        client
            .get(server.url("info"))
            .header("Host", "hub.example:443")
            .header("Origin", "https://evil.example"),
        StatusCode::FORBIDDEN,
    )
    .await;
    server.stop("TERM");
}

#[tokio::test]
#[ignore = "writes a SQLite fixture over 4 GiB for the offline recovery acceptance check"]
async fn offline_recovery_respects_page_budget_over_four_gib() {
    use efferian_protocol::{ExecutionId, ToolId, UpstreamId};
    use rusqlite::{Connection, params};

    let dir = RunDir::new();
    let state = dir.path("state");
    let config = dir.path("hub.toml");
    fs::write(&config, "max_page_count = 1100000\n").unwrap();
    let bootstrap = dir.path("bootstrap");
    success(
        hub()
            .args(["init", "--state-dir"])
            .arg(&state)
            .arg("--admin-token-out")
            .arg(&bootstrap)
            .output()
            .unwrap(),
    );
    let original = token(fs::read(bootstrap).unwrap());

    let mut db = Connection::open(state.join("hub.sqlite3")).unwrap();
    db.pragma_update(None, "journal_mode", "DELETE").unwrap();
    db.pragma_update(None, "max_page_count", 1_100_000).unwrap();
    let tool = ToolId::new().to_string();
    let upstream = UpstreamId::new().to_string();
    let tx = db.transaction().unwrap();
    for index in 0..1_368 {
        tx.execute(
            "INSERT INTO executions(execution_id,invoke_kind,request_id,request_digest,
              caller_principal_id,caller_token_id,tool_id,tool_version,public_name,executor_kind,
              upstream_id,state,deadline_at_ms,finished_at_ms,created_at_ms,result_expires_at_ms,
              expires_at_ms,result_bytes,sealed_result_blob)
             SELECT ?1,'tool_test',?2,'fixture',principal_id,token_id,?3,1,'fixture','upstream',
               ?4,'succeeded',0,0,0,1,1,?5,zeroblob(?5)
             FROM auth_tokens WHERE label = 'bootstrap'",
            params![
                ExecutionId::new().to_string(),
                format!("fixture-{index}"),
                tool,
                upstream,
                3 * 1024 * 1024
            ],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let pages: u32 = db
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .unwrap();
    assert!(pages > 1_048_576);
    drop(db);

    let mint = || {
        let mut command = hub();
        command
            .args(["admin", "create-token", "--state-dir"])
            .arg(&state)
            .args(["--principal", "admin"]);
        command
    };
    let denied = mint().output().unwrap();
    assert!(!denied.status.success());
    assert!(denied.stdout.is_empty());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("is below the SQLite page count"));
    let recovery = token(success(
        mint()
            .arg("--config")
            .arg(&config)
            .args(["--max-active-tokens-per-principal", "2"])
            .output()
            .unwrap(),
    ));
    let server = Server::start(&state, "1", Some(&config));
    let client = client();
    let tokens = json(
        client.get(server.url("tokens")).bearer_auth(&recovery),
        StatusCode::OK,
    )
    .await;
    let items = tokens["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    let bootstrap = items
        .iter()
        .find(|item| item["label"] == "bootstrap")
        .unwrap();
    let token_id = bootstrap["token_id"].as_str().unwrap();
    let revoked = client
        .post(server.url(&format!("tokens/{token_id}/revoke")))
        .bearer_auth(&recovery)
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
    json(
        client.get(server.url("me")).bearer_auth(&original),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    server.stop("TERM");
}
