use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, Permissions};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use efferian_protocol::{HubId, NodeId, PrincipalId};
use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
use tower_service::Service;

use crate::config::Config;
use crate::egress::EgressClient;
use crate::http::{self, AppState};
use crate::node_bridge::{BridgeCloseReason, NodeBridgeControl, NodeLiveStatus};
use crate::operations;
use crate::storage::{
    OpenMode, ShutdownReport, StorageClock, StorageError, StorageRuntime, WriteTxError, id,
};

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(crate) struct TestDir(pub PathBuf);

impl TestDir {
    pub fn new(prefix: &str) -> TestResult<Self> {
        let path = std::env::temp_dir().join(format!("efferian-{prefix}-{}", HubId::new()));
        DirBuilder::new().mode(0o700).create(&path)?;
        fs::set_permissions(&path, Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }

    pub fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(crate) struct ManualClock(AtomicI64);

impl ManualClock {
    pub fn new(ms: i64) -> Self {
        Self(AtomicI64::new(ms))
    }

    pub fn set(&self, ms: i64) {
        self.0.store(ms, Ordering::SeqCst);
    }
}

impl StorageClock for ManualClock {
    fn wall_now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    fn monotonic_now(&self) -> Result<Duration, StorageError> {
        Ok(Duration::ZERO)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClosedSession {
    pub node_id: NodeId,
    pub through_epoch: u64,
    pub reason: BridgeCloseReason,
    pub committed_epoch: Option<i64>,
    pub committed_revocation: Option<i64>,
}

pub(crate) struct RecordingBridge {
    database: PathBuf,
    sessions: Mutex<BTreeMap<NodeId, u64>>,
    closes: Mutex<Vec<ClosedSession>>,
}

impl RecordingBridge {
    pub fn new(database: PathBuf) -> Self {
        Self {
            database,
            sessions: Mutex::default(),
            closes: Mutex::default(),
        }
    }

    pub fn sessions(&self) -> MutexGuard<'_, BTreeMap<NodeId, u64>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn closes(&self) -> MutexGuard<'_, Vec<ClosedSession>> {
        self.closes.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl NodeBridgeControl for RecordingBridge {
    fn live_status(&self, node_id: NodeId) -> NodeLiveStatus {
        if self.sessions().contains_key(&node_id) {
            NodeLiveStatus::Ready
        } else {
            NodeLiveStatus::Offline
        }
    }

    fn online_nodes_count(&self) -> usize {
        self.sessions().len()
    }

    fn close_session(&self, node_id: NodeId, through_epoch: u64, reason: BridgeCloseReason) {
        let observed: rusqlite::Result<(Option<i64>, Option<i64>)> =
            Connection::open_with_flags(&self.database, OpenFlags::SQLITE_OPEN_READ_ONLY).and_then(
                |conn| {
                    conn.query_row(
                        "SELECT session_epoch, revoked_at_ms FROM nodes WHERE node_id = ?1",
                        [node_id.to_string()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                },
            );
        let (committed_epoch, committed_revocation) = observed.unwrap_or_default();
        self.closes().push(ClosedSession {
            node_id,
            through_epoch,
            reason,
            committed_epoch,
            committed_revocation,
        });
        let mut sessions = self.sessions();
        if sessions
            .get(&node_id)
            .is_some_and(|epoch| *epoch <= through_epoch)
        {
            sessions.remove(&node_id);
        }
    }
}

pub(crate) async fn send_json(
    router: &Router,
    method: Method,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> TestResult<(StatusCode, Value)> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "localhost:8080")
        .header("authorization", format!("Bearer {token}"));
    let body = if let Some(json) = body {
        req = req.header("content-type", "application/json");
        Body::from(serde_json::to_vec(&json)?)
    } else {
        Body::empty()
    };
    let response = router.clone().call(req.body(body)?).await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 256 * 1024).await?;
    let data = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, data))
}

pub(crate) struct TestHub {
    pub router: Router,
    pub state: AppState,
    pub runtime: StorageRuntime,
    pub admin_id: PrincipalId,
    pub admin_token: String,
    pub bridge: Arc<RecordingBridge>,
    pub clock: Arc<ManualClock>,
    pub _dir: TestDir,
}

impl TestHub {
    pub async fn start(prefix: &str, config: Config, start_ms: i64) -> TestResult<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = TestDir::new(prefix)?;
        let state_dir = dir.join("state");
        let output = dir.join("admin.token");
        let storage_config = config.storage_config();
        operations::init(&state_dir, "admin", &output, &storage_config)?;
        let admin_token = fs::read_to_string(output)?.trim_end().to_owned();
        let clock = Arc::new(ManualClock::new(start_ms));
        let (opened, vault) = operations::open_existing(
            &state_dir,
            OpenMode::ServeAutoMigrate,
            &storage_config,
            Arc::clone(&clock) as Arc<dyn StorageClock>,
        )?;
        let (storage, runtime) = opened.migrate_and_start_runtime()?;
        let admin_id = storage
            .read_snapshot(|conn| {
                conn.query_row(
                    "SELECT principal_id FROM principals WHERE name = 'admin'",
                    [],
                    |row| id(row, 0),
                )
                .map_err(StorageError::from)
            })
            .await?;
        let bridge = Arc::new(RecordingBridge::new(state_dir.join("hub.sqlite3")));
        let state = AppState {
            storage,
            vault,
            clock: Arc::clone(&clock) as Arc<dyn StorageClock>,
            egress: EgressClient::new(config.egress_policy()?)?,
            config: Arc::new(config),
            bridge: Arc::clone(&bridge) as Arc<dyn NodeBridgeControl>,
        };
        let router = http::router(state.clone(), 8080)?;
        Ok(Self {
            router,
            state,
            runtime,
            admin_id,
            admin_token,
            bridge,
            clock,
            _dir: dir,
        })
    }

    pub async fn request(
        &self,
        method: Method,
        uri: &str,
        token: &str,
        json: Option<Value>,
    ) -> TestResult<(StatusCode, Value)> {
        send_json(&self.router, method, uri, token, json).await
    }

    pub async fn request_admin(
        &self,
        method: Method,
        uri: &str,
        json: Option<Value>,
    ) -> TestResult<(StatusCode, Value)> {
        self.request(method, uri, &self.admin_token, json).await
    }

    pub async fn write(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<()> + Send + 'static,
    ) -> TestResult {
        self.state
            .storage
            .execute_work(
                0,
                move |tx| -> Result<_, WriteTxError<std::convert::Infallible>> {
                    Ok(f(tx.conn())?)
                },
            )
            .await?;
        Ok(())
    }

    pub async fn shutdown(self) {
        let report = self.runtime.shutdown().await;
        assert!(matches!(report, ShutdownReport::Complete), "{report:?}");
    }
}
