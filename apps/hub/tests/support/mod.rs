use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use efferian_hub::storage::{
    ExpectedHubIdentity, NewHubIdentity, OpenMode, OpenedDb, StorageClock, StorageConfig,
    SystemStorageClock, acquire_state_lock, create_staged, open_existing,
};
use efferian_protocol::HubId;
use rusqlite::Transaction;

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub struct TestDb {
    pub dir: PathBuf,
    pub id: HubId,
    pub config: StorageConfig,
    pub clock: Arc<dyn StorageClock>,
}

impl TestDb {
    pub fn new(config: StorageConfig) -> TestResult<Self> {
        let id = HubId::new();
        Ok(Self {
            id,
            dir: std::env::temp_dir().join(format!("efferian-{id}")),
            config,
            clock: Arc::new(SystemStorageClock::new()?),
        })
    }

    pub fn create<T>(&self, seed: impl FnOnce(&Transaction<'_>) -> TestResult<T>) -> TestResult<T> {
        let mut lock = acquire_state_lock(&self.dir)?;
        create_staged(
            &mut lock,
            self.identity(),
            &self.config,
            self.clock.as_ref(),
            seed,
        )
        .map_err(seed_error)
    }

    pub fn identity(&self) -> NewHubIdentity {
        NewHubIdentity {
            hub_id: self.id,
            active_key_id: 1,
            master_key_fingerprint: "test-fingerprint".to_owned(),
        }
    }

    pub fn expected(&self) -> ExpectedHubIdentity {
        ExpectedHubIdentity {
            active_key_id: 1,
            master_key_fingerprint: "test-fingerprint".to_owned(),
        }
    }

    pub fn open(&self, mode: OpenMode) -> TestResult<OpenedDb> {
        Ok(open_existing(
            acquire_state_lock(&self.dir)?,
            mode,
            self.expected(),
            &self.config,
            Arc::clone(&self.clock),
        )?)
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join("hub.sqlite3")
    }
}

fn seed_error(
    error: efferian_hub::storage::WriteError<Box<dyn std::error::Error + Send + Sync>>,
) -> Box<dyn std::error::Error + Send + Sync> {
    use efferian_hub::storage::WriteError;
    match error {
        WriteError::Domain(error) => error,
        other => other.to_string().into(),
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
