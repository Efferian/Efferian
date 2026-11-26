use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PlatformError {
    #[error("sidecar lock is held: {path:?}")]
    LockContended { path: PathBuf },
    #[error("invalid sidecar lock path {path:?}: {reason}")]
    InvalidLockTarget { path: PathBuf, reason: &'static str },
    #[error("sidecar lock file changed during acquisition: {path:?}")]
    LockFileChanged { path: PathBuf },
    #[error("invalid path {path:?}: {reason}")]
    InvalidPath { path: PathBuf, reason: &'static str },
    #[error("symlink is disallowed at {path:?}")]
    SymlinkNotAllowed { path: PathBuf },
    #[error("expected {expected} at {path:?}")]
    UnexpectedFileType {
        path: PathBuf,
        expected: &'static str,
    },
    #[error("insecure permissions {mode:04o} on {path:?}: {reason}")]
    InsecurePermissions {
        path: PathBuf,
        mode: u32,
        reason: &'static str,
    },
    #[error("unexpected owner on {path:?}: expected UID {expected_uid}, found {actual_uid}")]
    WrongOwner {
        path: PathBuf,
        expected_uid: u32,
        actual_uid: u32,
    },
    #[error("expected one hard link for {path:?}, found {nlink}")]
    InvalidHardLinkCount { path: PathBuf, nlink: u64 },
    #[error("file {path:?} exceeds the {max_bytes}-byte limit")]
    FileTooLarge { path: PathBuf, max_bytes: u64 },
    #[error("path is outside the allowed roots: {path:?}")]
    OutsideAllowedRoots { path: PathBuf },
    #[error("path overlaps a forbidden root: {path:?}")]
    ForbiddenRoot { path: PathBuf },
    #[error("monotonic clock unavailable: {source}")]
    ClockUnavailable {
        #[source]
        source: io::Error,
    },
    #[error("monotonic time is out of range")]
    ClockOverflow,
    #[error("system entropy unavailable: {detail}")]
    EntropyUnavailable { detail: String },
    #[error("invalid isolated process group ID: {pid}")]
    InvalidProcessGroup { pid: u32 },
    #[error("{operation} failed for {path:?}: {source}")]
    Io {
        operation: &'static str,
        path: Option<PathBuf>,
        #[source]
        source: io::Error,
    },
}

impl PlatformError {
    pub(crate) fn io(operation: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: Some(path.to_path_buf()),
            source,
        }
    }

    #[cfg(feature = "process")]
    pub(crate) fn process_io(operation: &'static str, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: None,
            source,
        }
    }
}
