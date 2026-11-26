//! Operating-system facilities shared by Efferian applications.
//!
//! Filesystem paths are checked at the time of each call. Operators must keep
//! the relevant directory entries and sensitive files under trusted ownership
//! and ACLs while clients use those paths. Trusted ancestor symlinks are allowed.

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("efferian-platform supports Linux and macOS");

mod clock;
mod error;
mod fs;
mod lock;
#[cfg(feature = "process")]
mod process;

pub use clock::{MonoInstant, MonotonicClock};
pub use error::PlatformError;
pub use fs::{EphemeralDir, EphemeralSecretFile, PrivateFs};
pub use lock::FileLock;
#[cfg(feature = "process")]
pub use process::{ProcessHandle, TerminateOutcome};

#[cfg(target_os = "linux")]
pub const DEFAULT_SAFE_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

#[cfg(target_os = "macos")]
pub const DEFAULT_SAFE_PATH: &str = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin";

pub const fn safe_path() -> &'static str {
    DEFAULT_SAFE_PATH
}

pub fn current_euid() -> u32 {
    // SAFETY: geteuid takes no arguments and has no memory preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;
