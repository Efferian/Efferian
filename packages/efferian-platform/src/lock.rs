use std::fs::{self, File, Metadata, OpenOptions, TryLockError};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::fs::{
    FILE_FLAGS, PRIVATE_FILE_MODE, check_mode, check_owner, check_single_link, check_type,
    checked_path, entry_metadata, open_file_error, same_inode,
};
use crate::{PlatformError, current_euid};

/// An exclusive lock on a persistent sidecar file.
#[derive(Debug)]
#[must_use = "retain the lock for the lifetime of the instance"]
pub struct FileLock {
    file: File,
    path: PathBuf,
    owner_pid: u32,
}

impl FileLock {
    pub fn acquire_exclusive(lock_path: &Path) -> Result<Self, PlatformError> {
        Self::acquire_with_verification(lock_path, verified_lock_path)
    }

    fn acquire_with_verification(
        lock_path: &Path,
        verify: impl FnOnce(&Path, &Metadata) -> Result<PathBuf, PlatformError>,
    ) -> Result<Self, PlatformError> {
        let invalid = || PlatformError::InvalidLockTarget {
            path: lock_path.to_path_buf(),
            reason: "expected a sidecar filename with a nonempty stem and .lock suffix",
        };
        let path = checked_path(lock_path, false).map_err(|_| invalid())?;
        if !path.file_name().is_some_and(|name| {
            name.as_bytes()
                .strip_suffix(b".lock")
                .is_some_and(|stem| !stem.is_empty())
        }) {
            return Err(invalid());
        }

        if let Some(metadata) = entry_metadata(path)? {
            check_type(path, &metadata, false)?;
        }
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(FILE_FLAGS);
        let file = match options.create_new(true).open(path) {
            Ok(file) => {
                file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
                    .map_err(|error| PlatformError::io("set_lock_permissions", path, error))?;
                file
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => options
                .create_new(false)
                .open(path)
                .map_err(|error| open_file_error(path, "open_lock", error))?,
            Err(error) => return Err(open_file_error(path, "open_lock", error)),
        };
        let opened = file
            .metadata()
            .map_err(|error| PlatformError::io("inspect_lock", path, error))?;
        check_type(path, &opened, false)?;
        check_owner(path, &opened, current_euid())?;
        check_single_link(path, &opened)?;
        check_mode(
            path,
            &opened,
            |mode| mode == PRIVATE_FILE_MODE,
            "expected mode 0600",
        )?;

        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(PlatformError::LockContended {
                    path: path.to_path_buf(),
                });
            }
            Err(TryLockError::Error(error)) => {
                return Err(PlatformError::io("lock_exclusive", path, error));
            }
        }

        let mut lock = Self {
            file,
            path: path.to_path_buf(),
            owner_pid: std::process::id(),
        };
        lock.path = verify(path, &opened)?;
        Ok(lock)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn verified_lock_path(path: &Path, opened: &Metadata) -> Result<PathBuf, PlatformError> {
    verify_lock_entry(path, opened)?;
    let canonical = fs::canonicalize(path).map_err(|error| lock_entry_error(path, error))?;
    verify_lock_entry(&canonical, opened)?;
    Ok(canonical)
}

fn lock_entry_error(path: &Path, error: io::Error) -> PlatformError {
    if error.kind() == io::ErrorKind::NotFound {
        return PlatformError::LockFileChanged {
            path: path.to_path_buf(),
        };
    }
    PlatformError::io("verify_lock_path", path, error)
}

fn verify_lock_entry(path: &Path, opened: &Metadata) -> Result<(), PlatformError> {
    let current = fs::symlink_metadata(path).map_err(|error| lock_entry_error(path, error))?;
    if !current.is_file() || !same_inode(opened, &current) || current.nlink() != 1 {
        return Err(PlatformError::LockFileChanged {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // An inherited descriptor shares the same kernel lock with the owner.
        // Closing it is safe. Unlocking it explicitly from a forked child is not.
        if std::process::id() == self.owner_pid {
            let _ = self.file.unlock();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDir;

    #[test]
    fn post_lock_validation_rejects_replaced_entry_and_new_hard_link()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new()?;
        let path = dir.path().join("hub.lock");
        drop(FileLock::acquire_exclusive(&path)?);
        let contender = OpenOptions::new().read(true).write(true).open(&path)?;
        let renamed = dir.path().join("renamed");
        let alias = dir.path().join("alias");
        for replace in [false, true] {
            let result = FileLock::acquire_with_verification(&path, |path, opened| {
                assert!(matches!(
                    contender.try_lock(),
                    Err(TryLockError::WouldBlock)
                ));
                if replace {
                    fs::rename(path, &renamed).and_then(|()| fs::write(path, b"replacement"))
                } else {
                    fs::hard_link(path, &alias)
                }
                .map_err(|error| PlatformError::io("change_test_entry", path, error))?;
                verified_lock_path(path, opened)
            });
            assert!(matches!(result, Err(PlatformError::LockFileChanged { .. })));
            if !replace {
                fs::remove_file(&alias)?;
            }
        }
        contender.try_lock()?;
        Ok(())
    }

    #[test]
    fn dropping_inherited_descriptor_does_not_unlock_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new()?;
        let path = dir.path().join("hub.lock");
        let owner = FileLock::acquire_exclusive(&path)?;
        // A dup shares the open file description as a forked descriptor would.
        drop(FileLock {
            file: owner.file.try_clone()?,
            path: path.clone(),
            owner_pid: 0,
        });
        assert!(matches!(
            FileLock::acquire_exclusive(&path),
            Err(PlatformError::LockContended { .. })
        ));
        drop(owner);
        assert!(path.is_file());
        drop(FileLock::acquire_exclusive(&path)?);
        Ok(())
    }
}
