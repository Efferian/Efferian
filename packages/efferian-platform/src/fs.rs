use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::{PlatformError, current_euid};

const PRIVATE_DIR_MODE: u32 = 0o700;
pub(crate) const PRIVATE_FILE_MODE: u32 = 0o600;
pub(crate) const FILE_FLAGS: i32 = libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;

pub(crate) fn checked_path(path: &Path, directory: bool) -> Result<&Path, PlatformError> {
    let bytes = path.as_os_str().as_bytes();
    let end = bytes
        .iter()
        .rposition(|&b| b != b'/')
        .map_or(bytes.len().min(1), |i| i + 1);
    let trimmed = &bytes[..end];
    let last = trimmed.rsplit(|&b| b == b'/').next();
    if bytes.is_empty()
        || bytes.contains(&0)
        || (!directory && end != bytes.len())
        || matches!(last, Some(b"." | b".."))
    {
        return Err(invalid_path(path, "invalid final path component"));
    }
    Ok(Path::new(OsStr::from_bytes(trimmed)))
}

fn invalid_path(path: &Path, reason: &'static str) -> PlatformError {
    PlatformError::InvalidPath {
        path: path.to_path_buf(),
        reason,
    }
}

fn check_name(name: &str) -> Result<(), PlatformError> {
    let path = Path::new(name);
    checked_path(path, false)?;
    if name.contains('/') {
        return Err(invalid_path(path, "expected a single path component"));
    }
    Ok(())
}

fn checked_absolute_path(path: &Path, directory: bool) -> Result<&Path, PlatformError> {
    let path = checked_path(path, directory)?;
    if !path.is_absolute()
        || path
            .as_os_str()
            .as_bytes()
            .split(|&b| b == b'/')
            .any(|b| b == b"..")
    {
        return Err(invalid_path(
            path,
            "expected an absolute path without parent traversal",
        ));
    }
    Ok(path)
}

pub(crate) fn check_type(
    path: &Path,
    metadata: &Metadata,
    directory: bool,
) -> Result<(), PlatformError> {
    if metadata.file_type().is_symlink() {
        return Err(PlatformError::SymlinkNotAllowed {
            path: path.to_path_buf(),
        });
    }
    if (directory && metadata.is_dir()) || (!directory && metadata.is_file()) {
        return Ok(());
    }
    Err(PlatformError::UnexpectedFileType {
        path: path.to_path_buf(),
        expected: if directory {
            "directory"
        } else {
            "regular file"
        },
    })
}

pub(crate) fn check_owner(
    path: &Path,
    metadata: &Metadata,
    expected_uid: u32,
) -> Result<(), PlatformError> {
    if metadata.uid() == expected_uid {
        return Ok(());
    }
    Err(PlatformError::WrongOwner {
        path: path.to_path_buf(),
        expected_uid,
        actual_uid: metadata.uid(),
    })
}

pub(crate) fn check_single_link(path: &Path, metadata: &Metadata) -> Result<(), PlatformError> {
    let nlink = metadata.nlink();
    if nlink == 1 {
        return Ok(());
    }
    Err(PlatformError::InvalidHardLinkCount {
        path: path.to_path_buf(),
        nlink,
    })
}

pub(crate) fn same_inode(first: &Metadata, second: &Metadata) -> bool {
    first.dev() == second.dev() && first.ino() == second.ino()
}

pub(crate) fn check_mode(
    path: &Path,
    metadata: &Metadata,
    allowed: impl FnOnce(u32) -> bool,
    reason: &'static str,
) -> Result<(), PlatformError> {
    let mode = metadata.mode() & 0o7777;
    if allowed(mode) {
        return Ok(());
    }
    Err(PlatformError::InsecurePermissions {
        path: path.to_path_buf(),
        mode,
        reason,
    })
}

pub(crate) fn entry_metadata(path: &Path) -> Result<Option<Metadata>, PlatformError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(PlatformError::io("inspect_path", path, error)),
    }
}

fn fd_metadata(path: &Path, file: &File) -> Result<Metadata, PlatformError> {
    file.metadata()
        .map_err(|error| PlatformError::io("inspect_open_file", path, error))
}

pub(crate) fn open_file_error(
    path: &Path,
    operation: &'static str,
    error: io::Error,
) -> PlatformError {
    if error.raw_os_error() == Some(libc::ELOOP) {
        return PlatformError::SymlinkNotAllowed {
            path: path.to_path_buf(),
        };
    }
    PlatformError::io(operation, path, error)
}

fn open_directory(path: &Path) -> Result<File, PlatformError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ENOTDIR)
                && let Ok(metadata) = fs::symlink_metadata(path)
                && let Err(problem) = check_type(path, &metadata, true)
            {
                return problem;
            }
            open_file_error(path, "open_directory", error)
        })
}

fn check_inode(path: &Path, first: &Metadata, second: &Metadata) -> Result<(), PlatformError> {
    if same_inode(first, second) {
        return Ok(());
    }
    Err(invalid_path(
        path,
        "path identity changed during validation",
    ))
}

fn canonicalize(path: &Path) -> Result<PathBuf, PlatformError> {
    fs::canonicalize(path).map_err(|error| PlatformError::io("canonicalize", path, error))
}

fn set_mode(path: &Path, file: &File, mode: u32) -> Result<(), PlatformError> {
    file.set_permissions(Permissions::from_mode(mode))
        .map_err(|error| PlatformError::io("set_permissions", path, error))
}

fn verified_dir(path: &Path, created: bool) -> Result<(PathBuf, File), PlatformError> {
    let path = checked_path(path, true)?;
    let file = open_directory(path)?;
    if created {
        set_mode(path, &file, PRIVATE_DIR_MODE)?;
    }
    let metadata = fd_metadata(path, &file)?;
    check_owner(path, &metadata, current_euid())?;
    check_mode(
        path,
        &metadata,
        |mode| mode == PRIVATE_DIR_MODE,
        "expected mode 0700",
    )?;
    let canonical = canonicalize(path)?;
    let current = fs::symlink_metadata(&canonical)
        .map_err(|error| PlatformError::io("inspect_canonical_directory", &canonical, error))?;
    check_type(&canonical, &current, true)?;
    check_inode(path, &metadata, &current)?;
    Ok((canonical, file))
}

fn create_dir(path: &Path, recursive: bool) -> io::Result<()> {
    DirBuilder::new()
        .mode(PRIVATE_DIR_MODE)
        .recursive(recursive)
        .create(path)
}

fn open_regular_file(path: &Path) -> Result<(File, Metadata), PlatformError> {
    if let Some(metadata) = entry_metadata(path)? {
        check_type(path, &metadata, false)?;
    }

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAGS)
        .open(path)
        .map_err(|error| open_file_error(path, "open_file", error))?;
    let metadata = fd_metadata(path, &file)?;
    check_type(path, &metadata, false)?;
    Ok((file, metadata))
}

fn create_unique_file(
    dir: &Path,
    prefix: &str,
    reserved_name: Option<&str>,
) -> Result<(EphemeralSecretFile, File), PlatformError> {
    for _ in 0..16 {
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|error| PlatformError::EntropyUnavailable {
            detail: error.to_string(),
        })?;
        let mut name = String::from(prefix);
        let _ = write!(name, "-{:032x}", u128::from_ne_bytes(random));
        if reserved_name == Some(name.as_str()) {
            continue;
        }
        let path = dir.join(name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => return Ok((EphemeralSecretFile { path, active: true }, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(PlatformError::io("create_private_file", &path, error)),
        }
    }
    Err(PlatformError::io(
        "create_private_file",
        dir,
        io::ErrorKind::AlreadyExists.into(),
    ))
}

fn write_contents(path: &Path, file: &mut File, bytes: &[u8]) -> Result<(), PlatformError> {
    set_mode(path, file, PRIVATE_FILE_MODE)?;
    file.write_all(bytes)
        .map_err(|error| PlatformError::io("write_private_file", path, error))
}

fn write_atomic(
    dir: &Path,
    name: &str,
    bytes: &[u8],
    publish: impl FnOnce(&Path, &Path) -> io::Result<()>,
    sync_parent: impl FnOnce(&File) -> io::Result<()>,
) -> Result<(), PlatformError> {
    check_name(name)?;
    let (dir, directory) = verified_dir(dir, false)?;
    let target = dir.join(name);
    if let Some(metadata) = entry_metadata(&target)? {
        check_type(&target, &metadata, false)?;
    }

    let (mut temp, mut file) = create_unique_file(&dir, ".eff-tmp", Some(name))?;
    write_contents(&temp.path, &mut file, bytes)?;
    file.sync_all()
        .map_err(|error| PlatformError::io("sync_private_file", &temp.path, error))?;
    drop(file);

    publish(&temp.path, &target)
        .map_err(|error| PlatformError::io("publish_private_file", &target, error))?;
    temp.active = false;
    sync_parent(&directory).map_err(|error| PlatformError::io("sync_published_parent", &dir, error))
}

/// Operations for private state and operator-managed paths.
pub struct PrivateFs;

impl PrivateFs {
    /// Create a private directory and return its canonical path.
    pub fn ensure_private_dir(path: &Path) -> Result<PathBuf, PlatformError> {
        let path = checked_path(path, true)?;
        let mut created = false;
        if let Some(metadata) = entry_metadata(path)? {
            check_type(path, &metadata, true)?;
        } else {
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                create_dir(parent, true).map_err(|error| {
                    PlatformError::io("create_private_ancestors", parent, error)
                })?;
            }
            match create_dir(path, false) {
                Ok(()) => created = true,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(PlatformError::io("create_private_directory", path, error));
                }
            }
        }
        let (canonical, _) = verified_dir(path, created)?;
        Ok(canonical)
    }

    /// Read at most `max_bytes` from an owned, single-link file with mode 0400 or 0600.
    pub fn read_private_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, PlatformError> {
        let path = checked_path(path, false)?;
        let (file, metadata) = open_regular_file(path)?;
        check_owner(path, &metadata, current_euid())?;
        check_single_link(path, &metadata)?;
        check_mode(
            path,
            &metadata,
            |mode| matches!(mode, 0o400 | PRIVATE_FILE_MODE),
            "expected mode 0400 or 0600",
        )?;
        let too_large = || PlatformError::FileTooLarge {
            path: path.to_path_buf(),
            max_bytes,
        };
        if metadata.len() > max_bytes {
            return Err(too_large());
        }
        let mut bytes = Vec::with_capacity(metadata.len().min(64 * 1024) as usize);
        file.take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| PlatformError::io("read_private_file", path, error))?;
        if bytes.len() as u64 > max_bytes {
            return Err(too_large());
        }
        Ok(bytes)
    }

    /// Publish a complete 0600 replacement in an existing private directory.
    ///
    /// An I/O error with operation `sync_published_parent` means the replacement
    /// is visible and its crash durability is unknown.
    pub fn write_private_file_atomic(
        dir: &Path,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), PlatformError> {
        write_atomic(
            dir,
            name,
            bytes,
            |temp, target| fs::rename(temp, target),
            File::sync_all,
        )
    }

    pub fn create_ephemeral_secret_file(
        dir: &Path,
        prefix: &str,
        bytes: &[u8],
    ) -> Result<EphemeralSecretFile, PlatformError> {
        if !(1..=64).contains(&prefix.len())
            || !prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(invalid_path(dir, "invalid ephemeral file prefix"));
        }
        let (dir, _) = verified_dir(dir, false)?;
        let (temp, mut file) = create_unique_file(&dir, prefix, None)?;
        write_contents(&temp.path, &mut file, bytes)?;
        file.flush()
            .map_err(|error| PlatformError::io("flush_ephemeral_file", &temp.path, error))?;
        Ok(temp)
    }

    pub fn create_ephemeral_dir(parent: &Path, name: &str) -> Result<EphemeralDir, PlatformError> {
        check_name(name)?;
        let (parent, _) = verified_dir(parent, false)?;
        let path = parent.join(name);
        create_dir(&path, false)
            .map_err(|error| PlatformError::io("create_ephemeral_directory", &path, error))?;
        let mut directory = EphemeralDir { path, active: true };
        let (canonical, _) = verified_dir(&directory.path, true)?;
        directory.path = canonical;
        Ok(directory)
    }

    pub fn wipe_private_dir_contents(dir: &Path) -> Result<(), PlatformError> {
        let (dir, _) = verified_dir(dir, false)?;
        wipe_contents(&dir)
    }

    /// Validate a working directory or a regular file under operator-managed roots.
    ///
    /// The returned path is checked at the time of the call. Trusted ownership
    /// and ACLs must keep the path entries and sensitive files stable during use.
    pub fn validate_path_within_roots(
        path: &Path,
        canonical_roots: &[PathBuf],
        forbidden_roots: &[PathBuf],
        expect_dir: bool,
    ) -> Result<PathBuf, PlatformError> {
        let path = checked_absolute_path(path, expect_dir)?;
        let original = fs::symlink_metadata(path)
            .map_err(|error| PlatformError::io("inspect_target", path, error))?;
        check_type(path, &original, expect_dir)?;
        let target = canonicalize(path)?;

        let mut allowed = false;
        for root in canonical_roots {
            let canonical = canonicalize(checked_absolute_path(root, true)?)?;
            let metadata = fs::symlink_metadata(&canonical)
                .map_err(|error| PlatformError::io("inspect_allowed_root", &canonical, error))?;
            check_type(&canonical, &metadata, true)?;
            allowed |= target.starts_with(&canonical);
        }
        if !allowed {
            return Err(PlatformError::OutsideAllowedRoots { path: target });
        }

        for forbidden in forbidden_roots {
            let raw = checked_absolute_path(forbidden, true)?;
            let canonical = resolve_forbidden_root(raw)?;
            if [path, target.as_path()].into_iter().any(|candidate| {
                [raw, canonical.as_path()].into_iter().any(|root| {
                    candidate.starts_with(root) || (expect_dir && root.starts_with(candidate))
                })
            }) {
                return Err(PlatformError::ForbiddenRoot { path: target });
            }
        }

        if expect_dir {
            let directory = open_directory(&target)?;
            check_inode(path, &original, &fd_metadata(&target, &directory)?)?;
        } else {
            let (_file, metadata) = open_regular_file(&target)?;
            check_inode(path, &original, &metadata)?;
            check_mode(
                &target,
                &metadata,
                |mode| mode & 0o022 == 0,
                "file is group- or world-writable",
            )?;
            let parent = target
                .parent()
                .ok_or_else(|| invalid_path(&target, "expected a parent directory"))?;
            let directory = open_directory(parent)?;
            let metadata = fd_metadata(parent, &directory)?;
            check_mode(
                parent,
                &metadata,
                |mode| mode & 0o022 == 0,
                "parent is group- or world-writable",
            )?;
        }
        Ok(target)
    }
}

fn resolve_forbidden_root(path: &Path) -> Result<PathBuf, PlatformError> {
    let mut missing = Vec::new();
    for ancestor in path.ancestors() {
        if entry_metadata(ancestor)?.is_some() {
            let mut canonical = canonicalize(ancestor)?;
            let metadata = fs::symlink_metadata(&canonical)
                .map_err(|error| PlatformError::io("inspect_forbidden_root", &canonical, error))?;
            check_type(&canonical, &metadata, true)?;
            canonical.extend(missing.into_iter().rev());
            return Ok(canonical);
        }
        let name = ancestor
            .file_name()
            .ok_or_else(|| invalid_path(path, "unresolvable forbidden root"))?;
        missing.push(name);
    }
    Err(invalid_path(path, "unresolvable forbidden root"))
}

/// An owned temporary secret file. Dropping it attempts to unlink it.
#[derive(Debug)]
pub struct EphemeralSecretFile {
    path: PathBuf,
    active: bool,
}

impl EphemeralSecretFile {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Unlink the file and report an unlink error if cleanup fails.
    pub fn close(mut self) -> Result<(), PlatformError> {
        self.unlink()
    }

    fn unlink(&mut self) -> Result<(), PlatformError> {
        ignore_missing(fs::remove_file(&self.path))
            .map_err(|error| PlatformError::io("remove_ephemeral_file", &self.path, error))?;
        self.active = false;
        Ok(())
    }
}

impl Drop for EphemeralSecretFile {
    fn drop(&mut self) {
        if self.active {
            let _ = self.unlink();
        }
    }
}

/// An owned temporary directory. Dropping it attempts to remove the tree.
#[derive(Debug)]
pub struct EphemeralDir {
    path: PathBuf,
    active: bool,
}

impl EphemeralDir {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Remove the directory tree and report a removal error if cleanup fails.
    pub fn remove(mut self) -> Result<(), PlatformError> {
        self.remove_tree()?;
        self.active = false;
        Ok(())
    }

    fn remove_tree(&self) -> Result<(), PlatformError> {
        remove_directory_tree(&self.path)
    }
}

impl Drop for EphemeralDir {
    fn drop(&mut self) {
        if self.active {
            let _ = self.remove_tree();
        }
    }
}

fn ignore_missing(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        result => result,
    }
}

fn remove_directory_tree(path: &Path) -> Result<(), PlatformError> {
    match ignore_missing(fs::remove_dir_all(path)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            let directory = open_directory(path)?;
            check_owner(path, &fd_metadata(path, &directory)?, current_euid())?;
            set_mode(path, &directory, PRIVATE_DIR_MODE)?;
            wipe_contents(path)?;
            ignore_missing(fs::remove_dir(path))
                .map_err(|error| PlatformError::io("remove_directory", path, error))
        }
        Err(error) => Err(PlatformError::io("remove_directory_tree", path, error)),
    }
}

fn wipe_contents(dir: &Path) -> Result<(), PlatformError> {
    let entries = fs::read_dir(dir)
        .map_err(|error| PlatformError::io("list_private_directory", dir, error))?;
    for entry in entries {
        let entry = entry.map_err(|error| PlatformError::io("read_directory_entry", dir, error))?;
        let path = entry.path();
        let kind = entry
            .file_type()
            .map_err(|error| PlatformError::io("inspect_directory_entry", &path, error))?;
        if kind.is_dir() {
            remove_directory_tree(&path)?;
        } else {
            ignore_missing(fs::remove_file(&path))
                .map_err(|error| PlatformError::io("remove_directory_entry", &path, error))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDir;

    #[test]
    fn owner_check_has_explicit_expected_and_actual_uids() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = TestDir::new()?;
        let metadata = fs::metadata(dir.path())?;
        let expected = metadata.uid() ^ 1;
        assert!(matches!(
            check_owner(dir.path(), &metadata, expected),
            Err(PlatformError::WrongOwner { expected_uid, actual_uid, .. })
                if expected_uid == expected && actual_uid == metadata.uid()
        ));
        Ok(())
    }

    #[test]
    fn atomic_write_reports_which_side_of_publication_failed()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new()?;
        let dir = dir.path();
        let target = dir.join("config");
        PrivateFs::write_private_file_atomic(dir, "config", b"old")?;

        let fail = write_atomic(
            dir,
            "config",
            b"unpublished",
            |temp, destination| {
                assert_eq!(fs::read(temp)?, b"unpublished");
                assert_eq!(fs::read(destination)?, b"old");
                Err(io::Error::from_raw_os_error(libc::EIO))
            },
            |_| Err(io::Error::other("directory was synced before publication")),
        );
        assert!(matches!(
            fail,
            Err(PlatformError::Io {
                operation: "publish_private_file",
                ..
            })
        ));
        assert_eq!(fs::read(&target)?, b"old");
        assert_eq!(fs::read_dir(dir)?.count(), 1);

        let fail = write_atomic(
            dir,
            "config",
            b"published",
            |temp, target| fs::rename(temp, target),
            |_| {
                assert_eq!(fs::read(&target)?, b"published");
                Err(io::Error::from_raw_os_error(libc::EIO))
            },
        );
        assert!(matches!(
            fail,
            Err(PlatformError::Io {
                operation: "sync_published_parent",
                ..
            })
        ));
        assert_eq!(fs::read(&target)?, b"published");
        assert_eq!(fs::read_dir(dir)?.count(), 1);
        Ok(())
    }
}
