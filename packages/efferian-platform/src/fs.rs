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
    open_directory_with(path, 0)
}

fn open_directory_with(path: &Path, flags: i32) -> Result<File, PlatformError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(flags | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
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

// A cwd or an SSH file's parent needs search permission, even when listing
// directory entries is forbidden. Let the kernel evaluate credentials and ACLs.
fn searchable_directory_metadata(path: &Path) -> Result<Metadata, PlatformError> {
    #[cfg(target_os = "macos")]
    let flags = libc::O_SEARCH;
    #[cfg(target_os = "linux")]
    let flags = libc::O_PATH;
    let directory = open_directory_with(path, flags)?;
    let metadata = fd_metadata(path, &directory)?;
    // O_PATH pins the directory without checking search permission on the leaf.
    #[cfg(target_os = "linux")]
    {
        let searched = fs::metadata(path.join("."))
            .map_err(|error| PlatformError::io("search_directory", path, error))?;
        check_inode(path, &metadata, &searched)?;
    }
    Ok(metadata)
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

struct CanonicalPaths {
    primary: PathBuf,
    volume_alias: Option<PathBuf>,
}

impl CanonicalPaths {
    fn new(primary: PathBuf, metadata: &Metadata) -> Result<Self, PlatformError> {
        #[cfg(target_os = "macos")]
        let volume_alias =
            startup_volume_alias(&primary, metadata, Path::new("/System/Volumes/Data"))?;
        #[cfg(target_os = "linux")]
        let volume_alias = {
            let _ = metadata;
            None
        };
        Ok(Self {
            primary,
            volume_alias,
        })
    }

    fn iter(&self) -> impl Iterator<Item = &Path> {
        std::iter::once(self.primary.as_path()).chain(self.volume_alias.as_deref())
    }

    fn append_missing(&mut self, suffix: &[&OsStr]) {
        for path in std::iter::once(&mut self.primary).chain(self.volume_alias.as_mut()) {
            path.extend(suffix.iter().rev());
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn startup_volume_alias(
    path: &Path,
    metadata: &Metadata,
    data_volume: &Path,
) -> Result<Option<PathBuf>, PlatformError> {
    // macOS realpath can retain either spelling of an APFS firmlink. The
    // other spelling counts only when it names the very same inode.
    let (candidate, candidate_on_data) = if let Ok(relative) = path.strip_prefix(data_volume) {
        (Path::new("/").join(relative), false)
    } else {
        let relative = path
            .strip_prefix("/")
            .map_err(|_| invalid_path(path, "expected a canonical path"))?;
        (data_volume.join(relative), true)
    };
    match fs::metadata(&candidate) {
        Ok(alias) if same_inode(metadata, &alias) => {
            let canonical = canonicalize(&candidate)?;
            Ok((canonical.starts_with(data_volume) == candidate_on_data).then_some(canonical))
        }
        Ok(_) => Ok(None),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(PlatformError::io(
            "inspect_startup_volume_alias",
            &candidate,
            error,
        )),
    }
}

fn set_mode(path: &Path, file: &File, mode: u32) -> Result<(), PlatformError> {
    file.set_permissions(Permissions::from_mode(mode))
        .map_err(|error| PlatformError::io("set_permissions", path, error))
}

fn restore_owned_directory_mode(path: &Path) -> Result<(), PlatformError> {
    match open_directory(path) {
        Ok(directory) => {
            check_owner(path, &fd_metadata(path, &directory)?, current_euid())?;
            set_mode(path, &directory, PRIVATE_DIR_MODE)
        }
        Err(PlatformError::Io { source, .. })
            if source.kind() == io::ErrorKind::PermissionDenied =>
        {
            restore_unreadable_directory(path)
        }
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn restore_unreadable_directory(path: &Path) -> Result<(), PlatformError> {
    use std::os::fd::AsRawFd;

    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| PlatformError::io("pin_unreadable_directory", path, error))?;
    check_owner(path, &fd_metadata(path, &directory)?, current_euid())?;
    // O_PATH pins the inode but does not support fchmod. The procfs descriptor
    // entry addresses that same directory while this File is alive.
    let fd_path = format!("/proc/self/fd/{}", directory.as_raw_fd());
    fs::set_permissions(fd_path, Permissions::from_mode(PRIVATE_DIR_MODE))
        .map_err(|error| PlatformError::io("restore_directory_mode", path, error))
}

#[cfg(target_os = "macos")]
fn restore_unreadable_directory(path: &Path) -> Result<(), PlatformError> {
    use std::ffi::CString;
    // Creation and startup cleanup have exclusive ownership of this entry.
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| PlatformError::io("inspect_directory_mode", path, error))?;
    check_type(path, &metadata, true)?;
    check_owner(path, &metadata, current_euid())?;
    let name = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| invalid_path(path, "path contains NUL"))?;
    // SAFETY: name is a live NUL-terminated pathname. fchmodat reads the name
    // during the call and does not retain the pointer.
    if unsafe {
        libc::fchmodat(
            libc::AT_FDCWD,
            name.as_ptr(),
            PRIVATE_DIR_MODE as libc::mode_t,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(PlatformError::io(
            "restore_directory_mode",
            path,
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn verified_dir(path: &Path) -> Result<(PathBuf, File), PlatformError> {
    let path = checked_path(path, true)?;
    let file = open_directory(path)?;
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

fn mkdir_private(path: &Path) -> io::Result<()> {
    DirBuilder::new().mode(PRIVATE_DIR_MODE).create(path)
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

fn open_linked_file(
    path: &Path,
    mut open: impl FnMut() -> Result<(File, Metadata), PlatformError>,
) -> Result<(File, Metadata), PlatformError> {
    let mut opened = open()?;
    // Atomic publication may unlink the previous file between open and fstat.
    for _ in 0..3 {
        if opened.1.nlink() != 0 {
            break;
        }
        opened = open()?;
    }
    check_single_link(path, &opened.1)?;
    Ok(opened)
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
    let (dir, directory) = verified_dir(dir)?;
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
        let mut missing = Vec::new();
        for ancestor in path.ancestors() {
            if ancestor.as_os_str().is_empty() || entry_metadata(ancestor)?.is_some() {
                break;
            }
            missing.push(ancestor);
        }
        for directory in missing.into_iter().rev() {
            match mkdir_private(directory) {
                Ok(()) => restore_owned_directory_mode(directory)?,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(PlatformError::io(
                        "create_private_directory",
                        directory,
                        error,
                    ));
                }
            }
        }
        let (canonical, _) = verified_dir(path)?;
        Ok(canonical)
    }

    /// Read at most `max_bytes` from an owned, single-link file with mode 0400 or 0600.
    pub fn read_private_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, PlatformError> {
        let path = checked_path(path, false)?;
        let (file, metadata) = open_linked_file(path, || open_regular_file(path))?;
        check_owner(path, &metadata, current_euid())?;
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
        let (dir, _) = verified_dir(dir)?;
        let (temp, mut file) = create_unique_file(&dir, prefix, None)?;
        write_contents(&temp.path, &mut file, bytes)?;
        file.flush()
            .map_err(|error| PlatformError::io("flush_ephemeral_file", &temp.path, error))?;
        Ok(temp)
    }

    pub fn create_ephemeral_dir(parent: &Path, name: &str) -> Result<EphemeralDir, PlatformError> {
        check_name(name)?;
        let (parent, _) = verified_dir(parent)?;
        let path = parent.join(name);
        mkdir_private(&path)
            .map_err(|error| PlatformError::io("create_ephemeral_directory", &path, error))?;
        let mut directory = EphemeralDir { path, active: true };
        restore_owned_directory_mode(&directory.path)?;
        let (canonical, _) = verified_dir(&directory.path)?;
        directory.path = canonical;
        Ok(directory)
    }

    /// Wipe during startup under the exclusive instance lock, before issuing any
    /// ephemeral guards. Each guard owns its entry name until cleanup completes.
    pub fn wipe_private_dir_contents(dir: &Path) -> Result<(), PlatformError> {
        let (dir, _) = verified_dir(dir)?;
        wipe_contents(&dir)
    }

    /// Validate a working directory or a regular file under operator-managed roots.
    ///
    /// The returned path is checked at the time of the call. Trusted ownership
    /// and ACLs must keep the path entries and sensitive files stable during use.
    /// macOS root comparisons include verified aliases on the startup Data
    /// volume.
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
        let target = CanonicalPaths::new(canonicalize(path)?, &original)?;

        let mut allowed = false;
        for root in canonical_roots {
            let canonical = canonicalize(checked_absolute_path(root, true)?)?;
            let metadata = fs::symlink_metadata(&canonical)
                .map_err(|error| PlatformError::io("inspect_allowed_root", &canonical, error))?;
            check_type(&canonical, &metadata, true)?;
            let root = CanonicalPaths::new(canonical, &metadata)?;
            allowed |= target
                .iter()
                .any(|path| root.iter().any(|root| path.starts_with(root)));
        }
        if !allowed {
            return Err(PlatformError::OutsideAllowedRoots {
                path: target.primary,
            });
        }

        let target_ancestors = if forbidden_roots.is_empty() {
            Vec::new()
        } else {
            ancestor_ids(&target.primary)?
        };
        for forbidden in forbidden_roots {
            let raw = checked_absolute_path(forbidden, true)?;
            let forbidden = resolve_forbidden_root(raw)?;
            let lexical_overlap = std::iter::once(path).chain(target.iter()).any(|candidate| {
                std::iter::once(raw)
                    .chain(forbidden.paths.iter())
                    .any(|root| {
                        candidate.starts_with(root) || (expect_dir && root.starts_with(candidate))
                    })
            });
            if lexical_overlap
                || forbidden.overlaps_by_identity(&target_ancestors, &original, expect_dir)?
            {
                return Err(PlatformError::ForbiddenRoot {
                    path: target.primary,
                });
            }
        }

        let target = target.primary;
        if expect_dir {
            check_inode(path, &original, &searchable_directory_metadata(&target)?)?;
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
            let metadata = searchable_directory_metadata(parent)?;
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

// Unix realpath can preserve alternate spellings of a case-folded directory.
// Compare existing directory identities as well as component-wise path forms.
fn ancestor_ids(path: &Path) -> Result<Vec<(u64, u64)>, PlatformError> {
    path.ancestors()
        .map(|ancestor| {
            let metadata = fs::metadata(ancestor)
                .map_err(|error| PlatformError::io("inspect_ancestor", ancestor, error))?;
            Ok((metadata.dev(), metadata.ino()))
        })
        .collect()
}

struct ForbiddenRoot {
    paths: CanonicalPaths,
    anchor: PathBuf,
    anchor_id: (u64, u64),
    planned: bool,
}

impl ForbiddenRoot {
    fn overlaps_by_identity(
        &self,
        target_ancestors: &[(u64, u64)],
        target: &Metadata,
        directory: bool,
    ) -> Result<bool, PlatformError> {
        if !self.planned && target_ancestors.contains(&self.anchor_id) {
            return Ok(true);
        }
        Ok(directory && ancestor_ids(&self.anchor)?.contains(&(target.dev(), target.ino())))
    }
}

fn resolve_forbidden_root(path: &Path) -> Result<ForbiddenRoot, PlatformError> {
    let mut missing = Vec::new();
    for ancestor in path.ancestors() {
        if entry_metadata(ancestor)?.is_some() {
            let canonical = canonicalize(ancestor)?;
            let metadata = fs::symlink_metadata(&canonical)
                .map_err(|error| PlatformError::io("inspect_forbidden_root", &canonical, error))?;
            check_type(&canonical, &metadata, true)?;
            let mut paths = CanonicalPaths::new(canonical.clone(), &metadata)?;
            paths.append_missing(&missing);
            return Ok(ForbiddenRoot {
                paths,
                anchor: canonical,
                anchor_id: (metadata.dev(), metadata.ino()),
                planned: !missing.is_empty(),
            });
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
#[must_use = "keep the guard until the secret file can be removed"]
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
#[must_use = "keep the guard until the directory can be removed"]
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
            restore_owned_directory_mode(path)?;
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
    fn root_identity_checks_existing_and_planned_directories()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new()?;
        let work = dir.path().join("work");
        let state = work.join("state");
        fs::create_dir_all(&state)?;
        let existing = resolve_forbidden_root(&state)?;
        let planned = resolve_forbidden_root(&state.join("future"))?;
        let state_ids = ancestor_ids(&state)?;
        assert!(existing.overlaps_by_identity(&state_ids, &fs::metadata(&state)?, false)?);
        assert!(planned.overlaps_by_identity(
            &ancestor_ids(&work)?,
            &fs::metadata(&work)?,
            true
        )?);
        assert!(!planned.overlaps_by_identity(&state_ids, &fs::metadata(&state)?, false)?);
        Ok(())
    }

    #[test]
    fn read_reopens_an_inode_unlinked_during_publication() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = TestDir::new()?;
        let path = dir.path().join("config");
        PrivateFs::write_private_file_atomic(dir.path(), "config", b"old")?;
        let mut old = Some(File::open(&path)?);
        PrivateFs::write_private_file_atomic(dir.path(), "config", b"new")?;
        let (mut file, _) = open_linked_file(&path, || {
            if let Some(file) = old.take() {
                let metadata = fd_metadata(&path, &file)?;
                assert_eq!(metadata.nlink(), 0);
                Ok((file, metadata))
            } else {
                open_regular_file(&path)
            }
        })?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        assert_eq!(bytes, b"new");
        Ok(())
    }

    #[test]
    fn startup_volume_forms_require_the_same_inode_and_keep_the_future_suffix()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = TestDir::new()?;
        let original = dir.path().join("original");
        fs::write(&original, b"original")?;
        let metadata = fs::metadata(&original)?;
        let data = dir.path().join("Data");
        let alias = data.join(original.strip_prefix("/")?);
        let parent = alias.parent().ok_or("missing alias parent")?;

        assert_eq!(startup_volume_alias(&original, &metadata, &data)?, None);
        fs::create_dir_all(parent)?;
        fs::write(&alias, b"other inode")?;
        assert_eq!(startup_volume_alias(&original, &metadata, &data)?, None);
        assert_eq!(
            startup_volume_alias(&alias, &fs::metadata(&alias)?, &data)?,
            None
        );
        fs::remove_file(&alias)?;
        std::os::unix::fs::symlink(&original, &alias)?;
        assert_eq!(startup_volume_alias(&original, &metadata, &data)?, None);
        fs::remove_file(&alias)?;
        fs::hard_link(&original, &alias)?;

        let physical_metadata = fs::metadata(&alias)?;
        assert_eq!(
            startup_volume_alias(&alias, &physical_metadata, &data)?.as_deref(),
            Some(original.as_path())
        );
        let mut paths = CanonicalPaths {
            volume_alias: startup_volume_alias(&original, &metadata, &data)?,
            primary: original.clone(),
        };
        assert_eq!(paths.volume_alias.as_deref(), Some(alias.as_path()));
        paths.append_missing(&[OsStr::new("leaf"), OsStr::new("future")]);
        assert!(paths.iter().eq([
            original.join("future/leaf").as_path(),
            alias.join("future/leaf").as_path()
        ]));
        assert!(paths.iter().any(|path| path.starts_with(&data)));
        Ok(())
    }

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
