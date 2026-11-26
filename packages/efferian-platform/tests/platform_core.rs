mod support;

use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Permissions};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt, chown, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use efferian_platform::{
    DEFAULT_SAFE_PATH, FileLock, MonotonicClock, PlatformError, PrivateFs, current_euid, safe_path,
};
use support::TestDir;

type TestResult = Result<(), Box<dyn Error>>;

fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    fs::set_permissions(path, Permissions::from_mode(mode))
}

fn mode(path: &Path) -> std::io::Result<u32> {
    Ok(fs::metadata(path)?.mode() & 0o7777)
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut raw = OsString::from(path.as_os_str());
    raw.push(suffix);
    raw.into()
}

fn fifo(path: &Path) -> TestResult {
    assert!(Command::new("mkfifo").arg(path).status()?.success());
    Ok(())
}

#[test]
fn sidecar_names_and_contention() -> TestResult {
    let dir = TestDir::new()?;
    for name in [
        "hub.sqlite3",
        "node.sqlite3-wal",
        "data.DB",
        "node.token",
        "config.toml",
        ".lock",
        "hub.lock/",
        "hub.lock/.",
        "hub.lock\0",
    ] {
        let path = dir.path().join(name);
        assert!(
            matches!(
                FileLock::acquire_exclusive(&path),
                Err(PlatformError::InvalidLockTarget { .. })
            ),
            "{name:?}"
        );
    }
    assert_eq!(fs::read_dir(dir.path())?.count(), 0);

    let path = dir.path().join("hub.lock");
    let lock = FileLock::acquire_exclusive(&path)?;
    assert_eq!(lock.path(), path);
    assert_eq!(mode(&path)?, 0o600);
    assert!(matches!(
        FileLock::acquire_exclusive(&path),
        Err(PlatformError::LockContended { .. })
    ));
    FileLock::acquire_exclusive(&dir.path().join("node.lock"))?;
    drop(lock);
    assert!(path.is_file());
    FileLock::acquire_exclusive(&path)?;
    Ok(())
}

#[test]
fn sidecar_rejects_aliases_non_regular_files_and_wide_permissions() -> TestResult {
    let dir = TestDir::new()?;
    let path = dir.path().join("hub.lock");
    FileLock::acquire_exclusive(&path)?;
    let alias = dir.path().join("alias.lock");

    symlink(&path, &alias)?;
    assert!(matches!(
        FileLock::acquire_exclusive(&alias),
        Err(PlatformError::SymlinkNotAllowed { .. })
    ));
    fs::remove_file(&alias)?;
    fs::hard_link(&path, &alias)?;
    assert!(matches!(
        FileLock::acquire_exclusive(&path),
        Err(PlatformError::InvalidHardLinkCount { nlink: 2, .. })
    ));
    fs::remove_file(&alias)?;
    set_mode(&path, 0o644)?;
    assert!(matches!(
        FileLock::acquire_exclusive(&path),
        Err(PlatformError::InsecurePermissions { mode: 0o644, .. })
    ));
    fifo(&alias)?;
    assert!(matches!(
        FileLock::acquire_exclusive(&alias),
        Err(PlatformError::UnexpectedFileType { .. })
    ));
    Ok(())
}

#[test]
fn private_directories_check_the_raw_leaf_and_allow_an_ancestor_alias() -> TestResult {
    let dir = TestDir::new()?;
    let nested = dir.path().join("real/state/keys");
    assert_eq!(PrivateFs::ensure_private_dir(&nested)?, nested);
    assert_eq!(mode(&nested)?, 0o700);
    assert_eq!(mode(&dir.path().join("real/state"))?, 0o700);

    let alias = dir.path().join("alias");
    symlink(dir.path().join("real"), &alias)?;
    assert_eq!(
        PrivateFs::ensure_private_dir(&alias.join("state/keys/"))?,
        nested
    );
    for path in [alias.clone(), with_suffix(&alias, "///")] {
        assert!(matches!(
            PrivateFs::ensure_private_dir(&path),
            Err(PlatformError::SymlinkNotAllowed { .. })
        ));
    }
    assert!(matches!(
        PrivateFs::ensure_private_dir(&with_suffix(&alias, "/./")),
        Err(PlatformError::InvalidPath { .. })
    ));

    let dangling = dir.path().join("dangling");
    symlink(dir.path().join("absent"), &dangling)?;
    assert!(matches!(
        PrivateFs::ensure_private_dir(&dangling),
        Err(PlatformError::SymlinkNotAllowed { .. })
    ));

    let wide = dir.path().join("wide");
    fs::create_dir(&wide)?;
    set_mode(&wide, 0o755)?;
    assert!(matches!(
        PrivateFs::ensure_private_dir(&wide),
        Err(PlatformError::InsecurePermissions { mode: 0o755, .. })
    ));
    assert_eq!(mode(&wide)?, 0o755);
    Ok(())
}

#[test]
fn private_reads_enforce_permissions_links_type_and_size() -> TestResult {
    let dir = TestDir::new()?;
    let path = dir.path().join("secret");
    PrivateFs::write_private_file_atomic(dir.path(), "secret", b"bytes")?;

    for allowed in [0o400, 0o600] {
        set_mode(&path, allowed)?;
        assert_eq!(PrivateFs::read_private_file(&path, 5)?, b"bytes");
        assert!(matches!(
            PrivateFs::read_private_file(&path, 4),
            Err(PlatformError::FileTooLarge { max_bytes: 4, .. })
        ));
    }
    for rejected in [0o604, 0o640, 0o644, 0o700, 0o1600] {
        set_mode(&path, rejected)?;
        assert!(
            matches!(PrivateFs::read_private_file(&path, 5), Err(PlatformError::InsecurePermissions { mode, .. }) if mode == rejected)
        );
    }
    set_mode(&path, 0o600)?;

    let special = dir.path().join("special");
    symlink(&path, &special)?;
    assert!(matches!(
        PrivateFs::read_private_file(&special, 5),
        Err(PlatformError::SymlinkNotAllowed { .. })
    ));
    fs::remove_file(&special)?;
    fs::hard_link(&path, &special)?;
    assert!(matches!(
        PrivateFs::read_private_file(&path, 5),
        Err(PlatformError::InvalidHardLinkCount { nlink: 2, .. })
    ));
    fs::remove_file(&special)?;
    fifo(&special)?;
    assert!(matches!(
        PrivateFs::read_private_file(&special, 5),
        Err(PlatformError::UnexpectedFileType { .. })
    ));
    assert!(matches!(
        PrivateFs::read_private_file(&with_suffix(&path, "/"), 5),
        Err(PlatformError::InvalidPath { .. })
    ));
    Ok(())
}

#[test]
fn private_reads_reject_foreign_owners_at_the_os_boundary() -> TestResult {
    let dir = TestDir::new()?;
    let owned = dir.path().join("foreign");
    let system = Path::new("/etc/passwd");
    let foreign = if current_euid() == 0 {
        PrivateFs::write_private_file_atomic(dir.path(), "foreign", b"bytes")?;
        chown(&owned, Some(65534), None)?;
        &owned
    } else {
        system
    };
    let actual = fs::metadata(foreign)?.uid();
    assert_ne!(actual, current_euid());
    assert!(matches!(
        PrivateFs::read_private_file(foreign, u64::MAX),
        Err(PlatformError::WrongOwner { expected_uid, actual_uid, .. })
            if expected_uid == current_euid() && actual_uid == actual
    ));
    Ok(())
}

#[test]
fn atomic_replacement_keeps_the_old_open_inode_and_rejects_invalid_targets() -> TestResult {
    use std::io::Read as _;

    let dir = TestDir::new()?;
    PrivateFs::write_private_file_atomic(dir.path(), "config", b"old")?;
    let target = dir.path().join("config");
    let mut old = File::open(&target)?;
    PrivateFs::write_private_file_atomic(dir.path(), "config", b"new")?;
    assert_eq!(PrivateFs::read_private_file(&target, 3)?, b"new");
    let mut old_bytes = Vec::new();
    old.read_to_end(&mut old_bytes)?;
    assert_eq!(old_bytes, b"old");
    assert_eq!(mode(&target)?, 0o600);

    for name in ["", ".", "..", "sub/name", "invalid\0name", "config/"] {
        assert!(matches!(
            PrivateFs::write_private_file_atomic(dir.path(), name, b"invalid"),
            Err(PlatformError::InvalidPath { .. })
        ));
    }
    symlink(&target, dir.path().join("symlink"))?;
    fs::create_dir(dir.path().join("directory"))?;
    assert!(matches!(
        PrivateFs::write_private_file_atomic(dir.path(), "symlink", b"invalid"),
        Err(PlatformError::SymlinkNotAllowed { .. })
    ));
    assert!(matches!(
        PrivateFs::write_private_file_atomic(dir.path(), "directory", b"invalid"),
        Err(PlatformError::UnexpectedFileType { .. })
    ));
    set_mode(dir.path(), 0o755)?;
    assert!(matches!(
        PrivateFs::write_private_file_atomic(dir.path(), "config", b"invalid"),
        Err(PlatformError::InsecurePermissions { .. })
    ));
    assert_eq!(fs::read(&target)?, b"new");
    assert_eq!(fs::read_dir(dir.path())?.count(), 3);
    Ok(())
}

#[test]
fn ephemeral_resources_clean_up_on_drop_and_on_explicit_removal() -> TestResult {
    let dir = TestDir::new()?;
    for prefix in ["", "with space", "with/slash", "ё"] {
        assert!(matches!(
            PrivateFs::create_ephemeral_secret_file(dir.path(), prefix, b"bytes"),
            Err(PlatformError::InvalidPath { .. })
        ));
    }
    let one = PrivateFs::create_ephemeral_secret_file(dir.path(), "ssh_key-1", b"bytes")?;
    let two = PrivateFs::create_ephemeral_secret_file(dir.path(), "ssh_key-1", b"bytes")?;
    assert_ne!(one.path(), two.path());
    assert_eq!(mode(one.path())?, 0o600);
    assert_eq!(PrivateFs::read_private_file(one.path(), 5)?, b"bytes");
    let one_path = one.path().to_path_buf();
    let two_path = two.path().to_path_buf();
    one.close()?;
    drop(two);
    assert!(!one_path.exists());
    assert!(!two_path.exists());

    let eph = PrivateFs::create_ephemeral_dir(dir.path(), "execution")?;
    let path = eph.path().to_path_buf();
    assert_eq!(mode(&path)?, 0o700);
    assert!(PrivateFs::create_ephemeral_dir(dir.path(), "execution").is_err());
    let nested = PrivateFs::ensure_private_dir(&path.join("nested"))?;
    fs::write(nested.join("script"), b"script")?;
    set_mode(&nested, 0o500)?;
    drop(eph);
    assert!(!path.exists());

    PrivateFs::create_ephemeral_dir(dir.path(), "execution")?.remove()?;
    assert!(!path.exists());
    Ok(())
}

#[test]
fn wiping_preserves_the_private_root_and_does_not_follow_symlinks() -> TestResult {
    let outer = TestDir::new()?;
    let outside = PrivateFs::ensure_private_dir(&outer.path().join("outside"))?;
    fs::write(outside.join("keep"), b"keep")?;

    let root = PrivateFs::ensure_private_dir(&outer.path().join("root"))?;
    let nested = PrivateFs::ensure_private_dir(&root.join("nested/readonly"))?;
    fs::write(nested.join("remove"), b"remove")?;
    symlink(&outside, nested.join("link"))?;
    set_mode(&nested, 0o500)?;
    symlink(&outside, root.join("link"))?;
    fs::write(root.join("file"), b"remove")?;

    PrivateFs::wipe_private_dir_contents(&root)?;
    assert_eq!(mode(&root)?, 0o700);
    assert_eq!(fs::read_dir(&root)?.count(), 0);
    assert_eq!(fs::read(outside.join("keep"))?, b"keep");
    Ok(())
}

#[test]
fn validates_component_boundaries_and_both_directions_of_forbidden_overlap() -> TestResult {
    let outer = TestDir::new()?;
    let root = PrivateFs::ensure_private_dir(&outer.path().join("allowed"))?;
    let state = PrivateFs::ensure_private_dir(&root.join("state"))?;
    let child = PrivateFs::ensure_private_dir(&state.join("child"))?;
    let sibling = PrivateFs::ensure_private_dir(&root.join("state-work"))?;
    let outside = PrivateFs::ensure_private_dir(&outer.path().join("allowed-other"))?;
    let alias = outer.path().join("alias");
    symlink(&root, &alias)?;
    let allowed = [alias.clone()];
    let forbidden = [alias.join("state")];
    for path in [&root, &state, &child] {
        assert!(matches!(
            PrivateFs::validate_path_within_roots(path, &allowed, &forbidden, true),
            Err(PlatformError::ForbiddenRoot { .. })
        ));
    }
    assert_eq!(
        PrivateFs::validate_path_within_roots(
            &alias.join("state-work/"),
            &allowed,
            &forbidden,
            true
        )?,
        sibling
    );
    assert!(matches!(
        PrivateFs::validate_path_within_roots(&outside, &allowed, &forbidden, true),
        Err(PlatformError::OutsideAllowedRoots { .. })
    ));
    assert!(matches!(
        PrivateFs::validate_path_within_roots(
            &sibling,
            &allowed,
            &[alias.join("state-work/future/deeper")],
            true
        ),
        Err(PlatformError::ForbiddenRoot { .. })
    ));
    assert!(matches!(
        PrivateFs::validate_path_within_roots(&alias, &allowed, &[], true),
        Err(PlatformError::SymlinkNotAllowed { .. })
    ));
    assert!(matches!(
        PrivateFs::validate_path_within_roots(&with_suffix(&sibling, "/./"), &allowed, &[], true),
        Err(PlatformError::InvalidPath { .. })
    ));
    assert!(matches!(
        PrivateFs::validate_path_within_roots(&state.join("../state-work"), &allowed, &[], true),
        Err(PlatformError::InvalidPath { .. })
    ));
    assert!(matches!(
        PrivateFs::validate_path_within_roots(Path::new("relative"), &allowed, &[], true),
        Err(PlatformError::InvalidPath { .. })
    ));
    let invalid = root.join(OsStr::from_bytes(b"invalid\0path"));
    assert!(matches!(
        PrivateFs::validate_path_within_roots(&invalid, &allowed, &[], true),
        Err(PlatformError::InvalidPath { .. })
    ));

    let broken = root.join("broken");
    symlink(root.join("absent"), &broken)?;
    for unusable in [
        broken.clone(),
        broken.join("future"),
        PathBuf::from("relative"),
    ] {
        assert!(
            PrivateFs::validate_path_within_roots(&sibling, &allowed, &[unusable], true).is_err()
        );
    }
    Ok(())
}

#[test]
fn validates_regular_files_and_their_parent_permissions() -> TestResult {
    let dir = TestDir::new()?;
    let parent = PrivateFs::ensure_private_dir(&dir.path().join("ssh"))?;
    let path = parent.join("known_hosts");
    fs::write(&path, b"known hosts")?;
    let roots = [dir.path().to_path_buf()];
    set_mode(&path, 0o644)?;
    set_mode(&parent, 0o755)?;
    assert_eq!(
        PrivateFs::validate_path_within_roots(&path, &roots, &[], false)?,
        path
    );
    assert!(matches!(
        PrivateFs::validate_path_within_roots(&path, &roots, std::slice::from_ref(&parent), false),
        Err(PlatformError::ForbiddenRoot { .. })
    ));

    set_mode(&path, 0o664)?;
    assert!(matches!(
        PrivateFs::validate_path_within_roots(&path, &roots, &[], false),
        Err(PlatformError::InsecurePermissions { mode: 0o664, .. })
    ));
    set_mode(&path, 0o644)?;
    set_mode(&parent, 0o775)?;
    assert!(matches!(
        PrivateFs::validate_path_within_roots(&path, &roots, &[], false),
        Err(PlatformError::InsecurePermissions { mode: 0o775, .. })
    ));
    assert!(matches!(
        PrivateFs::validate_path_within_roots(&parent, &roots, &[], false),
        Err(PlatformError::UnexpectedFileType { .. })
    ));
    assert!(matches!(
        PrivateFs::validate_path_within_roots(&path, &roots, &[], true),
        Err(PlatformError::UnexpectedFileType { .. })
    ));
    let named_pipe = parent.join("fifo");
    fifo(&named_pipe)?;
    assert!(matches!(
        PrivateFs::validate_path_within_roots(&named_pipe, &roots, &[], false),
        Err(PlatformError::UnexpectedFileType { .. })
    ));
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn macos_firmlink_spellings_share_the_root_policy() -> TestResult {
    let dir = TestDir::new()?;
    let logical = dir.path();
    let data = Path::new("/System/Volumes/Data");
    if logical.starts_with(data) {
        return Ok(());
    }
    let physical = data.join(logical.strip_prefix("/")?);
    let logical_inode = fs::metadata(logical)?.ino();
    if !fs::metadata(&physical).is_ok_and(|metadata| metadata.ino() == logical_inode) {
        // A test directory on a separate volume has no startup Data alias.
        return Ok(());
    }

    let target = PrivateFs::ensure_private_dir(&logical.join("work"))?;
    let physical_target = physical.join("work");
    assert_eq!(
        PrivateFs::validate_path_within_roots(&target, std::slice::from_ref(&physical), &[], true)?,
        target
    );
    assert_eq!(
        PrivateFs::validate_path_within_roots(
            &physical_target,
            &[logical.to_path_buf()],
            &[],
            true
        )?,
        physical_target
    );
    for forbidden in [
        data.to_path_buf(),
        physical_target.clone(),
        physical_target.join("future/state"),
    ] {
        assert!(matches!(
            PrivateFs::validate_path_within_roots(
                &target,
                &[logical.to_path_buf()],
                &[forbidden],
                true
            ),
            Err(PlatformError::ForbiddenRoot { .. })
        ));
    }
    Ok(())
}

#[test]
fn monotonic_clock_arithmetic_and_safe_path() -> TestResult {
    let start = MonotonicClock::now()?;
    assert!(MonotonicClock::now()? >= start);
    let delta = Duration::from_millis(5);
    std::thread::sleep(delta);
    let later = MonotonicClock::now()?;
    assert!(
        later
            .checked_duration_since(start)
            .is_some_and(|elapsed| elapsed >= delta)
    );
    assert_eq!(start.checked_duration_since(later), None);
    assert_eq!(start.saturating_duration_since(later), Duration::ZERO);
    let moved = start.checked_add(delta).ok_or("instant overflow")?;
    assert_eq!(moved.as_nanos() - start.as_nanos(), 5_000_000);
    assert_eq!(moved.as_millis() - start.as_millis(), 5);
    assert_eq!(moved.checked_sub(delta), Some(start));
    assert_eq!(start.checked_add(Duration::MAX), None);
    assert_eq!(start.checked_sub(Duration::MAX), None);
    assert!(start.elapsed()? >= delta);
    assert_eq!(safe_path(), DEFAULT_SAFE_PATH);
    if cfg!(target_os = "macos") {
        assert_eq!(
            safe_path(),
            "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
        );
    } else {
        assert_eq!(safe_path(), "/usr/local/bin:/usr/bin:/bin");
    }
    Ok(())
}
