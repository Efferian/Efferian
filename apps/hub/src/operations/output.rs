use std::fs::{self, File, Metadata, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use efferian_protocol::{HubId, SecretString};

use super::{OperationError, RESERVED, path_io};

pub(super) enum TokenOutput {
    Stdout,
    File(FileOutput, TemporaryFile),
}

impl TokenOutput {
    pub(super) fn preflight(state_dir: &Path, path: &Path) -> Result<Self, OperationError> {
        if path.as_os_str() == "-" {
            Ok(Self::Stdout)
        } else {
            let target = FileOutput::preflight(state_dir, path)?;
            let temporary = target.reserve()?;
            Ok(Self::File(target, temporary))
        }
    }

    pub(super) fn write(self, secret: &SecretString) -> Result<(), OperationError> {
        fn write_token(out: &mut impl Write, secret: &SecretString) -> io::Result<()> {
            out.write_all(secret.expose_secret().as_bytes())?;
            out.write_all(b"\n")?;
            out.flush()
        }

        match self {
            Self::Stdout => {
                write_token(&mut io::stdout().lock(), secret).map_err(OperationError::Stdout)
            }
            Self::File(target, mut temporary) => {
                write_token(&mut temporary.file, secret)
                    .map_err(|error| path_io("write token output", &temporary.path, error))?;
                temporary.publish(target)
            }
        }
    }
}

pub(super) struct FileOutput {
    path: PathBuf,
    directory: File,
}

impl FileOutput {
    pub(super) fn preflight(state_dir: &Path, path: &Path) -> Result<Self, OperationError> {
        let text = path
            .to_str()
            .ok_or_else(|| invalid_output(path, "expected a UTF-8 path"))?;
        let name = text
            .rsplit('/')
            .next()
            .filter(|part| !matches!(*part, "" | "." | ".."))
            .ok_or_else(|| invalid_output(path, "expected a filename"))?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = fs::canonicalize(parent)
            .map_err(|error| path_io("resolve output directory", parent, error))?;
        // A trailing /. requires a directory during pathname resolution, before
        // opening a special file could block.
        let directory = File::open(parent.join(".")).map_err(|error| {
            if error.kind() == io::ErrorKind::NotADirectory {
                invalid_output(path, "output parent is not a directory")
            } else {
                path_io("open output directory", &parent, error)
            }
        })?;
        let parent_meta = directory
            .metadata()
            .map_err(|error| path_io("inspect output directory", &parent, error))?;
        if !parent_meta.is_dir() {
            return Err(invalid_output(path, "output parent is not a directory"));
        }
        let state_meta = fs::metadata(state_dir)
            .map_err(|error| path_io("inspect state directory", state_dir, error))?;
        if same_inode(&parent_meta, &state_meta) && RESERVED.contains(&name) {
            return Err(invalid_output(path, "reserved Hub state filename"));
        }
        let state_dir = fs::canonicalize(state_dir)
            .map_err(|error| path_io("resolve state directory", state_dir, error))?;
        if parent.starts_with(state_dir.join(super::STAGING)) {
            return Err(invalid_output(
                path,
                "output is inside the Hub staging directory",
            ));
        }
        let target = parent.join(name);
        if target.to_str().is_none() {
            return Err(invalid_output(path, "resolved output path is not UTF-8"));
        }
        if !absent(&target)? {
            return Err(invalid_output(path, "output already exists"));
        }
        Ok(Self {
            path: target,
            directory,
        })
    }

    pub(super) fn reserve(&self) -> Result<TemporaryFile, OperationError> {
        let path = self
            .path
            .with_file_name(format!(".efferian-output-{}", HubId::new()));
        let file = create_private_file(&path)?;
        Ok(TemporaryFile {
            path,
            file,
            clean_on_drop: true,
        })
    }
}

pub(super) struct TemporaryFile {
    path: PathBuf,
    file: File,
    clean_on_drop: bool,
}

impl TemporaryFile {
    pub(super) fn utf8_path(&self) -> Result<&str, OperationError> {
        self.path
            .to_str()
            .ok_or_else(|| invalid_output(&self.path, "expected a UTF-8 path"))
    }

    pub(super) fn publish(mut self, target: FileOutput) -> Result<(), OperationError> {
        if !self.path_is_open_file()? {
            return Err(invalid_output(&self.path, "temporary file was replaced"));
        }
        self.file
            .sync_all()
            .map_err(|error| path_io("sync temporary output", &self.path, error))?;
        fs::hard_link(&self.path, &target.path)
            .map_err(|error| path_io("publish output without replacing", &target.path, error))?;

        // Once linked, retain the temporary name on unlink failure and report it
        // so the operator can restore the single-link invariant.
        self.clean_on_drop = false;
        fs::remove_file(&self.path).map_err(|source| OperationError::PublishedWithTemporary {
            target: target.path.clone(),
            temporary: self.path.clone(),
            source,
        })?;
        target
            .directory
            .sync_all()
            .map_err(|source| OperationError::PublishedDurabilityUnknown {
                target: target.path,
                temporary: self.path.clone(),
                source,
            })
    }

    fn path_is_open_file(&self) -> Result<bool, OperationError> {
        let opened = self
            .file
            .metadata()
            .map_err(|error| path_io("inspect open temporary output", &self.path, error))?;
        let entry = fs::symlink_metadata(&self.path)
            .map_err(|error| path_io("inspect temporary output entry", &self.path, error))?;
        Ok(same_inode(&entry, &opened))
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if self.clean_on_drop && self.path_is_open_file().unwrap_or(false) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub(super) fn create_private_file(path: &Path) -> Result<File, OperationError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| path_io("create private file", path, error))?;
    if let Err(error) = file.set_permissions(Permissions::from_mode(0o600)) {
        let _ = fs::remove_file(path);
        return Err(path_io("set private file permissions", path, error));
    }
    Ok(file)
}

pub(super) fn absent(path: &Path) -> Result<bool, OperationError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(path_io("inspect path", path, error)),
    }
}

fn same_inode(first: &Metadata, second: &Metadata) -> bool {
    first.dev() == second.dev() && first.ino() == second.ino()
}

fn invalid_output(path: &Path, reason: &'static str) -> OperationError {
    OperationError::InvalidOutput {
        path: path.to_owned(),
        reason,
    }
}
