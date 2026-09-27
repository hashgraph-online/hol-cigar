//! Fixed filenames in a caller-protected directory. No discovery, permissive chmod or cleanup.
use super::{BrokerError, BrokerStorageOptions};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub(super) struct PrivatePath {
    pub(super) database: PathBuf,
    directory: File,
    identity: (u64, u64),
    directory_identity: (u64, u64),
}

impl PrivatePath {
    pub(super) fn prepare(options: &BrokerStorageOptions) -> Result<(Self, bool), BrokerError> {
        if options.create_directory {
            let parent = options
                .directory
                .parent()
                .ok_or(BrokerError::InvalidInput)?;
            trusted_ancestry(parent)?;
            trusted_ancestry(&parent.canonicalize().map_err(unavailable)?)?;
            match fs::DirBuilder::new().mode(0o700).create(&options.directory) {
                Ok(()) => {
                    File::open(parent)
                        .map_err(unavailable)?
                        .sync_all()
                        .map_err(unavailable)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(unavailable(error)),
            }
        }
        let parent = fs::symlink_metadata(&options.directory).map_err(unavailable)?;
        private(&parent, true)?;
        trusted_ancestry(&options.directory)?;
        let canonical = options.directory.canonicalize().map_err(unavailable)?;
        trusted_ancestry(&canonical)?;
        let directory = File::open(&canonical).map_err(unavailable)?;
        let opened = directory.metadata().map_err(unavailable)?;
        private(&opened, true)?;
        if identity(&parent) != identity(&opened) {
            return Err(BrokerError::Unavailable);
        }
        let database = canonical.join("broker.sqlite3");
        let created = match fs::symlink_metadata(&database) {
            Ok(metadata) => {
                private(&metadata, false)?;
                false
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&database)
                    .map_err(unavailable)?
                    .sync_all()
                    .map_err(unavailable)?;
                true
            }
            Err(error) => return Err(unavailable(error)),
        };
        let metadata = fs::symlink_metadata(&database).map_err(unavailable)?;
        private(&metadata, false)?;
        // An existing empty/truncated store must never be mistaken for a new empty graph.
        if !created && metadata.len() == 0 {
            return Err(BrokerError::Unavailable);
        }
        let path = Self {
            database,
            directory,
            identity: identity(&metadata),
            directory_identity: identity(&opened),
        };
        path.verify(options)?;
        Ok((path, created))
    }

    pub(super) fn verify(&self, options: &BrokerStorageOptions) -> Result<(), BrokerError> {
        let parent = self.database.parent().ok_or(BrokerError::Unavailable)?;
        trusted_ancestry(parent)?;
        let metadata = fs::symlink_metadata(parent).map_err(unavailable)?;
        private(&metadata, true)?;
        if identity(&metadata) != self.directory_identity {
            return Err(BrokerError::Unavailable);
        }
        let metadata = check_file(&self.database, options.max_database_bytes)?;
        if identity(&metadata) != self.identity {
            return Err(BrokerError::Unavailable);
        }
        for suffix in ["-journal", "-wal", "-shm"] {
            let sidecar = parent.join(format!("broker.sqlite3{suffix}"));
            match fs::symlink_metadata(&sidecar) {
                Ok(_) => {
                    if suffix != "-journal" {
                        return Err(BrokerError::Unavailable);
                    }
                    check_file(&sidecar, options.max_database_bytes + 1024 * 1024)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(unavailable(error)),
            }
        }
        Ok(())
    }

    pub(super) fn sync_creation(&self) -> Result<(), BrokerError> {
        self.directory.sync_all().map_err(unavailable)
    }
}

fn check_file(path: &Path, limit: usize) -> Result<fs::Metadata, BrokerError> {
    let metadata = fs::symlink_metadata(path).map_err(unavailable)?;
    private(&metadata, false)?;
    if metadata.len() > limit as u64 {
        return Err(BrokerError::Quota);
    }
    Ok(metadata)
}
fn private(metadata: &fs::Metadata, directory: bool) -> Result<(), BrokerError> {
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.file_type().is_symlink()
        || if directory {
            !metadata.is_dir() || metadata.mode() & 0o7777 != 0o700
        } else {
            !metadata.is_file() || metadata.mode() & 0o7777 != 0o600 || metadata.nlink() != 1
        }
    {
        return Err(BrokerError::Unavailable);
    }
    Ok(())
}
fn identity(metadata: &fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn trusted_ancestry(path: &Path) -> Result<(), BrokerError> {
    let owner = rustix::process::geteuid().as_raw();
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(unavailable)?;
        // Otherwise a different OS user could rename an ancestor between verification and
        // SQLite opening its rollback journal. Root and the host's own UID are trusted here.
        if metadata.uid() != 0 && metadata.uid() != owner {
            return Err(BrokerError::Unavailable);
        }
        // Root/host-owned aliases such as macOS /var are permitted; canonical ancestry is
        // checked separately. A sticky temporary directory protects its owned children.
        if !metadata.file_type().is_symlink()
            && (!metadata.is_dir()
                || (metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0))
        {
            return Err(BrokerError::Unavailable);
        }
    }
    Ok(())
}
fn unavailable(_: std::io::Error) -> BrokerError {
    BrokerError::Unavailable
}
