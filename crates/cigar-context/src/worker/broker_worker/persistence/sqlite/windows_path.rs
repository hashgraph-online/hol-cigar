//! Handle-pinned private NTFS storage; all Windows FFI stays in the audited platform adapter.
use super::{BrokerError, BrokerStorageOptions};
use cigar_windows_ipc::{PrivateStorageDirectory, StorageFileIdentity};
use std::fs::File;
use std::path::PathBuf;

pub(super) struct PrivatePath {
    pub(super) database: PathBuf,
    directory: PrivateStorageDirectory,
    file: File,
    identity: StorageFileIdentity,
}

impl PrivatePath {
    pub(super) fn prepare(options: &BrokerStorageOptions) -> Result<(Self, bool), BrokerError> {
        let directory = PrivateStorageDirectory::open(&options.directory, options.create_directory)
            .map_err(unavailable)?;
        let (file, identity, created) = directory
            .open_or_create_file("broker.sqlite3")
            .map_err(unavailable)?;
        if !created && file.metadata().map_err(unavailable)?.len() == 0 {
            return Err(BrokerError::Unavailable);
        }
        let path = Self {
            database: directory.path().join("broker.sqlite3"),
            directory,
            file,
            identity,
        };
        path.verify(options)?;
        Ok((path, created))
    }

    pub(super) fn verify(&self, options: &BrokerStorageOptions) -> Result<(), BrokerError> {
        self.directory.verify().map_err(unavailable)?;
        let (identity, bytes) = self
            .directory
            .inspect_file("broker.sqlite3")
            .map_err(unavailable)?;
        if identity != self.identity {
            return Err(BrokerError::Unavailable);
        }
        if bytes > options.max_database_bytes as u64 {
            return Err(BrokerError::Quota);
        }
        for suffix in ["-journal", "-wal", "-shm"] {
            match self
                .directory
                .inspect_file(&format!("broker.sqlite3{suffix}"))
            {
                Ok((_, bytes)) => {
                    if suffix != "-journal" {
                        return Err(BrokerError::Unavailable);
                    }
                    if bytes > (options.max_database_bytes + 1024 * 1024) as u64 {
                        return Err(BrokerError::Quota);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(unavailable(error)),
            }
        }
        Ok(())
    }

    pub(super) fn sync_creation(&self) -> Result<(), BrokerError> {
        // Flush the retained write-through file after SQLite commits its initialization.
        // This is not Unix directory fsync or a claim of qualified hardware power-loss recovery.
        self.file.sync_all().map_err(unavailable)
    }
}

fn unavailable(_: std::io::Error) -> BrokerError {
    BrokerError::Unavailable
}
