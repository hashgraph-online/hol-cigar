//! Audited Windows local-IPC and credential-file ACL adapter.
//!
//! CIGAR otherwise forbids unsafe Rust. Windows exposes file ownership, file creation security, and
//! named-pipe security descriptors through pointer-based APIs, so this crate is the single narrow
//! exception allowed by the implementation specification. It converts owned UTF-16 buffers,
//! checks every OS result, bounds returned strings, frees every `LocalAlloc` result, and exposes
//! only safe functions.

#![cfg_attr(not(windows), allow(dead_code))]

mod pointer;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{
    PrivateStorageDirectory, StorageFileIdentity, create_or_validate_owner_only_directory,
    create_owner_only_credential_file, file_owner_sid, open_or_create_owner_only_lock_file,
    open_owner_only_credential_file, replace_owner_only_file_write_through,
    validate_owner_only_directory,
};

#[cfg(all(windows, feature = "named-pipe"))]
pub use windows::create_user_only_named_pipe;
