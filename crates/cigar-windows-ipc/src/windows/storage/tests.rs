use super::{PrivateStorageDirectory, process_owner_sid, process_token_sid, validate_path};
use crate::windows::{
    AclPolicy, LocalAllocation, create_or_validate_owner_only_directory, file_owner_sid,
    null_terminated, validate_owner_acl,
};
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write as _};
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::Path;
use std::ptr::null_mut;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SetFileSecurityW, TokenOwner,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
use windows_sys::Win32::System::SystemServices::IO_REPARSE_TAG_MOUNT_POINT;

fn junction(link: &Path, target: &Path) -> io::Result<()> {
    let canonical = target.canonicalize()?;
    let canonical = canonical
        .to_str()
        .ok_or_else(|| io::Error::other("invalid fixture path"))?;
    let target = canonical.strip_prefix(r"\\?\").unwrap_or(canonical);
    let substitute: Vec<_> = format!(r"\??\{target}").encode_utf16().collect();
    let bytes = substitute.len() * 2;
    if bytes > 16 * 1024 - 20 {
        return Err(io::Error::other("fixture path exceeds reparse bound"));
    }
    // Mount-point REPARSE_DATA_BUFFER: an 8-byte outer header followed by four
    // u16 offsets/lengths, the substitute name plus NUL, and an empty print name plus NUL.
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    buffer.extend_from_slice(&((bytes + 12) as u16).to_le_bytes());
    for field in [0, 0, bytes as u16, (bytes + 2) as u16, 0] {
        buffer.extend_from_slice(&field.to_le_bytes());
    }
    for unit in substitute.into_iter().chain([0, 0]) {
        buffer.extend_from_slice(&unit.to_le_bytes());
    }
    fs::create_dir(link)?;
    let directory = fs::OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(link)?;
    let mut returned = 0;
    // SAFETY: the owned directory handle and complete bounded mount-point buffer remain live.
    // The synchronous IOCTL receives the exact buffer length, a valid scalar output and no
    // output/overlapped buffer. Only the newly created test directory is changed.
    if unsafe {
        DeviceIoControl(
            directory.as_raw_handle(),
            FSCTL_SET_REPARSE_POINT,
            buffer.as_ptr().cast(),
            buffer.len() as u32,
            null_mut(),
            0,
            &mut returned,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn broaden_acl(path: &Path) -> io::Result<()> {
    let owner = process_owner_sid()?;
    let sddl = null_terminated(OsStr::new(&format!("D:P(A;;FA;;;{owner})(A;;FR;;;WD)")));
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: NUL-terminated SDDL lives through conversion; the resulting LocalAlloc descriptor
    // is placed in the same owning guard as production ACL handling.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor = LocalAllocation::new(descriptor)?;
    let path = null_terminated(path.as_os_str());
    // SAFETY: both NUL-terminated path and descriptor remain allocated. This test changes only
    // the DACL of its own temporary fixture, to demonstrate fail-closed validation.
    if unsafe {
        SetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.as_ptr(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[test]
fn storage_sidecars_inherit_private_access_and_files_are_never_truncated() -> io::Result<()> {
    let parent = tempfile::tempdir()?;
    let path = parent.path().join("store");
    let directory = PrivateStorageDirectory::open(&path, true)?;
    let (mut file, identity, created) = directory.open_or_create_file("broker.sqlite3")?;
    assert!(created);
    file.write_all(b"evidence")?;
    file.sync_all()?;
    let (second, same, created) = directory.open_or_create_file("broker.sqlite3")?;
    assert!(!created);
    assert_eq!(identity, same);
    assert_eq!(directory.inspect_file("broker.sqlite3")?, (identity, 8));
    let journal = path.join("broker.sqlite3-journal");
    fs::write(&journal, b"private journal")?;
    // The OS uses TokenOwner for inherited files; elevated tokens may differ from TokenUser.
    let default_owner = process_token_sid(TokenOwner)?;
    assert_eq!(file_owner_sid(&journal)?, default_owner);
    if default_owner == "S-1-5-32-544" && default_owner != process_owner_sid()? {
        assert!(
            validate_owner_acl(
                &fs::File::open(&journal)?,
                &process_owner_sid()?,
                true,
                AclPolicy::StorageFile {
                    allow_admin_owner: false
                },
            )
            .is_err()
        );
    }
    assert_eq!(directory.inspect_file("broker.sqlite3-journal")?.1, 15);
    fs::remove_file(&journal)?;
    drop((second, file, directory));
    let directory = PrivateStorageDirectory::open(&path, false)?;
    assert_eq!(directory.inspect_file("broker.sqlite3")?, (identity, 8));
    Ok(())
}

#[test]
fn held_directories_and_database_cannot_be_replaced_or_opened_for_reparse_writes() -> io::Result<()>
{
    let parent = tempfile::tempdir()?;
    let path = parent.path().join("store");
    let directory = PrivateStorageDirectory::open(&path, true)?;
    let (file, _, _) = directory.open_or_create_file("broker.sqlite3")?;
    assert!(fs::rename(&path, parent.path().join("replacement")).is_err());
    assert!(fs::rename(parent.path(), parent.path().with_extension("replacement")).is_err());
    assert!(fs::rename(path.join("broker.sqlite3"), path.join("renamed")).is_err());
    assert!(
        fs::OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(parent.path())
            .is_err()
    );
    directory.verify()?;
    drop(file);
    drop(directory);
    let writable = fs::OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(parent.path())?;
    assert!(PrivateStorageDirectory::open(&path, false).is_err());
    drop(writable);
    fs::rename(&path, parent.path().join("replacement"))?;
    Ok(())
}

#[test]
fn ambient_or_noninheritable_directories_are_rejected_without_acl_repair() -> io::Result<()> {
    let parent = tempfile::tempdir()?;
    let ambient = parent.path().join("ambient");
    fs::create_dir(&ambient)?;
    for create in [false, true] {
        assert!(PrivateStorageDirectory::open(&ambient, create).is_err());
    }
    let credential_directory = parent.path().canonicalize()?.join("credential-directory");
    create_or_validate_owner_only_directory(&credential_directory)?;
    assert!(PrivateStorageDirectory::open(&credential_directory, false).is_err());
    let private = parent.path().join("private");
    let directory = PrivateStorageDirectory::open(&private, true)?;
    broaden_acl(&private)?;
    assert!(directory.verify().is_err());
    assert!(PrivateStorageDirectory::open(&private, true).is_err());
    Ok(())
}

#[test]
fn hardlinks_and_broadened_file_acls_are_rejected() -> io::Result<()> {
    let parent = tempfile::tempdir()?;
    let directory = PrivateStorageDirectory::open(&parent.path().join("store"), true)?;
    let path = directory.path().join("broker.sqlite3");
    let (mut file, _, _) = directory.open_or_create_file("broker.sqlite3")?;
    file.write_all(b"unchanged")?;
    drop(file);
    let alias = directory.path().join("alias");
    fs::hard_link(&path, &alias)?;
    assert!(directory.inspect_file("broker.sqlite3").is_err());
    assert!(directory.open_or_create_file("broker.sqlite3").is_err());
    fs::remove_file(alias)?;
    broaden_acl(&path)?;
    assert!(directory.inspect_file("broker.sqlite3").is_err());
    assert!(directory.open_or_create_file("broker.sqlite3").is_err());
    assert_eq!(fs::read(path)?, b"unchanged");
    Ok(())
}

#[test]
fn invalid_paths_and_device_or_stream_leaf_names_are_rejected_before_io() -> io::Result<()> {
    for path in [
        r"relative",
        r"C:relative",
        r"C:\",
        r"\\server\share\store",
        r"\\?\UNC\server\share\store",
        r"\\.\pipe\store",
        r"C:\parent\..\store",
        r"C:\parent\store:alternate",
        r"C:\parent\store.",
        "C:\\parent\\nul\0suffix",
    ] {
        assert!(
            validate_path(Path::new(path)).is_err(),
            "accepted invalid path"
        );
    }
    let parent = tempfile::tempdir()?;
    let directory = PrivateStorageDirectory::open(&parent.path().join("store"), true)?;
    for name in [
        "", ".", "..", "NUL", "COM1", "LPT1.txt", "x.", "x/y", "x:y", "\\path",
    ] {
        assert!(
            directory.open_or_create_file(name).is_err(),
            "accepted invalid leaf"
        );
    }
    assert_eq!(fs::read_dir(directory.path())?.count(), 0);
    Ok(())
}

#[test]
fn directory_junctions_are_rejected_at_the_leaf_and_in_ancestors() -> io::Result<()> {
    let parent = tempfile::tempdir()?;
    let target = parent.path().join("target");
    let directory = PrivateStorageDirectory::open(&target, true)?;
    let (mut file, _, _) = directory.open_or_create_file("broker.sqlite3")?;
    file.write_all(b"private evidence")?;
    drop((file, directory));
    let alias = parent.path().join("alias");
    junction(&alias, &target)?;
    assert!(PrivateStorageDirectory::open(&alias, false).is_err());
    let child = target.join("child");
    drop(PrivateStorageDirectory::open(&child, true)?);
    assert!(PrivateStorageDirectory::open(&alias.join("child"), false).is_err());
    assert_eq!(
        fs::read(target.join("broker.sqlite3"))?,
        b"private evidence"
    );
    fs::remove_dir(alias)?;
    Ok(())
}
