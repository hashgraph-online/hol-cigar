//! Windows implementation and local safety proofs.

use crate::pointer::bounded_utf16_to_string;
use std::ffi::{OsStr, c_void};
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
use std::path::Path;
use std::ptr::null_mut;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{
    ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetNamedSecurityInfoW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    IsValidAcl, IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW, OPEN_ALWAYS, OPEN_EXISTING,
    READ_CONTROL,
};
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

const MAX_SID_TEXT_UNITS: usize = 256;
const MAX_PIPE_INSTANCES: usize = 64;
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
const SID_FIXED_BYTES: usize = 8;
const SID_SUBAUTHORITY_BYTES: usize = 4;

struct LocalAllocation(*mut c_void);

impl LocalAllocation {
    fn new(pointer: *mut c_void) -> io::Result<Self> {
        if pointer.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(pointer))
        }
    }

    const fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: this wrapper is constructed only from pointers returned by Windows APIs whose
        // contract assigns ownership to the caller through `LocalFree`. It is non-clone and frees
        // the allocation exactly once during drop.
        unsafe {
            let _result: HLOCAL = LocalFree(self.0);
        }
    }
}

/// Resolves the canonical directory owner's textual SID using an owned security descriptor.
pub fn file_owner_sid(path: &Path) -> io::Result<String> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "project path must be absolute",
        ));
    }
    let canonical = path.canonicalize()?;
    let wide = null_terminated(canonical.as_os_str());
    let mut owner: PSID = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `wide` is a live NUL-terminated UTF-16 buffer; output pointers refer to local
    // variables. Unrequested group/DACL/SACL outputs are null. On success Windows returns one
    // `LocalAlloc` security descriptor retained below until the owner SID has been converted.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _descriptor = LocalAllocation::new(descriptor)?;
    if owner.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "project owner SID is absent",
        ));
    }
    sid_to_string(owner)
}

/// Creates a new regular credential file with a protected DACL granting only its parent owner.
///
/// The file is opened with create-new semantics and the returned handle is validated before it is
/// exposed, so inherited directory ACEs can never become part of the credential boundary.
pub fn create_owner_only_credential_file(path: &Path) -> io::Result<File> {
    let owner_sid = credential_owner_sid(path)?;
    let descriptor = owner_only_file_descriptor(&owner_sid)?;
    let wide_path = null_terminated(path.as_os_str());
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).map_err(|_error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "security attributes size overflow",
            )
        })?,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    // SAFETY: the path and security descriptor buffers remain live through `CreateFileW`; the
    // security attributes have the exact Windows representation and do not escape. A successful
    // call transfers one owned kernel handle, which is immediately wrapped by `File` below.
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
            0,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `CreateFileW` returned a fresh, valid, exclusively owned handle. `File` assumes sole
    // ownership and closes it exactly once, including if the validation below fails.
    let file = unsafe { File::from_raw_handle(handle) };
    validate_owner_only_handle(&file, &owner_sid, true)?;
    if !file.metadata()?.is_file() {
        return Err(unsafe_credential_acl());
    }
    Ok(file)
}

/// Opens an existing regular credential file only when its owner and protected DACL are safe.
///
/// ACL validation is performed against the same handle returned to the caller, preventing a path
/// replacement between permission validation and reading credential bytes.
pub fn open_owner_only_credential_file(path: &Path) -> io::Result<File> {
    let owner_sid = credential_owner_sid(path)?;
    let wide_path = null_terminated(path.as_os_str());
    // SAFETY: the path is a live NUL-terminated UTF-16 buffer. Null security attributes and
    // template handles are permitted for `OPEN_EXISTING`. A successful handle is owned below.
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful `CreateFileW` result is a fresh owned handle and is transferred once
    // into `File`, which closes it on every subsequent error path.
    let file = unsafe { File::from_raw_handle(handle) };
    validate_owner_only_handle(&file, &owner_sid, true)?;
    if !file.metadata()?.is_file() {
        return Err(unsafe_credential_acl());
    }
    Ok(file)
}

/// Opens or atomically creates an owner-only regular file suitable for cross-process locking.
///
/// All cooperating processes may open the file concurrently; the caller must still acquire the
/// operating-system file lock before entering its critical section.
pub fn open_or_create_owner_only_lock_file(path: &Path) -> io::Result<File> {
    let owner_sid = credential_owner_sid(path)?;
    let descriptor = owner_only_file_descriptor(&owner_sid)?;
    let wide_path = null_terminated(path.as_os_str());
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).map_err(|_error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "security attributes size overflow",
            )
        })?,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    // SAFETY: the path and protected descriptor are live NUL-terminated/owned buffers for the
    // duration of `CreateFileW`. `OPEN_ALWAYS` applies the descriptor only to a newly created
    // file; an existing file is rejected below unless its handle has the exact protected ACL.
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &attributes,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful call returned one fresh owned handle, transferred exactly once to
    // `File`; validation errors still close it through `File::drop`.
    let file = unsafe { File::from_raw_handle(handle) };
    validate_owner_only_handle(&file, &owner_sid, true)?;
    if !file.metadata()?.is_file() {
        return Err(unsafe_credential_acl());
    }
    Ok(file)
}

/// Verifies that one canonical directory has a protected DACL granting only its owner.
pub fn validate_owner_only_directory(path: &Path) -> io::Result<()> {
    if !path.is_absolute() || path.canonicalize()? != path {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory path must be absolute and canonical",
        ));
    }
    let owner_sid = file_owner_sid(path)?;
    let wide_path = null_terminated(path.as_os_str());
    // SAFETY: `wide_path` remains live and NUL-terminated. Backup semantics permits a directory
    // handle, while open-reparse-point ensures a junction or symlink itself is inspected.
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful call returned one fresh owned handle, transferred exactly once.
    let directory = unsafe { File::from_raw_handle(handle) };
    validate_owner_only_handle(&directory, &owner_sid, false)?;
    if !directory.metadata()?.is_dir() {
        return Err(unsafe_credential_acl());
    }
    Ok(())
}

/// Atomically creates a canonical owner-only directory, or validates an existing one.
pub fn create_or_validate_owner_only_directory(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_metadata) => return validate_owner_only_directory(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let owner_sid = credential_owner_sid(path)?;
    let descriptor = owner_only_file_descriptor(&owner_sid)?;
    let wide_path = null_terminated(path.as_os_str());
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).map_err(|_error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "security attributes size overflow",
            )
        })?,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    // SAFETY: the path and protected descriptor remain live through `CreateDirectoryW`; the
    // security attributes do not escape and Windows copies the descriptor into the new object.
    let created = unsafe { CreateDirectoryW(wide_path.as_ptr(), &attributes) };
    if created == 0 {
        let error = io::Error::last_os_error();
        if std::fs::symlink_metadata(path).is_err() {
            return Err(error);
        }
    }
    validate_owner_only_directory(path)
}

/// Atomically publishes one owner-only file over another with write-through durability.
pub fn replace_owner_only_file_write_through(source: &Path, destination: &Path) -> io::Result<()> {
    let source_parent = source
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "source parent is absent"))?;
    let destination_parent = destination.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "destination parent is absent")
    })?;
    if source_parent != destination_parent {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "replacement files must share one directory",
        ));
    }
    validate_owner_only_directory(source_parent)?;
    drop(open_owner_only_credential_file(source)?);
    match std::fs::symlink_metadata(destination) {
        Ok(_metadata) => drop(open_owner_only_credential_file(destination)?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let source_wide = null_terminated(source.as_os_str());
    let destination_wide = null_terminated(destination.as_os_str());
    // SAFETY: both bounded path buffers are live and NUL-terminated for the call. Both parents
    // were proven identical and owner-only, and all open validation handles were dropped before
    // the same-volume atomic replacement. `MOVEFILE_WRITE_THROUGH` waits for durable completion.
    let replaced = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if replaced == 0 {
        return Err(io::Error::last_os_error());
    }
    drop(open_owner_only_credential_file(destination)?);
    Ok(())
}

fn credential_owner_sid(path: &Path) -> io::Result<String> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential path must be absolute",
        ));
    }
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential path must name a file",
        )
    })?;
    if file_name
        .encode_wide()
        .any(|unit| unit == 0 || unit == u16::from(b':'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential filename is invalid",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "credential parent is absent")
    })?;
    let canonical = parent.canonicalize()?;
    if canonical != parent {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential parent must be canonical",
        ));
    }
    file_owner_sid(&canonical)
}

fn owner_only_file_descriptor(owner_sid: &str) -> io::Result<LocalAllocation> {
    if !safe_sid_text(owner_sid) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential owner SID is invalid",
        ));
    }
    let sddl = format!("O:{owner_sid}D:P(A;;FA;;;{owner_sid})");
    let wide_sddl = null_terminated(OsStr::new(&sddl));
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `wide_sddl` is NUL-terminated and live for the call, and the output points to a
    // valid local variable. Windows allocates the self-relative descriptor with `LocalAlloc`.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    LocalAllocation::new(descriptor)
}

fn validate_owner_only_handle(
    file: &File,
    expected_owner: &str,
    require_single_link: bool,
) -> io::Result<()> {
    if !safe_sid_text(expected_owner) {
        return Err(unsafe_credential_acl());
    }
    let expected_text = null_terminated(OsStr::new(expected_owner));
    let mut expected_sid: PSID = null_mut();
    // SAFETY: the expected SID is a bounded, validated, NUL-terminated UTF-16 buffer. Windows
    // returns a separate `LocalAlloc` SID whose lifetime is guarded below.
    let converted = unsafe { ConvertStringSidToSidW(expected_text.as_ptr(), &mut expected_sid) };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    let expected_sid = LocalAllocation::new(expected_sid)?;

    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `file` owns a live kernel file handle. All requested outputs point to valid local
    // variables. Windows returns one `LocalAlloc` descriptor retaining the owner and DACL storage.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let descriptor = LocalAllocation::new(descriptor)?;
    if owner.is_null() || dacl.is_null() {
        return Err(unsafe_credential_acl());
    }
    // SAFETY: both SIDs are non-null and remain inside live LocalAlloc buffers. Windows validates
    // their structure before the equality comparison.
    if unsafe { IsValidSid(owner) } == 0
        || unsafe { IsValidSid(expected_sid.as_ptr()) } == 0
        || unsafe { EqualSid(owner, expected_sid.as_ptr()) } == 0
    {
        return Err(unsafe_credential_acl());
    }

    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: `descriptor` owns the complete security descriptor returned by Windows and remains
    // live. Both scalar outputs point to initialized local storage.
    if unsafe { GetSecurityDescriptorControl(descriptor.as_ptr(), &mut control, &mut revision) }
        == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Err(unsafe_credential_acl());
    }

    let mut information = ACL_SIZE_INFORMATION::default();
    let information_size =
        u32::try_from(std::mem::size_of::<ACL_SIZE_INFORMATION>()).map_err(|_error| {
            io::Error::new(io::ErrorKind::InvalidData, "ACL information size overflow")
        })?;
    // SAFETY: `dacl` points inside the live descriptor; the fixed-size output buffer and its exact
    // byte length are valid, and the requested information class matches that buffer type.
    if unsafe { IsValidAcl(dacl) } == 0
        || unsafe {
            GetAclInformation(
                dacl,
                (&mut information as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
                information_size,
                AclSizeInformation,
            )
        } == 0
        || information.AceCount != 1
    {
        return Err(unsafe_credential_acl());
    }

    let mut ace_pointer: *mut c_void = null_mut();
    // SAFETY: the preceding ACL query proved there is exactly one ACE at index zero, and the DACL
    // storage remains live inside `descriptor` for the entire inspection below.
    if unsafe { GetAce(dacl, 0, &mut ace_pointer) } == 0 || ace_pointer.is_null() {
        return Err(unsafe_credential_acl());
    }
    // SAFETY: `GetAce` returned ACE zero inside an ACL that `IsValidAcl` accepted, so the fixed
    // header is present and aligned. Its declared size is checked before the larger typed access.
    let header = unsafe { &*ace_pointer.cast::<ACE_HEADER>() };
    let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
        || header.AceFlags != 0
        || usize::from(header.AceSize) < sid_offset.saturating_add(SID_FIXED_BYTES)
    {
        return Err(unsafe_credential_acl());
    }
    // SAFETY: the validated ACE type and size establish the documented `ACCESS_ALLOWED_ACE`
    // representation, and its storage remains live inside `descriptor`.
    let ace = unsafe { &*ace_pointer.cast::<ACCESS_ALLOWED_ACE>() };
    let ace_sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
    // SAFETY: the preceding size check proves the complete fixed SID header is inside this valid
    // ACE, so its one-byte subauthority count at offset one can be inspected without overread.
    let subauthority_count = usize::from(unsafe { *ace_sid.cast::<u8>().add(1) });
    let sid_length =
        SID_FIXED_BYTES.saturating_add(subauthority_count.saturating_mul(SID_SUBAUTHORITY_BYTES));
    if sid_offset.saturating_add(sid_length) > usize::from(header.AceSize) {
        return Err(unsafe_credential_acl());
    }
    // SAFETY: the typed ACE layout places the variable-length SID at `SidStart`; the ACL and
    // descriptor are still live, and the bounded length calculation proves the entire SID lies
    // within the ACE. A valid SID is required before comparing it with the owner.
    if unsafe { IsValidSid(ace_sid) } == 0 || unsafe { EqualSid(ace_sid, owner) } == 0 {
        return Err(unsafe_credential_acl());
    }
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `file` owns a live handle and the fixed-layout output points to initialized local
    // storage for the entire call.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (require_single_link && information.nNumberOfLinks != 1)
    {
        return Err(unsafe_credential_acl());
    }
    Ok(())
}

fn unsafe_credential_acl() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "credential file ACL is not owner-only",
    )
}

/// Creates one byte-mode local-only named-pipe server whose protected DACL grants only `owner_sid`.
pub fn create_user_only_named_pipe(
    pipe_name: &str,
    owner_sid: &str,
    first_instance: bool,
) -> io::Result<NamedPipeServer> {
    if !safe_pipe_name(pipe_name) || !safe_sid_text(owner_sid) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "named-pipe security input is invalid",
        ));
    }
    let sddl = format!("O:{owner_sid}D:P(A;;GA;;;{owner_sid})");
    let wide_sddl = null_terminated(OsStr::new(&sddl));
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `wide_sddl` is NUL-terminated and lives through the call. The output pointer is a
    // valid local variable. Windows returns a self-relative descriptor allocated with LocalAlloc.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    let descriptor = LocalAllocation::new(descriptor)?;
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).map_err(|_error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "security attributes size overflow",
            )
        })?,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first_instance)
        .reject_remote_clients(true)
        .max_instances(MAX_PIPE_INSTANCES)
        .in_buffer_size(PIPE_BUFFER_BYTES)
        .out_buffer_size(PIPE_BUFFER_BYTES);
    // SAFETY: `attributes` has the exact Windows representation, its descriptor allocation stays
    // live until `CreateNamedPipeW` returns, and Tokio copies the security descriptor into the new
    // kernel object during this call. Neither pointer escapes the function.
    unsafe {
        options.create_with_security_attributes_raw(
            pipe_name,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
        )
    }
}

fn sid_to_string(sid: PSID) -> io::Result<String> {
    let mut text_pointer = null_mut();
    // SAFETY: `sid` is checked non-null and points inside the live descriptor owned by the caller.
    // Windows returns a separate LocalAlloc UTF-16 string through `text_pointer`.
    let converted = unsafe { ConvertSidToStringSidW(sid, &mut text_pointer) };
    if converted == 0 {
        return Err(io::Error::last_os_error());
    }
    let allocation = LocalAllocation::new(text_pointer.cast::<c_void>())?;
    let pointer = allocation.as_ptr().cast::<u16>();
    // SAFETY: the Windows conversion contract returns a live NUL-terminated UTF-16 allocation.
    // `allocation` retains it throughout the bounded scan and decode.
    unsafe { bounded_utf16_to_string(pointer, MAX_SID_TEXT_UNITS) }
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidData, message))
}

fn null_terminated(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn safe_pipe_name(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix(r"\\.\pipe\cigar-") else {
        return false;
    };
    !suffix.is_empty()
        && value.len() <= 256
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn safe_sid_text(value: &str) -> bool {
    value.starts_with("S-1-")
        && value.len() <= MAX_SID_TEXT_UNITS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'S' || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::{
        LocalAllocation, create_or_validate_owner_only_directory,
        create_owner_only_credential_file, create_user_only_named_pipe, file_owner_sid,
        null_terminated, open_or_create_owner_only_lock_file, open_owner_only_credential_file,
        replace_owner_only_file_write_through, safe_pipe_name,
    };
    use std::ffi::OsStr;
    use std::io::Write as _;
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        SetFileSecurityW,
    };

    fn replace_with_broadened_dacl(path: &std::path::Path, owner_sid: &str) -> std::io::Result<()> {
        let sddl = format!("D:P(A;;FA;;;{owner_sid})(A;;FR;;;WD)");
        let wide_sddl = null_terminated(OsStr::new(&sddl));
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: the SDDL is NUL-terminated and live through conversion. Windows returns a
        // LocalAlloc descriptor, which the non-clone allocation guard frees exactly once.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide_sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if converted == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let descriptor = LocalAllocation::new(descriptor)?;
        let wide_path = null_terminated(path.as_os_str());
        // SAFETY: the canonical path is a live NUL-terminated UTF-16 buffer and the self-relative
        // descriptor remains allocated for the entire call. Only DACL information is applied.
        let updated = unsafe {
            SetFileSecurityW(
                wide_path.as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.as_ptr(),
            )
        };
        if updated == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[tokio::test]
    async fn current_directory_owner_can_secure_a_first_pipe_instance()
    -> Result<(), Box<dyn std::error::Error>> {
        let current = std::env::current_dir()?.canonicalize()?;
        let owner = file_owner_sid(&current)?;
        assert!(owner.starts_with("S-1-"));
        let name = format!(r"\\.\pipe\cigar-platform-test-{}", std::process::id());
        assert!(safe_pipe_name(&name));
        assert!(!safe_pipe_name(r"\\.\pipe\cigar-parent\child"));
        assert!(!safe_pipe_name(r"\\server\pipe\cigar-platform-test"));
        let server = create_user_only_named_pipe(&name, &owner, true)?;
        assert!(create_user_only_named_pipe(&name, &owner, true).is_err());
        drop(server);
        Ok(())
    }

    #[test]
    fn credential_file_is_protected_and_broadened_dacl_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "cigar-credential-acl-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&directory)?;
        let directory = directory.canonicalize()?;
        let path = directory.join("local.token");
        let owner_sid = file_owner_sid(&directory)?;

        let mut created = create_owner_only_credential_file(&path)?;
        created.write_all(b"bounded-test-token")?;
        created.sync_all()?;
        drop(created);
        drop(open_owner_only_credential_file(&path)?);

        replace_with_broadened_dacl(&path, &owner_sid)?;
        assert!(open_owner_only_credential_file(&path).is_err());
        std::fs::remove_file(path)?;
        std::fs::remove_dir(directory)?;
        Ok(())
    }

    #[test]
    fn checkpoint_directory_lock_replace_and_hardlink_guards_are_owner_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "cigar-checkpoint-acl-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        let directory = root.join("owner-only");
        create_or_validate_owner_only_directory(&directory)?;

        let lock_path = directory.join(".checkpoints.lock");
        let first_lock = open_or_create_owner_only_lock_file(&lock_path)?;
        let second_lock = open_or_create_owner_only_lock_file(&lock_path)?;
        drop(first_lock);
        drop(second_lock);

        let checkpoint = directory.join("checkpoints.json");
        let mut initial = create_owner_only_credential_file(&checkpoint)?;
        initial.write_all(b"initial")?;
        initial.sync_all()?;
        drop(initial);
        let replacement = directory.join(".replacement");
        let mut replacement_file = create_owner_only_credential_file(&replacement)?;
        replacement_file.write_all(b"replacement")?;
        replacement_file.sync_all()?;
        drop(replacement_file);
        replace_owner_only_file_write_through(&replacement, &checkpoint)?;
        assert_eq!(std::fs::read(&checkpoint)?, b"replacement");

        let hardlink = directory.join("checkpoint-hardlink");
        std::fs::hard_link(&checkpoint, &hardlink)?;
        assert!(open_owner_only_credential_file(&checkpoint).is_err());
        std::fs::remove_file(hardlink)?;
        std::fs::remove_file(checkpoint)?;
        std::fs::remove_file(lock_path)?;
        std::fs::remove_dir(directory)?;
        std::fs::remove_dir(root)?;
        Ok(())
    }
}
