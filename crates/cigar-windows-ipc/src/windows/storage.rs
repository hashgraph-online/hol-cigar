//! Pinned local-NTFS storage with an inheritable owner-only DACL for SQLite sidecars.
use super::{
    AclPolicy, LocalAllocation, null_terminated, owner_only_file_descriptor, sid_to_string,
    unsafe_credential_acl, validate_owner_acl,
};
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_INSUFFICIENT_BUFFER, GENERIC_READ,
    GENERIC_WRITE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, IsValidSid, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, GetDriveTypeW, GetFileInformationByHandle,
    GetVolumeInformationByHandleW, OPEN_EXISTING, READ_CONTROL,
};
use windows_sys::Win32::System::SystemServices::FILE_PERSISTENT_ACLS;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;

#[cfg(test)]
mod tests;

/// Same-volume NTFS identity, obtained from an opened handle rather than path metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageFileIdentity {
    volume: u32,
    index: u64,
}

/// Owner-only storage on a fixed local NTFS volume. All directory ancestors remain pinned
/// without write/delete sharing, preventing reparse changes and rename/replacement while held.
/// This does not sandbox the current user or privileged administrators.
pub struct PrivateStorageDirectory {
    path: PathBuf,
    owner: String,
    directories: Vec<File>,
}

impl PrivateStorageDirectory {
    /// Validate existing private storage, or explicitly create only its final directory.
    /// Existing ACLs are never rewritten. UNC/device paths, reparse points and other filesystems
    /// are rejected. Directory protection includes inheritable ACEs for newly created sidecars.
    pub fn open(path: &Path, create: bool) -> io::Result<Self> {
        validate_path(path)?;
        let owner = process_owner_sid()?;
        let mut ancestors: Vec<_> = path.ancestors().map(Path::to_path_buf).collect();
        ancestors.reverse();
        let mut directories = Vec::new();
        for ancestor in &ancestors {
            if ancestor == path && create {
                create_directory(ancestor, &owner)?;
            }
            let directory = open_directory(ancestor)?;
            let information = information(&directory)?;
            if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            {
                return Err(unsafe_credential_acl());
            }
            if directories.is_empty() {
                validate_volume(ancestor, &directory)?;
            }
            directories.push(directory);
        }
        let last = directories.last().ok_or_else(unsafe_credential_acl)?;
        validate_owner_acl(last, &owner, false, AclPolicy::StorageDirectory)?;
        // Every component was opened and pinned before canonicalization; it cannot follow an
        // unexamined junction or switch to a different directory during this call.
        let result = Self {
            path: path.canonicalize()?,
            owner,
            directories,
        };
        result.verify()?;
        Ok(result)
    }

    /// The canonical, pinned directory path supplied to the local SQLite VFS.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Recheck live directory handles and the root's exact owner-only inheritance policy.
    pub fn verify(&self) -> io::Result<()> {
        for directory in &self.directories {
            let information = information(directory)?;
            if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            {
                return Err(unsafe_credential_acl());
            }
        }
        validate_owner_acl(
            self.directories.last().ok_or_else(unsafe_credential_acl)?,
            &self.owner,
            false,
            AclPolicy::StorageDirectory,
        )
    }

    /// Open/create one regular private file without truncation, retaining a no-delete-sharing
    /// handle compatible with SQLite reads/writes. Returns the handle, identity and created flag.
    pub fn open_or_create_file(&self, name: &str) -> io::Result<(File, StorageFileIdentity, bool)> {
        self.verify()?;
        let path = self.leaf(name)?;
        let descriptor = owner_only_file_descriptor(&self.owner)?;
        let attributes = attributes(&descriptor)?;
        let wide = null_terminated(path.as_os_str());
        // SAFETY: owned, NUL-terminated path and security descriptor live through the call.
        // CREATE_NEW never truncates existing data; the successful handle is wrapped once below.
        let mut handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &attributes,
                CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
                null_mut(),
            )
        };
        let created = handle != INVALID_HANDLE_VALUE;
        if !created {
            let error = io::Error::last_os_error();
            if !matches!(error.raw_os_error(), Some(value) if value == ERROR_FILE_EXISTS as i32 || value == ERROR_ALREADY_EXISTS as i32)
            {
                return Err(error);
            }
            // SAFETY: same live path; OPEN_EXISTING cannot create/truncate a replacement.
            handle = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
                    null_mut(),
                )
            };
        }
        let file = owned_file(handle)?;
        let identity = self.validate_file(&file)?;
        if created {
            file.sync_all()?;
        }
        Ok((file, identity, created))
    }

    /// Inspect a regular single-link sidecar or database without following a reparse point.
    /// A sidecar may inherit the directory's sole owner ACE; broad/conditional ACLs are rejected.
    pub fn inspect_file(&self, name: &str) -> io::Result<(StorageFileIdentity, u64)> {
        self.verify()?;
        let path = self.leaf(name)?;
        let wide = null_terminated(path.as_os_str());
        // SAFETY: owned NUL-terminated path; the fresh handle is wrapped immediately. Delete
        // sharing permits SQLite's normal sidecar removal, after this short inspection finishes.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        let file = owned_file(handle)?;
        Ok((self.validate_file(&file)?, file.metadata()?.len()))
    }

    fn validate_file(&self, file: &File) -> io::Result<StorageFileIdentity> {
        validate_owner_acl(file, &self.owner, true, AclPolicy::StorageFile)?;
        let info = information(file)?;
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            return Err(unsafe_credential_acl());
        }
        Ok(StorageFileIdentity {
            volume: info.dwVolumeSerialNumber,
            index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        })
    }

    fn leaf(&self, name: &str) -> io::Result<PathBuf> {
        let upper = name
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if name.is_empty()
            || name.len() > 128
            || name.ends_with('.')
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
            || matches!(upper.as_str(), "" | "CON" | "PRN" | "AUX" | "NUL")
            || ((upper.starts_with("COM") || upper.starts_with("LPT"))
                && upper.len() == 4
                && upper.bytes().last().is_some_and(|c| c.is_ascii_digit()))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid storage filename",
            ));
        }
        Ok(self.path.join(name))
    }
}

fn validate_path(path: &Path) -> io::Result<()> {
    let local = matches!(path.components().next(), Some(Component::Prefix(prefix))
        if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)));
    if !path.is_absolute()
        || !local
        || path.as_os_str().encode_wide().any(|c| c == 0)
        || path.components().any(|c| match c {
            Component::ParentDir | Component::CurDir => true,
            Component::Normal(name) => name.to_str().is_none_or(|name| {
                name.ends_with(['.', ' '])
                    || name
                        .chars()
                        .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c))
            }),
            _ => false,
        })
        || !matches!(path.components().next_back(), Some(Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "storage requires a local absolute path",
        ));
    }
    Ok(())
}

fn open_directory(path: &Path) -> io::Result<File> {
    let wide = null_terminated(path.as_os_str());
    // SAFETY: the path buffer remains live. Backup semantics opens directories; opening the
    // reparse point itself lets the caller reject it. Omitting write/delete sharing prevents
    // concurrent reparse-point writes and pins this component against rename/replacement.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    owned_file(handle)
}

fn owned_file(handle: windows_sys::Win32::Foundation::HANDLE) -> io::Result<File> {
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: callers supply only fresh successful CreateFileW handles, transferred exactly once.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn information(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut result = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the file owns a live handle and result has the exact initialized OS representation.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut result) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result)
}

fn validate_volume(root: &Path, directory: &File) -> io::Result<()> {
    let wide = null_terminated(root.as_os_str());
    // SAFETY: root is a live NUL-terminated local drive-root path.
    if unsafe { GetDriveTypeW(wide.as_ptr()) } != DRIVE_FIXED {
        return Err(unsafe_credential_acl());
    }
    let mut filesystem = [0_u16; 32];
    let mut flags = 0;
    // SAFETY: the root handle is live, outputs are valid bounded arrays/scalars, optional outputs
    // are null. The fixed array is initialized before Windows fills it.
    if unsafe {
        GetVolumeInformationByHandleW(
            directory.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let count = filesystem
        .iter()
        .position(|c| *c == 0)
        .ok_or_else(unsafe_credential_acl)?;
    let name = String::from_utf16(filesystem.get(..count).ok_or_else(unsafe_credential_acl)?)
        .map_err(|_| unsafe_credential_acl())?;
    if flags & FILE_PERSISTENT_ACLS == 0 || name != "NTFS" {
        return Err(unsafe_credential_acl());
    }
    Ok(())
}

fn attributes(descriptor: &LocalAllocation) -> io::Result<SECURITY_ATTRIBUTES> {
    Ok(SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| unsafe_credential_acl())?,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    })
}

fn create_directory(path: &Path, owner: &str) -> io::Result<()> {
    // SID text comes only from the process token's OS conversion, never from caller input.
    let sddl = format!("O:{owner}D:P(A;OICI;FA;;;{owner})");
    let wide_sddl = null_terminated(std::ffi::OsStr::new(&sddl));
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: bounded generated SDDL is NUL-terminated; the output owns a LocalAlloc descriptor.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor = LocalAllocation::new(descriptor)?;
    let attributes = attributes(&descriptor)?;
    let wide = null_terminated(path.as_os_str());
    // SAFETY: path, security attributes and descriptor live through the call. Existing directory
    // ACLs are not changed; their live handles must pass the exact policy immediately afterwards.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
            return Err(error);
        }
    }
    Ok(())
}

fn process_owner_sid() -> io::Result<String> {
    let mut token = null_mut();
    // SAFETY: GetCurrentProcess yields a valid borrowed pseudo-handle; output receives a new
    // token handle with query-only access. No impersonation/privilege changes are performed.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful OpenProcessToken transfers one owned handle, closed exactly once.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut size = 0;
    // SAFETY: a null/zero buffer requests only the required size, through a valid scalar output.
    let result =
        unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut size) };
    if result != 0
        || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || size as usize > 16 * 1024
        || (size as usize) < std::mem::size_of::<TOKEN_USER>()
    {
        return Err(unsafe_credential_acl());
    }
    let mut buffer = vec![0_usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    let mut written = size;
    // SAFETY: the initialized usize buffer is correctly aligned for TOKEN_USER and has at least
    // size bytes. Windows writes only that capacity and returns the actual required length.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            size,
            &mut written,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if written > size || (written as usize) < std::mem::size_of::<TOKEN_USER>() {
        return Err(unsafe_credential_acl());
    }
    // SAFETY: successful TokenUser query initializes this aligned fixed header inside the buffer.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let offset = (user.User.Sid as usize)
        .checked_sub(buffer.as_ptr() as usize)
        .ok_or_else(unsafe_credential_acl)?;
    if offset
        .checked_add(8)
        .is_none_or(|end| end > written as usize)
    {
        return Err(unsafe_credential_acl());
    }
    // SAFETY: the previous range check proves the full fixed SID header exists in this buffer.
    let count = usize::from(unsafe { *user.User.Sid.cast::<u8>().add(1) });
    if offset
        .checked_add(8 + 4 * count)
        .is_none_or(|end| end > written as usize)
    {
        return Err(unsafe_credential_acl());
    }
    // SAFETY: the complete variable-length SID lies inside the initialized token buffer.
    if unsafe { IsValidSid(user.User.Sid) } == 0 {
        return Err(unsafe_credential_acl());
    }
    // The full SID was range-checked and remains live until conversion finishes.
    sid_to_string(user.User.Sid)
}
