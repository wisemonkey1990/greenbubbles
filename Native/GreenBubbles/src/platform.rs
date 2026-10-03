//! Operating-system differences, kept in one place.
//!
//! The engine was written against POSIX file semantics: owner-only modes,
//! `O_NOFOLLOW` opens, `uid`/`nlink`/`ino` checks, advisory locks and Unix
//! sockets. Every call site goes through this module instead of `std::os::unix`
//! or `libc`, so a second platform only has to provide the items below.
//!
//! On Unix every item is the standard-library or `libc` original; behavior on
//! macOS is unchanged. The Windows definitions are a compile-compatible first
//! pass and are deliberately weaker than the Unix ones in three ways:
//!
//! * There is no POSIX mode. `mode()` reports `0o600` or `0o700` (and `0o400`
//!   or `0o500` for read-only entries) so the "no group/other access" checks
//!   pass. Real isolation then comes from the NTFS ACL that a file inherits
//!   from the per-user profile directory, which is private to the user by
//!   default. These checks do not inspect the ACL.
//! * File ownership is not inspected. `uid()` and [`geteuid`] both return `0`.
//! * `nlink` is reported as `1`, and the `dev`/`ino` pair is approximated by
//!   the volume-less creation time, which still changes when a file is
//!   replaced. Time-of-check/time-of-use detection therefore relies on the
//!   modification time and size.
//!
//! Replacing those three approximations with real ACL, owner and file-index
//! checks is tracked in `docs/WINDOWS_PORT.md`.

/// The current user's home directory as the platform names it: `HOME` on Unix
/// and `USERPROFILE` on Windows. Empty values count as unset.
pub fn home_dir() -> Option<std::path::PathBuf> {
    let name = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
}

#[cfg(unix)]
mod imp {
    use std::io;
    use std::path::Path;

    pub use libc::{ELOOP, O_CLOEXEC, O_DIRECTORY, O_NOFOLLOW};
    pub use std::os::unix::ffi::{OsStrExt, OsStringExt};
    pub use std::os::unix::fs::{
        symlink, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt,
    };

    /// The effective user id of this process.
    pub fn geteuid() -> u32 {
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }

    /// Sets the POSIX permission bits of `path`.
    pub fn set_mode(path: impl AsRef<Path>, mode: u32) -> io::Result<()> {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }

    /// Bytes available to an unprivileged process on the volume holding `path`.
    pub fn available_space(path: &Path) -> io::Result<u64> {
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
        let mut statistics = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: `c_path` is NUL-terminated and `statistics` points to writable,
        // correctly aligned storage that is read only after statvfs succeeds.
        if unsafe { libc::statvfs(c_path.as_ptr(), statistics.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful statvfs call initialized the complete structure.
        let statistics = unsafe { statistics.assume_init() };
        let bytes = u128::from(statistics.f_bavail).saturating_mul(u128::from(statistics.f_frsize));
        Ok(u64::try_from(bytes).unwrap_or(u64::MAX))
    }

    /// Forcibly ends the process with the given id. Errors are ignored: the
    /// caller is a watchdog that has already given up on the process.
    pub fn terminate_process(pid: u32) {
        if let Ok(pid) = libc::pid_t::try_from(pid) {
            // SAFETY: `kill` takes plain integers and has no memory effects.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::fs::{Metadata, OpenOptions, Permissions};
    use std::io;
    use std::os::windows::ffi::OsStrExt as WideOsStrExt;
    use std::os::windows::fs::MetadataExt as WindowsMetadataExt;
    use std::path::Path;

    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetDiskFreeSpaceExW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_READONLY,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    /// Not used on Windows; kept so call sites can name the same constants.
    pub const O_CLOEXEC: i32 = 0;
    /// Open the link itself rather than its target.
    pub const O_NOFOLLOW: i32 = FILE_FLAG_OPEN_REPARSE_POINT as i32;
    /// Allow opening a directory handle.
    pub const O_DIRECTORY: i32 = FILE_FLAG_BACKUP_SEMANTICS as i32;
    /// Windows reports a refused reparse-point open as an ordinary error, so
    /// no raw code ever equals this sentinel.
    pub const ELOOP: i32 = i32::MIN;

    pub fn geteuid() -> u32 {
        0
    }

    pub trait OpenOptionsExt {
        fn mode(&mut self, mode: u32) -> &mut Self;
        fn custom_flags(&mut self, flags: i32) -> &mut Self;
    }

    impl OpenOptionsExt for OpenOptions {
        fn mode(&mut self, _mode: u32) -> &mut Self {
            self
        }

        fn custom_flags(&mut self, flags: i32) -> &mut Self {
            std::os::windows::fs::OpenOptionsExt::custom_flags(self, flags as u32)
        }
    }

    pub trait PermissionsExt {
        fn mode(&self) -> u32;
    }

    impl PermissionsExt for Permissions {
        fn mode(&self) -> u32 {
            if self.readonly() {
                0o400
            } else {
                0o600
            }
        }
    }

    pub trait MetadataExt {
        fn mode(&self) -> u32;
        fn uid(&self) -> u32;
        fn nlink(&self) -> u64;
        fn dev(&self) -> u64;
        fn ino(&self) -> u64;
        fn mtime(&self) -> i64;
        fn mtime_nsec(&self) -> i64;
        fn ctime(&self) -> i64;
        fn ctime_nsec(&self) -> i64;
    }

    /// 100 ns intervals between 1601-01-01 and 1970-01-01.
    const WINDOWS_TO_UNIX_EPOCH_TICKS: i64 = 116_444_736_000_000_000;

    impl MetadataExt for Metadata {
        fn mode(&self) -> u32 {
            let attributes = self.file_attributes();
            let directory = attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
            let readonly = attributes & FILE_ATTRIBUTE_READONLY != 0;
            match (directory, readonly) {
                (true, false) => 0o700,
                (true, true) => 0o500,
                (false, false) => 0o600,
                (false, true) => 0o400,
            }
        }

        fn uid(&self) -> u32 {
            0
        }

        fn nlink(&self) -> u64 {
            1
        }

        fn dev(&self) -> u64 {
            0
        }

        fn ino(&self) -> u64 {
            self.creation_time()
        }

        fn mtime(&self) -> i64 {
            (self.last_write_time() as i64 - WINDOWS_TO_UNIX_EPOCH_TICKS).div_euclid(10_000_000)
        }

        fn mtime_nsec(&self) -> i64 {
            (self.last_write_time() as i64 - WINDOWS_TO_UNIX_EPOCH_TICKS).rem_euclid(10_000_000)
                * 100
        }

        // `std` does not expose NTFS ChangeTime on stable; the write time is
        // the closest available signal.
        fn ctime(&self) -> i64 {
            self.mtime()
        }

        fn ctime_nsec(&self) -> i64 {
            self.mtime_nsec()
        }
    }

    /// Windows has no socket file type that `std` can report.
    pub trait FileTypeExt {
        fn is_socket(&self) -> bool;
    }

    impl FileTypeExt for std::fs::FileType {
        fn is_socket(&self) -> bool {
            false
        }
    }

    pub trait OsStrExt {
        fn as_bytes(&self) -> Vec<u8>;
    }

    /// Windows paths are UTF-16; this is the lossy UTF-8 form, adequate for
    /// prefix matching on the ASCII names this crate generates.
    impl OsStrExt for std::ffi::OsStr {
        fn as_bytes(&self) -> Vec<u8> {
            self.to_string_lossy().into_owned().into_bytes()
        }
    }

    pub trait OsStringExt {
        fn from_vec(bytes: Vec<u8>) -> std::ffi::OsString;
    }

    impl OsStringExt for std::ffi::OsString {
        fn from_vec(bytes: Vec<u8>) -> std::ffi::OsString {
            String::from_utf8_lossy(&bytes).into_owned().into()
        }
    }

    pub fn set_mode(path: impl AsRef<Path>, mode: u32) -> io::Result<()> {
        let path = path.as_ref();
        let mut permissions = std::fs::metadata(path)?.permissions();
        permissions.set_readonly(mode & 0o200 == 0);
        std::fs::set_permissions(path, permissions)
    }

    pub fn symlink(target: impl AsRef<Path>, link: impl AsRef<Path>) -> io::Result<()> {
        if std::fs::metadata(target.as_ref()).is_ok_and(|metadata| metadata.is_dir()) {
            std::os::windows::fs::symlink_dir(target, link)
        } else {
            std::os::windows::fs::symlink_file(target, link)
        }
    }

    pub fn available_space(path: &Path) -> io::Result<u64> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut available = 0_u64;
        // SAFETY: `wide` is NUL-terminated and the other pointers are either
        // null (ignored outputs) or point to a live `u64`.
        let ok = unsafe {
            GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut available,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(available)
    }

    pub fn terminate_process(pid: u32) {
        // SAFETY: plain integer arguments; the handle is closed before return.
        unsafe {
            let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if !handle.is_null() {
                TerminateProcess(handle, 1);
                CloseHandle(handle);
            }
        }
    }
}

pub use imp::*;
