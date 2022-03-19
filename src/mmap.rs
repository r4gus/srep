//! This module defines a [`Mmap`] struct and associated functions
//! to represents a file or device mapped into the virtual address 
//! space of the calling process.
//!
//! This is an abstraction of the `mmap` and `munmap` functions as
//! described by <https://www.man7.org/linux/man-pages/man2/mmap.2.html>.

use std::os::raw::{c_void, c_int, c_ulong};
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::ptr;
use std::io;
use crate::core::{
    __off_t,
    mmap, munmap,
    PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC,
    MAP_SHARED, MAP_SHARED_VALIDATE, MAP_PRIVATE,
    MAP_32BIT, MAP_ANONYMOUS, MAP_FIXED,
    EACCES, EAGAIN, EBADF, EEXIST, EINVAL, ENFILE,
    ENODEV, ENOMEM, EOVERFLOW, EPERM, ETXTBSY,
    size_t,
};

/// Create a mmap mapping flag consisting of a
/// mapping type and zero or more additional flags.
///
/// Syntax: `mapping!(MType, Flag*)`.
#[macro_export]
macro_rules! mapping {
    ($mtype:expr , $($flag:expr),*) => {
        Mapping::new($mtype)
            $(.with($flag))*
    };
    ($mtype:expr) => {
        Mapping::new($mtype)
    };
    ($mtype:expr , $($flag:expr),* ,) => {
        mapping!($mtype, $($flag),*)
    };
}

/// Get the current errno value.
///
/// This should be called immediately after a call to a platform function!
fn errno() -> u32 {
    if let Some(e) = io::Error::last_os_error().raw_os_error() {
        e as u32
    } else {
        u32::MAX
    }
}

/// Wrapper for a mapping in the virtual address space
/// of the calling process.
pub struct Mmap(*mut c_void, u64);

/// The desired memory protection of a mapping.
#[repr(u32)]
#[derive(Debug, Clone, PartialEq)]
pub enum Prot {
    None = PROT_NONE,
    /// Pages may be read.
    Read = PROT_READ,
    /// Pages may be written.
    Write = PROT_WRITE,
    /// Pages may be executed.
    Exec = PROT_EXEC,
    /// Pages may be read or written.
    ReadWrite = PROT_READ | PROT_WRITE,
    /// Pages may be read or executed.
    ReadExec = PROT_READ | PROT_EXEC,
    /// Pages may be written or executed.
    WriteExec = PROT_WRITE | PROT_EXEC,
    /// Pages may be read, written or executed.
    ReadWriteExec = PROT_READ | PROT_WRITE | PROT_EXEC,
}

/// Determine whether updates to the mapping are
/// visible to other processes mapping the same region,
/// and whether updates are carried through to the
/// underlying file.
#[repr(u32)]
#[derive(Debug, Clone, PartialEq)]
pub enum MType {
    /// Share the given mapping.
    /// * Updates to the mapping are visible toother processes
    /// mapping the same region.
    /// * They are carried through to the underlying file (only
    /// if file based).
    Shared = MAP_SHARED,
    /// Same as MType::Shared but let the kernel verify all passed
    /// flags are known. With this flag the mapping fails for
    /// unknown flags. This mapping type is also required to be
    /// able to use some mapping flags (e.g. Flag::Sync).
    SharedValidate = MAP_SHARED_VALIDATE,
    /// Create a private copy-on-write mapping. Updates to the
    /// mapping are not visible to other processes mapping the
    /// same file, and are not carried throgh to the underlying
    /// file. It is unspecified whether changes made to the
    /// fileafter the mapping call are visible in the mapped region.
    Private = MAP_PRIVATE,
}

/// In addition to a [`MType`] type, zero or more flags can be
/// added to a [`Mapping`] by using the [`Mapping::with`] function.
#[repr(u32)]
#[derive(Debug, Clone, PartialEq)]
pub enum Flag {
    /// Put the mapping into the first 2 Gigabytes of the process
    /// address space. Only supported on x86-64, for 64-bit programs.
    /// The flag is ignored when [`Flag::Fixed`] is set.
    Bit32 = MAP_32BIT,
    /// The mapping is not backed by any file; its contents are
    /// initialized to zero. The [`std::fs::File`] argument is ignored;
    Anonymous = MAP_ANONYMOUS,
    /// Don't interpret addr as a hint; place the mapping at
    /// exactly that address. __addr must be suitably aligned__,
    /// e.g. a multiple of the page size.
    Fixed = MAP_FIXED,
}

/// The combination of exactly one mapping type [`MType`] and zero
/// or more [`Flag`]s.
///
/// # Examples 
///
/// ```
/// use srep::mmap::{MType, Flag, Mapping};
/// use srep::mapping;
/// 
/// let flags = Mapping::new(MType::Private) // Create a new private memory mapping ...
///     .with(Flag::Bit32); // ... within the first 2 Gb of the process address space.
///
/// // Create the same flags using the `mapping!` macro.
/// let mflags = mapping!(MType::Private, Flag::Bit32);
///
/// assert_eq!(flags, mflags);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Hash)]
pub struct Mapping(c_int);

impl Mapping{
    /// Create a new mapping type with flags using the given MType.
    ///
    /// # Arguments
    ///
    /// * `mtype` - The mapping type ([`MType`]) to use.
    pub fn new(mtype: MType) -> Self {
        Self(mtype as c_int)
    }
    
    /// Add a flag to the given mapping flags.
    ///
    /// # Arguments
    ///
    /// * `flag` - The [`Flag`] to set.
    pub fn with(mut self, flag: Flag) -> Self {
        self.0 |= flag as c_int;
        self
    }

    /// Check if the given flag is present.
    pub fn has_flag(&self, flag: Flag) -> bool {
        self.0 & flag as c_int != 0
    }
    
    /// Check if the given mapping type is set.
    pub fn has_type(&self, t: MType) -> bool {
        (self.0 & 0b11) == t as c_int
    }
    
    /// Return the raw bitmask.
    pub fn as_raw(&self) -> c_int {
        self.0
    }
}

impl PartialEq<u32> for Mapping {
    fn eq(&self, other: &u32) -> bool {
        self.0 as u32 == *other
    }
}

/// Errors that can occure as a result of [`Mmap::new`].
#[derive(Debug, Clone, PartialEq)]
pub enum MapError {
    /// A file descriptor refers to a non-regular file.
    /// Or a file mapping was requested, but fd is not
    /// open for reading. Or [`MType::Shared`] was requested
    /// and [`Prot::Write`] is set, but fd is not open in read/
    /// write (O_RDWR) mode. Or Prot::Write is set, but the
    /// file is append-only.
    Access,
    /// The file has been locked, or too much memory has been
    /// locked.
    Again,
    /// fd is not a valid file descriptor (and [`Flag::Anonymous`] was
    /// not set).
    ///
    /// This should never happen because [`Mmap::new`] makes sure
    /// that Flag::Anonymous is set if no File has been provided.
    BadFile,
    /// Flag::MapFixedNoreplace was specified in flags, and the
    /// range covered by addr and length clashes with an existing
    /// mapping.
    Exists,
    /// 1. Invalid addr, length, or offset (e.g. to large,
    /// not aligned, ...).
    /// 2. length was 0.
    /// 3. flags contained none of [`MType::Shared`], [`MType::Private`], or
    /// [`MType::SharedValidate`]. This should never happen because one
    /// must alway specify exactly one of the mentioned types.
    Invalid,
    /// The system-wide limit on the total number of open files has
    /// been reached.
    FileLimit,
    /// The underlying filesystem of the specified file does not
    /// support memory mapping.
    NoMapping,
    /// 1. The process's maximum number of mappings would have been
    /// exceeded.
    /// 2. The process's RLIMIT_DATA limit would have been exceeded.
    NoMemory,
    /// On 32-bit architecture together with the large file extension
    /// the number of pages used for length plus number of pages used for
    /// offset would overflow unsigned long (32 bits).
    Overflow,
    /// 1. The prot argument asks for [`Prot::Exec`] but the mapped area
    /// belongs to a file on a filesystem that was mounted no-exec.
    /// 2. The operation was prevented by a file seal.
    /// 3. The [`Flag::Hugetlb`] was specified, but the caller was not
    /// privileged (did not have the CAP_IPC_LOCK capability) and
    /// is not a member of the sysctl_hugetlb_shm_group group.
    Permission,
    /// The Flag::Denywrite was set but the object specified by fd
    /// is open for writing.
    Txtbsy,
    /// Unknown error not covered by one of the specified errno values.
    /// <https://www.man7.org/linux/man-pages/man2/mmap.2.html>
    Unknown(u32),
}

impl std::error::Error for MapError {
}

impl std::fmt::Display for MapError {
    fn fmt(&self, out: &mut std::fmt::Formatter) -> std::fmt::Result {
        use self::MapError::*;

        write!(out, "{}",
            match *self {
                Access => "fd not open for reading, writing or doesn't refer to regular file",
                Again => "file has been locked, or too much memory has been locked",
                BadFile => "not a valid file descriptor",
                Exists => "the range coverd by addr and length clashes with an existing mapping",
                Invalid => "invalid addr, length or offset",
                FileLimit => "system-wide limit of open files has been reached",
                NoMapping => "filesystem does not support memory mapping",
                NoMemory => "maximum number of mappings exceeded",
                Overflow => "pages used for length and offset would overflow 32 bit",
                Permission => "filesystem mounted not executable",
                Txtbsy => "DENY_WRITE set but file is open for writing",
                Unknown(_) => "unknown",
            }
        )
    }
}

#[cfg(unix)]
impl Mmap {
    /// Create a new mapping in the virtual address space of
    /// the calling process.
    ///
    /// # Arguments
    ///
    /// * `len` - The length of the mapping (which must be greater than 0).
    /// * `prot` - The desired memory protection of the mapping.
    /// * `flags` - Determines whether updates to the mapping are visible to
    /// other processes mapping the same regin, and whether updates are
    /// carried through to the underlying file. In addition, zero or more
    /// flag-values can be added to request a specific behaviour.
    /// * `file` - A optional file that backs the mapping. If no file is specified
    /// or if the [`Flag::Anonymous`] flag ist set, an anonymous mapping is created.
    /// * `offset` - The offset in the file where the file mapping starts.
    ///
    /// # Errors
    ///
    /// This function returns a error if the specified len is 0 or
    /// if the mapping failed (see [`MapError`]).
    pub fn new(
        len: u64, 
        prot: Prot, 
        flags: Mapping, 
        file: Option<&File>, 
        offset: isize
    ) -> Result<Self, MapError> {
        let fd;
        let mut fl = flags;

        if len == 0 {
            // The length must be greater than 0.
            return Err(MapError::Invalid);
        }
        
        // Create an anonymous mapping if file is None or if the
        // Anonymous flag is set.
        if matches!(file, Some(_)) && !flags.has_flag(Flag::Anonymous) {
            fd = file.unwrap().as_raw_fd();
        } else {
            // Some implementations require fd to be -1 if 
            // MAP_ANONYMOUS is specified.
            fd = -1;
            fl = fl.with(Flag::Anonymous);
        }

        let mem = unsafe {
            mmap(
                ptr::null_mut::<c_void>(), 
                len as c_ulong, 
                prot as c_int, 
                fl.as_raw(), 
                fd,
                offset as __off_t
            )
        };
        
        unsafe {
            // Bindgen is currently unable to translate
            // #define MAP_FAILED ((void *) -1) so we
            // build the pointer manually.
            if mem == ptr::null_mut::<c_void>().offset(-1) {
                return Err(
                    match errno() {
                        EACCES => MapError::Access,
                        EAGAIN => MapError::Again,
                        EBADF => MapError::BadFile,
                        EEXIST => MapError::Exists,
                        EINVAL => MapError::Invalid,
                        ENFILE => MapError::FileLimit,
                        ENODEV => MapError::NoMapping,
                        ENOMEM => MapError::NoMemory,
                        EOVERFLOW => MapError::Overflow,
                        EPERM => MapError::Permission,
                        ETXTBSY => MapError::Txtbsy,
                        e => MapError::Unknown(e),
                    }
                );
            }
        }

        Ok(Self(mem, len))
    }

    pub fn mem(&self) -> *const c_void {
        self.0
    }
}

#[cfg(unix)]
impl Drop for Mmap {
    /// Delete the mapping from the given address range.
    ///
    /// # Panics
    ///
    /// The function may panic due to invalid arguments (probably
    /// EINVAL) but this is very unlikely.
    fn drop(&mut self) {
        unsafe {
            munmap(self.0, self.1 as size_t);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapping_type() {
        let flags = Mapping::new(MType::Shared)
            .with(Flag::Bit32)
            .with(Flag::Anonymous);

        assert_eq!(flags, MAP_SHARED | MAP_32BIT | MAP_ANONYMOUS);
    }

    #[test]
    fn test_mapping_macro() {
        let flags = mapping!(MType::Shared, Flag::Bit32, Flag::Anonymous);

        assert_eq!(flags, MAP_SHARED | MAP_32BIT | MAP_ANONYMOUS);
    }

    #[test]
    fn test_mapping_macro2() {
        assert_eq!(mapping!(MType::Private), MAP_PRIVATE);
    }
    
    #[test]
    fn test_mapping_macro3() {
        assert_eq!(mapping!(MType::Private, Flag::Anonymous,), MAP_PRIVATE | MAP_ANONYMOUS);
    }

    #[test]
    fn test_has_flag() {
        let flags = mapping!(MType::Shared, Flag::Bit32, Flag::Anonymous);
        
        assert!(flags.has_flag(Flag::Bit32));
        assert!(flags.has_flag(Flag::Anonymous));
        assert_eq!(flags.has_flag(Flag::Fixed), false);
    }

    #[test]
    fn test_has_type() {
        let flags = mapping!(MType::Shared, Flag::Bit32, Flag::Anonymous);
        
        assert!(flags.has_type(MType::Shared));
        assert!(!flags.has_type(MType::SharedValidate));
        assert!(!flags.has_type(MType::Private));    
    }
}
