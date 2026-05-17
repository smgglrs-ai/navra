//! File-descriptor-based path resolution to mitigate TOCTOU race conditions.
//!
//! Instead of check-then-open (vulnerable to symlink swaps between the
//! canonicalize and the open), we open-then-check: acquire the fd first,
//! resolve the canonical path from the open fd via `/proc/self/fd`, then
//! run the ACL check against the resolved path. Reads and writes use the
//! already-open fd, so no second open occurs.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// Resolve the canonical path of an open file descriptor.
///
/// On Linux, reads `/proc/self/fd/{fd}` which always resolves to the
/// real path of the file the fd points to, regardless of any symlink
/// swaps that happen after the open.
#[cfg(target_os = "linux")]
pub fn resolve_fd(fd: std::os::unix::io::RawFd) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{fd}"))
}

/// Fallback for non-Linux: not supported.
///
/// Callers should fall back to the pre-open canonicalize path on
/// platforms where `/proc/self/fd` is not available.
#[cfg(not(target_os = "linux"))]
pub fn resolve_fd(_fd: std::os::unix::io::RawFd) -> io::Result<PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "fd-based path resolution requires Linux (/proc/self/fd)",
    ))
}

/// Open a file for reading and resolve its canonical path from the fd.
///
/// Returns `(File, canonical_path)`. The canonical path is the real
/// path the fd points to, safe from symlink swaps after the open.
pub fn open_and_resolve(path: &Path) -> io::Result<(File, PathBuf)> {
    let file = File::open(path)?;
    let canonical = resolve_fd_or_canonicalize(&file, path)?;
    Ok((file, canonical))
}

/// Open (or create) a file for writing and resolve its canonical path.
///
/// Uses `O_WRONLY | O_CREAT | O_TRUNC` semantics (like `File::create`).
/// Returns `(File, canonical_path)`.
pub fn create_and_resolve(path: &Path) -> io::Result<(File, PathBuf)> {
    let file = File::create(path)?;
    let canonical = resolve_fd_or_canonicalize(&file, path)?;
    Ok((file, canonical))
}

/// Open an existing file for read+write and resolve its canonical path.
///
/// The file must already exist. Used by `file_edit` which needs to
/// read the content, modify it, then write back through the same fd.
pub fn open_rw_and_resolve(path: &Path) -> io::Result<(File, PathBuf)> {
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let canonical = resolve_fd_or_canonicalize(&file, path)?;
    Ok((file, canonical))
}

/// Try fd-based resolution first, fall back to canonicalize on non-Linux.
/// Public variant for use by handlers that need to open files with custom
/// options (e.g., write-without-truncate) before resolving the canonical path.
pub fn resolve_fd_or_canonicalize_pub(file: &File, original_path: &Path) -> io::Result<PathBuf> {
    resolve_fd_or_canonicalize(file, original_path)
}

/// Try fd-based resolution first, fall back to canonicalize on non-Linux.
fn resolve_fd_or_canonicalize(file: &File, original_path: &Path) -> io::Result<PathBuf> {
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    match resolve_fd(fd) {
        Ok(p) => Ok(p),
        Err(_) => {
            // Non-Linux fallback: canonicalize the original path.
            // This still has a TOCTOU window, but it's the best we
            // can do without /proc/self/fd.
            original_path.canonicalize()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    #[test]
    fn open_and_resolve_regular_file() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("test.txt");
        std::fs::write(&file_path, "hello").unwrap();

        let (mut file, canonical) = open_and_resolve(&file_path).unwrap();
        assert!(canonical.is_absolute());
        // The canonical path should end with the filename
        assert!(canonical.ends_with("test.txt"));

        // Verify we can read through the fd
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert_eq!(content, "hello");
    }

    #[test]
    fn open_and_resolve_symlink_resolves_to_target() {
        let tmp = TempDir::new().unwrap();
        let real_file = tmp.path().join("real.txt");
        let link_path = tmp.path().join("link.txt");
        std::fs::write(&real_file, "target content").unwrap();

        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_file, &link_path).unwrap();

        let (mut file, canonical) = open_and_resolve(&link_path).unwrap();

        // The canonical path should point to the real file, not the symlink
        let real_canonical = real_file.canonicalize().unwrap();
        assert_eq!(canonical, real_canonical);

        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert_eq!(content, "target content");
    }

    #[test]
    fn create_and_resolve_new_file() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("new.txt");

        let (_file, canonical) = create_and_resolve(&file_path).unwrap();
        assert!(canonical.is_absolute());
        assert!(canonical.ends_with("new.txt"));
        assert!(file_path.exists());
    }

    #[test]
    fn open_rw_and_resolve_existing_file() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("rw.txt");
        std::fs::write(&file_path, "original").unwrap();

        let (mut file, canonical) = open_rw_and_resolve(&file_path).unwrap();
        assert!(canonical.is_absolute());

        // Verify we can read
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert_eq!(content, "original");
    }

    #[test]
    fn open_and_resolve_nonexistent_fails() {
        let result = open_and_resolve(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_fd_on_linux() {
        use std::os::unix::io::AsRawFd;
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("fdtest.txt");
        std::fs::write(&file_path, "x").unwrap();

        let file = File::open(&file_path).unwrap();
        let resolved = resolve_fd(file.as_raw_fd()).unwrap();
        assert_eq!(resolved, file_path.canonicalize().unwrap());
    }
}
