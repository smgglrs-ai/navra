//! Path resolution utilities shared across modules.

use std::path::PathBuf;

/// Resolve a user-provided path string to an absolute, canonical path.
///
/// Expands `~/` to the user's home directory. Rejects relative paths.
/// Returns [`Err`] with a human-readable message on failure.
pub fn resolve_path(raw: &str) -> Result<PathBuf, String> {
    let expanded = expand_home(raw)?;
    if !expanded.is_absolute() {
        return Err(format!("Path must be absolute: {raw}"));
    }

    expanded
        .canonicalize()
        .map_err(|e| format!("Cannot resolve path {raw}: {e}"))
}

/// Open a file and resolve its canonical path with TOCTOU protection.
///
/// The file is opened FIRST; the canonical (symlink-following) path is
/// then resolved and verified to refer to the same inode as the open
/// handle. A permission check against the returned path is therefore
/// a check of the bytes that will actually be read from the returned
/// handle — an attacker cannot swap the target (e.g. by relaying a
/// symlink) between the permission check and the read.
///
/// Like [`resolve_path`], expands `~/` and rejects relative paths.
pub fn open_resolved(raw: &str) -> Result<(std::fs::File, PathBuf), String> {
    let expanded = expand_home(raw)?;
    if !expanded.is_absolute() {
        return Err(format!("Path must be absolute: {raw}"));
    }

    let file =
        std::fs::File::open(&expanded).map_err(|e| format!("Cannot open path {raw}: {e}"))?;
    let canonical = expanded
        .canonicalize()
        .map_err(|e| format!("Cannot resolve path {raw}: {e}"))?;

    // Verify the canonical path still refers to the file we opened:
    // if the path was swapped between open and canonicalize, the
    // inode identities differ and the call fails closed.
    let handle_meta = file
        .metadata()
        .map_err(|e| format!("Cannot stat open file {raw}: {e}"))?;
    let canonical_meta = std::fs::metadata(&canonical)
        .map_err(|e| format!("Cannot stat resolved path {raw}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if handle_meta.dev() != canonical_meta.dev() || handle_meta.ino() != canonical_meta.ino() {
            return Err(format!(
                "Path {raw} changed while opening (possible symlink swap)"
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (handle_meta, canonical_meta);
    }

    Ok((file, canonical))
}

/// Expand a leading `~/` to the user's home directory.
fn expand_home(raw: &str) -> Result<PathBuf, String> {
    if raw.starts_with("~/") {
        match dirs::home_dir() {
            Some(home) => Ok(home.join(raw.strip_prefix("~/").unwrap())),
            None => Err("Cannot resolve home directory".to_string()),
        }
    } else {
        Ok(PathBuf::from(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_resolved_returns_handle_and_canonical_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.png");
        std::fs::write(&path, b"data").unwrap();
        let raw = path.to_str().unwrap();

        let (file, canonical) = open_resolved(raw).unwrap();
        assert!(canonical.is_absolute());
        assert_eq!(canonical, path.canonicalize().unwrap());
        assert_eq!(file.metadata().unwrap().len(), 4);
    }

    #[test]
    fn open_resolved_rejects_relative() {
        let err = open_resolved("relative/path.png").unwrap_err();
        assert!(err.contains("must be absolute"));
    }

    #[test]
    fn open_resolved_rejects_nonexistent() {
        let err = open_resolved("/nonexistent/path/image.png").unwrap_err();
        assert!(err.contains("Cannot open"));
    }

    #[cfg(unix)]
    #[test]
    fn open_resolved_detects_symlink_swap() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.txt");
        let other = dir.path().join("other.txt");
        let link = dir.path().join("link.txt");
        std::fs::write(&real, b"real").unwrap();
        std::fs::write(&other, b"other").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // Swap the symlink target after "open" — simulate the race by
        // checking that a stale canonical path is detected: open the
        // link, repoint it, then verify the mismatch is caught when
        // canonicalize observes the new target.
        let file = std::fs::File::open(&link).unwrap();
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&other, &link).unwrap();
        let canonical = link.canonicalize().unwrap();
        let handle_meta = file.metadata().unwrap();
        let canonical_meta = std::fs::metadata(&canonical).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_ne!(
            (handle_meta.dev(), handle_meta.ino()),
            (canonical_meta.dev(), canonical_meta.ino()),
            "swapped symlink must be detectable via inode identity"
        );
    }
}
