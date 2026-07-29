//! Path resolution utilities shared across modules.

use std::path::PathBuf;

/// Resolve a user-provided path string to an absolute, canonical path.
///
/// Expands `~/` to the user's home directory. Rejects relative paths.
/// Returns [`Err`] with a human-readable message on failure.
pub fn resolve_path(raw: &str) -> Result<PathBuf, String> {
    let expanded = if raw.starts_with("~/") {
        match dirs::home_dir() {
            Some(home) => home.join(raw.strip_prefix("~/").unwrap()),
            None => return Err("Cannot resolve home directory".to_string()),
        }
    } else {
        PathBuf::from(raw)
    };

    if !expanded.is_absolute() {
        return Err(format!("Path must be absolute: {raw}"));
    }

    expanded
        .canonicalize()
        .map_err(|e| format!("Cannot resolve path {raw}: {e}"))
}
