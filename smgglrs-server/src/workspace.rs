use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum WorkspaceError {
    Io(std::io::Error),
    Source(String),
}

impl std::fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "workspace I/O error: {e}"),
            Self::Source(msg) => write!(f, "workspace source error: {msg}"),
        }
    }
}

impl std::error::Error for WorkspaceError {}

impl From<std::io::Error> for WorkspaceError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub struct WorkspaceResult {
    pub files: Vec<PathBuf>,
}

pub trait WorkspaceProvider: Send + Sync {
    fn populate(&self, target_dir: &Path) -> Result<(), WorkspaceError>;
    fn collect(&self, source_dir: &Path) -> Result<WorkspaceResult, WorkspaceError>;
}

/// Populates a workspace by recursively copying from a host directory.
pub struct DirectoryWorkspace {
    pub source_path: PathBuf,
}

impl WorkspaceProvider for DirectoryWorkspace {
    fn populate(&self, target_dir: &Path) -> Result<(), WorkspaceError> {
        if !self.source_path.is_dir() {
            return Err(WorkspaceError::Source(format!(
                "source path does not exist or is not a directory: {}",
                self.source_path.display()
            )));
        }
        copy_dir_recursive(&self.source_path, target_dir)
    }

    fn collect(&self, source_dir: &Path) -> Result<WorkspaceResult, WorkspaceError> {
        let mut files = Vec::new();
        collect_files(source_dir, source_dir, &mut files)?;
        Ok(WorkspaceResult { files })
    }
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), WorkspaceError> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let dst_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &dst_path)?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), &dst_path)?;
        }
    }
    Ok(())
}

fn collect_files(
    base: &Path,
    dir: &Path,
    out: &mut Vec<PathBuf>,
) -> Result<(), WorkspaceError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_files(base, &entry.path(), out)?;
        } else if file_type.is_file() {
            if let Ok(rel) = entry.path().strip_prefix(base) {
                out.push(rel.to_path_buf());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn directory_workspace_populate_and_collect() {
        let src = tempfile::tempdir().unwrap();
        fs::write(src.path().join("hello.txt"), "world").unwrap();
        fs::create_dir(src.path().join("sub")).unwrap();
        fs::write(src.path().join("sub/nested.rs"), "fn main() {}").unwrap();

        let dst = tempfile::tempdir().unwrap();
        let ws = DirectoryWorkspace {
            source_path: src.path().to_path_buf(),
        };
        ws.populate(dst.path()).unwrap();

        assert_eq!(fs::read_to_string(dst.path().join("hello.txt")).unwrap(), "world");
        assert_eq!(
            fs::read_to_string(dst.path().join("sub/nested.rs")).unwrap(),
            "fn main() {}"
        );

        let result = ws.collect(dst.path()).unwrap();
        let mut names: Vec<String> = result
            .files
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        names.sort();
        assert_eq!(names, vec!["hello.txt", "sub/nested.rs"]);
    }

    #[test]
    fn directory_workspace_missing_source() {
        let ws = DirectoryWorkspace {
            source_path: PathBuf::from("/nonexistent/path"),
        };
        let dst = tempfile::tempdir().unwrap();
        assert!(ws.populate(dst.path()).is_err());
    }
}
