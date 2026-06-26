use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct LibraryConfig {
    /// Directories to scan for `*.toml` library fragments.
    /// Default: `["~/.config/navra/libraries"]`.
    #[serde(default = "default_library_dirs")]
    pub library_dirs: Vec<String>,
}

impl Default for LibraryConfig {
    fn default() -> Self {
        Self {
            library_dirs: default_library_dirs(),
        }
    }
}

fn default_library_dirs() -> Vec<String> {
    vec!["~/.config/navra/libraries".to_string()]
}

fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        dirs::home_dir()
            .map(|h| h.join(&path[2..]))
            .unwrap_or_else(|| PathBuf::from(path))
    } else {
        PathBuf::from(path)
    }
}

/// Resolve configured library dirs, expanding `~`.
pub fn resolve_dirs(dirs: &[String]) -> Vec<PathBuf> {
    dirs.iter().map(|d| expand_tilde(d)).collect()
}

/// Scan library directories for `*.toml` files, returning each file's
/// path and parsed TOML value. Files are sorted by name within each
/// directory for deterministic merge order.
pub fn scan_libraries(dirs: &[PathBuf]) -> anyhow::Result<Vec<(PathBuf, toml::Value)>> {
    let mut results = Vec::new();

    for dir in dirs {
        if !dir.exists() {
            continue;
        }
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "toml")
                    .unwrap_or(false)
            })
            .map(|e| e.path())
            .collect();
        entries.sort();

        for path in entries {
            let content = std::fs::read_to_string(&path).map_err(|e| {
                anyhow::anyhow!("failed to read library file {}: {e}", path.display())
            })?;
            let value: toml::Value = toml::from_str(&content).map_err(|e| {
                anyhow::anyhow!("invalid TOML in library file {}: {e}", path.display())
            })?;
            results.push((path, value));
        }
    }

    Ok(results)
}

/// Deep-merge library TOML fragments into the main config value.
///
/// Rules:
/// - Main config wins on key conflicts (library cannot override main).
/// - Two libraries defining the same key produce an error.
/// - Array values are appended.
/// - Tables are recursively merged.
pub fn merge_libraries(
    main: &mut toml::Value,
    libs: Vec<(PathBuf, toml::Value)>,
) -> anyhow::Result<()> {
    // Track which library defined each key path for conflict detection.
    let mut lib_origins: BTreeMap<String, PathBuf> = BTreeMap::new();

    // Snapshot main config key paths before merging so we know what
    // was defined by the operator vs. added by libraries.
    let main_keys = collect_all_key_paths(main);

    for (path, lib_value) in libs {
        let lib_table = match lib_value {
            toml::Value::Table(t) => t,
            _ => {
                anyhow::bail!(
                    "library file {} must be a TOML table at the top level",
                    path.display()
                );
            }
        };

        let main_table = main
            .as_table_mut()
            .ok_or_else(|| anyhow::anyhow!("main config is not a TOML table"))?;

        for (key, value) in lib_table {
            merge_value(
                main_table,
                &key,
                value,
                &path,
                &mut lib_origins,
                &key,
                &main_keys,
            )?;
        }
    }

    Ok(())
}

/// Collect all dot-separated key paths from a TOML value for main config tracking.
fn collect_all_key_paths(value: &toml::Value) -> std::collections::HashSet<String> {
    let mut paths = std::collections::HashSet::new();
    if let Some(table) = value.as_table() {
        collect_key_paths_inner(table, "", &mut paths);
    }
    paths
}

fn collect_key_paths_inner(
    table: &toml::map::Map<String, toml::Value>,
    prefix: &str,
    paths: &mut std::collections::HashSet<String>,
) {
    for (k, v) in table {
        let path = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        paths.insert(path.clone());
        if let toml::Value::Table(sub) = v {
            collect_key_paths_inner(sub, &path, paths);
        }
    }
}

fn merge_value(
    target: &mut toml::map::Map<String, toml::Value>,
    key: &str,
    value: toml::Value,
    source_path: &Path,
    origins: &mut BTreeMap<String, PathBuf>,
    key_path: &str,
    main_keys: &std::collections::HashSet<String>,
) -> anyhow::Result<()> {
    match target.get_mut(key) {
        Some(existing) => {
            match (existing, value) {
                (toml::Value::Table(existing_table), toml::Value::Table(lib_table)) => {
                    for (k, v) in lib_table {
                        let nested_path = format!("{key_path}.{k}");
                        merge_value(
                            existing_table,
                            &k,
                            v,
                            source_path,
                            origins,
                            &nested_path,
                            main_keys,
                        )?;
                    }
                }
                (toml::Value::Array(existing_arr), toml::Value::Array(lib_arr)) => {
                    if main_keys.contains(key_path) {
                        // Main config array — append library entries.
                        existing_arr.extend(lib_arr);
                    } else if let Some(prev) = origins.get(key_path) {
                        if prev != source_path {
                            anyhow::bail!(
                                "duplicate key '{key_path}' defined in both {} and {}",
                                prev.display(),
                                source_path.display()
                            );
                        }
                        existing_arr.extend(lib_arr);
                    } else {
                        existing_arr.extend(lib_arr);
                    }
                }
                _ => {
                    // Scalar exists in target. If from main, main wins.
                    // If from another library, conflict.
                    if !main_keys.contains(key_path)
                        && let Some(prev) = origins.get(key_path)
                            && prev != source_path {
                                anyhow::bail!(
                                    "duplicate key '{key_path}' defined in both {} and {}",
                                    prev.display(),
                                    source_path.display()
                                );
                            }
                }
            }
        }
        None => {
            if let toml::Value::Table(ref lib_table) = value {
                let mut new_table = toml::map::Map::new();
                for (k, v) in lib_table.clone() {
                    let nested_path = format!("{key_path}.{k}");
                    merge_value(
                        &mut new_table,
                        &k,
                        v,
                        source_path,
                        origins,
                        &nested_path,
                        main_keys,
                    )?;
                }
                target.insert(key.to_string(), toml::Value::Table(new_table));
            } else {
                if let Some(prev) = origins.get(key_path)
                    && prev != source_path {
                        anyhow::bail!(
                            "duplicate key '{key_path}' defined in both {} and {}",
                            prev.display(),
                            source_path.display()
                        );
                    }
                origins.insert(key_path.to_string(), source_path.to_path_buf());
                target.insert(key.to_string(), value);
            }
        }
    }

    Ok(())
}

/// Summarize what keys a library provides, for the `config list-libraries` CLI.
pub struct LibrarySummary {
    pub path: PathBuf,
    pub keys: Vec<String>,
}

pub fn summarize_libraries(libs: &[(PathBuf, toml::Value)]) -> Vec<LibrarySummary> {
    libs.iter()
        .map(|(path, value)| {
            let keys = match value {
                toml::Value::Table(t) => collect_top_keys(t, ""),
                _ => vec!["(invalid)".to_string()],
            };
            LibrarySummary {
                path: path.clone(),
                keys,
            }
        })
        .collect()
}

fn collect_top_keys(table: &toml::map::Map<String, toml::Value>, prefix: &str) -> Vec<String> {
    let mut keys = Vec::new();
    for (k, v) in table {
        let full = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        match v {
            toml::Value::Table(sub) if !sub.is_empty() => {
                keys.extend(collect_top_keys(sub, &full));
            }
            _ => keys.push(full),
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_lib(dir: &Path, name: &str, content: &str) {
        let path = dir.join(name);
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    #[test]
    fn scan_and_merge_basic() {
        let dir = TempDir::new().unwrap();
        write_lib(
            dir.path(),
            "hipaa.toml",
            r#"
[permissions.hipaa]
allow = ["~/health-data/**"]
operations = ["read"]
safety = "guardian-deep"
"#,
        );

        let main_toml = r#"
[server]
tcp = "127.0.0.1:9315"
"#;
        let mut main: toml::Value = toml::from_str(main_toml).unwrap();

        let libs = scan_libraries(&[dir.path().to_path_buf()]).unwrap();
        assert_eq!(libs.len(), 1);

        merge_libraries(&mut main, libs).unwrap();

        let table = main.as_table().unwrap();
        let perms = table["permissions"].as_table().unwrap();
        assert!(perms.contains_key("hipaa"));
        let hipaa = perms["hipaa"].as_table().unwrap();
        assert_eq!(hipaa["safety"].as_str().unwrap(), "guardian-deep");
    }

    #[test]
    fn duplicate_key_across_libraries() {
        let dir = TempDir::new().unwrap();
        write_lib(
            dir.path(),
            "lib_a.toml",
            r#"
[permissions.shared]
operations = ["read"]
"#,
        );
        write_lib(
            dir.path(),
            "lib_b.toml",
            r#"
[permissions.shared]
operations = ["write"]
"#,
        );

        let main_toml = r#"
[server]
tcp = "127.0.0.1:9315"
"#;
        let mut main: toml::Value = toml::from_str(main_toml).unwrap();

        let libs = scan_libraries(&[dir.path().to_path_buf()]).unwrap();
        let err = merge_libraries(&mut main, libs).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("duplicate key"), "got: {msg}");
        assert!(msg.contains("lib_a.toml"), "got: {msg}");
        assert!(msg.contains("lib_b.toml"), "got: {msg}");
    }

    #[test]
    fn main_config_wins() {
        let dir = TempDir::new().unwrap();
        write_lib(
            dir.path(),
            "override.toml",
            r#"
[server]
tcp = "0.0.0.0:1234"
"#,
        );

        let main_toml = r#"
[server]
tcp = "127.0.0.1:9315"
"#;
        let mut main: toml::Value = toml::from_str(main_toml).unwrap();

        let libs = scan_libraries(&[dir.path().to_path_buf()]).unwrap();
        merge_libraries(&mut main, libs).unwrap();

        let tcp = main["server"]["tcp"].as_str().unwrap();
        assert_eq!(tcp, "127.0.0.1:9315");
    }

    #[test]
    fn empty_library_dir() {
        let dir = TempDir::new().unwrap();

        let libs = scan_libraries(&[dir.path().to_path_buf()]).unwrap();
        assert!(libs.is_empty());

        let main_toml = r#"
[server]
tcp = "127.0.0.1:9315"
"#;
        let mut main: toml::Value = toml::from_str(main_toml).unwrap();
        merge_libraries(&mut main, libs).unwrap();
    }

    #[test]
    fn nonexistent_library_dir() {
        let libs = scan_libraries(&[PathBuf::from("/nonexistent/path/abc123")]).unwrap();
        assert!(libs.is_empty());
    }

    #[test]
    fn invalid_toml_produces_error() {
        let dir = TempDir::new().unwrap();
        write_lib(dir.path(), "bad.toml", "this is not valid toml {{{{");

        let err = scan_libraries(&[dir.path().to_path_buf()]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("bad.toml"), "got: {msg}");
        assert!(msg.contains("invalid TOML"), "got: {msg}");
    }

    #[test]
    fn array_values_appended() {
        let dir = TempDir::new().unwrap();
        write_lib(
            dir.path(),
            "extra_upstream.toml",
            r#"
[[upstream]]
name = "lib-server"
transport = "http"
url = "http://localhost:9999/mcp"
"#,
        );

        let main_toml = r#"
[server]
tcp = "127.0.0.1:9315"

[[upstream]]
name = "main-server"
transport = "http"
url = "http://localhost:8001/mcp"
"#;
        let mut main: toml::Value = toml::from_str(main_toml).unwrap();

        let libs = scan_libraries(&[dir.path().to_path_buf()]).unwrap();
        merge_libraries(&mut main, libs).unwrap();

        let upstream = main["upstream"].as_array().unwrap();
        assert_eq!(upstream.len(), 2);
        assert_eq!(upstream[0]["name"].as_str().unwrap(), "main-server");
        assert_eq!(upstream[1]["name"].as_str().unwrap(), "lib-server");
    }

    #[test]
    fn nested_table_merge() {
        let dir = TempDir::new().unwrap();
        write_lib(
            dir.path(),
            "extra_perms.toml",
            r#"
[permissions.library_only]
operations = ["read"]
allow = ["/lib/**"]
"#,
        );

        let main_toml = r#"
[server]
tcp = "127.0.0.1:9315"

[permissions.admin]
operations = ["read", "write"]
allow = ["/home/**"]
"#;
        let mut main: toml::Value = toml::from_str(main_toml).unwrap();

        let libs = scan_libraries(&[dir.path().to_path_buf()]).unwrap();
        merge_libraries(&mut main, libs).unwrap();

        let perms = main["permissions"].as_table().unwrap();
        assert!(perms.contains_key("admin"));
        assert!(perms.contains_key("library_only"));
    }

    #[test]
    fn summarize_shows_keys() {
        let dir = TempDir::new().unwrap();
        write_lib(
            dir.path(),
            "test.toml",
            r#"
[permissions.hipaa]
operations = ["read"]

[[upstream]]
name = "test"
"#,
        );

        let libs = scan_libraries(&[dir.path().to_path_buf()]).unwrap();
        let summaries = summarize_libraries(&libs);
        assert_eq!(summaries.len(), 1);
        let keys = &summaries[0].keys;
        assert!(keys.iter().any(|k| k.contains("permissions")));
        assert!(keys.iter().any(|k| k == "upstream"));
    }

    #[test]
    fn multiple_dirs_scanned() {
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();
        write_lib(
            dir1.path(),
            "a.toml",
            r#"
[permissions.from_dir1]
operations = ["read"]
"#,
        );
        write_lib(
            dir2.path(),
            "b.toml",
            r#"
[permissions.from_dir2]
operations = ["write"]
"#,
        );

        let libs = scan_libraries(&[dir1.path().to_path_buf(), dir2.path().to_path_buf()]).unwrap();
        assert_eq!(libs.len(), 2);

        let mut main: toml::Value = toml::from_str("[server]\ntcp = \"127.0.0.1:9315\"").unwrap();
        merge_libraries(&mut main, libs).unwrap();

        let perms = main["permissions"].as_table().unwrap();
        assert!(perms.contains_key("from_dir1"));
        assert!(perms.contains_key("from_dir2"));
    }
}
