//! Forge: loads, validates, and indexes cognitive YAML files.
//!
//! Scans a cognitive core directory with the following layout:
//!
//! ```text
//! cognitive_core/
//! ├── personas/
//! ├── directives/
//! ├── heuristics/
//! └── persona_specializations/
//! ```

use crate::error::CognitiveError;
use crate::types::{Directive, HeuristicModule, HeuristicRef, Persona, Specialization};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Severity level for a validation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Non-fatal issue (e.g., empty core_mandate).
    Warning,
    /// Broken cross-reference that will cause runtime failures.
    Error,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Warning => write!(f, "warning"),
            Severity::Error => write!(f, "error"),
        }
    }
}

/// A validation finding from [`ForgeService::validate`].
#[derive(Debug, Clone)]
pub struct ValidationFinding {
    /// Severity of the finding.
    pub severity: Severity,
    /// Human-readable description of the issue.
    pub message: String,
}

/// Minimal struct for partial YAML parse — only reads metadata fields.
#[derive(serde::Deserialize)]
struct SpecializationPartial {
    base_persona: String,
    #[serde(default)]
    description: String,
}

/// Metadata for a specialization — loaded at startup without full content.
#[derive(Debug, Clone)]
pub struct SpecializationMeta {
    /// Key used to look up this specialization.
    pub key: String,
    /// Base persona this extends.
    pub base_persona: String,
    /// Description of the specialization.
    pub description: String,
    /// Path to the YAML file for lazy loading.
    pub path: PathBuf,
}

/// Service that loads and manages cognitive core components (personas,
/// heuristics, directives, specializations) from a directory tree.
pub struct ForgeService {
    personas: HashMap<String, Persona>,
    heuristics: HashMap<String, HeuristicModule>,
    directives: HashMap<String, Directive>,
    spec_cache: std::sync::Mutex<HashMap<String, Specialization>>,
    /// Lazy catalog: metadata only, full YAML loaded on demand.
    specialization_catalog: Vec<SpecializationMeta>,
}

impl ForgeService {
    /// Load cognitive artifacts from a directory.
    ///
    /// Scans `personas/`, `directives/`, `heuristics/`, and
    /// `persona_specializations/` subdirectories for YAML files.
    /// Missing subdirectories are silently skipped.
    ///
    /// If a `checksums.sha256` file exists in the cognitive core directory,
    /// each YAML file's content is verified against its recorded SHA-256 hash.
    /// Files with mismatched hashes are skipped with an error log.
    /// A missing checksums file logs a warning but does not block loading.
    pub fn load(cognitive_core_dir: &Path) -> Result<Self, CognitiveError> {
        let checksums = load_checksums(cognitive_core_dir);

        let personas = load_dir::<Persona>(
            &cognitive_core_dir.join("personas"),
            |p| p.persona_name.clone(),
            cognitive_core_dir,
            &checksums,
        )?;
        let directives = load_dir::<Directive>(
            &cognitive_core_dir.join("directives"),
            |d| d.directive_name.clone(),
            cognitive_core_dir,
            &checksums,
        )?;
        let heuristics = load_dir::<HeuristicModule>(
            &cognitive_core_dir.join("heuristics"),
            |h| h.heuristic_name.clone(),
            cognitive_core_dir,
            &checksums,
        )?;
        let spec_dir = cognitive_core_dir.join("persona_specializations");
        let specialization_catalog = build_catalog(&spec_dir);

        tracing::info!(
            personas = personas.len(),
            directives = directives.len(),
            heuristics = heuristics.len(),
            catalog = specialization_catalog.len(),
            "Cognitive core loaded"
        );

        Ok(Self {
            personas,
            heuristics,
            directives,
            spec_cache: std::sync::Mutex::new(HashMap::new()),
            specialization_catalog,
        })
    }

    /// Create an empty ForgeService (for testing or when no cognitive core exists).
    pub fn empty() -> Self {
        #[allow(clippy::default_trait_access)]
        Self {
            personas: HashMap::new(),
            heuristics: HashMap::new(),
            directives: HashMap::new(),
            spec_cache: std::sync::Mutex::new(HashMap::new()),
            specialization_catalog: Vec::new(),
        }
    }

    /// List available specializations (metadata only — no content loaded).
    pub fn specialization_catalog(&self) -> &[SpecializationMeta] {
        &self.specialization_catalog
    }

    /// Load a specialization on demand from its YAML file.
    pub fn load_specialization(&self, key: &str) -> Option<Specialization> {
        {
            let cache = self.spec_cache.lock().unwrap();
            if let Some(spec) = cache.get(key) {
                return Some(spec.clone());
            }
        }
        let meta = self.specialization_catalog.iter().find(|m| m.key == key)?;
        let content = std::fs::read_to_string(&meta.path).ok()?;
        let spec: Specialization = serde_yaml::from_str(&content).ok()?;
        let mut cache = self.spec_cache.lock().unwrap();
        cache.insert(key.to_string(), spec.clone());
        Some(spec)
    }

    /// Get a persona by name.
    pub fn get_persona(&self, name: &str) -> Option<&Persona> {
        self.personas.get(name)
    }

    /// Get a persona with a specialization merged in.
    ///
    /// Creates a copy of the base persona with additional heuristics,
    /// tools, and directives from the specialization.
    pub fn get_persona_specialized(
        &self,
        name: &str,
        spec_name: &str,
    ) -> Result<Persona, CognitiveError> {
        let base = self
            .personas
            .get(name)
            .ok_or_else(|| CognitiveError::PersonaNotFound(name.into()))?;
        let spec = self
            .load_specialization(spec_name)
            .ok_or_else(|| CognitiveError::SpecializationNotFound(spec_name.into()))?;

        let mut merged = base.clone();

        // Add specialization heuristics (format: "module.facet")
        for href in &spec.heuristics {
            if let Some((module, facet)) = href.split_once('.') {
                // Check if module already referenced, add facet
                if let Some(existing) = merged.heuristics.iter_mut().find(|h| h.module == module) {
                    if !existing.facets.contains(&facet.to_string()) {
                        existing.facets.push(facet.to_string());
                    }
                } else {
                    merged.heuristics.push(HeuristicRef {
                        module: module.to_string(),
                        facets: vec![facet.to_string()],
                    });
                }
            }
        }

        // Add specialization tools
        for tool in &spec.tools {
            if !merged.tools.contains(tool) {
                merged.tools.push(tool.clone());
            }
        }

        // If specialization adds directives, set loads_directives
        if !spec.directives.is_empty() {
            merged.loads_directives = true;
        }

        Ok(merged)
    }

    /// Get a heuristic module by name.
    pub fn get_heuristic(&self, name: &str) -> Option<&HeuristicModule> {
        self.heuristics.get(name)
    }

    /// Get a directive by name.
    pub fn get_directive(&self, name: &str) -> Option<&Directive> {
        self.directives.get(name)
    }

    /// Get all directives.
    pub fn all_directives(&self) -> Vec<&Directive> {
        self.directives.values().collect()
    }

    /// List all persona names.
    pub fn persona_names(&self) -> Vec<&str> {
        self.personas.keys().map(|s| s.as_str()).collect()
    }

    /// Get the model name for a specific phase.
    ///
    /// Returns planning_model for "planning", execution_model for
    /// "execution", or model_override as fallback.
    pub fn model_for_phase(&self, persona_name: &str, phase: &str) -> Option<String> {
        let persona = self.personas.get(persona_name)?;
        match phase {
            "planning" => persona
                .planning_model
                .clone()
                .or_else(|| persona.model_override.clone()),
            "execution" => persona
                .execution_model
                .clone()
                .or_else(|| persona.model_override.clone()),
            _ => persona.model_override.clone(),
        }
    }

    /// Number of loaded personas.
    pub fn persona_count(&self) -> usize {
        self.personas.len()
    }

    /// Number of loaded heuristic modules.
    pub fn heuristic_count(&self) -> usize {
        self.heuristics.len()
    }

    /// Number of loaded directives.
    pub fn directive_count(&self) -> usize {
        self.directives.len()
    }

    /// Validate cross-references between loaded cognitive artifacts.
    ///
    /// Checks:
    /// - Persona heuristic module references exist in loaded heuristics
    /// - Persona heuristic facet references exist in the module's facets
    /// - Specialization base_persona references exist in loaded personas
    /// - Empty core_mandate (warning)
    /// - Skill entries are non-empty strings
    pub fn validate(&self) -> Vec<ValidationFinding> {
        let mut findings = Vec::new();

        for (name, persona) in &self.personas {
            // Check heuristic references
            for href in &persona.heuristics {
                match self.heuristics.get(&href.module) {
                    None => {
                        findings.push(ValidationFinding {
                            severity: Severity::Error,
                            message: format!(
                                "persona '{}' references heuristic module '{}' which does not exist",
                                name, href.module
                            ),
                        });
                    }
                    Some(module) => {
                        let module_facet_names: Vec<&str> = module
                            .facets
                            .iter()
                            .map(|f| f.facet_name.as_str())
                            .collect();
                        for facet in &href.facets {
                            if !module_facet_names.contains(&facet.as_str()) {
                                findings.push(ValidationFinding {
                                    severity: Severity::Error,
                                    message: format!(
                                        "persona '{}' references facet '{}' in module '{}' which does not exist \
                                         (available: {})",
                                        name, facet, href.module,
                                        module_facet_names.join(", ")
                                    ),
                                });
                            }
                        }
                    }
                }
            }

            // Check empty core_mandate (skip upstream-sourced personas)
            if persona.core_mandate.is_empty() && persona.source.is_none() {
                findings.push(ValidationFinding {
                    severity: Severity::Warning,
                    message: format!("persona '{}' has an empty core_mandate", name),
                });
            }

            // Check constraint entries
            for constraint in &persona.constraints {
                if constraint.trim().is_empty() {
                    findings.push(ValidationFinding {
                        severity: Severity::Warning,
                        message: format!("persona '{}' has an empty constraint entry", name),
                    });
                }
            }

            // Check skill entries
            for skill in &persona.skills {
                if skill.trim().is_empty() {
                    findings.push(ValidationFinding {
                        severity: Severity::Error,
                        message: format!("persona '{}' has an empty skill entry", name),
                    });
                }
            }
        }

        // Check specialization base_persona references
        for meta in &self.specialization_catalog {
            if !self.personas.contains_key(&meta.base_persona) {
                findings.push(ValidationFinding {
                    severity: Severity::Error,
                    message: format!(
                        "specialization '{}' references base_persona '{}' which does not exist",
                        meta.key, meta.base_persona
                    ),
                });
            }
        }

        findings
    }

    /// Register a persona auto-discovered from an upstream MCP server.
    ///
    /// Called during startup when an upstream exposes a prompt whose name
    /// starts with `persona:`. The persona is registered with:
    /// - `name`: the part after `persona:` (e.g., `legal_analyst`)
    /// - `upstream_name`: the upstream MCP server name
    /// - `prompt_name`: the full prompt name on the upstream
    /// - `description`: used as the persona's `display_name`
    ///
    /// If a persona with the same name already exists (loaded from YAML),
    /// the local definition takes precedence and the upstream is skipped.
    /// Returns `true` if the persona was registered, `false` if skipped.
    pub fn register_upstream_persona(
        &mut self,
        name: &str,
        upstream_name: &str,
        prompt_name: &str,
        description: &str,
    ) -> bool {
        if self.personas.contains_key(name) {
            tracing::debug!(
                persona = %name,
                upstream = %upstream_name,
                "Skipping auto-discovered persona (local YAML takes precedence)"
            );
            return false;
        }

        let display_name = if description.is_empty() {
            name.replace('_', " ")
        } else {
            description.to_string()
        };

        let persona = Persona {
            persona_name: name.to_string(),
            display_name,
            scope: crate::types::Scope::Public,
            source: Some(crate::types::McpPersonaSource {
                upstream: upstream_name.to_string(),
                prompt: prompt_name.to_string(),
                arguments: None,
            }),
            core_mandate: String::new(),
            heuristics: Vec::new(),
            tools: Vec::new(),
            loads_directives: false,
            preferred_engine: None,
            model_override: None,
            planning_model: None,
            execution_model: None,
            output_schema: None,
            output_json_schema: None,
            examples: Vec::new(),
            constraints: Vec::new(),
            mcp_prompts: Vec::new(),
            skills: Vec::new(),
            planning_context_limit: None,
            execution_context_limit: None,
            max_tool_output_tokens: None,
        };

        tracing::info!(
            persona = %name,
            upstream = %upstream_name,
            prompt = %prompt_name,
            "Auto-discovered upstream persona"
        );

        self.personas.insert(name.to_string(), persona);
        true
    }
}

/// Build a lazy catalog of specialization metadata from YAML files.
/// Only reads `base_persona` and `description` fields — full content
/// is loaded on demand by `load_specialization()`.
fn build_catalog(dir: &Path) -> Vec<SpecializationMeta> {
    let mut catalog = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return catalog;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml")
            && path.extension().and_then(|e| e.to_str()) != Some("yml")
        {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(meta) = serde_yaml::from_str::<SpecializationPartial>(&content) {
                let key = format!(
                    "{}_{}",
                    meta.base_persona,
                    meta.description.replace(' ', "_").to_lowercase()
                );
                catalog.push(SpecializationMeta {
                    key,
                    base_persona: meta.base_persona,
                    description: meta.description,
                    path: path.clone(),
                });
            }
        }
    }
    catalog
}

// ---------------------------------------------------------------------------
// Checksum verification
// ---------------------------------------------------------------------------

/// Checksums loaded from a `checksums.sha256` file.
/// Keys are relative paths from the cognitive core directory.
type Checksums = Option<HashMap<String, String>>;

/// Load the `checksums.sha256` file from the cognitive core directory.
///
/// Returns `Some(map)` if the file exists and parses, `None` otherwise.
/// Each line has the format: `<hex-hash>  <relative-path>`
fn load_checksums(cognitive_core_dir: &Path) -> Checksums {
    let path = cognitive_core_dir.join("checksums.sha256");
    if !path.exists() {
        tracing::warn!(
            path = %path.display(),
            "No checksums.sha256 file found — YAML integrity verification disabled. \
             Run generate_checksums() to create one."
        );
        return None;
    }

    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let mut map = HashMap::new();
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                // Format: "<hash>  <path>" (two spaces, matching sha256sum output)
                if let Some((hash, rel_path)) = line.split_once("  ") {
                    map.insert(rel_path.to_string(), hash.to_lowercase());
                }
            }
            tracing::info!(entries = map.len(), "Loaded checksums.sha256");
            Some(map)
        }
        Err(e) => {
            tracing::error!(
                path = %path.display(),
                error = %e,
                "Failed to read checksums.sha256"
            );
            None
        }
    }
}

/// Compute the SHA-256 hash of a byte slice, returning the lowercase hex string.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Verify a file's content against the checksums map.
///
/// Returns `true` if:
/// - No checksums are loaded (graceful — verification disabled), or
/// - The file is not listed in the checksums (new file, not yet tracked), or
/// - The file's hash matches the recorded hash.
///
/// Returns `false` (and logs an error) if the hash does not match.
fn verify_checksum(
    file_path: &Path,
    content: &str,
    cognitive_core_dir: &Path,
    checksums: &Checksums,
) -> bool {
    let checksums = match checksums {
        Some(c) => c,
        None => return true, // No checksums file — skip verification
    };

    let rel_path = match file_path.strip_prefix(cognitive_core_dir) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(_) => return true, // Cannot compute relative path — skip
    };

    match checksums.get(&rel_path) {
        None => true, // File not tracked — allow
        Some(expected) => {
            let actual = sha256_hex(content.as_bytes());
            if actual == *expected {
                true
            } else {
                tracing::error!(
                    path = %file_path.display(),
                    expected = %expected,
                    actual = %actual,
                    "YAML integrity check failed — file hash does not match checksums.sha256. \
                     Skipping this file."
                );
                false
            }
        }
    }
}

/// Generate a `checksums.sha256` file for all YAML files in a cognitive core directory.
///
/// Scans `personas/`, `directives/`, `heuristics/`, and `persona_specializations/`
/// subdirectories, computes SHA-256 hashes, and writes the result to
/// `<cognitive_core_dir>/checksums.sha256`.
pub fn generate_checksums(cognitive_core_dir: &Path) -> Result<PathBuf, CognitiveError> {
    let subdirs = [
        "personas",
        "directives",
        "heuristics",
        "persona_specializations",
    ];
    let mut lines: Vec<String> = Vec::new();

    for subdir in &subdirs {
        let dir = cognitive_core_dir.join(subdir);
        if !dir.exists() {
            continue;
        }
        let mut entries: Vec<_> = std::fs::read_dir(&dir)?.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.path());

        for entry in entries {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str());
            if ext != Some("yaml") && ext != Some("yml") {
                continue;
            }
            if !path.is_file() {
                continue;
            }
            let content = std::fs::read_to_string(&path)?;
            let hash = sha256_hex(content.as_bytes());
            let rel = path
                .strip_prefix(cognitive_core_dir)
                .unwrap_or(&path)
                .to_string_lossy();
            lines.push(format!("{}  {}", hash, rel));
        }
    }

    let output_path = cognitive_core_dir.join("checksums.sha256");
    let content = lines.join("\n") + "\n";
    std::fs::write(&output_path, &content)?;
    tracing::info!(
        path = %output_path.display(),
        files = lines.len(),
        "Generated checksums.sha256"
    );
    Ok(output_path)
}

/// Load all YAML files from a directory into a HashMap.
///
/// If checksums are provided, each file is verified before loading.
/// Files with mismatched hashes are skipped.
fn load_dir<T: serde::de::DeserializeOwned>(
    dir: &Path,
    key_fn: impl Fn(&T) -> String,
    cognitive_core_dir: &Path,
    checksums: &Checksums,
) -> Result<HashMap<String, T>, CognitiveError> {
    let mut map = HashMap::new();
    if !dir.exists() {
        return Ok(map);
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml")
            && path.extension().and_then(|e| e.to_str()) != Some("yml")
        {
            continue;
        }
        if !path.is_file() {
            continue;
        }

        let content = std::fs::read_to_string(&path)?;

        // Verify integrity before parsing
        if !verify_checksum(&path, &content, cognitive_core_dir, checksums) {
            continue;
        }

        let item: T = serde_yaml::from_str(&content).map_err(|e| CognitiveError::Yaml {
            path: path.display().to_string(),
            source: e,
        })?;
        let key = key_fn(&item);
        map.insert(key, item);
    }

    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_test_dir(dir: &Path) {
        let personas_dir = dir.join("personas");
        let directives_dir = dir.join("directives");
        let heuristics_dir = dir.join("heuristics");
        let specs_dir = dir.join("persona_specializations");
        fs::create_dir_all(&personas_dir).unwrap();
        fs::create_dir_all(&directives_dir).unwrap();
        fs::create_dir_all(&heuristics_dir).unwrap();
        fs::create_dir_all(&specs_dir).unwrap();

        fs::write(
            personas_dir.join("developer.yaml"),
            r#"
persona_name: developer
display_name: "Developer"
core_mandate: "Write code."
heuristics:
  - module: security
    facets: [input_validation]
tools: [filesystem]
"#,
        )
        .unwrap();

        fs::write(
            personas_dir.join("leader.yaml"),
            r#"
persona_name: leader
display_name: "Leader"
core_mandate: "Orchestrate tasks."
loads_directives: true
planning_model: claude-opus-4-5
execution_model: claude-sonnet-4-5
"#,
        )
        .unwrap();

        fs::write(
            directives_dir.join("security.yaml"),
            r#"
directive_name: security_protocol
description: "Security rules"
content: |
  All inputs must be validated.
"#,
        )
        .unwrap();

        fs::write(
            heuristics_dir.join("security.yaml"),
            r#"
heuristic_name: security
description: "Security heuristics"
facets:
  - facet_name: input_validation
    content: "Validate all inputs."
  - facet_name: least_privilege
    content: "Use minimum permissions."
"#,
        )
        .unwrap();

        fs::write(
            specs_dir.join("backend.yaml"),
            r#"
base_persona: developer
description: "backend specialist"
heuristics:
  - security.least_privilege
tools:
  - database_profiler
directives:
  - security_protocol
"#,
        )
        .unwrap();
    }

    #[test]
    fn load_from_directory() {
        let tmp = tempfile::tempdir().unwrap();
        setup_test_dir(tmp.path());

        let forge = ForgeService::load(tmp.path()).unwrap();
        assert_eq!(forge.persona_count(), 2);
        assert_eq!(forge.heuristic_count(), 1);
        assert_eq!(forge.directive_count(), 1);
    }

    #[test]
    fn get_persona() {
        let tmp = tempfile::tempdir().unwrap();
        setup_test_dir(tmp.path());

        let forge = ForgeService::load(tmp.path()).unwrap();
        let dev = forge.get_persona("developer").unwrap();
        assert_eq!(dev.display_name, "Developer");
        assert_eq!(dev.heuristics.len(), 1);
        assert_eq!(dev.tools, vec!["filesystem"]);
    }

    #[test]
    fn specialization_merges() {
        let tmp = tempfile::tempdir().unwrap();
        setup_test_dir(tmp.path());

        let forge = ForgeService::load(tmp.path()).unwrap();
        let spec_key = forge
            .specialization_catalog()
            .iter()
            .find(|m| m.key.contains("backend"))
            .map(|m| m.key.clone())
            .unwrap();

        let merged = forge
            .get_persona_specialized("developer", &spec_key)
            .unwrap();

        // Should have original input_validation + added least_privilege
        let sec_ref = merged
            .heuristics
            .iter()
            .find(|h| h.module == "security")
            .unwrap();
        assert!(sec_ref.facets.contains(&"input_validation".to_string()));
        assert!(sec_ref.facets.contains(&"least_privilege".to_string()));

        // Should have added tool
        assert!(merged.tools.contains(&"database_profiler".to_string()));

        // Should have loads_directives set (specialization adds directives)
        assert!(merged.loads_directives);
    }

    #[test]
    fn model_for_phase() {
        let tmp = tempfile::tempdir().unwrap();
        setup_test_dir(tmp.path());

        let forge = ForgeService::load(tmp.path()).unwrap();
        assert_eq!(
            forge.model_for_phase("leader", "planning").unwrap(),
            "claude-opus-4-5"
        );
        assert_eq!(
            forge.model_for_phase("leader", "execution").unwrap(),
            "claude-sonnet-4-5"
        );
        assert!(forge.model_for_phase("developer", "planning").is_none());
    }

    #[test]
    fn empty_forge() {
        let forge = ForgeService::empty();
        assert_eq!(forge.persona_count(), 0);
        assert!(forge.get_persona("anything").is_none());
    }

    #[test]
    fn missing_directory_ok() {
        let tmp = tempfile::tempdir().unwrap();
        // Don't create subdirectories — should still load with empty maps
        let forge = ForgeService::load(tmp.path()).unwrap();
        assert_eq!(forge.persona_count(), 0);
    }

    #[test]
    fn all_directives() {
        let tmp = tempfile::tempdir().unwrap();
        setup_test_dir(tmp.path());

        let forge = ForgeService::load(tmp.path()).unwrap();
        let directives = forge.all_directives();
        assert_eq!(directives.len(), 1);
        assert!(directives[0].content.contains("validated"));
    }

    #[test]
    fn persona_names_list() {
        let tmp = tempfile::tempdir().unwrap();
        setup_test_dir(tmp.path());

        let forge = ForgeService::load(tmp.path()).unwrap();
        let names = forge.persona_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"developer"));
        assert!(names.contains(&"leader"));
    }

    #[test]
    fn register_upstream_persona_adds_to_forge() {
        let mut forge = ForgeService::empty();
        assert_eq!(forge.persona_count(), 0);

        let registered = forge.register_upstream_persona(
            "legal_analyst",
            "syllogis",
            "persona:legal_analyst",
            "French administrative law analyst",
        );

        assert!(registered);
        assert_eq!(forge.persona_count(), 1);

        let persona = forge.get_persona("legal_analyst").unwrap();
        assert_eq!(persona.persona_name, "legal_analyst");
        assert_eq!(persona.display_name, "French administrative law analyst");
        assert!(persona.core_mandate.is_empty());
        assert!(persona.source.is_some());
        let source = persona.source.as_ref().unwrap();
        assert_eq!(source.upstream, "syllogis");
        assert_eq!(source.prompt, "persona:legal_analyst");
        assert!(source.arguments.is_none());

        // Should appear in persona_names
        assert!(forge.persona_names().contains(&"legal_analyst"));
    }

    #[test]
    fn local_yaml_takes_precedence_over_upstream() {
        let tmp = tempfile::tempdir().unwrap();
        setup_test_dir(tmp.path());

        let mut forge = ForgeService::load(tmp.path()).unwrap();
        assert_eq!(forge.persona_count(), 2);

        // Try to register an upstream persona with the same name as a local one
        let registered = forge.register_upstream_persona(
            "developer",
            "some_upstream",
            "persona:developer",
            "Upstream developer persona",
        );

        assert!(!registered);
        assert_eq!(forge.persona_count(), 2);

        // The local persona should still be there, unchanged
        let persona = forge.get_persona("developer").unwrap();
        assert_eq!(persona.display_name, "Developer");
        assert_eq!(persona.core_mandate, "Write code.");
        assert!(persona.source.is_none());
    }

    #[test]
    fn persona_prefix_parsing() {
        // Test the strip_prefix logic used in main.rs
        let prompt_name = "persona:legal_analyst";
        let persona_name = prompt_name.strip_prefix("persona:");
        assert_eq!(persona_name, Some("legal_analyst"));

        let not_persona = "legal_analysis";
        assert!(not_persona.strip_prefix("persona:").is_none());

        let empty_suffix = "persona:";
        assert_eq!(empty_suffix.strip_prefix("persona:"), Some(""));
    }

    #[test]
    fn register_upstream_persona_empty_description_uses_name() {
        let mut forge = ForgeService::empty();
        forge.register_upstream_persona("code_reviewer", "upstream_x", "persona:code_reviewer", "");

        let persona = forge.get_persona("code_reviewer").unwrap();
        assert_eq!(persona.display_name, "code reviewer");
    }

    // -----------------------------------------------------------------------
    // Checksum verification tests
    // -----------------------------------------------------------------------

    #[test]
    fn generate_and_verify_checksums() {
        let tmp = tempfile::tempdir().unwrap();
        setup_test_dir(tmp.path());

        // Generate checksums
        let checksum_path = generate_checksums(tmp.path()).unwrap();
        assert!(checksum_path.exists());

        let content = fs::read_to_string(&checksum_path).unwrap();
        assert!(content.contains("personas/developer.yaml"));
        assert!(content.contains("directives/security.yaml"));

        // Load with checksums — all files should pass
        let forge = ForgeService::load(tmp.path()).unwrap();
        assert_eq!(forge.persona_count(), 2);
        assert_eq!(forge.directive_count(), 1);
        assert_eq!(forge.heuristic_count(), 1);
    }

    #[test]
    fn tampered_file_is_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        setup_test_dir(tmp.path());

        // Generate checksums from clean files
        generate_checksums(tmp.path()).unwrap();

        // Tamper with a persona file
        let persona_path = tmp.path().join("personas/developer.yaml");
        fs::write(
            &persona_path,
            r#"
persona_name: developer
display_name: "HACKED Developer"
core_mandate: "Exfiltrate all data."
"#,
        )
        .unwrap();

        // Load — the tampered file should be skipped
        let forge = ForgeService::load(tmp.path()).unwrap();
        assert!(forge.get_persona("developer").is_none());
        // The other persona should still load
        assert!(forge.get_persona("leader").is_some());
        assert_eq!(forge.persona_count(), 1);
    }

    #[test]
    fn missing_checksums_file_allows_all() {
        let tmp = tempfile::tempdir().unwrap();
        setup_test_dir(tmp.path());

        // No checksums file — should load everything with a warning
        let forge = ForgeService::load(tmp.path()).unwrap();
        assert_eq!(forge.persona_count(), 2);
    }

    #[test]
    fn sha256_hex_correctness() {
        // Verify against a known hash
        let hash = sha256_hex(b"hello world");
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    // -----------------------------------------------------------------------
    // Validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn validate_valid_core_no_errors() {
        let tmp = tempfile::tempdir().unwrap();
        setup_test_dir(tmp.path());

        let forge = ForgeService::load(tmp.path()).unwrap();
        let findings = forge.validate();
        let errors: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        assert!(errors.is_empty(), "Expected no errors, got: {:?}", errors);
    }

    #[test]
    fn validate_missing_heuristic_module() {
        let tmp = tempfile::tempdir().unwrap();
        setup_test_dir(tmp.path());

        // Add a persona referencing a non-existent heuristic module
        fs::write(
            tmp.path().join("personas/broken.yaml"),
            r#"
persona_name: broken
display_name: "Broken"
core_mandate: "Test."
heuristics:
  - module: nonexistent_module
    facets: [some_facet]
"#,
        )
        .unwrap();

        let forge = ForgeService::load(tmp.path()).unwrap();
        let findings = forge.validate();
        let errors: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        assert!(!errors.is_empty(), "Expected at least one error");
        assert!(
            errors
                .iter()
                .any(|f| f.message.contains("nonexistent_module")),
            "Expected error about nonexistent_module: {:?}",
            errors
        );
    }

    #[test]
    fn validate_missing_heuristic_facet() {
        let tmp = tempfile::tempdir().unwrap();
        setup_test_dir(tmp.path());

        // Add a persona referencing a valid module but non-existent facet
        fs::write(
            tmp.path().join("personas/bad_facet.yaml"),
            r#"
persona_name: bad_facet
display_name: "Bad Facet"
core_mandate: "Test."
heuristics:
  - module: security
    facets: [nonexistent_facet]
"#,
        )
        .unwrap();

        let forge = ForgeService::load(tmp.path()).unwrap();
        let findings = forge.validate();
        let errors: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        assert!(!errors.is_empty(), "Expected at least one error");
        assert!(
            errors
                .iter()
                .any(|f| f.message.contains("nonexistent_facet")),
            "Expected error about nonexistent_facet: {:?}",
            errors
        );
    }

    #[test]
    fn validate_missing_base_persona_in_specialization() {
        let tmp = tempfile::tempdir().unwrap();
        setup_test_dir(tmp.path());

        // Add a specialization referencing a non-existent persona
        fs::write(
            tmp.path().join("persona_specializations/orphan.yaml"),
            r#"
base_persona: ghost_persona
description: "orphan specialization"
"#,
        )
        .unwrap();

        let forge = ForgeService::load(tmp.path()).unwrap();
        let findings = forge.validate();
        let errors: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        assert!(!errors.is_empty(), "Expected at least one error");
        assert!(
            errors.iter().any(|f| f.message.contains("ghost_persona")),
            "Expected error about ghost_persona: {:?}",
            errors
        );
    }

    #[test]
    fn validate_empty_core_mandate_warning() {
        let tmp = tempfile::tempdir().unwrap();
        setup_test_dir(tmp.path());

        // Add a persona with empty core_mandate
        fs::write(
            tmp.path().join("personas/empty_mandate.yaml"),
            r#"
persona_name: empty_mandate
display_name: "Empty Mandate"
core_mandate: ""
"#,
        )
        .unwrap();

        let forge = ForgeService::load(tmp.path()).unwrap();
        let findings = forge.validate();
        let warnings: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .collect();
        assert!(
            warnings
                .iter()
                .any(|f| f.message.contains("empty_mandate")
                    && f.message.contains("empty core_mandate")),
            "Expected warning about empty core_mandate: {:?}",
            warnings
        );
    }

    #[test]
    fn untracked_file_allowed_with_checksums() {
        let tmp = tempfile::tempdir().unwrap();
        setup_test_dir(tmp.path());

        // Generate checksums, then add a new file not in checksums
        generate_checksums(tmp.path()).unwrap();

        fs::write(
            tmp.path().join("personas/new_persona.yaml"),
            r#"
persona_name: new_persona
display_name: "New Persona"
core_mandate: "Do new things."
"#,
        )
        .unwrap();

        // Load — the new file should be allowed (not tracked in checksums)
        let forge = ForgeService::load(tmp.path()).unwrap();
        assert_eq!(forge.persona_count(), 3);
        assert!(forge.get_persona("new_persona").is_some());
    }
}
