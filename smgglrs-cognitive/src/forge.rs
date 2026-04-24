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
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Registry of cognitive artifacts loaded from YAML files.
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
    /// Eagerly loaded specializations (backward compat).
    specializations: HashMap<String, Specialization>,
    /// Lazy catalog: metadata only, full YAML loaded on demand.
    specialization_catalog: Vec<SpecializationMeta>,
}

impl ForgeService {
    /// Load cognitive artifacts from a directory.
    ///
    /// Scans `personas/`, `directives/`, `heuristics/`, and
    /// `persona_specializations/` subdirectories for YAML files.
    /// Missing subdirectories are silently skipped.
    pub fn load(cognitive_core_dir: &Path) -> Result<Self, CognitiveError> {
        let personas = load_dir::<Persona>(
            &cognitive_core_dir.join("personas"),
            |p| p.persona_name.clone(),
        )?;
        let directives = load_dir::<Directive>(
            &cognitive_core_dir.join("directives"),
            |d| d.directive_name.clone(),
        )?;
        let heuristics = load_dir::<HeuristicModule>(
            &cognitive_core_dir.join("heuristics"),
            |h| h.heuristic_name.clone(),
        )?;
        // Load specializations eagerly (backward compat) and build lazy catalog
        let spec_dir = cognitive_core_dir.join("persona_specializations");
        let specializations = load_dir::<Specialization>(
            &spec_dir,
            |s| format!("{}_{}", s.base_persona, s.description.replace(' ', "_").to_lowercase()),
        )?;

        let specialization_catalog = build_catalog(&spec_dir);

        tracing::info!(
            personas = personas.len(),
            directives = directives.len(),
            heuristics = heuristics.len(),
            specializations = specializations.len(),
            catalog = specialization_catalog.len(),
            "Cognitive core loaded"
        );

        Ok(Self {
            personas,
            heuristics,
            directives,
            specializations,
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
            specializations: HashMap::new(),
            specialization_catalog: Vec::new(),
        }
    }

    /// List available specializations (metadata only — no content loaded).
    pub fn specialization_catalog(&self) -> &[SpecializationMeta] {
        &self.specialization_catalog
    }

    /// Load a specialization on demand from its YAML file.
    pub fn load_specialization(&self, key: &str) -> Option<Specialization> {
        // Check eagerly loaded first
        if let Some(spec) = self.specializations.get(key) {
            return Some(spec.clone());
        }
        // Fall back to catalog (lazy load from disk)
        let meta = self.specialization_catalog.iter().find(|m| m.key == key)?;
        let content = std::fs::read_to_string(&meta.path).ok()?;
        serde_yaml::from_str(&content).ok()
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
                if let Some(existing) = merged
                    .heuristics
                    .iter_mut()
                    .find(|h| h.module == module)
                {
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
            mcp_prompts: Vec::new(),
            skills: Vec::new(),
            planning_context_limit: None,
            execution_context_limit: None,
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
    let Ok(entries) = std::fs::read_dir(dir) else { return catalog };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml")
            && path.extension().and_then(|e| e.to_str()) != Some("yml")
        {
            continue;
        }
        if let Ok(content) = std::fs::read_to_string(&path) {
            // Parse just enough to get metadata
            if let Ok(spec) = serde_yaml::from_str::<Specialization>(&content) {
                let key = format!(
                    "{}_{}",
                    spec.base_persona,
                    spec.description.replace(' ', "_").to_lowercase()
                );
                catalog.push(SpecializationMeta {
                    key,
                    base_persona: spec.base_persona,
                    description: spec.description,
                    path: path.clone(),
                });
            }
        }
    }
    catalog
}

/// Load all YAML files from a directory into a HashMap.
fn load_dir<T: serde::de::DeserializeOwned>(
    dir: &Path,
    key_fn: impl Fn(&T) -> String,
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
        // Find the specialization key
        let spec_key = forge
            .specializations
            .keys()
            .find(|k| k.contains("backend"))
            .unwrap()
            .clone();

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
        forge.register_upstream_persona(
            "code_reviewer",
            "upstream_x",
            "persona:code_reviewer",
            "",
        );

        let persona = forge.get_persona("code_reviewer").unwrap();
        assert_eq!(persona.display_name, "code reviewer");
    }
}
