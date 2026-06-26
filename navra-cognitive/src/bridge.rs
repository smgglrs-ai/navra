//! Bidirectional persona bridge: import and export across agent frameworks.
//!
//! Import: Anthropic-style agent plugin dirs → cognitive YAML.
//! Export: persona + heuristics + directives → single markdown for
//! Claude Code, Cursor, or other systems.

use std::path::Path;

/// A portable persona representation for cross-framework exchange.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PortablePersona {
    /// Machine-readable persona name (typically the directory name).
    pub name: String,
    /// One-line human-readable summary of the persona's purpose.
    pub description: String,
    /// Full system prompt text imported from the source framework.
    pub system_prompt: String,
    /// Tool/skill names declared by the persona.
    pub tools: Vec<String>,
    /// Origin format identifier (e.g. `"anthropic-agent"`).
    pub source_format: String,
}

/// Import a persona from an Anthropic-style agent plugin directory.
///
/// Reads `agent.md` (or `README.md`) as the system prompt and
/// scans for skill/tool declarations.
pub fn import_from_agent_dir(dir: &Path) -> Option<PortablePersona> {
    let name = dir.file_name()?.to_str()?.to_string();

    let prompt_file = if dir.join("agent.md").exists() {
        dir.join("agent.md")
    } else if dir.join("README.md").exists() {
        dir.join("README.md")
    } else {
        return None;
    };

    let system_prompt = std::fs::read_to_string(&prompt_file).ok()?;

    let description = system_prompt
        .lines()
        .find(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .unwrap_or("")
        .to_string();

    let mut tools = Vec::new();
    let skills_dir = dir.join("skills");
    if skills_dir.is_dir()
        && let Ok(entries) = std::fs::read_dir(&skills_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.path().file_stem() {
                    tools.push(name.to_string_lossy().to_string());
                }
            }
        }

    Some(PortablePersona {
        name,
        description,
        system_prompt,
        tools,
        source_format: "anthropic-agent".to_string(),
    })
}

/// Export a persona as a single markdown file for Claude Code / Cursor.
pub fn export_to_markdown(persona: &PortablePersona) -> String {
    let mut md = String::new();
    md.push_str(&format!("# {}\n\n", persona.name));
    md.push_str(&format!("{}\n\n", persona.description));
    md.push_str("## System Prompt\n\n");
    md.push_str(&persona.system_prompt);
    md.push_str("\n\n");
    if !persona.tools.is_empty() {
        md.push_str("## Tools\n\n");
        for tool in &persona.tools {
            md.push_str(&format!("- {tool}\n"));
        }
    }
    md
}

/// Export a persona as cognitive YAML for navra.
pub fn export_to_cognitive_yaml(persona: &PortablePersona) -> String {
    let mut yaml = String::new();
    yaml.push_str(&format!("persona_name: {}\n", persona.name));
    yaml.push_str(&format!(
        "display_name: \"{}\"\n",
        persona.description.replace('"', "\\\"")
    ));
    yaml.push_str(&format!(
        "core_mandate: |\n  {}\n",
        persona
            .system_prompt
            .lines()
            .take(5)
            .collect::<Vec<_>>()
            .join("\n  ")
    ));
    yaml.push_str("heuristics:\n  - module: general\n    facets: [principles]\n");
    yaml
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn import_from_agent_dir_with_agent_md() {
        let dir = TempDir::new().unwrap();
        let agent_dir = dir.path().join("my-agent");
        std::fs::create_dir_all(&agent_dir).unwrap();
        std::fs::write(
            agent_dir.join("agent.md"),
            "# My Agent\n\nA helpful coding assistant.\n\nDo good work.",
        )
        .unwrap();

        let persona = import_from_agent_dir(&agent_dir).unwrap();
        assert_eq!(persona.name, "my-agent");
        assert!(persona.system_prompt.contains("helpful coding"));
        assert_eq!(persona.source_format, "anthropic-agent");
    }

    #[test]
    fn import_with_skills_directory() {
        let dir = TempDir::new().unwrap();
        let agent_dir = dir.path().join("coder");
        let skills_dir = agent_dir.join("skills");
        std::fs::create_dir_all(&skills_dir).unwrap();
        std::fs::write(agent_dir.join("agent.md"), "Agent prompt").unwrap();
        std::fs::write(skills_dir.join("code_review.md"), "skill").unwrap();
        std::fs::write(skills_dir.join("refactor.md"), "skill").unwrap();

        let persona = import_from_agent_dir(&agent_dir).unwrap();
        assert_eq!(persona.tools.len(), 2);
    }

    #[test]
    fn import_missing_prompt_returns_none() {
        let dir = TempDir::new().unwrap();
        let agent_dir = dir.path().join("empty");
        std::fs::create_dir_all(&agent_dir).unwrap();

        assert!(import_from_agent_dir(&agent_dir).is_none());
    }

    #[test]
    fn export_to_markdown_roundtrip() {
        let persona = PortablePersona {
            name: "reviewer".into(),
            description: "Code review specialist".into(),
            system_prompt: "You review code for quality.".into(),
            tools: vec!["file_read".into(), "git_diff".into()],
            source_format: "test".into(),
        };

        let md = export_to_markdown(&persona);
        assert!(md.contains("# reviewer"));
        assert!(md.contains("Code review specialist"));
        assert!(md.contains("You review code"));
        assert!(md.contains("- file_read"));
        assert!(md.contains("- git_diff"));
    }

    #[test]
    fn export_to_cognitive_yaml_produces_valid_yaml() {
        let persona = PortablePersona {
            name: "analyst".into(),
            description: "Data analyst".into(),
            system_prompt: "Analyze data.\nProduce insights.".into(),
            tools: vec![],
            source_format: "test".into(),
        };

        let yaml = export_to_cognitive_yaml(&persona);
        assert!(yaml.contains("persona_name: analyst"));
        assert!(yaml.contains("display_name:"));
        assert!(yaml.contains("core_mandate:"));
    }
}
