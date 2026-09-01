// --- Persona management CLI commands ---

use std::path::{Path, PathBuf};

/// Resolve the cognitive_core directory from flag, config, or default.
fn resolve_cognitive_core(flag: Option<&str>) -> PathBuf {
    if let Some(path) = flag {
        return PathBuf::from(crate::util::expand_tilde(path));
    }
    // Try loading config to get the cognitive_core path
    if let Ok(cfg) = crate::config::Config::load(None) {
        if let Some(ref cc) = cfg.cognitive_core {
            return PathBuf::from(crate::util::expand_tilde(cc));
        }
    }
    // Default
    dirs::config_dir()
        .unwrap_or_default()
        .join("navra/cognitive_core")
}

/// Create a new persona from a starter template.
pub(crate) fn persona_new(name: &str, output: Option<&str>) -> anyhow::Result<()> {
    let cognitive_core = resolve_cognitive_core(output);
    let personas_dir = cognitive_core.join("personas");
    std::fs::create_dir_all(&personas_dir)?;

    let file_path = personas_dir.join(format!("{name}.yaml"));
    if file_path.exists() {
        anyhow::bail!(
            "Persona already exists: {}. Edit it directly or remove it first.",
            file_path.display()
        );
    }

    // Convert snake_case name to Display Name
    let display_name: String = name
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(c) => c.to_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    let template = format!(
        r#"persona_name: {name}
display_name: "{display_name}"
core_mandate: >
  Describe this persona's role, expertise, and behavioral guidelines.

# Optional: reference heuristic modules and facets
# heuristics:
#   - module: security
#     facets: [least_privilege]

# Optional: restrict available tools
# tools:
#   - file_read
#   - rag_query

# Optional: per-phase model routing
# planning_model: granite-34b
# execution_model: granite-8b
"#
    );

    std::fs::write(&file_path, template)?;
    println!("Created persona at {}", file_path.display());
    println!("Run `navra validate-cognitive` to check references.");

    Ok(())
}

/// List available personas from the cognitive core directory.
pub(crate) fn persona_list(cognitive_core_flag: Option<&str>) -> anyhow::Result<()> {
    let cognitive_core = resolve_cognitive_core(cognitive_core_flag);
    let path = Path::new(&cognitive_core);

    if !path.exists() {
        eprintln!(
            "Cognitive core directory not found: {}\n\
             Create one with `navra persona new <name>` or specify --cognitive-core.",
            path.display()
        );
        std::process::exit(1);
    }

    let forge = navra_cognitive::ForgeService::load(path)?;
    let mut names = forge.persona_names();
    names.sort();

    if names.is_empty() {
        println!("No personas found in {}", path.display());
        println!("Create one with: navra persona new <name>");
        return Ok(());
    }

    // Print header
    println!(
        "{:<24} {:<26} {}",
        "Name", "Display Name", "Mandate (first line)"
    );
    println!(
        "{:<24} {:<26} {}",
        "\u{2500}".repeat(20),
        "\u{2500}".repeat(22),
        "\u{2500}".repeat(30)
    );

    for name in &names {
        if let Some(persona) = forge.get_persona(name) {
            let mandate_first_line = persona
                .core_mandate
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("")
                .trim();
            // Truncate mandate to fit
            let mandate_display = if mandate_first_line.len() > 50 {
                format!("{}...", &mandate_first_line[..47])
            } else {
                mandate_first_line.to_string()
            };
            println!(
                "{:<24} {:<26} {}",
                persona.persona_name, persona.display_name, mandate_display
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persona_new_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().to_str().unwrap();

        persona_new("test_persona", Some(output)).unwrap();

        let file = dir.path().join("personas/test_persona.yaml");
        assert!(file.exists(), "persona file should be created");

        let content = std::fs::read_to_string(&file).unwrap();
        assert!(content.contains("persona_name: test_persona"));
        assert!(content.contains("display_name: \"Test Persona\""));
        assert!(content.contains("core_mandate:"));
    }

    #[test]
    fn persona_new_rejects_existing() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().to_str().unwrap();

        persona_new("duplicate", Some(output)).unwrap();
        let result = persona_new("duplicate", Some(output));
        assert!(result.is_err(), "should reject duplicate persona");
    }

    #[test]
    fn persona_list_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        // Create the personas subdirectory but leave it empty
        std::fs::create_dir_all(dir.path().join("personas")).unwrap();

        let result = persona_list(Some(dir.path().to_str().unwrap()));
        assert!(result.is_ok());
    }

    #[test]
    fn persona_list_with_personas() {
        let dir = tempfile::tempdir().unwrap();
        let personas_dir = dir.path().join("personas");
        std::fs::create_dir_all(&personas_dir).unwrap();

        std::fs::write(
            personas_dir.join("test.yaml"),
            "persona_name: test\ndisplay_name: \"Test\"\ncore_mandate: \"Do testing.\"\n",
        )
        .unwrap();

        let result = persona_list(Some(dir.path().to_str().unwrap()));
        assert!(result.is_ok());
    }
}
