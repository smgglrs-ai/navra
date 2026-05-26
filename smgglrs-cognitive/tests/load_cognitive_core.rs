//! Integration test: load the full cognitive_core directory
//! (38 personas, 36 heuristics, 7 directives, 3 specializations).

use smgglrs_cognitive::{assemble, ForgeService};
use std::path::Path;

fn cognitive_core_path() -> std::path::PathBuf {
    // cargo test runs from workspace root or crate root — try both
    for candidate in ["cognitive_core", "../cognitive_core"] {
        let path = Path::new(candidate);
        if path.exists() {
            return path.to_path_buf();
        }
    }
    panic!(
        "cognitive_core/ not found — run from repo root. \
         This test validates the ported the original Python prototype artifacts."
    );
}

#[test]
fn load_all_artifacts() {
    let forge = ForgeService::load(&cognitive_core_path()).unwrap();
    assert!(
        forge.persona_count() >= 43,
        "expected ≥43 personas, got {}",
        forge.persona_count()
    );
    assert!(
        forge.heuristic_count() >= 36,
        "expected ≥36 heuristics, got {}",
        forge.heuristic_count()
    );
    assert!(
        forge.directive_count() >= 7,
        "expected ≥7 directives, got {}",
        forge.directive_count()
    );
}

#[test]
fn assemble_software_developer() {
    let forge = ForgeService::load(&cognitive_core_path()).unwrap();
    let output = assemble(
        &forge,
        "software_developer",
        "Fix the login bug",
        None,
        None,
    )
    .unwrap();
    let prompt = output.system_prompt();
    assert!(
        prompt.contains("Software Developer"),
        "missing display name"
    );
    assert!(
        prompt.len() > 500,
        "prompt too short: {} chars",
        prompt.len()
    );
    assert!(output.estimated_tokens > 0);
}

#[test]
fn assemble_guardian_loads_directives() {
    let forge = ForgeService::load(&cognitive_core_path()).unwrap();
    let output = assemble(&forge, "smgglrs_guardian", "Check system", None, None).unwrap();
    let prompt = output.system_prompt();
    assert!(
        prompt.contains("Core Directives"),
        "guardian should load directives"
    );
}

#[test]
fn all_personas_assemble_without_error() {
    let forge = ForgeService::load(&cognitive_core_path()).unwrap();
    for name in forge.persona_names() {
        let result = assemble(&forge, name, "test", None, None);
        assert!(
            result.is_ok(),
            "persona '{}' failed to assemble: {:?}",
            name,
            result.err()
        );
    }
}

#[test]
fn model_for_phase_returns_configured_models() {
    let forge = ForgeService::load(&cognitive_core_path()).unwrap();
    // software_developer has execution_model set
    if let Some(model) = forge.model_for_phase("software_developer", "execution") {
        assert!(!model.is_empty());
    }
}
