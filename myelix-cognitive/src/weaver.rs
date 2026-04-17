//! Weaver: assembles persona + directives + heuristics into a structured prompt.
//!
//! The output is split into a cacheable prefix (stable within a session)
//! and dynamic context (changes per invocation) to support prompt caching.
//!
//! When a context budget is provided, the Weaver truncates retrieved
//! context to fit within the budget. The system prompt (cacheable prefix)
//! is never truncated — it defines agent identity.

use crate::budget::{self, ContextBudget};
use crate::error::CognitiveError;
use crate::forge::ForgeService;
use crate::types::Persona;

/// Structured output from the Weaver for prompt caching support.
///
/// The system prompt is split into:
/// - **cacheable_prefix**: Stable within a session (directives + mandate + heuristics + examples)
/// - **dynamic_context**: May change per invocation (retrieved context, specialist catalog)
#[derive(Debug)]
pub struct WeaverOutput {
    /// Stable prompt prefix: directives + core mandate + heuristics + examples.
    pub cacheable_prefix: String,
    /// Dynamic context: retrieved documents, memory, specialist catalog.
    pub dynamic_context: String,
    /// Formatted user request.
    pub user_prompt: String,
    /// Output schema name for validation (if persona specifies one).
    pub output_schema: Option<String>,
    /// Inline JSON schema for structured output enforcement.
    /// When set, the model request should use ResponseFormat::JsonSchema.
    pub output_json_schema: Option<serde_json::Value>,
    /// Estimated token count for the full system prompt.
    pub estimated_tokens: u32,
    /// Context limit from the persona (if set).
    pub context_limit: Option<u32>,
}

impl WeaverOutput {
    /// Full system prompt (cacheable_prefix + dynamic_context).
    pub fn system_prompt(&self) -> String {
        let mut parts = Vec::new();
        if !self.dynamic_context.is_empty() {
            parts.push(self.dynamic_context.as_str());
        }
        if !self.cacheable_prefix.is_empty() {
            parts.push(self.cacheable_prefix.as_str());
        }
        parts.join("\n\n")
    }

    /// Tokens remaining for conversation history and model output,
    /// given a total context window size.
    pub fn remaining_tokens(&self, context_window: u32) -> u32 {
        context_window.saturating_sub(self.estimated_tokens)
    }
}

/// Assemble a structured prompt for a persona.
///
/// # Arguments
/// - `forge` — loaded cognitive artifacts
/// - `persona_name` — persona to assemble for
/// - `user_prompt` — the user's request
/// - `specialization` — optional specialization name to merge
/// - `context` — optional retrieved context to include
pub fn assemble(
    forge: &ForgeService,
    persona_name: &str,
    user_prompt: &str,
    specialization: Option<&str>,
    context: Option<&str>,
) -> Result<WeaverOutput, CognitiveError> {
    assemble_with_phase(forge, persona_name, user_prompt, specialization, context, None)
}

/// Assemble with an explicit phase for context limit selection.
///
/// When `phase` is `Some("planning")` or `Some("execution")`, the
/// persona's per-phase context limit is used to budget retrieved context.
pub fn assemble_with_phase(
    forge: &ForgeService,
    persona_name: &str,
    user_prompt: &str,
    specialization: Option<&str>,
    context: Option<&str>,
    phase: Option<&str>,
) -> Result<WeaverOutput, CognitiveError> {
    let persona = if let Some(spec_name) = specialization {
        forge.get_persona_specialized(persona_name, spec_name)?
    } else {
        forge
            .get_persona(persona_name)
            .ok_or_else(|| CognitiveError::PersonaNotFound(persona_name.into()))?
            .clone()
    };

    let cacheable_prefix = build_cacheable_prefix(forge, &persona);
    let output_schema = persona.output_schema.clone();
    let output_json_schema = persona.output_json_schema.clone();

    // Select context limit based on phase
    let context_limit = match phase {
        Some("planning") => persona.planning_context_limit,
        Some("execution") => persona.execution_context_limit,
        _ => persona.planning_context_limit.or(persona.execution_context_limit),
    };

    // Budget-aware context truncation
    let dynamic_context = if let (Some(limit), Some(ctx)) = (context_limit, context) {
        let mut budget = ContextBudget::new(limit);
        budget.set_system_prompt(&cacheable_prefix);
        let (_, context_budget) = budget.split();

        let raw_context = build_dynamic_context(Some(ctx));
        if budget::estimate_tokens(&raw_context) > context_budget {
            tracing::info!(
                persona = persona_name,
                limit = limit,
                context_tokens = budget::estimate_tokens(&raw_context),
                context_budget = context_budget,
                "Truncating retrieved context to fit budget"
            );
            budget::truncate_to_budget(&raw_context, context_budget)
        } else {
            raw_context
        }
    } else {
        build_dynamic_context(context)
    };

    let full_prompt = if dynamic_context.is_empty() {
        cacheable_prefix.clone()
    } else {
        format!("{dynamic_context}\n\n{cacheable_prefix}")
    };
    let estimated_tokens = budget::estimate_tokens(&full_prompt);

    Ok(WeaverOutput {
        cacheable_prefix,
        dynamic_context,
        user_prompt: format!("## My Current Request:\n{user_prompt}"),
        output_schema,
        output_json_schema,
        estimated_tokens,
        context_limit,
    })
}

/// Build the dynamic context section (changes per invocation).
fn build_dynamic_context(context: Option<&str>) -> String {
    match context {
        Some(ctx) if !ctx.is_empty() => {
            format!("### Retrieved Context ###\n{ctx}\n---")
        }
        _ => String::new(),
    }
}

/// Build the cacheable prefix (stable within a session).
///
/// Assembly order (matching Python Weaver):
/// 1. Core directives (if loads_directives)
/// 2. Core mandate
/// 3. Resolved heuristics
/// 4. Few-shot examples (up to 3)
fn build_cacheable_prefix(forge: &ForgeService, persona: &Persona) -> String {
    let mut sections = Vec::new();

    // 1. Core directives (Guardian only)
    if persona.loads_directives {
        let directives = forge.all_directives();
        if !directives.is_empty() {
            let mut directive_text = String::from("# Core Directives\n");
            for d in &directives {
                directive_text.push_str(&format!("\n## {}\n{}\n", d.directive_name, d.content));
            }
            sections.push(directive_text);
        }
    }

    // 2. Core mandate
    sections.push(format!(
        "# Core Mandate: {}\n\n{}",
        persona.display_name, persona.core_mandate
    ));

    // 3. Resolved heuristics
    let heuristic_text = resolve_heuristics(forge, &persona.heuristics);
    if !heuristic_text.is_empty() {
        sections.push(format!("## Heuristics to Apply\n\n{heuristic_text}"));
    }

    // 4. Few-shot examples (up to 3)
    if !persona.examples.is_empty() {
        let mut examples_text = String::from("## Examples\n");
        for (i, ex) in persona.examples.iter().take(3).enumerate() {
            examples_text.push_str(&format!(
                "\n### Example {}: {}\n**Input:** {}\n**Output:** {}\n",
                i + 1,
                ex.title,
                ex.input,
                ex.output,
            ));
            if let Some(ref thought) = ex.thought_process {
                examples_text.push_str(&format!("**Thought process:** {thought}\n"));
            }
        }
        sections.push(examples_text);
    }

    sections.join("\n\n")
}

/// Resolve heuristic references to their facet content.
fn resolve_heuristics(
    forge: &ForgeService,
    refs: &[crate::types::HeuristicRef],
) -> String {
    let mut parts = Vec::new();
    for href in refs {
        let module = match forge.get_heuristic(&href.module) {
            Some(m) => m,
            None => {
                tracing::warn!(module = %href.module, "Heuristic module not found, skipping");
                continue;
            }
        };
        for facet_name in &href.facets {
            match module.facets.iter().find(|f| f.facet_name == *facet_name) {
                Some(facet) => {
                    let display = facet
                        .display_name
                        .as_deref()
                        .unwrap_or(&facet.facet_name);
                    parts.push(format!("### {display}\n{}", facet.content));
                }
                None => {
                    tracing::warn!(
                        module = %href.module,
                        facet = %facet_name,
                        "Facet not found in heuristic module, skipping"
                    );
                }
            }
        }
    }
    parts.join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_forge(dir: &std::path::Path) -> ForgeService {
        let personas_dir = dir.join("personas");
        let directives_dir = dir.join("directives");
        let heuristics_dir = dir.join("heuristics");
        fs::create_dir_all(&personas_dir).unwrap();
        fs::create_dir_all(&directives_dir).unwrap();
        fs::create_dir_all(&heuristics_dir).unwrap();

        fs::write(
            personas_dir.join("developer.yaml"),
            r#"
persona_name: developer
display_name: "Software Developer"
core_mandate: "Write high-quality code."
heuristics:
  - module: security
    facets: [input_validation]
  - module: craftsmanship
    facets: [code_quality]
output_schema: impl_result
"#,
        )
        .unwrap();

        fs::write(
            personas_dir.join("guardian.yaml"),
            r#"
persona_name: guardian
display_name: "Guardian"
core_mandate: "Protect the system."
loads_directives: true
"#,
        )
        .unwrap();

        fs::write(
            directives_dir.join("security.yaml"),
            r#"
directive_name: security_protocol
content: "Validate all inputs. Never trust external data."
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
    display_name: "Input Validation"
    content: "Always validate and sanitize external inputs."
"#,
        )
        .unwrap();

        fs::write(
            heuristics_dir.join("craftsmanship.yaml"),
            r#"
heuristic_name: craftsmanship
description: "Code quality"
facets:
  - facet_name: code_quality
    content: "Write clean, readable, well-tested code."
"#,
        )
        .unwrap();

        ForgeService::load(dir).unwrap()
    }

    #[test]
    fn assemble_basic_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let forge = setup_forge(tmp.path());

        let output = assemble(&forge, "developer", "Fix the login bug", None, None).unwrap();

        assert!(output.cacheable_prefix.contains("Software Developer"));
        assert!(output.cacheable_prefix.contains("Write high-quality code"));
        assert!(output.cacheable_prefix.contains("Input Validation"));
        assert!(output.cacheable_prefix.contains("validate and sanitize"));
        assert!(output.cacheable_prefix.contains("clean, readable"));
        assert!(output.dynamic_context.is_empty());
        assert_eq!(output.user_prompt, "## My Current Request:\nFix the login bug");
        assert_eq!(output.output_schema.as_deref(), Some("impl_result"));
    }

    #[test]
    fn assemble_with_context() {
        let tmp = tempfile::tempdir().unwrap();
        let forge = setup_forge(tmp.path());

        let output = assemble(
            &forge,
            "developer",
            "Fix it",
            None,
            Some("Error log: NullPointerException at line 42"),
        )
        .unwrap();

        assert!(output.dynamic_context.contains("Retrieved Context"));
        assert!(output.dynamic_context.contains("NullPointerException"));
    }

    #[test]
    fn assemble_guardian_includes_directives() {
        let tmp = tempfile::tempdir().unwrap();
        let forge = setup_forge(tmp.path());

        let output = assemble(&forge, "guardian", "Analyze threat", None, None).unwrap();

        assert!(output.cacheable_prefix.contains("Core Directives"));
        assert!(output.cacheable_prefix.contains("security_protocol"));
        assert!(output.cacheable_prefix.contains("Validate all inputs"));
    }

    #[test]
    fn assemble_non_guardian_skips_directives() {
        let tmp = tempfile::tempdir().unwrap();
        let forge = setup_forge(tmp.path());

        let output = assemble(&forge, "developer", "Code", None, None).unwrap();

        assert!(!output.cacheable_prefix.contains("Core Directives"));
    }

    #[test]
    fn system_prompt_combines_parts() {
        let tmp = tempfile::tempdir().unwrap();
        let forge = setup_forge(tmp.path());

        let output = assemble(
            &forge,
            "developer",
            "Task",
            None,
            Some("Some context"),
        )
        .unwrap();

        let full = output.system_prompt();
        assert!(full.contains("Retrieved Context"));
        assert!(full.contains("Core Mandate"));
        assert!(full.contains("Heuristics"));
    }

    #[test]
    fn assemble_unknown_persona_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let forge = setup_forge(tmp.path());

        let result = assemble(&forge, "nonexistent", "Task", None, None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CognitiveError::PersonaNotFound(_)
        ));
    }

    #[test]
    fn empty_context_not_included() {
        let tmp = tempfile::tempdir().unwrap();
        let forge = setup_forge(tmp.path());

        let output = assemble(&forge, "developer", "Task", None, Some("")).unwrap();
        assert!(output.dynamic_context.is_empty());
    }
}
