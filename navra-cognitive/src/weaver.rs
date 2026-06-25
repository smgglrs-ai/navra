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
use crate::types::{InjectPosition, Persona, ResolvedPrompt};

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
    assemble_with_phase(
        forge,
        persona_name,
        user_prompt,
        specialization,
        context,
        None,
    )
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
    assemble_full(
        forge,
        persona_name,
        user_prompt,
        specialization,
        context,
        phase,
        &[],
    )
}

/// Assemble with resolved upstream prompts injected at their specified positions.
///
/// This is the full-featured entry point. The `resolved_prompts` slice
/// contains upstream MCP prompts that have already been fetched via
/// `prompts/get`. The Weaver inserts them at the positions specified by
/// each [`ResolvedPrompt::position`].
pub fn assemble_full(
    forge: &ForgeService,
    persona_name: &str,
    user_prompt: &str,
    specialization: Option<&str>,
    context: Option<&str>,
    phase: Option<&str>,
    resolved_prompts: &[ResolvedPrompt],
) -> Result<WeaverOutput, CognitiveError> {
    let persona = if let Some(spec_name) = specialization {
        forge.get_persona_specialized(persona_name, spec_name)?
    } else {
        forge
            .get_persona(persona_name)
            .ok_or_else(|| CognitiveError::PersonaNotFound(persona_name.into()))?
            .clone()
    };

    let cacheable_prefix = build_cacheable_prefix(forge, &persona, resolved_prompts);
    let output_schema = persona.output_schema.clone();
    let output_json_schema = persona.output_json_schema.clone();

    // Select context limit based on phase
    let context_limit = match phase {
        Some("planning") => persona.planning_context_limit,
        Some("execution") => persona.execution_context_limit,
        _ => persona
            .planning_context_limit
            .or(persona.execution_context_limit),
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
/// 2. `BeforeMandate` upstream prompts
/// 3. Core mandate
/// 4. `AfterMandate` upstream prompts
/// 5. Resolved heuristics
/// 6. `AfterHeuristics` upstream prompts
/// 7. Few-shot examples (up to 3)
/// 8. `AfterExamples` upstream prompts
fn build_cacheable_prefix(
    forge: &ForgeService,
    persona: &Persona,
    resolved_prompts: &[ResolvedPrompt],
) -> String {
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

    // 2. BeforeMandate upstream prompts
    inject_at_position(
        &mut sections,
        resolved_prompts,
        &InjectPosition::BeforeMandate,
    );

    // 3. Core mandate
    sections.push(format!(
        "# Core Mandate: {}\n\n{}",
        persona.display_name, persona.core_mandate
    ));

    // 4. AfterMandate upstream prompts
    inject_at_position(
        &mut sections,
        resolved_prompts,
        &InjectPosition::AfterMandate,
    );

    // 4b. Constraints (negative instructions)
    if !persona.constraints.is_empty() {
        let mut constraints_text = String::from("## Constraints\n");
        for c in &persona.constraints {
            constraints_text.push_str(&format!("\n- {c}"));
        }
        sections.push(constraints_text);
    }

    // 5. Resolved heuristics
    let heuristic_text = resolve_heuristics(forge, &persona.heuristics);
    if !heuristic_text.is_empty() {
        sections.push(format!("## Heuristics to Apply\n\n{heuristic_text}"));
    }

    // 6. AfterHeuristics upstream prompts
    inject_at_position(
        &mut sections,
        resolved_prompts,
        &InjectPosition::AfterHeuristics,
    );

    // 7. Few-shot examples (up to 3)
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

    // 8. AfterExamples upstream prompts
    inject_at_position(
        &mut sections,
        resolved_prompts,
        &InjectPosition::AfterExamples,
    );

    sections.join("\n\n")
}

/// Maximum characters per individual upstream MCP prompt injected into
/// the system prompt. Prompts exceeding this are truncated to mitigate
/// prompt injection via oversized upstream content.
const MAX_PROMPT_CHARS: usize = 8000;

/// Maximum total characters across all upstream MCP prompts injected
/// into the system prompt in a single assembly.
const MAX_TOTAL_PROMPT_CHARS: usize = 20000;

/// Insert resolved prompts matching the given position into sections.
///
/// Each prompt is capped at [`MAX_PROMPT_CHARS`] characters, and the
/// cumulative total across all positions is capped at
/// [`MAX_TOTAL_PROMPT_CHARS`]. Truncated prompts are logged as warnings.
fn inject_at_position(
    sections: &mut Vec<String>,
    prompts: &[ResolvedPrompt],
    position: &InjectPosition,
) {
    // Calculate how many prompt chars have already been injected
    let existing_prompt_chars: usize = sections
        .iter()
        .filter(|s| s.starts_with("## Upstream Prompt:"))
        .map(|s| s.len())
        .sum();
    let mut budget_remaining = MAX_TOTAL_PROMPT_CHARS.saturating_sub(existing_prompt_chars);

    for rp in prompts.iter().filter(|rp| &rp.position == position) {
        if budget_remaining == 0 {
            tracing::warn!(
                label = %rp.label,
                "Upstream prompt dropped: total prompt budget exhausted ({} chars)",
                MAX_TOTAL_PROMPT_CHARS,
            );
            continue;
        }

        let content = if rp.content.len() > MAX_PROMPT_CHARS {
            tracing::warn!(
                label = %rp.label,
                original_len = rp.content.len(),
                max = MAX_PROMPT_CHARS,
                "Upstream MCP prompt truncated to prevent prompt injection"
            );
            // Truncate at a char boundary
            let mut end = MAX_PROMPT_CHARS;
            while end > 0 && !rp.content.is_char_boundary(end) {
                end -= 1;
            }
            &rp.content[..end]
        } else {
            &rp.content
        };

        let entry = format!("## Upstream Prompt: {}\n\n{}", rp.label, content);
        let entry_len = entry.len();
        if entry_len > budget_remaining {
            tracing::warn!(
                label = %rp.label,
                "Upstream prompt truncated by total budget ({} remaining of {})",
                budget_remaining,
                MAX_TOTAL_PROMPT_CHARS,
            );
            let mut end = budget_remaining;
            while end > 0 && !entry.is_char_boundary(end) {
                end -= 1;
            }
            sections.push(entry[..end].to_string());
            budget_remaining = 0;
        } else {
            sections.push(entry);
            budget_remaining -= entry_len;
        }
    }
}

/// Load skill cards from a directory of YAML files.
///
/// Each YAML file should deserialize to a [`crate::types::SkillCard`]. Files that
/// fail to parse are logged and skipped (graceful degradation).
pub fn load_skill_cards(dir: &std::path::Path) -> Vec<crate::types::SkillCard> {
    let mut cards = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return cards,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml")
            && path.extension().and_then(|e| e.to_str()) != Some("yml")
        {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_yaml::from_str::<crate::types::SkillCard>(&content) {
                Ok(card) => cards.push(card),
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "Failed to parse skill card");
                }
            },
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "Failed to read skill card");
            }
        }
    }
    cards
}

/// Select the top matching skill cards for the given task text.
///
/// Matches by counting keyword overlap between the task text
/// (lowercased) and each card's keywords. Returns up to `max_cards`
/// cards, capped at `max_tokens` total estimated tokens.
pub fn select_skill_cards<'a>(
    cards: &'a [crate::types::SkillCard],
    task_text: &str,
    max_cards: usize,
    max_tokens: u32,
) -> Vec<&'a crate::types::SkillCard> {
    let task_lower = task_text.to_lowercase();
    let task_words: Vec<&str> = task_lower.split_whitespace().collect();

    let mut scored: Vec<(usize, &crate::types::SkillCard)> = cards
        .iter()
        .map(|card| {
            let score = card
                .keywords
                .iter()
                .filter(|kw| {
                    let kw_lower = kw.to_lowercase();
                    task_words.iter().any(|tw| tw.contains(&kw_lower))
                        || task_lower.contains(&kw_lower)
                })
                .count();
            (score, card)
        })
        .filter(|(score, _)| *score > 0)
        .collect();

    scored.sort_by(|a, b| b.0.cmp(&a.0));

    let mut selected = Vec::new();
    let mut total_tokens = 0u32;
    for (_, card) in scored.into_iter().take(max_cards) {
        let card_tokens = budget::estimate_tokens(&card.content);
        if total_tokens + card_tokens > max_tokens {
            break;
        }
        total_tokens += card_tokens;
        selected.push(card);
    }
    selected
}

/// Format selected skill cards as a context section for injection.
pub fn format_skill_cards(cards: &[&crate::types::SkillCard]) -> String {
    if cards.is_empty() {
        return String::new();
    }
    let mut sections = Vec::new();
    sections.push("## Skill Cards".to_string());
    for card in cards {
        sections.push(format!("### {}\n{}", card.name, card.content));
    }
    sections.join("\n\n")
}

/// Resolve heuristic references to their facet content.
fn resolve_heuristics(forge: &ForgeService, refs: &[crate::types::HeuristicRef]) -> String {
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
                    let display = facet.display_name.as_deref().unwrap_or(&facet.facet_name);
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
        assert_eq!(
            output.user_prompt,
            "## My Current Request:\nFix the login bug"
        );
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

        let output = assemble(&forge, "developer", "Task", None, Some("Some context")).unwrap();

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

    #[test]
    fn inject_prompt_after_mandate() {
        let tmp = tempfile::tempdir().unwrap();
        let forge = setup_forge(tmp.path());

        let prompts = vec![ResolvedPrompt {
            position: InjectPosition::AfterMandate,
            content: "Use search_codes to find real articles.".to_string(),
            label: "syllogis:legal_analysis".to_string(),
        }];

        let output = assemble_full(
            &forge,
            "developer",
            "Analyze case",
            None,
            None,
            None,
            &prompts,
        )
        .unwrap();

        let prefix = &output.cacheable_prefix;
        assert!(prefix.contains("Upstream Prompt: syllogis:legal_analysis"));
        assert!(prefix.contains("Use search_codes to find real articles."));

        // Verify ordering: mandate before upstream prompt, upstream prompt before heuristics
        let mandate_pos = prefix.find("Core Mandate").unwrap();
        let upstream_pos = prefix.find("Upstream Prompt").unwrap();
        let heuristics_pos = prefix.find("Heuristics to Apply").unwrap();
        assert!(mandate_pos < upstream_pos);
        assert!(upstream_pos < heuristics_pos);
    }

    #[test]
    fn inject_prompt_before_mandate() {
        let tmp = tempfile::tempdir().unwrap();
        let forge = setup_forge(tmp.path());

        let prompts = vec![ResolvedPrompt {
            position: InjectPosition::BeforeMandate,
            content: "Domain context goes here.".to_string(),
            label: "upstream:context".to_string(),
        }];

        let output =
            assemble_full(&forge, "developer", "Task", None, None, None, &prompts).unwrap();

        let prefix = &output.cacheable_prefix;
        let upstream_pos = prefix.find("Upstream Prompt: upstream:context").unwrap();
        let mandate_pos = prefix.find("Core Mandate").unwrap();
        assert!(upstream_pos < mandate_pos);
    }

    #[test]
    fn inject_prompt_after_heuristics() {
        let tmp = tempfile::tempdir().unwrap();
        let forge = setup_forge(tmp.path());

        let prompts = vec![ResolvedPrompt {
            position: InjectPosition::AfterHeuristics,
            content: "Post-heuristic instructions.".to_string(),
            label: "upstream:post_heuristics".to_string(),
        }];

        let output =
            assemble_full(&forge, "developer", "Task", None, None, None, &prompts).unwrap();

        let prefix = &output.cacheable_prefix;
        let heuristics_pos = prefix.find("Heuristics to Apply").unwrap();
        let upstream_pos = prefix
            .find("Upstream Prompt: upstream:post_heuristics")
            .unwrap();
        assert!(heuristics_pos < upstream_pos);
    }

    #[test]
    fn inject_prompt_after_examples() {
        let tmp = tempfile::tempdir().unwrap();
        let forge = setup_forge(tmp.path());

        let prompts = vec![ResolvedPrompt {
            position: InjectPosition::AfterExamples,
            content: "Final instructions.".to_string(),
            label: "upstream:final".to_string(),
        }];

        let output =
            assemble_full(&forge, "developer", "Task", None, None, None, &prompts).unwrap();

        let prefix = &output.cacheable_prefix;
        assert!(prefix.contains("Final instructions."));
        // AfterExamples should be the last section
        let upstream_pos = prefix.find("Upstream Prompt: upstream:final").unwrap();
        assert!(upstream_pos > prefix.find("Heuristics to Apply").unwrap());
    }

    #[test]
    fn inject_multiple_prompts_at_different_positions() {
        let tmp = tempfile::tempdir().unwrap();
        let forge = setup_forge(tmp.path());

        let prompts = vec![
            ResolvedPrompt {
                position: InjectPosition::BeforeMandate,
                content: "Before mandate.".to_string(),
                label: "a:before".to_string(),
            },
            ResolvedPrompt {
                position: InjectPosition::AfterMandate,
                content: "After mandate.".to_string(),
                label: "b:after".to_string(),
            },
            ResolvedPrompt {
                position: InjectPosition::AfterExamples,
                content: "At the end.".to_string(),
                label: "c:end".to_string(),
            },
        ];

        let output =
            assemble_full(&forge, "developer", "Task", None, None, None, &prompts).unwrap();

        let prefix = &output.cacheable_prefix;
        let before_pos = prefix.find("a:before").unwrap();
        let mandate_pos = prefix.find("Core Mandate").unwrap();
        let after_pos = prefix.find("b:after").unwrap();
        let end_pos = prefix.find("c:end").unwrap();

        assert!(before_pos < mandate_pos);
        assert!(mandate_pos < after_pos);
        assert!(after_pos < end_pos);
    }

    #[test]
    fn inject_prompt_truncated_when_oversized() {
        let tmp = tempfile::tempdir().unwrap();
        let forge = setup_forge(tmp.path());

        // Create a prompt that exceeds MAX_PROMPT_CHARS (8000)
        let oversized_content = "X".repeat(10000);
        let prompts = vec![ResolvedPrompt {
            position: InjectPosition::AfterMandate,
            content: oversized_content.clone(),
            label: "upstream:oversized".to_string(),
        }];

        let output =
            assemble_full(&forge, "developer", "Task", None, None, None, &prompts).unwrap();

        let prefix = &output.cacheable_prefix;
        assert!(prefix.contains("Upstream Prompt: upstream:oversized"));
        // The injected content should be truncated, not the full 10000 chars
        let upstream_section = prefix
            .split("## Upstream Prompt: upstream:oversized")
            .nth(1)
            .unwrap();
        assert!(
            upstream_section.len() < oversized_content.len(),
            "Oversized prompt should have been truncated"
        );
    }

    #[test]
    fn inject_prompt_total_budget_caps_multiple_prompts() {
        let tmp = tempfile::tempdir().unwrap();
        let forge = setup_forge(tmp.path());

        // Create multiple prompts that together exceed MAX_TOTAL_PROMPT_CHARS (20000)
        let large_content = "Y".repeat(7000);
        let prompts = vec![
            ResolvedPrompt {
                position: InjectPosition::AfterMandate,
                content: large_content.clone(),
                label: "a:first".to_string(),
            },
            ResolvedPrompt {
                position: InjectPosition::AfterMandate,
                content: large_content.clone(),
                label: "b:second".to_string(),
            },
            ResolvedPrompt {
                position: InjectPosition::AfterMandate,
                content: large_content.clone(),
                label: "c:third".to_string(),
            },
            ResolvedPrompt {
                position: InjectPosition::AfterMandate,
                content: large_content.clone(),
                label: "d:fourth".to_string(),
            },
        ];

        let output =
            assemble_full(&forge, "developer", "Task", None, None, None, &prompts).unwrap();

        let prefix = &output.cacheable_prefix;
        // At least the first two should be present; the fourth (28000+ chars)
        // should be dropped or truncated by the total budget
        assert!(prefix.contains("a:first"));
        assert!(prefix.contains("b:second"));
        // Total upstream prompt content should not exceed MAX_TOTAL_PROMPT_CHARS
        let total_upstream: usize = prefix
            .split("## Upstream Prompt:")
            .skip(1) // skip the part before the first match
            .map(|s| s.len())
            .sum();
        assert!(
            total_upstream <= super::MAX_TOTAL_PROMPT_CHARS + 500, // small margin for headers
            "Total upstream content {} exceeds budget {}",
            total_upstream,
            super::MAX_TOTAL_PROMPT_CHARS,
        );
    }

    #[test]
    fn no_upstream_prompts_matches_original() {
        let tmp = tempfile::tempdir().unwrap();
        let forge = setup_forge(tmp.path());

        let without = assemble(&forge, "developer", "Task", None, None).unwrap();
        let with_empty = assemble_full(&forge, "developer", "Task", None, None, None, &[]).unwrap();

        assert_eq!(without.cacheable_prefix, with_empty.cacheable_prefix);
    }

    #[test]
    fn skill_card_keyword_matching() {
        let cards = vec![
            crate::types::SkillCard {
                name: "file_ops".to_string(),
                keywords: vec!["read".into(), "write".into(), "file".into()],
                content: "Use file_read for content.".to_string(),
            },
            crate::types::SkillCard {
                name: "git_workflow".to_string(),
                keywords: vec!["git".into(), "commit".into(), "branch".into()],
                content: "Use git_status first.".to_string(),
            },
            crate::types::SkillCard {
                name: "security".to_string(),
                keywords: vec!["security".into(), "auth".into(), "vulnerability".into()],
                content: "Check for hardcoded secrets.".to_string(),
            },
        ];

        // Task about reading files should match file_ops
        let selected = select_skill_cards(&cards, "Read the config file", 2, 500);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].name, "file_ops");

        // Task about git should match git_workflow
        let selected = select_skill_cards(&cards, "Show git status and commit", 2, 500);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].name, "git_workflow");

        // No matching keywords
        let selected = select_skill_cards(&cards, "Deploy the application", 2, 500);
        assert!(selected.is_empty());
    }

    #[test]
    fn skill_card_injection_under_500_tokens() {
        let cards = vec![
            crate::types::SkillCard {
                name: "card_a".to_string(),
                keywords: vec!["test".into()],
                content: "A".repeat(400), // ~114 tokens
            },
            crate::types::SkillCard {
                name: "card_b".to_string(),
                keywords: vec!["test".into()],
                content: "B".repeat(400), // ~114 tokens
            },
            crate::types::SkillCard {
                name: "card_c".to_string(),
                keywords: vec!["test".into()],
                content: "C".repeat(2000), // ~571 tokens — too large alone
            },
        ];

        let selected = select_skill_cards(&cards, "run test suite", 2, 500);
        // card_a and card_b fit, card_c would bust the budget
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].name, "card_a");
        assert_eq!(selected[1].name, "card_b");

        let formatted = format_skill_cards(&selected.iter().copied().collect::<Vec<_>>());
        let tokens = crate::budget::estimate_tokens(&formatted);
        assert!(
            tokens <= 500,
            "Formatted skill cards exceeded 500 tokens: {tokens}"
        );
    }

    #[test]
    fn load_skill_cards_from_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let skills_dir = tmp.path().join("skills");
        fs::create_dir_all(&skills_dir).unwrap();
        fs::write(
            skills_dir.join("test_card.yaml"),
            r#"
name: test_card
keywords: [test, example]
content: "Test content for skill card."
"#,
        )
        .unwrap();

        let cards = load_skill_cards(&skills_dir);
        assert_eq!(cards.len(), 1);
        assert_eq!(cards[0].name, "test_card");
        assert_eq!(cards[0].keywords, vec!["test", "example"]);
    }

    #[test]
    fn load_skill_cards_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let cards = load_skill_cards(tmp.path());
        assert!(cards.is_empty());
    }

    #[test]
    fn format_skill_cards_empty() {
        let formatted = format_skill_cards(&[]);
        assert!(formatted.is_empty());
    }
}
