//! Upstream MCP prompt resolution.
//!
//! Fetches prompts from upstream MCP servers referenced in a persona's
//! `mcp_prompts` field and returns [`navra_cognitive::ResolvedPrompt`] values ready for
//! injection by the Weaver.

use crate::client::McpClient;
use crate::error::AgentError;
use navra_cognitive::{McpPromptRef, ResolvedPrompt};
use std::collections::HashMap;

/// Resolve a set of [`McpPromptRef`] entries by calling `prompts/get`
/// on the MCP client for each one.
///
/// Template variables like `{{ input }}` in argument values are replaced
/// with `user_prompt` before the call.
///
/// The MCP client must be connected to a server (or gateway) that exposes
/// the referenced prompts. When used with navra as the gateway, the
/// upstream name in [`McpPromptRef`] identifies which upstream server the
/// prompt belongs to — the gateway proxies the `prompts/get` call.
///
/// For now, prompts are fetched from a single MCP connection. The
/// `upstream` field in [`McpPromptRef`] is used as a prefix to namespace
/// the prompt name (e.g., `syllogis:legal_analysis`).
pub async fn resolve_mcp_prompts(
    client: &mut McpClient,
    refs: &[McpPromptRef],
    user_prompt: &str,
) -> Result<Vec<ResolvedPrompt>, AgentError> {
    let mut resolved = Vec::with_capacity(refs.len());

    for pref in refs {
        // Resolve template variables in arguments
        let arguments = match &pref.arguments {
            Some(args) => args
                .iter()
                .map(|(k, v)| {
                    let resolved_val = resolve_template(v, user_prompt);
                    (k.clone(), resolved_val)
                })
                .collect::<HashMap<String, String>>(),
            None => HashMap::new(),
        };

        // Fetch the prompt. The prompt name may be just the prompt name
        // if the gateway routes by upstream, or "upstream:prompt" for
        // namespaced access.
        let prompt_name = &pref.prompt;
        let label = format!("{}:{}", pref.upstream, pref.prompt);

        match client.get_prompt(prompt_name, arguments).await {
            Ok(result) => {
                // Concatenate all message contents into a single text block
                let content = result
                    .messages
                    .iter()
                    .filter_map(|m| match &m.content {
                        navra_protocol::PromptMessageContent::Text { text } => Some(text.as_str()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("\n\n");

                if content.is_empty() {
                    tracing::warn!(
                        upstream = %pref.upstream,
                        prompt = %pref.prompt,
                        "Upstream prompt returned empty content, skipping"
                    );
                    continue;
                }

                tracing::info!(
                    upstream = %pref.upstream,
                    prompt = %pref.prompt,
                    position = ?pref.inject_position,
                    content_len = content.len(),
                    "Resolved upstream prompt"
                );

                resolved.push(ResolvedPrompt {
                    position: pref.inject_position.clone(),
                    content,
                    label,
                });
            }
            Err(e) => {
                tracing::warn!(
                    upstream = %pref.upstream,
                    prompt = %pref.prompt,
                    error = %e,
                    "Failed to resolve upstream prompt, skipping"
                );
            }
        }
    }

    Ok(resolved)
}

/// Resolve an [`navra_cognitive::McpPersonaSource`] by calling `prompts/get` on the upstream.
///
/// Returns the concatenated prompt messages as a single string, which
/// becomes the persona's `core_mandate`.
pub async fn resolve_persona_source(
    client: &mut McpClient,
    source: &navra_cognitive::McpPersonaSource,
) -> Result<String, AgentError> {
    let arguments = source.arguments.clone().unwrap_or_default();
    let prompt_name = &source.prompt;

    let result = client
        .get_prompt(prompt_name, arguments)
        .await
        .map_err(|e| {
            AgentError::Config(format!(
                "failed to resolve persona source {}:{}: {}",
                source.upstream, source.prompt, e
            ))
        })?;

    let content = result
        .messages
        .iter()
        .filter_map(|m| match &m.content {
            navra_protocol::PromptMessageContent::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n\n");

    if content.is_empty() {
        return Err(AgentError::Config(format!(
            "persona source {}:{} returned empty content",
            source.upstream, source.prompt
        )));
    }

    tracing::info!(
        upstream = %source.upstream,
        prompt = %source.prompt,
        content_len = content.len(),
        "Resolved MCP persona source"
    );

    Ok(content)
}

/// Resolve a persona's MCP source and `mcp_prompts`, returning a
/// fully-populated [`navra_cognitive::Persona`] ready for the Weaver.
///
/// - If `persona.source` is `Some`, calls [`resolve_persona_source()`]
///   and sets the result as `core_mandate`.
/// - Any `mcp_prompts` entries are resolved via [`resolve_mcp_prompts()`].
/// - Returns the resolved persona and the resolved prompts for the Weaver.
pub async fn resolve_persona(
    client: &mut McpClient,
    persona: &navra_cognitive::Persona,
    user_prompt: &str,
) -> Result<
    (
        navra_cognitive::Persona,
        Vec<navra_cognitive::ResolvedPrompt>,
    ),
    AgentError,
> {
    let mut resolved_persona = persona.clone();

    // Resolve MCP persona source -> core_mandate
    if let Some(ref source) = persona.source {
        let mandate = resolve_persona_source(client, source).await?;
        resolved_persona.core_mandate = mandate;

        tracing::info!(
            persona = %persona.persona_name,
            upstream = %source.upstream,
            prompt = %source.prompt,
            "Set core_mandate from MCP source"
        );
    }

    // Resolve mcp_prompts entries
    let resolved_prompts = if !persona.mcp_prompts.is_empty() {
        resolve_mcp_prompts(client, &persona.mcp_prompts, user_prompt).await?
    } else {
        Vec::new()
    };

    Ok((resolved_persona, resolved_prompts))
}

/// Replace `{{ input }}` template variables in a string with the user prompt.
fn resolve_template(template: &str, user_prompt: &str) -> String {
    template.replace("{{ input }}", user_prompt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use navra_cognitive::InjectPosition;

    #[test]
    fn resolve_template_replaces_input() {
        let result = resolve_template("Analyze: {{ input }}", "breach of contract case");
        assert_eq!(result, "Analyze: breach of contract case");
    }

    #[test]
    fn resolve_template_no_variable() {
        let result = resolve_template("static text", "ignored");
        assert_eq!(result, "static text");
    }

    #[test]
    fn resolve_template_multiple_occurrences() {
        let result = resolve_template("{{ input }} and {{ input }}", "X");
        assert_eq!(result, "X and X");
    }

    #[test]
    fn mcp_prompt_ref_serde_roundtrip() {
        let pref = McpPromptRef {
            upstream: "syllogis".to_string(),
            prompt: "legal_analysis".to_string(),
            inject_position: InjectPosition::AfterMandate,
            arguments: Some(
                [("case_description".to_string(), "{{ input }}".to_string())]
                    .into_iter()
                    .collect(),
            ),
        };

        let yaml = serde_yaml::to_string(&pref).unwrap();
        let back: McpPromptRef = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.upstream, "syllogis");
        assert_eq!(back.prompt, "legal_analysis");
        assert_eq!(back.inject_position, InjectPosition::AfterMandate);
        assert!(back.arguments.unwrap().contains_key("case_description"));
    }

    #[test]
    fn inject_position_serde_all_variants() {
        for (variant, expected) in [
            (InjectPosition::BeforeMandate, "\"before_mandate\""),
            (InjectPosition::AfterMandate, "\"after_mandate\""),
            (InjectPosition::AfterHeuristics, "\"after_heuristics\""),
            (InjectPosition::AfterExamples, "\"after_examples\""),
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
            let back: InjectPosition = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }
}
