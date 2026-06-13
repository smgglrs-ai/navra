//! Iterative map-reduce execution for large-context analysis.
//!
//! Pattern: Scout → Map (per-item) → Reduce → Evaluate → loop until convergence.
//!
//! This is the correct way to analyze large codebases: break the work
//! into per-file tasks, synthesize findings, then decide whether to
//! go deeper. Each round produces diminishing returns until the cost
//! of another round exceeds the expected value.

use navra_agent::Agent;
use navra_auth::ifc::TaintTracker;
use navra_model::{CreateResponseRequest, InputItem, ModelBackend, ModelResponse};
use navra_protocol::label::DataLabel;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// How the scout phase selects files to analyze.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum ScoutMode {
    /// Model picks files (original behavior). Can miss files.
    Model,
    /// Cycle through ALL files in batches. Full coverage guaranteed.
    #[default]
    Exhaustive,
}

/// Configuration for an iterative analysis.
#[derive(Debug, Clone, Deserialize)]
pub struct IterativeConfig {
    /// Name of this analysis.
    pub name: String,
    /// Maximum number of rounds before stopping.
    #[serde(default = "default_max_rounds")]
    pub max_rounds: u32,
    /// Minimum new findings to justify another round.
    #[serde(default = "default_min_delta")]
    pub min_delta: u32,
    /// Maximum items to process per map phase.
    #[serde(default = "default_max_items_per_round")]
    pub max_items_per_round: usize,
    /// How files are selected for analysis.
    #[serde(default)]
    pub scout_mode: ScoutMode,
    /// Specialist for the scout phase (used in Model mode).
    pub scout_specialist: String,
    /// Specialist for the map phase (per-item analysis).
    pub map_specialist: String,
    /// Specialist for the reduce phase (synthesis).
    pub reduce_specialist: String,
}

fn default_max_rounds() -> u32 {
    5
}
fn default_min_delta() -> u32 {
    2
}
fn default_max_items_per_round() -> usize {
    10
}

/// A single finding from the analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for deduplication.
    pub id: String,
    /// File where the finding was discovered.
    pub file: String,
    /// Severity: critical, high, medium, low.
    pub severity: String,
    /// Short description.
    pub description: String,
    /// CWE or category.
    pub category: String,
    /// Round in which this finding was discovered.
    #[serde(default)]
    pub round: u32,
    /// Line number in the file (1-based).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// Column number (1-based).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    /// Code snippet providing evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// Suggested fix or remediation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// Confidence level: high, medium, low.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
}

/// Structured output wrapper for flow task findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredFindings {
    /// Individual findings.
    pub findings: Vec<Finding>,
    /// Summary counts by severity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<FindingsSummary>,
}

/// Summary statistics for a set of findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingsSummary {
    pub total: usize,
    #[serde(default)]
    pub critical: usize,
    #[serde(default)]
    pub high: usize,
    #[serde(default)]
    pub medium: usize,
    #[serde(default)]
    pub low: usize,
}

/// Result of a completed iterative analysis.
#[derive(Debug)]
pub struct IterativeResult {
    /// All findings across all rounds.
    pub findings: Vec<Finding>,
    /// Number of rounds executed.
    pub rounds: u32,
    /// Whether convergence was reached (vs max_rounds).
    pub converged: bool,
    /// Per-round metrics.
    pub round_metrics: Vec<RoundMetric>,
    /// Total tokens consumed.
    pub total_input_tokens: u32,
    pub total_output_tokens: u32,
    /// Accumulated taint.
    pub taint: DataLabel,
}

/// Metrics for a single round.
#[derive(Debug, Clone)]
pub struct RoundMetric {
    /// Round number (1-based).
    pub round: u32,
    /// Items analyzed in this round.
    pub items_analyzed: usize,
    /// New findings in this round.
    pub new_findings: usize,
    /// Cumulative findings after this round.
    pub total_findings: usize,
    /// Delta (improvement) vs previous round.
    pub delta: f64,
}

/// Executor for iterative scout → map → reduce analysis.
pub struct IterativeExecutor {
    agents: HashMap<String, Agent>,
}

impl Default for IterativeExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl IterativeExecutor {
    pub fn new() -> Self {
        Self {
            agents: HashMap::new(),
        }
    }

    /// Register an agent for a specialist name.
    pub fn agent(mut self, specialist: impl Into<String>, agent: Agent) -> Self {
        self.agents.insert(specialist.into(), agent);
        self
    }

    /// Run the iterative analysis.
    pub async fn run(
        &mut self,
        config: &IterativeConfig,
        initial_prompt: &str,
    ) -> Result<IterativeResult, crate::error::FlowError> {
        let mut all_findings: Vec<Finding> = Vec::new();
        let mut round_metrics: Vec<RoundMetric> = Vec::new();
        let mut taint = TaintTracker::new();
        let mut total_input = 0u32;
        let mut total_output = 0u32;
        let mut analyzed_items: Vec<String> = Vec::new();
        let mut converged = false;

        for round in 1..=config.max_rounds {
            tracing::info!(round = round, "Starting iterative round");

            // --- Phase 1: Scout ---
            // Ask the scout to identify items to analyze, excluding already-analyzed ones.
            let scout_prompt = if round == 1 {
                format!(
                    "{}\n\nIdentify the most important items to analyze. \
                     Return a JSON array of strings (file paths or item names). \
                     Limit to {} items, prioritized by importance.",
                    initial_prompt, config.max_items_per_round
                )
            } else {
                format!(
                    "{}\n\nPrevious rounds analyzed: {:?}\n\
                     Previous findings summary: {} findings so far.\n\n\
                     Identify NEW items to analyze that were NOT in the previous list. \
                     Focus on files referenced by existing findings, or files related \
                     to the areas where issues were found. \
                     Return a JSON array of strings. Limit to {} items.",
                    initial_prompt,
                    analyzed_items,
                    all_findings.len(),
                    config.max_items_per_round
                )
            };

            let scout_agent = self
                .agents
                .get_mut(&config.scout_specialist)
                .ok_or_else(|| {
                    crate::error::FlowError::UnknownSpecialist(config.scout_specialist.clone())
                })?;

            let scout_result = scout_agent.run(&scout_prompt).await.map_err(|e| {
                crate::error::FlowError::Agent {
                    node: "scout".into(),
                    source: e,
                }
            })?;

            taint.absorb(scout_result.taint);
            total_input += scout_result.input_tokens;
            total_output += scout_result.output_tokens;

            // Parse items from scout output (try JSON array, fall back to line-split)
            let items = parse_items(&scout_result.response);
            if items.is_empty() {
                tracing::info!(round = round, "Scout returned no new items, stopping");
                converged = true;
                break;
            }

            tracing::info!(round = round, items = items.len(), "Scout identified items");

            // --- Phase 2: Map (per-item analysis) ---
            let mut round_findings: Vec<Finding> = Vec::new();

            for item in &items {
                if analyzed_items.contains(item) {
                    continue; // Skip already-analyzed items
                }

                let map_prompt = format!(
                    "Analyze this single item for issues: {}\n\n\
                     Return a JSON array of findings. Each finding: \
                     {{\"id\": \"unique\", \"file\": \"path\", \"severity\": \"high\", \
                     \"description\": \"what\", \"category\": \"CWE-NNN\"}}\n\n\
                     If no issues found, return: []",
                    item
                );

                let map_agent = self.agents.get_mut(&config.map_specialist).ok_or_else(|| {
                    crate::error::FlowError::UnknownSpecialist(config.map_specialist.clone())
                })?;

                match map_agent.run(&map_prompt).await {
                    Ok(result) => {
                        taint.absorb(result.taint);
                        total_input += result.input_tokens;
                        total_output += result.output_tokens;

                        // Parse findings from the response
                        let mut findings = parse_findings(&result.response, round);
                        round_findings.append(&mut findings);
                    }
                    Err(e) => {
                        tracing::warn!(item = %item, error = %e, "Map task failed, skipping");
                    }
                }

                analyzed_items.push(item.clone());
            }

            // --- Phase 3: Reduce (synthesis) ---
            let prev_total = all_findings.len();
            all_findings.extend(round_findings);

            // Deduplicate by id
            let mut seen = std::collections::HashSet::new();
            all_findings.retain(|f| seen.insert(f.id.clone()));

            let deduped_new = all_findings.len() - prev_total;

            let delta = if prev_total > 0 {
                deduped_new as f64 / prev_total as f64
            } else if deduped_new > 0 {
                1.0
            } else {
                0.0
            };

            round_metrics.push(RoundMetric {
                round,
                items_analyzed: items.len(),
                new_findings: deduped_new,
                total_findings: all_findings.len(),
                delta,
            });

            tracing::info!(
                round = round,
                new = deduped_new,
                total = all_findings.len(),
                delta = format!("{:.1}%", delta * 100.0),
                "Round complete"
            );

            // --- Phase 4: Evaluate convergence ---
            if (deduped_new as u32) < config.min_delta {
                tracing::info!(
                    round = round,
                    new = deduped_new,
                    threshold = config.min_delta,
                    "Converged: new findings below threshold"
                );
                converged = true;
                break;
            }
        }

        // --- Final reduce: ask the synthesis specialist to consolidate ---
        if !all_findings.is_empty() {
            let reduce_prompt = format!(
                "Consolidate these {} findings into a prioritized report:\n\n{}\n\n\
                 Group by severity (critical first), remove duplicates, \
                 and add a brief overall assessment.",
                all_findings.len(),
                serde_json::to_string_pretty(&all_findings).unwrap_or_default()
            );

            if let Some(reduce_agent) = self.agents.get_mut(&config.reduce_specialist) {
                match reduce_agent.run(&reduce_prompt).await {
                    Ok(result) => {
                        taint.absorb(result.taint);
                        total_input += result.input_tokens;
                        total_output += result.output_tokens;
                        tracing::info!("Final synthesis complete");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Final synthesis failed");
                    }
                }
            }
        }

        Ok(IterativeResult {
            findings: all_findings,
            rounds: round_metrics.len() as u32,
            converged,
            round_metrics,
            total_input_tokens: total_input,
            total_output_tokens: total_output,
            taint: taint.level(),
        })
    }
}

/// Call a model directly (no MCP agent) with a system prompt and user prompt.
async fn call_model(
    backend: &dyn ModelBackend,
    system: &str,
    user: &str,
) -> Result<(String, u32, u32), crate::error::FlowError> {
    let request = CreateResponseRequest {
        model: String::new(),
        input: vec![InputItem::system(system), InputItem::user(user)],
        max_output_tokens: Some(2048),
        temperature: Some(0.3),
        ..CreateResponseRequest::new(String::new(), vec![])
    };

    let response: ModelResponse =
        backend
            .respond(&request)
            .await
            .map_err(|e| crate::error::FlowError::Agent {
                node: "model".into(),
                source: e.into(),
            })?;

    let text = response.text().unwrap_or_default();
    let input_tokens = response.usage.as_ref().map(|u| u.input_tokens).unwrap_or(0);
    let output_tokens = response
        .usage
        .as_ref()
        .map(|u| u.output_tokens)
        .unwrap_or(0);
    Ok((text, input_tokens, output_tokens))
}

/// Run iterative analysis using a model backend directly (no MCP agent).
///
/// This is the preferred entry point for local analysis where the files
/// are read from disk, not via MCP tools. The `file_reader` closure
/// provides file content given a path.
pub async fn run_iterative(
    backend: &dyn ModelBackend,
    forge: &navra_cognitive::ForgeService,
    config: &IterativeConfig,
    initial_prompt: &str,
    all_files: &[String],
    file_reader: impl Fn(&str) -> Option<String>,
) -> Result<IterativeResult, crate::error::FlowError> {
    let mut all_findings: Vec<Finding> = Vec::new();
    let mut round_metrics: Vec<RoundMetric> = Vec::new();
    let mut total_input = 0u32;
    let mut total_output = 0u32;
    let mut analyzed_items: Vec<String> = Vec::new();
    let mut converged = false;

    // Build system prompts from Weaver for each phase
    let scout_system = navra_cognitive::assemble(
        forge,
        &config.scout_specialist,
        "identify files",
        None,
        None,
    )
    .map(|w| w.system_prompt())
    .unwrap_or_default();

    let map_system =
        navra_cognitive::assemble(forge, &config.map_specialist, "audit file", None, None)
            .map(|w| w.system_prompt())
            .unwrap_or_default();

    let reduce_system =
        navra_cognitive::assemble(forge, &config.reduce_specialist, "synthesize", None, None)
            .map(|w| w.system_prompt())
            .unwrap_or_default();

    // For exhaustive mode: build a queue of all files
    let mut file_queue: std::collections::VecDeque<String> =
        if config.scout_mode == ScoutMode::Exhaustive {
            all_files.iter().cloned().collect()
        } else {
            std::collections::VecDeque::new()
        };

    for round in 1..=config.max_rounds {
        println!("\n  ━━━ Round {}/{} ━━━", round, config.max_rounds);

        // --- Phase 1: Scout (select files for this round) ---
        let new_items: Vec<String> = if config.scout_mode == ScoutMode::Exhaustive {
            // Deterministic: take next batch from the queue
            let batch: Vec<String> = file_queue
                .drain(..file_queue.len().min(config.max_items_per_round))
                .filter(|f| !analyzed_items.contains(f))
                .collect();
            if batch.is_empty() {
                println!(
                    "  Scout: all {} files analyzed → complete",
                    analyzed_items.len()
                );
                converged = true;
                break;
            }
            println!(
                "  Scout: {} files (batch {}, {} remaining)",
                batch.len(),
                round,
                file_queue.len()
            );
            batch
        } else {
            // Model-driven: ask the LLM to pick files
            let scout_prompt = if round == 1 {
                format!(
                    "{}\n\nIdentify the most important files to analyze. \
                     Return ONLY a JSON array of file paths, nothing else. \
                     Limit to {} files, prioritized by importance.",
                    initial_prompt, config.max_items_per_round
                )
            } else {
                format!(
                    "{}\n\nAlready analyzed: {:?}\n\
                     Found {} findings so far.\n\n\
                     Identify NEW files NOT in the list above.\n\
                     Return ONLY a JSON array of file paths.\n\
                     Limit to {} files.",
                    initial_prompt,
                    analyzed_items,
                    all_findings.len(),
                    config.max_items_per_round
                )
            };

            let (scout_output, si, so) = call_model(backend, &scout_system, &scout_prompt).await?;
            total_input += si;
            total_output += so;

            let items = parse_items(&scout_output);
            let batch: Vec<String> = items
                .into_iter()
                .filter(|i| !analyzed_items.contains(i))
                .take(config.max_items_per_round)
                .collect();
            if batch.is_empty() {
                println!("  Scout: no new items identified → converged");
                converged = true;
                break;
            }
            println!("  Scout: {} new files to analyze", batch.len());
            batch
        };

        // --- Phase 2: Map (per-file) ---
        let mut round_findings: Vec<Finding> = Vec::new();

        for item in &new_items {
            let content = match file_reader(item) {
                Some(c) => c,
                None => {
                    println!("    {} — not found, skipping", item);
                    continue;
                }
            };

            let lines = content.lines().count();
            print!("    {} ({} lines) — ", item, lines);

            let map_prompt = format!(
                "AUDIT THIS FILE. Output ONLY a JSON array of findings.\n\
                 Format: [{{\"id\": \"unique\", \"file\": \"{}\", \"severity\": \"high|medium|low|critical\", \
                 \"description\": \"what is wrong\", \"category\": \"CWE-NNN\"}}]\n\
                 If no issues, output: []\n\n\
                 ```\n{}\n```",
                item, content
            );

            let (map_output, mi, mo) = call_model(backend, &map_system, &map_prompt).await?;
            total_input += mi;
            total_output += mo;

            let mut findings = parse_findings(&map_output, round);
            let count = findings.len();
            if count == 0 && !map_output.trim().is_empty() && map_output.trim() != "[]" {
                // Model returned text but we couldn't parse findings — show first lines
                let preview: String = map_output.lines().take(3).collect::<Vec<_>>().join(" | ");
                println!(
                    "{} findings (raw: {}...)",
                    count,
                    &preview[..preview.len().min(80)]
                );
            } else {
                println!("{} findings", count);
            }
            round_findings.append(&mut findings);
            analyzed_items.push(item.clone());
        }

        // --- Phase 3: Deduplicate and evaluate ---
        let prev_total = all_findings.len();
        all_findings.extend(round_findings);

        let mut seen = std::collections::HashSet::new();
        all_findings.retain(|f| seen.insert(f.id.clone()));

        let deduped_new = all_findings.len() - prev_total;
        let delta = if prev_total > 0 {
            deduped_new as f64 / prev_total as f64
        } else if deduped_new > 0 {
            1.0
        } else {
            0.0
        };

        round_metrics.push(RoundMetric {
            round,
            items_analyzed: new_items.len(),
            new_findings: deduped_new,
            total_findings: all_findings.len(),
            delta,
        });

        println!(
            "  Round {}: +{} findings (total: {}, delta: {:.0}%)",
            round,
            deduped_new,
            all_findings.len(),
            delta * 100.0
        );

        if (deduped_new as u32) < config.min_delta {
            println!(
                "  Converged: new findings ({}) < threshold ({})",
                deduped_new, config.min_delta
            );
            converged = true;
            break;
        }
    }

    // --- Final reduce ---
    if !all_findings.is_empty() && !reduce_system.is_empty() {
        println!("\n  ━━━ Synthesis ━━━");
        let reduce_prompt = format!(
            "Consolidate these {} findings into a prioritized report. \
             Group by severity (critical first). Add a brief overall assessment.\n\n{}",
            all_findings.len(),
            serde_json::to_string_pretty(&all_findings).unwrap_or_default()
        );
        let (synthesis, ri, ro) = call_model(backend, &reduce_system, &reduce_prompt).await?;
        total_input += ri;
        total_output += ro;
        println!("{}", synthesis);
    }

    Ok(IterativeResult {
        findings: all_findings,
        rounds: round_metrics.len() as u32,
        converged,
        round_metrics,
        total_input_tokens: total_input,
        total_output_tokens: total_output,
        taint: DataLabel::default(),
    })
}

/// Parse a list of items from model output.
/// Tries JSON array first, falls back to line-by-line.
fn parse_items(output: &str) -> Vec<String> {
    // Try JSON array
    if let Ok(items) = serde_json::from_str::<Vec<String>>(output) {
        return items;
    }

    // Try to find a JSON array in the text
    if let Some(start) = output.find('[') {
        if let Some(end) = output.rfind(']') {
            if let Ok(items) = serde_json::from_str::<Vec<String>>(&output[start..=end]) {
                return items;
            }
        }
    }

    // Fall back to non-empty lines that look like file paths
    output
        .lines()
        .map(|l| {
            l.trim()
                .trim_matches(|c: char| c == '-' || c == '*' || c == '"')
        })
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && (l.contains('/') || l.ends_with(".rs")))
        .map(|l| l.to_string())
        .collect()
}

/// Parse findings from model output.
fn parse_findings(output: &str, round: u32) -> Vec<Finding> {
    // Try JSON array
    if let Ok(mut findings) = serde_json::from_str::<Vec<Finding>>(output) {
        for f in &mut findings {
            f.round = round;
        }
        return findings;
    }

    // Try to find a JSON array in the text
    if let Some(start) = output.find('[') {
        if let Some(end) = output.rfind(']') {
            if let Ok(mut findings) = serde_json::from_str::<Vec<Finding>>(&output[start..=end]) {
                for f in &mut findings {
                    f.round = round;
                }
                return findings;
            }
        }
    }

    // Fall back: treat each non-empty line as a finding
    output
        .lines()
        .filter(|l| !l.trim().is_empty())
        .enumerate()
        .filter(|(_, l)| {
            let lower = l.to_lowercase();
            lower.contains("cwe")
                || lower.contains("finding")
                || lower.contains("vulnerability")
                || lower.contains("issue")
                || lower.contains("unwrap")
                || lower.contains("unsafe")
        })
        .map(|(i, l)| Finding {
            id: format!("r{round}-{i}"),
            file: String::new(),
            severity: "medium".to_string(),
            description: l.trim().to_string(),
            category: String::new(),
            round,
            line: None,
            column: None,
            evidence: None,
            remediation: None,
            confidence: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_items_json_array() {
        let items = parse_items(r#"["src/auth.rs", "src/server.rs"]"#);
        assert_eq!(items, vec!["src/auth.rs", "src/server.rs"]);
    }

    #[test]
    fn parse_items_embedded_json() {
        let items = parse_items("Here are the files:\n[\"a.rs\", \"b.rs\"]\nDone.");
        assert_eq!(items, vec!["a.rs", "b.rs"]);
    }

    #[test]
    fn parse_items_line_fallback() {
        let items = parse_items("- src/auth/mod.rs\n- src/server.rs\nnot a file\n");
        assert_eq!(items, vec!["src/auth/mod.rs", "src/server.rs"]);
    }

    #[test]
    fn parse_findings_json() {
        let json = r#"[{"id": "1", "file": "a.rs", "severity": "high", "description": "unwrap in handler", "category": "CWE-248"}]"#;
        let findings = parse_findings(json, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "high");
        assert_eq!(findings[0].round, 1);
    }

    #[test]
    fn parse_findings_text_fallback() {
        let text =
            "1. CWE-248: unwrap in handler\n2. Some description\n3. CWE-22: path traversal\n";
        let findings = parse_findings(text, 2);
        assert_eq!(findings.len(), 2); // lines 1 and 3 match
        assert_eq!(findings[0].round, 2);
    }

    #[test]
    fn parse_items_empty() {
        assert!(parse_items("").is_empty());
        assert!(parse_items("no files here").is_empty());
    }

    #[test]
    fn parse_findings_empty_json() {
        let findings = parse_findings("[]", 1);
        assert!(findings.is_empty());
    }

    #[test]
    fn convergence_config_defaults() {
        let config: IterativeConfig = toml::from_str(
            r#"
            name = "test"
            scout_specialist = "scout"
            map_specialist = "auditor"
            reduce_specialist = "analyst"
        "#,
        )
        .unwrap();
        assert_eq!(config.max_rounds, 5);
        assert_eq!(config.min_delta, 2);
        assert_eq!(config.max_items_per_round, 10);
    }
}
