use crate::agent_spawn::{TeammateSpawnContext, spawn_teammate_agent};
use crate::team_tools::ModelCard;
use navra_protocol::compat::CallToolResultExt;

/// Handle team_message tool call.
///
/// Spawns the teammate as a full MCP agent in the background.
pub async fn handle_team_message(
    args: serde_json::Value,
    spawn_ctx: &TeammateSpawnContext,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => return CallToolResult::error_msg("Missing team_id"),
    };
    let to = match args.get("to").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => return CallToolResult::error_msg("Missing to"),
    };
    let message = match args.get("message").and_then(|v| v.as_str()) {
        Some(m) => m.to_string(),
        None => return CallToolResult::error_msg("Missing message"),
    };

    if let Err(e) = spawn_ctx
        .team_registry
        .send_message(&team_id, &to, &message)
    {
        return CallToolResult::error_msg(e);
    }

    // Get the team's timeout and iteration budget
    let (timeout_secs, teammate_max_iterations) = {
        let teams = spawn_ctx
            .team_registry
            .teams
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        teams
            .get(&team_id)
            .map(|t| {
                let elapsed = t.created_at.elapsed().as_secs();
                let remaining = t.budget.timeout_secs.saturating_sub(elapsed);
                (remaining, t.budget.max_iterations)
            })
            .unwrap_or((600, 50))
    };

    let handle = spawn_teammate_agent(
        spawn_ctx,
        &team_id,
        &to,
        &message,
        teammate_max_iterations,
        timeout_secs,
        false,
    );

    // Store the handle so it can be aborted on team shutdown
    spawn_ctx.team_registry.store_handle(&team_id, &to, handle);

    // Stagger teammate spawns to avoid concurrent rate limit hits
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    CallToolResult::text(format!(
        "Task sent to '{}'. Teammate is running as a full MCP agent \
         with tool access (file_tree, file_grep, file_read, team_bb_publish). \
         Use team_status to check progress, team_result to read output.",
        to
    ))
}

/// Determine required model capabilities from task context.
/// Returns (needs_tools, needs_reasoning, needs_json).
fn task_requirements(persona: Option<&str>, mandate: &str) -> (bool, bool, bool) {
    let mandate_lower = mandate.to_lowercase();

    let needs_reasoning = mandate_lower.contains("analyz")
        || mandate_lower.contains("trace")
        || mandate_lower.contains("reason")
        || mandate_lower.contains("synthesiz")
        || mandate_lower.contains("review")
        || mandate_lower.contains("assess")
        || mandate_lower.contains("cross-file")
        || mandate_lower.contains("cross-cutting")
        || matches!(
            persona,
            Some(
                "analyst"
                    | "synthesizer"
                    | "principal_engineer"
                    | "strategic_advisor"
                    | "devils_advocate"
            )
        );

    let needs_tools = mandate_lower.contains("read")
        || mandate_lower.contains("file_read")
        || mandate_lower.contains("file_tree")
        || mandate_lower.contains("scan")
        || mandate_lower.contains("search")
        || mandate_lower.contains("explore")
        || mandate_lower.contains("review")
        || mandate_lower.contains("audit");

    let needs_json = mandate_lower.contains("json array")
        || mandate_lower.contains("json object")
        || mandate_lower.contains("output only a json")
        || mandate_lower.contains("output only json")
        || mandate_lower.contains("respond with json");

    (needs_tools, needs_reasoning, needs_json)
}

/// Select the best model from available cards for a task.
///
/// Matches task requirements (tool use, reasoning) to model
/// capabilities, preferring local and free models as tiebreakers.
pub fn select_model_for_task(
    cards: &[ModelCard],
    persona: Option<&str>,
    mandate: &str,
) -> Option<String> {
    if cards.is_empty() {
        return None;
    }

    let (needs_tools, needs_reasoning, needs_json) = task_requirements(persona, mandate);

    // Filter out embedding-only models — they can't chat or call tools
    let chat_cards: Vec<&ModelCard> = cards
        .iter()
        .filter(|c| {
            let uri = &c.model_uri;
            // Skip models known to be embedding-only
            !uri.contains("embed") && !uri.contains("nomic") && !uri.contains("bge")
        })
        .collect();
    let candidates = if chat_cards.is_empty() {
        cards.iter().collect()
    } else {
        chat_cards
    };

    let mut scored: Vec<(&ModelCard, i32)> = candidates
        .iter()
        .map(|card| {
            let card = *card;
            let a = &card.agentic;
            let mut score: i32 = 0;

            // JSON compliance is critical for planner tasks
            if needs_json {
                match a.json_compliance.as_deref() {
                    Some("strict") => score += 15,
                    Some("best-effort") => score += 5,
                    _ => {}
                }
            }

            // Use explicit agentic metadata if available
            let has_agentic = a.tool_use.is_some() || a.reasoning.is_some();

            if has_agentic {
                if needs_tools {
                    match a.tool_use.as_deref() {
                        Some("advanced") => score += 10,
                        Some("basic") => score += 5,
                        _ => {}
                    }
                }

                if needs_reasoning {
                    match a.reasoning.as_deref() {
                        Some("extended") => score += 20,
                        Some("basic") => score += 5,
                        _ => {}
                    }
                } else {
                    match a.speed_tier.as_deref() {
                        Some("fast") => score += 8,
                        Some("medium") => score += 4,
                        _ => {}
                    }
                }
            } else {
                let param_b = card
                    .vendor
                    .parameters
                    .as_deref()
                    .and_then(|p| {
                        let p = p.to_uppercase();
                        p.trim_end_matches('B').parse::<f64>().ok()
                    })
                    .unwrap_or(0.0);

                if needs_reasoning || needs_tools || needs_json {
                    // Prefer 12-20B for specialist tasks (fits in GPU with
                    // concurrent KV caches). ≥20B is penalized because model
                    // swapping under concurrent load can hang the GPU.
                    if (12.0..=20.0).contains(&param_b) {
                        score += 20;
                    } else if param_b >= 20.0 {
                        score += 5;
                    } else {
                        score -= 50;
                    } // ≤10B models can't reliably call tools via Ollama
                } else if param_b <= 10.0 {
                    score += 8;
                } else if param_b <= 20.0 {
                    score += 4;
                }
            }

            if a.locality.as_deref() == Some("local") {
                score += 5;
            }

            match a.cost_tier.as_deref() {
                Some("free") => score += 3,
                Some("low") => score += 1,
                _ => {}
            }

            (card, score)
        })
        .collect();

    scored.sort_by_key(|b| std::cmp::Reverse(b.1));

    if let Some((best, score)) = scored.first() {
        tracing::info!(
            model = %best.inference_name(),
            score = score,
            needs_tools = needs_tools,
            needs_reasoning = needs_reasoning,
            needs_json = needs_json,
            persona = persona.unwrap_or("none"),
            "Auto-selected model for task"
        );
        Some(best.inference_name().to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::team_tools::{TeamBudget, TeamRegistry};

    fn test_registry() -> TeamRegistry {
        TeamRegistry::new()
    }

    #[test]
    fn bb_notifications_returns_entries_from_others() {
        let reg = test_registry();
        let tid = reg
            .create_team("t", None, "lead", 0, TeamBudget::default())
            .unwrap();
        reg.add_teammate(&tid, "alice", None, "m", "local", vec![], vec![], None, None, None)
            .unwrap();
        reg.add_teammate(&tid, "bob", None, "m", "local", vec![], vec![], None, None, None)
            .unwrap();

        // Alice publishes
        reg.bb_publish(
            &tid,
            "finding-1",
            "data",
            "alice",
            navra_core::protocol::label::DataLabel::TRUSTED_PUBLIC,
        );

        // Bob sees it
        let notifs = reg.bb_notifications(&tid, "bob").unwrap();
        assert_eq!(notifs.len(), 1);
        assert_eq!(notifs[0].key, "finding-1");
        assert_eq!(notifs[0].author, "alice");

        // Alice does NOT see her own entry
        let notifs = reg.bb_notifications(&tid, "alice").unwrap();
        assert_eq!(notifs.len(), 0);
    }

    #[test]
    fn bb_notifications_advances_timestamp() {
        let reg = test_registry();
        let tid = reg
            .create_team("t", None, "lead", 0, TeamBudget::default())
            .unwrap();
        reg.add_teammate(&tid, "alice", None, "m", "local", vec![], vec![], None, None, None)
            .unwrap();
        reg.add_teammate(&tid, "bob", None, "m", "local", vec![], vec![], None, None, None)
            .unwrap();

        reg.bb_publish(
            &tid,
            "k1",
            "v1",
            "alice",
            navra_core::protocol::label::DataLabel::TRUSTED_PUBLIC,
        );

        // First call returns the entry
        let n1 = reg.bb_notifications(&tid, "bob").unwrap();
        assert_eq!(n1.len(), 1);

        // Second call returns empty (timestamp advanced)
        let n2 = reg.bb_notifications(&tid, "bob").unwrap();
        assert_eq!(n2.len(), 0);
    }

    #[test]
    fn bb_notifications_multiple_entries_in_order() {
        let reg = test_registry();
        let tid = reg
            .create_team("t", None, "lead", 0, TeamBudget::default())
            .unwrap();
        reg.add_teammate(&tid, "alice", None, "m", "local", vec![], vec![], None, None, None)
            .unwrap();
        reg.add_teammate(&tid, "bob", None, "m", "local", vec![], vec![], None, None, None)
            .unwrap();
        reg.add_teammate(&tid, "carol", None, "m", "local", vec![], vec![], None, None, None)
            .unwrap();

        reg.bb_publish(
            &tid,
            "k1",
            "v1",
            "alice",
            navra_core::protocol::label::DataLabel::TRUSTED_PUBLIC,
        );
        reg.bb_publish(
            &tid,
            "k2",
            "v2",
            "carol",
            navra_core::protocol::label::DataLabel::TRUSTED_PUBLIC,
        );
        reg.bb_publish(
            &tid,
            "k3",
            "v3",
            "alice",
            navra_core::protocol::label::DataLabel::TRUSTED_PUBLIC,
        );

        let notifs = reg.bb_notifications(&tid, "bob").unwrap();
        assert_eq!(notifs.len(), 3);
        let keys: Vec<&str> = notifs.iter().map(|n| n.key.as_str()).collect();
        assert_eq!(keys, vec!["k1", "k2", "k3"]);
    }

    #[test]
    fn bb_notifications_unknown_team_returns_error() {
        let reg = test_registry();
        let result = reg.bb_notifications("no-such-team", "agent");
        assert!(result.is_err());
    }

    #[test]
    fn bb_notifications_unknown_agent_still_works() {
        // An agent not in the teammates map should still get entries
        // (with since=0) and not panic.
        let reg = test_registry();
        let tid = reg
            .create_team("t", None, "lead", 0, TeamBudget::default())
            .unwrap();
        reg.add_teammate(&tid, "alice", None, "m", "local", vec![], vec![], None, None, None)
            .unwrap();

        reg.bb_publish(
            &tid,
            "k1",
            "v1",
            "alice",
            navra_core::protocol::label::DataLabel::TRUSTED_PUBLIC,
        );

        let notifs = reg.bb_notifications(&tid, "outsider").unwrap();
        // outsider sees alice's entry (since=0)
        assert_eq!(notifs.len(), 1);
    }
}
