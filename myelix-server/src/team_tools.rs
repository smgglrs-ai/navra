//! MCP tools for dynamic agent team orchestration.
//!
//! The team lead creates teammates on the fly, assigns personas and
//! models, sends them tasks, and reads results. Teammates are full
//! agents with MCP tool access (docs_tree, docs_grep, docs_read)
//! and a shared blackboard for cross-agent knowledge sharing.
//!
//! Teammates can create subteams for recursive decomposition,
//! bounded by max_depth and resource budgets.
//!
//! Model selection is IFC-aware: teammates working on sensitive data
//! are automatically assigned local models to prevent data exfiltration.

use myelix_core::protocol::{ToolDefinition, ToolInputSchema};
use std::collections::HashMap;
use std::sync::{atomic::{AtomicU32, Ordering}, Mutex};
use std::time::Instant;
use tokio::task::JoinHandle;

/// A teammate in the team.
#[derive(Debug, Clone)]
pub struct Teammate {
    pub name: String,
    pub persona: Option<String>,
    pub model: String,
    pub locality: String, // "local", "remote", "auto"
    pub status: String,   // "idle", "working", "done", "failed"
    pub task: Option<String>,
    pub output: Option<String>,
    pub created_at: Instant,
}

/// Re-export the composite model card from the hub.
pub use myelix_model_hub::ModelCard;

/// A blackboard entry shared across the team.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BlackboardEntry {
    pub key: String,
    pub value: String,
    pub author: String,
    pub timestamp_secs: u64,
}

/// Resource budget for a team tree.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TeamBudget {
    /// Maximum depth of subteam nesting (0 = no subteams).
    pub max_depth: u32,
    /// Maximum total agents across the team tree.
    pub max_agents: u32,
    /// Maximum total tokens across the team tree.
    pub max_tokens: u64,
    /// Timeout in seconds for the entire team.
    pub timeout_secs: u64,
}

impl Default for TeamBudget {
    fn default() -> Self {
        Self {
            max_depth: 2,
            max_agents: 10,
            max_tokens: 500_000,
            timeout_secs: 600,
        }
    }
}

/// A team of agents with shared blackboard and resource budgets.
#[derive(Debug)]
pub struct Team {
    pub team_id: String,
    pub name: String,
    pub description: Option<String>,
    pub lead: String,
    pub depth: u32, // 0 = root team, 1 = subteam, etc.
    pub budget: TeamBudget,
    pub teammates: HashMap<String, Teammate>,
    pub blackboard: Vec<BlackboardEntry>,
    pub tokens_used: AtomicU32,
    pub created_at: Instant,
    /// Abort handles for running teammate tasks.
    pub task_handles: HashMap<String, JoinHandle<()>>,
}

/// Registry of active teams.
#[derive(Default)]
pub struct TeamRegistry {
    pub(crate) teams: Mutex<HashMap<String, Team>>,
    next_id: Mutex<u64>,
    total_agents: AtomicU32,
    /// Available models for teammates.
    pub model_cards: Vec<ModelCard>,
}

impl TeamRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_models(mut self, cards: Vec<ModelCard>) -> Self {
        self.model_cards = cards;
        self
    }

    pub fn create_team(
        &self,
        name: &str,
        description: Option<&str>,
        lead: &str,
        depth: u32,
        budget: TeamBudget,
    ) -> Result<String, String> {
        // Check depth limit
        if depth > budget.max_depth {
            return Err(format!(
                "Maximum team depth exceeded ({}/{})",
                depth, budget.max_depth
            ));
        }

        // Check agent limit
        let current = self.total_agents.load(Ordering::Relaxed);
        if current >= budget.max_agents as u32 {
            return Err(format!(
                "Maximum agents exceeded ({}/{})",
                current, budget.max_agents
            ));
        }

        let mut id = self.next_id.lock().unwrap_or_else(|e| e.into_inner());
        *id += 1;
        let team_id = format!("team-{}", *id);

        let team = Team {
            team_id: team_id.clone(),
            name: name.to_string(),
            description: description.map(String::from),
            lead: lead.to_string(),
            depth,
            budget,
            teammates: HashMap::new(),
            blackboard: Vec::new(),
            tokens_used: AtomicU32::new(0),
            created_at: Instant::now(),
            task_handles: HashMap::new(),
        };

        self.teams
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(team_id.clone(), team);

        Ok(team_id)
    }

    pub fn add_teammate(
        &self,
        team_id: &str,
        name: &str,
        persona: Option<&str>,
        model: &str,
        locality: &str,
    ) -> Result<(), String> {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        let team = teams
            .get_mut(team_id)
            .ok_or_else(|| format!("Unknown team: {team_id}"))?;

        if team.teammates.contains_key(name) {
            return Err(format!("Teammate '{name}' already exists"));
        }

        // Check agent budget
        let current = self.total_agents.load(Ordering::Relaxed);
        if current >= team.budget.max_agents as u32 {
            return Err(format!(
                "Agent budget exceeded ({}/{})",
                current, team.budget.max_agents
            ));
        }

        team.teammates.insert(
            name.to_string(),
            Teammate {
                name: name.to_string(),
                persona: persona.map(String::from),
                model: model.to_string(),
                locality: locality.to_string(),
                status: "idle".to_string(),
                task: None,
                output: None,
                created_at: Instant::now(),
            },
        );

        self.total_agents.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn send_message(&self, team_id: &str, to: &str, message: &str) -> Result<(), String> {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        let team = teams
            .get_mut(team_id)
            .ok_or_else(|| format!("Unknown team: {team_id}"))?;

        // Check timeout
        if team.created_at.elapsed().as_secs() > team.budget.timeout_secs {
            return Err(format!("Team timeout exceeded ({}s)", team.budget.timeout_secs));
        }

        let teammate = team
            .teammates
            .get_mut(to)
            .ok_or_else(|| format!("Unknown teammate: {to}"))?;

        teammate.task = Some(message.to_string());
        teammate.status = "working".to_string();
        Ok(())
    }

    /// Get the team's depth and budget (for subteam creation).
    pub fn get_team_info(&self, team_id: &str) -> Option<(u32, TeamBudget)> {
        let teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        teams.get(team_id).map(|t| (t.depth, t.budget.clone()))
    }

    pub fn bb_publish(&self, team_id: &str, key: &str, value: &str, author: &str) {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(team) = teams.get_mut(team_id) {
            // Upsert: replace existing entry with same key
            team.blackboard.retain(|e| e.key != key);
            team.blackboard.push(BlackboardEntry {
                key: key.to_string(),
                value: value.to_string(),
                author: author.to_string(),
                timestamp_secs: team.created_at.elapsed().as_secs(),
            });
        }
    }

    pub fn bb_read(&self, team_id: &str, key: &str) -> Option<BlackboardEntry> {
        let teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        teams
            .get(team_id)?
            .blackboard
            .iter()
            .find(|e| e.key == key)
            .cloned()
    }

    pub fn bb_keys(&self, team_id: &str) -> Vec<String> {
        let teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        teams
            .get(team_id)
            .map(|t| t.blackboard.iter().map(|e| e.key.clone()).collect())
            .unwrap_or_default()
    }

    /// Store a task handle for a running teammate.
    pub fn store_handle(&self, team_id: &str, teammate: &str, handle: JoinHandle<()>) {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(team) = teams.get_mut(team_id) {
            // Abort any previous handle for this teammate
            if let Some(old) = team.task_handles.insert(teammate.to_string(), handle) {
                old.abort();
            }
        }
    }

    /// Check if the team's timeout has expired and abort all tasks if so.
    /// Returns true if the team timed out.
    pub fn check_timeout(&self, team_id: &str) -> bool {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(team) = teams.get_mut(team_id) {
            if team.created_at.elapsed().as_secs() > team.budget.timeout_secs {
                for (name, handle) in team.task_handles.drain() {
                    tracing::warn!(team = team_id, teammate = %name, "Aborting timed-out teammate task");
                    handle.abort();
                }
                return true;
            }
        }
        false
    }

    pub fn set_output(&self, team_id: &str, teammate: &str, output: String) {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(team) = teams.get_mut(team_id) {
            if let Some(tm) = team.teammates.get_mut(teammate) {
                tm.output = Some(output);
                tm.status = "done".to_string();
            }
        }
    }

    pub fn set_failed(&self, team_id: &str, teammate: &str, error: String) {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(team) = teams.get_mut(team_id) {
            if let Some(tm) = team.teammates.get_mut(teammate) {
                tm.output = Some(error);
                tm.status = "failed".to_string();
            }
        }
    }

    pub fn add_tokens(&self, team_id: &str, tokens: u32) {
        let teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(team) = teams.get(team_id) {
            team.tokens_used.fetch_add(tokens, Ordering::Relaxed);
        }
    }

    pub fn get_status(&self, team_id: &str) -> Option<serde_json::Value> {
        let teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        let team = teams.get(team_id)?;

        let members: Vec<serde_json::Value> = team
            .teammates
            .values()
            .map(|tm| {
                serde_json::json!({
                    "name": tm.name,
                    "persona": tm.persona,
                    "model": tm.model,
                    "locality": tm.locality,
                    "status": tm.status,
                    "has_output": tm.output.is_some(),
                })
            })
            .collect();

        let bb_keys: Vec<&str> = team.blackboard.iter().map(|e| e.key.as_str()).collect();
        let tokens = team.tokens_used.load(Ordering::Relaxed);

        Some(serde_json::json!({
            "team_id": team.team_id,
            "name": team.name,
            "depth": team.depth,
            "elapsed_secs": team.created_at.elapsed().as_secs(),
            "members": members,
            "blackboard_keys": bb_keys,
            "tokens_used": tokens,
            "budget": {
                "max_depth": team.budget.max_depth,
                "max_agents": team.budget.max_agents,
                "max_tokens": team.budget.max_tokens,
                "timeout_secs": team.budget.timeout_secs,
            },
        }))
    }

    pub fn get_result(&self, team_id: &str, teammate: &str) -> Option<serde_json::Value> {
        let teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        let team = teams.get(team_id)?;
        let tm = team.teammates.get(teammate)?;

        Some(serde_json::json!({
            "name": tm.name,
            "status": tm.status,
            "output": tm.output,
        }))
    }

    pub fn shutdown(&self, team_id: &str) -> Result<serde_json::Value, String> {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        let mut team = teams
            .remove(team_id)
            .ok_or_else(|| format!("Unknown team: {team_id}"))?;

        // Abort all running teammate tasks
        let aborted: Vec<String> = team.task_handles.drain()
            .map(|(name, handle)| {
                tracing::info!(team = team_id, teammate = %name, "Aborting teammate task on shutdown");
                handle.abort();
                name
            })
            .collect();

        let agent_count = team.teammates.len() as u32;
        self.total_agents.fetch_sub(agent_count, Ordering::Relaxed);

        Ok(serde_json::json!({
            "team_id": team_id,
            "name": team.name,
            "members_removed": team.teammates.keys().collect::<Vec<_>>(),
            "tasks_aborted": aborted,
            "tokens_used": team.tokens_used.load(Ordering::Relaxed),
            "blackboard_entries": team.blackboard.len(),
            "duration_secs": team.created_at.elapsed().as_secs(),
        }))
    }
}

// --- Tool definitions ---

pub fn team_create_def() -> ToolDefinition {
    ToolDefinition {
        name: "team_create".to_string(),
        description: Some(
            "Create a team of agent teammates with a shared blackboard. \
             Returns a team_id. Teammates can communicate via blackboard \
             (team_bb_publish/team_bb_read) and can create subteams \
             for recursive decomposition (bounded by max_depth)."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                ("name".to_string(), serde_json::json!({"type": "string", "description": "Team name"})),
                ("description".to_string(), serde_json::json!({"type": "string", "description": "What this team will accomplish"})),
                ("max_depth".to_string(), serde_json::json!({"type": "integer", "description": "Max subteam nesting depth (default: 2)"})),
                ("max_agents".to_string(), serde_json::json!({"type": "integer", "description": "Max total agents across team tree (default: 10)"})),
                ("max_tokens".to_string(), serde_json::json!({"type": "integer", "description": "Max total tokens across team tree (default: 500000)"})),
                ("timeout_secs".to_string(), serde_json::json!({"type": "integer", "description": "Team timeout in seconds (default: 600)"})),
            ])),
            required: Some(vec!["name".to_string()]),
        },
    }
}

pub fn team_add_def() -> ToolDefinition {
    ToolDefinition {
        name: "team_add".to_string(),
        description: Some(
            "Add a teammate to a team. Teammates are full agents with \
             tool access (docs_tree, docs_grep, docs_read) and can \
             publish findings to the shared blackboard. Specify locality: \
             'local' for sensitive data (on-device model), 'remote' for \
             complex reasoning (cloud API), 'auto' for IFC-based selection."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                ("team_id".to_string(), serde_json::json!({"type": "string"})),
                ("name".to_string(), serde_json::json!({"type": "string", "description": "Teammate name (unique within team)"})),
                ("persona".to_string(), serde_json::json!({"type": "string", "description": "Persona name from cognitive core"})),
                ("model".to_string(), serde_json::json!({"type": "string", "description": "Model name or 'auto'"})),
                ("locality".to_string(), serde_json::json!({"type": "string", "enum": ["local", "remote", "auto"], "description": "'local' = data stays on device, 'remote' = cloud API, 'auto' = IFC decides"})),
            ])),
            required: Some(vec!["team_id".to_string(), "name".to_string()]),
        },
    }
}

pub fn team_message_def() -> ToolDefinition {
    ToolDefinition {
        name: "team_message".to_string(),
        description: Some(
            "Send a task to a teammate. The teammate runs asynchronously \
             with full tool access (docs_tree, docs_grep, docs_read) and \
             can publish findings to the team's shared blackboard. \
             Use team_status to check progress, team_result to read output."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                ("team_id".to_string(), serde_json::json!({"type": "string"})),
                ("to".to_string(), serde_json::json!({"type": "string", "description": "Teammate name, or '*' for broadcast"})),
                ("message".to_string(), serde_json::json!({"type": "string", "description": "Task description"})),
            ])),
            required: Some(vec!["team_id".to_string(), "to".to_string(), "message".to_string()]),
        },
    }
}

pub fn team_status_def() -> ToolDefinition {
    ToolDefinition {
        name: "team_status".to_string(),
        description: Some(
            "Check team status: teammate progress, blackboard keys, \
             token usage, and budget remaining."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                ("team_id".to_string(), serde_json::json!({"type": "string"})),
            ])),
            required: Some(vec!["team_id".to_string()]),
        },
    }
}

pub fn team_result_def() -> ToolDefinition {
    ToolDefinition {
        name: "team_result".to_string(),
        description: Some("Read a teammate's output.".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                ("team_id".to_string(), serde_json::json!({"type": "string"})),
                ("teammate".to_string(), serde_json::json!({"type": "string"})),
            ])),
            required: Some(vec!["team_id".to_string(), "teammate".to_string()]),
        },
    }
}

pub fn team_bb_publish_def() -> ToolDefinition {
    ToolDefinition {
        name: "team_bb_publish".to_string(),
        description: Some(
            "Publish a finding or data to the team's shared blackboard. \
             Other teammates can read it via team_bb_read. The lead can \
             read all entries via team_status (shows keys) and team_bb_read."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                ("team_id".to_string(), serde_json::json!({"type": "string"})),
                ("key".to_string(), serde_json::json!({"type": "string", "description": "Entry key (e.g., 'auth-findings', 'unwrap-count')"})),
                ("value".to_string(), serde_json::json!({"type": "string", "description": "Entry value (findings, data, etc.)"})),
            ])),
            required: Some(vec!["team_id".to_string(), "key".to_string(), "value".to_string()]),
        },
    }
}

pub fn team_bb_read_def() -> ToolDefinition {
    ToolDefinition {
        name: "team_bb_read".to_string(),
        description: Some(
            "Read an entry from the team's shared blackboard."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                ("team_id".to_string(), serde_json::json!({"type": "string"})),
                ("key".to_string(), serde_json::json!({"type": "string", "description": "Entry key to read"})),
            ])),
            required: Some(vec!["team_id".to_string(), "key".to_string()]),
        },
    }
}

pub fn team_shutdown_def() -> ToolDefinition {
    ToolDefinition {
        name: "team_shutdown".to_string(),
        description: Some(
            "Shut down a team. Shows final stats (tokens used, findings count). \
             You MUST call this before producing your final response."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                ("team_id".to_string(), serde_json::json!({"type": "string"})),
            ])),
            required: Some(vec!["team_id".to_string()]),
        },
    }
}

pub fn models_list_def() -> ToolDefinition {
    ToolDefinition {
        name: "models_list".to_string(),
        description: Some(
            "List available models with composite model cards. Each card has three layers:\n\
             \n\
             **vendor**: Auto-populated from registry (family, parameters, quantization, \
             context_window, tasks, license, format). Technical facts about the model.\n\
             \n\
             **agentic**: Operator-defined capabilities for agent selection:\n\
             - strengths/weaknesses: what the model excels at or struggles with\n\
             - recommended_tasks/avoid_tasks: task types it should or shouldn't handle\n\
             - tool_use: 'none', 'basic', or 'advanced'\n\
             - cost_tier: 'free' (local), 'low', 'medium', 'high'\n\
             - speed_tier: 'fast', 'medium', 'slow'\n\
             \n\
             **runtime**: Learned from actual agent runs (total_calls, success_rate, \
             avg_latency_ms, per-task breakdown). Empty until the model has been used.\n\
             \n\
             **Selection guidelines:**\n\
             - For sensitive data: use models where vendor.source is 'ollama' or 'file' (local)\n\
             - For complex reasoning: prefer models with agentic.tool_use = 'advanced'\n\
             - For simple tasks: prefer speed_tier = 'fast' and cost_tier = 'free'\n\
             - Check runtime.by_task if available — real data beats operator assumptions"
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: None,
            required: None,
        },
    }
}
