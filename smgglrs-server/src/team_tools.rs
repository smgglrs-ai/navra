//! MCP tools for dynamic agent team orchestration.
//!
//! The team lead creates teammates on the fly, assigns personas and
//! models, sends them tasks, and reads results. Teammates are full
//! agents with MCP tool access (file_tree, file_grep, file_read)
//! and a shared blackboard for cross-agent knowledge sharing.
//!
//! Teammates can create subteams for recursive decomposition,
//! bounded by max_depth and resource budgets.
//!
//! Model selection is IFC-aware: teammates working on sensitive data
//! are automatically assigned local models to prevent data exfiltration.

use smgglrs_core::identity::CapSigner;
use smgglrs_core::protocol::{ToolDefinition, ToolInputSchema};
use std::collections::HashMap;
use std::sync::{atomic::{AtomicU32, Ordering}, Mutex};
use std::time::Instant;
use tokio::task::JoinHandle;

/// Default operations granted to teammates.
pub const DEFAULT_OPERATIONS: &[&str] = &["read", "search", "list"];

/// Default tools granted to teammates.
pub const DEFAULT_TOOLS: &[&str] = &[
    "file_tree", "file_grep", "file_read", "team_bb_publish",
    "models_list", "personas_list", "flow_escalate",
];

/// A teammate in the team.
#[derive(Debug, Clone)]
pub struct Teammate {
    pub name: String,
    pub persona: Option<String>,
    pub model: String,
    pub locality: String,   // "local", "remote", "auto"
    pub operations: Vec<String>, // allowed operations for capability token
    pub tools: Vec<String>,      // allowed tools for capability token
    pub status: String,     // "idle", "working", "done", "failed"
    pub task: Option<String>,
    pub output: Option<String>,
    pub created_at: Instant,
}

/// Re-export the composite model card from the hub.
pub use smgglrs_model_hub::ModelCard;

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
    /// Maximum ReAct iterations per teammate.
    pub max_iterations: usize,
}

impl Default for TeamBudget {
    fn default() -> Self {
        Self {
            max_depth: 2,
            max_agents: 10,
            max_tokens: 500_000,
            timeout_secs: 600,
            max_iterations: 50,
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
        if current >= budget.max_agents {
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
        operations: Vec<String>,
        tools: Vec<String>,
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
        if current >= team.budget.max_agents {
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
                operations,
                tools,
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
                    "operations": tm.operations,
                    "tools": tm.tools,
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
            "description": team.description,
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

    pub fn get_teammate_status(&self, team_id: &str, teammate: &str) -> Option<String> {
        let teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        teams.get(team_id)
            .and_then(|t| t.teammates.get(teammate))
            .map(|tm| tm.status.clone())
    }

    pub fn get_teammate_output(&self, team_id: &str, teammate: &str) -> Option<String> {
        let teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        teams.get(team_id)
            .and_then(|t| t.teammates.get(teammate))
            .and_then(|tm| tm.output.clone())
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
                ("max_iterations".to_string(), serde_json::json!({"type": "integer", "description": "Max ReAct iterations per teammate (default: 50)"})),
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
             scoped tool access and can publish findings to the shared \
             blackboard. Specify locality: 'local' for sensitive data \
             (on-device model), 'remote' for complex reasoning (cloud API), \
             'auto' for IFC-based selection.\n\n\
             Use 'operations' and 'tools' to control what the teammate \
             can do. Operations are capability-level permissions (e.g. \
             'read', 'search', 'list', 'write', 'git.commit'). Tools \
             are the specific MCP tools the teammate can call. Both \
             default to a safe read-only set if omitted."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                ("team_id".to_string(), serde_json::json!({"type": "string"})),
                ("name".to_string(), serde_json::json!({"type": "string", "description": "Teammate name (unique within team)"})),
                ("persona".to_string(), serde_json::json!({"type": "string", "description": "Persona name from cognitive core"})),
                ("model".to_string(), serde_json::json!({"type": "string", "description": "Model name from models_list (e.g. 'granite3.3:8b'). Use fast/small models for file reading tasks, large models only for synthesis. Defaults to 'auto' (smallest available)."})),
                ("locality".to_string(), serde_json::json!({"type": "string", "enum": ["local", "remote", "auto"], "description": "'local' = data stays on device, 'remote' = cloud API, 'auto' = IFC decides"})),
                ("operations".to_string(), serde_json::json!({"type": "array", "items": {"type": "string"}, "description": "Allowed operations (default: ['read', 'search', 'list'])"})),
                ("tools".to_string(), serde_json::json!({"type": "array", "items": {"type": "string"}, "description": "Allowed MCP tools (default: ['file_tree', 'file_grep', 'file_read', 'team_bb_publish'])"})),
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
             with full tool access (file_tree, file_grep, file_read) and \
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
             - reasoning: 'basic' or 'extended' (chain-of-thought)\n\
             - json_compliance: 'strict' or 'best-effort'\n\
             - locality: 'local' (on-device) or 'remote' (cloud API)\n\
             \n\
             **runtime**: Learned from actual agent runs (total_calls, success_rate, \
             avg_latency_ms, per-task breakdown). Empty until the model has been used.\n\
             \n\
             **Selection guidelines:**\n\
             - For file reading, data gathering: prefer locality='local' and cost_tier='free'\n\
             - For synthesis, complex reasoning: use reasoning='extended' or tool_use='advanced'\n\
             - For sensitive data: MUST use locality='local' (data stays on device)\n\
             - For simple tasks: prefer speed_tier='fast' and cost_tier='free'\n\
             - Minimize use of cost_tier='high' models — use only when task requires it\n\
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

pub fn personas_list_def() -> ToolDefinition {
    ToolDefinition {
        name: "personas_list".to_string(),
        description: Some(
            "List available specialist personas from the cognitive core. \
             Each persona has a name, display name, core mandate, and \
             heuristic modules. Use persona names in the `persona` field \
             of team_add to assign specialist behavior to teammates."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: None,
            required: None,
        },
    }
}

// --- Handler functions ---

/// Handle team_create tool call.
pub async fn handle_team_create(
    args: serde_json::Value,
    reg: std::sync::Arc<TeamRegistry>,
    budget_cfg: &crate::config::BudgetConfig,
    agent_name: &str,
) -> smgglrs_core::protocol::CallToolResult {
    use smgglrs_core::protocol::CallToolResult;

    let name = args.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed");
    let desc = args.get("description").and_then(|v| v.as_str());
    let budget = TeamBudget {
        max_depth: args.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(budget_cfg.max_depth as u64) as u32,
        max_agents: args.get("max_agents").and_then(|v| v.as_u64()).unwrap_or(budget_cfg.max_agents as u64) as u32,
        max_tokens: args.get("max_tokens").and_then(|v| v.as_u64()).unwrap_or(500_000),
        timeout_secs: args.get("timeout_secs").and_then(|v| v.as_u64()).unwrap_or(budget_cfg.timeout_secs),
        max_iterations: args.get("max_iterations").and_then(|v| v.as_u64()).unwrap_or(budget_cfg.max_iterations as u64) as usize,
    };
    match reg.create_team(name, desc, agent_name, 0, budget) {
        Ok(team_id) => {
            tracing::info!(team_id = %team_id, name = name, lead = %agent_name, "Team created");
            CallToolResult::text(format!("Team created.\nteam_id: {team_id}\nname: {name}"))
        }
        Err(e) => CallToolResult::error(e),
    }
}

/// Handle team_add tool call.
pub async fn handle_team_add(
    args: serde_json::Value,
    reg: std::sync::Arc<TeamRegistry>,
) -> smgglrs_core::protocol::CallToolResult {
    use smgglrs_core::protocol::CallToolResult;

    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(id) => id, None => return CallToolResult::error("Missing team_id"),
    };
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n, None => return CallToolResult::error("Missing name"),
    };
    let persona = args.get("persona").and_then(|v| v.as_str());
    let model = args.get("model").and_then(|v| v.as_str()).unwrap_or("auto");
    let locality = args.get("locality").and_then(|v| v.as_str()).unwrap_or("auto");

    let operations: Vec<String> = args.get("operations")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_else(|| DEFAULT_OPERATIONS.iter().map(|s| s.to_string()).collect());

    let tools: Vec<String> = args.get("tools")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_else(|| DEFAULT_TOOLS.iter().map(|s| s.to_string()).collect());

    match reg.add_teammate(team_id, name, persona, model, locality, operations.clone(), tools.clone()) {
        Ok(()) => {
            tracing::info!(team = team_id, name = name, persona = ?persona, model = model, locality = locality, operations = ?operations, tools = ?tools, "Teammate added");
            CallToolResult::text(format!(
                "Added '{name}' to team (persona: {}, model: {model}, locality: {locality}, operations: {operations:?}, tools: {tools:?})",
                persona.unwrap_or("default"),
            ))
        }
        Err(e) => CallToolResult::error(e),
    }
}

/// Handle team_status tool call.
pub async fn handle_team_status(
    args: serde_json::Value,
    reg: std::sync::Arc<TeamRegistry>,
) -> smgglrs_core::protocol::CallToolResult {
    use smgglrs_core::protocol::CallToolResult;

    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(id) => id, None => return CallToolResult::error("Missing team_id"),
    };
    match reg.get_status(team_id) {
        Some(status) => CallToolResult::text(serde_json::to_string_pretty(&status).unwrap_or_default()),
        None => CallToolResult::error(format!("Unknown team: {team_id}")),
    }
}

/// Handle team_result tool call.
pub async fn handle_team_result(
    args: serde_json::Value,
    reg: std::sync::Arc<TeamRegistry>,
) -> smgglrs_core::protocol::CallToolResult {
    use smgglrs_core::protocol::CallToolResult;

    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(id) => id, None => return CallToolResult::error("Missing team_id"),
    };
    let teammate = match args.get("teammate").and_then(|v| v.as_str()) {
        Some(t) => t, None => return CallToolResult::error("Missing teammate"),
    };
    match reg.get_result(team_id, teammate) {
        Some(result) => CallToolResult::text(serde_json::to_string_pretty(&result).unwrap_or_default()),
        None => CallToolResult::error(format!("No result from '{teammate}'")),
    }
}

/// Handle team_shutdown tool call.
pub async fn handle_team_shutdown(
    args: serde_json::Value,
    reg: std::sync::Arc<TeamRegistry>,
) -> smgglrs_core::protocol::CallToolResult {
    use smgglrs_core::protocol::CallToolResult;

    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(id) => id, None => return CallToolResult::error("Missing team_id"),
    };
    match reg.shutdown(team_id) {
        Ok(info) => {
            tracing::info!(team = team_id, "Team shut down");
            CallToolResult::text(serde_json::to_string_pretty(&info).unwrap_or_default())
        }
        Err(e) => CallToolResult::error(e),
    }
}

/// Handle team_bb_publish tool call.
pub async fn handle_team_bb_publish(
    args: serde_json::Value,
    reg: std::sync::Arc<TeamRegistry>,
    agent_name: &str,
) -> smgglrs_core::protocol::CallToolResult {
    use smgglrs_core::protocol::CallToolResult;

    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(id) => id, None => return CallToolResult::error("Missing team_id"),
    };
    let key = match args.get("key").and_then(|v| v.as_str()) {
        Some(k) => k, None => return CallToolResult::error("Missing key"),
    };
    let value = match args.get("value").and_then(|v| v.as_str()) {
        Some(v) => v, None => return CallToolResult::error("Missing value"),
    };
    reg.bb_publish(team_id, key, value, agent_name);
    CallToolResult::text(format!("Published '{key}' to team blackboard"))
}

/// Handle team_bb_read tool call.
pub async fn handle_team_bb_read(
    args: serde_json::Value,
    reg: std::sync::Arc<TeamRegistry>,
) -> smgglrs_core::protocol::CallToolResult {
    use smgglrs_core::protocol::CallToolResult;

    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(id) => id, None => return CallToolResult::error("Missing team_id"),
    };
    let key = match args.get("key").and_then(|v| v.as_str()) {
        Some(k) => k, None => return CallToolResult::error("Missing key"),
    };
    match reg.bb_read(team_id, key) {
        Some(entry) => CallToolResult::text(
            serde_json::to_string_pretty(&entry).unwrap_or_default()
        ),
        None => CallToolResult::error(format!("No blackboard entry: {key}")),
    }
}

/// Handle models_list tool call.
pub async fn handle_models_list(
    cards: Vec<ModelCard>,
) -> smgglrs_core::protocol::CallToolResult {
    use smgglrs_core::protocol::CallToolResult;
    CallToolResult::text(serde_json::to_string_pretty(&cards).unwrap_or_default())
}

/// Handle personas_list tool call.
pub async fn handle_personas_list(
    data: Vec<serde_json::Value>,
) -> smgglrs_core::protocol::CallToolResult {
    use smgglrs_core::protocol::CallToolResult;
    CallToolResult::text(serde_json::to_string_pretty(&data).unwrap_or_default())
}

/// Context needed to spawn a teammate as a background agent task.
pub struct TeammateSpawnContext {
    pub team_registry: std::sync::Arc<TeamRegistry>,
    pub smgglrs_addr: String,
    pub signer: std::sync::Arc<smgglrs_core::identity::Ed25519Signer>,
    pub forge: Option<std::sync::Arc<smgglrs_cognitive::ForgeService>>,
    /// Root capability payload used as the parent for delegated teammate tokens.
    /// When `Some`, teammate tokens are minted via `build_delegated_payload`
    /// with proper delegation chain (parent nonce, attenuation validation).
    /// When `None`, falls back to flat `build_payload` (backward compatible).
    pub root_payload: Option<smgglrs_core::auth::capability::CapabilityPayload>,
}

/// Spawn a teammate agent in a background task.
///
/// This is the shared logic used by team_message, flow_start, and
/// flow_escalate. Returns a JoinHandle for the background task.
pub fn spawn_teammate_agent(
    ctx: &TeammateSpawnContext,
    team_id: &str,
    teammate_id: &str,
    message: &str,
    max_iterations: usize,
    timeout_secs: u64,
    generates_tasks: bool,
) -> tokio::task::JoinHandle<()> {
    let reg = std::sync::Arc::clone(&ctx.team_registry);
    let signer = std::sync::Arc::clone(&ctx.signer);
    let forge = ctx.forge.clone();
    let root_payload = ctx.root_payload.clone();
    let smgglrs_addr = ctx.smgglrs_addr.clone();
    let team_id = team_id.to_string();
    let teammate_id = teammate_id.to_string();
    let message = message.to_string();

    tokio::spawn(async move {
        let deadline = std::time::Duration::from_secs(timeout_secs);
        let timeout_reg = reg.clone();
        let timeout_team = team_id.clone();
        let timeout_task = teammate_id.clone();
        let result = tokio::time::timeout(deadline, async move {
            let mcp_url = format!("http://{smgglrs_addr}/mcp");

            let (tm_ops, tm_tools) = {
                let teams = reg.teams.lock().unwrap_or_else(|e| e.into_inner());
                teams.get(&team_id)
                    .and_then(|t| t.teammates.get(&teammate_id))
                    .map(|tm| (tm.operations.clone(), tm.tools.clone()))
                    .unwrap_or_else(|| (
                        DEFAULT_OPERATIONS.iter().map(|s| s.to_string()).collect(),
                        DEFAULT_TOOLS.iter().map(|s| s.to_string()).collect(),
                    ))
            };
            let tm_tools_desc = tm_tools.join(", ");
            let did = format!("did:teammate:{}:{}", team_id, teammate_id);
            let token = if let Some(ref root) = root_payload {
                // Delegated token: scoped to teammate's operations/tools,
                // chained from the server's root capability payload.
                match smgglrs_core::auth::capability::build_delegated_payload(
                    root, &did, tm_ops, tm_tools, 2, timeout_secs,
                ) {
                    Ok(payload) => match smgglrs_core::auth::capability::encode_token(&payload, signer.as_ref()) {
                        Ok(t) => t,
                        Err(e) => {
                            tracing::error!(team = %team_id, to = %teammate_id, error = %e, "Failed to encode teammate token");
                            reg.set_failed(&team_id, &teammate_id, format!("Token error: {e}"));
                            return;
                        }
                    },
                    Err(e) => {
                        tracing::error!(team = %team_id, to = %teammate_id, error = %e, "Failed to build delegated token");
                        reg.set_failed(&team_id, &teammate_id, format!("Token delegation error: {e}"));
                        return;
                    }
                }
            } else {
                // Flat token (backward compatible): no parent delegation chain.
                let cap = smgglrs_core::auth::capability::CapabilitySet {
                    paths: vec!["**".to_string()],
                    operations: tm_ops,
                    tools: tm_tools,
                    credentials: vec![],
                };
                let payload = smgglrs_core::auth::capability::build_payload(
                    signer.did(), &did, cap, 2, timeout_secs,
                );
                match smgglrs_core::auth::capability::encode_token(&payload, signer.as_ref()) {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::error!(team = %team_id, to = %teammate_id, error = %e, "Failed to mint teammate token");
                        reg.set_failed(&team_id, &teammate_id, format!("Token error: {e}"));
                        return;
                    }
                }
            };

            let tm_persona = {
                let teams = reg.teams.lock().unwrap_or_else(|e| e.into_inner());
                teams.get(&team_id)
                    .and_then(|t| t.teammates.get(&teammate_id))
                    .and_then(|tm| tm.persona.clone())
            };

            let escalate_hint = if !generates_tasks {
                "\nIf your task requires reviewing more than 5 files or covers multiple distinct concern areas, call flow_escalate to spawn a sub-team. Provide the mandate and any context you have gathered so far."
            } else {
                ""
            };

            let system_prompt = if let Some(ref persona_name) = tm_persona {
                let persona_prompt = forge.as_ref().and_then(|f| {
                    let output = smgglrs_cognitive::assemble(f, persona_name, "", None, None).ok()?;
                    Some(output.system_prompt())
                });
                match persona_prompt {
                    Some(prompt) => format!(
                        "{prompt}\n\n\
                         You are working as part of a team.\n\
                         You have access to MCP tools: {tools}.{escalate_hint}\n\
                         Your team_id is: {team_id}",
                        tools = tm_tools_desc
                    ),
                    None => format!(
                        "You are a specialist agent named '{}' (persona: {}).\n\n\
                         You have access to MCP tools: {}.{escalate_hint}\n\
                         Your team_id is: {}",
                        teammate_id, persona_name, tm_tools_desc, team_id
                    ),
                }
            } else {
                format!(
                    "You are a specialist agent named '{}'.\n\n\
                     You have access to MCP tools: {}.{escalate_hint}\n\
                     Your team_id is: {}",
                    teammate_id, tm_tools_desc, team_id
                )
            };

            let mut teammate_model = {
                let teams = reg.teams.lock().unwrap_or_else(|e| e.into_inner());
                teams.get(&team_id)
                    .and_then(|t| t.teammates.get(&teammate_id))
                    .map(|tm| tm.model.clone())
                    .unwrap_or_else(|| "auto".to_string())
            };

            // Validate model name
            if teammate_model != "auto"
                && !reg.model_cards.iter().any(|c| c.model_uri == teammate_model)
            {
                tracing::warn!(
                    task = %teammate_id, model = %teammate_model,
                    "Unknown model, falling back to auto-select"
                );
                teammate_model = "auto".to_string();
            }
            if teammate_model == "auto" {
                if let Some(selected) = select_model_for_task(
                    &reg.model_cards,
                    tm_persona.as_deref(),
                    &message,
                ) {
                    teammate_model = selected;
                } else if std::env::var("ANTHROPIC_API_KEY").is_ok()
                    || std::env::var("ANTHROPIC_VERTEX_PROJECT_ID").is_ok()
                {
                    teammate_model = "claude-sonnet-4-6@default".to_string();
                } else {
                    teammate_model = "granite3.3:8b".to_string();
                }
            }

            eprintln!("  [teammate] {} → model: {}", teammate_id, teammate_model);

            let is_claude = teammate_model.starts_with("claude");

            macro_rules! run_teammate {
                ($backend:expr) => {{
                    let r = async {
                        let mut builder = smgglrs_agent::Agent::builder()
                            .endpoint(&mcp_url).await?
                            .auth_token(&token)
                            .model($backend)
                            .system_prompt(&system_prompt)
                            .max_iterations(max_iterations)
                            .force_tool_iterations(if generates_tasks { 0 } else { 1 })
                            .temperature(0.3)
                            .max_tokens(8192);
                        if generates_tasks {
                            builder = builder.allowed_tools(vec![
                                "models_list".to_string(),
                                "personas_list".to_string(),
                            ]);
                        }
                        let mut agent = builder.build().await?;
                        agent.run(&message).await
                    };
                    r.await
                }};
            }

            let agent_result = if is_claude {
                let use_vertex = std::env::var("CLAUDE_CODE_USE_VERTEX").is_ok()
                    || std::env::var("ANTHROPIC_VERTEX_PROJECT_ID").is_ok();
                if use_vertex {
                    let project = std::env::var("ANTHROPIC_VERTEX_PROJECT_ID")
                        .unwrap_or_else(|_| "my-project".to_string());
                    let region = std::env::var("CLOUD_ML_REGION")
                        .unwrap_or_else(|_| "us-east5".to_string());
                    let url = format!(
                        "https://{region}-aiplatform.googleapis.com/v1/projects/{project}/locations/{region}/publishers/anthropic/models/{teammate_model}:rawPredict"
                    );
                    let token_output = std::process::Command::new("gcloud")
                        .args(["auth", "print-access-token"])
                        .output();
                    let gcloud_token = match token_output {
                        Ok(output) if output.status.success() => {
                            let t = String::from_utf8_lossy(&output.stdout).trim().to_string();
                            if t.is_empty() {
                                tracing::error!(teammate = %teammate_id, "gcloud returned empty token");
                                reg.set_failed(&team_id, &teammate_id, "Empty gcloud token".to_string());
                                return;
                            }
                            t
                        }
                        Ok(output) => {
                            let err = String::from_utf8_lossy(&output.stderr);
                            tracing::error!(teammate = %teammate_id, error = %err, "gcloud token failed");
                            reg.set_failed(&team_id, &teammate_id, format!("gcloud error: {err}"));
                            return;
                        }
                        Err(e) => {
                            tracing::error!(teammate = %teammate_id, error = %e, "gcloud not available");
                            reg.set_failed(&team_id, &teammate_id, format!("gcloud error: {e}"));
                            return;
                        }
                    };
                    run_teammate!(smgglrs_model::AnthropicBackend::new(
                        &url, &teammate_model, Some(gcloud_token), smgglrs_model::Locality::Remote,
                    ))
                } else {
                    let key = std::env::var("ANTHROPIC_API_KEY").ok();
                    run_teammate!(smgglrs_model::AnthropicBackend::new(
                        "https://api.anthropic.com", &teammate_model, key, smgglrs_model::Locality::Remote,
                    ))
                }
            } else {
                run_teammate!(smgglrs_model::OpenAiBackend::new(
                    "http://localhost:11434/v1", &teammate_model, None, smgglrs_model::Locality::Local,
                ))
            };

            match agent_result {
                Ok(result) => {
                    let tokens = result.input_tokens + result.output_tokens;
                    reg.add_tokens(&team_id, tokens);
                    tracing::info!(
                        team = %team_id, to = %teammate_id,
                        iterations = result.iterations,
                        tokens = tokens,
                        "Teammate completed"
                    );
                    reg.set_output(&team_id, &teammate_id, result.response);
                }
                Err(e) => {
                    tracing::error!(team = %team_id, to = %teammate_id, error = %e, "Teammate failed");
                    reg.set_failed(&team_id, &teammate_id, format!("Agent error: {e}"));
                }
            }
        }).await;

        if result.is_err() {
            tracing::warn!(team = %timeout_team, to = %timeout_task, "Teammate timed out after {timeout_secs}s");
            timeout_reg.set_failed(&timeout_team, &timeout_task, format!("Timed out after {timeout_secs}s"));
        }
    })
}

/// Handle team_message tool call.
///
/// Spawns the teammate as a full MCP agent in the background.
pub async fn handle_team_message(
    args: serde_json::Value,
    spawn_ctx: &TeammateSpawnContext,
) -> smgglrs_core::protocol::CallToolResult {
    use smgglrs_core::protocol::CallToolResult;

    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(), None => return CallToolResult::error("Missing team_id"),
    };
    let to = match args.get("to").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(), None => return CallToolResult::error("Missing to"),
    };
    let message = match args.get("message").and_then(|v| v.as_str()) {
        Some(m) => m.to_string(), None => return CallToolResult::error("Missing message"),
    };

    if let Err(e) = spawn_ctx.team_registry.send_message(&team_id, &to, &message) {
        return CallToolResult::error(e);
    }

    // Get the team's timeout and iteration budget
    let (timeout_secs, teammate_max_iterations) = {
        let teams = spawn_ctx.team_registry.teams.lock().unwrap_or_else(|e| e.into_inner());
        teams.get(&team_id)
            .map(|t| {
                let elapsed = t.created_at.elapsed().as_secs();
                let remaining = t.budget.timeout_secs.saturating_sub(elapsed);
                (remaining, t.budget.max_iterations)
            })
            .unwrap_or((600, 50))
    };

    let handle = spawn_teammate_agent(
        spawn_ctx, &team_id, &to, &message,
        teammate_max_iterations, timeout_secs, false,
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
        || matches!(persona, Some("analyst" | "synthesizer" | "principal_engineer"
            | "strategic_advisor" | "devils_advocate"));

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

    let mut scored: Vec<(&ModelCard, i32)> = cards.iter().map(|card| {
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
            let param_b = card.vendor.parameters.as_deref()
                .and_then(|p| {
                    let p = p.to_uppercase();
                    p.trim_end_matches('B').parse::<f64>().ok()
                })
                .unwrap_or(0.0);

            if needs_reasoning || needs_tools || needs_json {
                if param_b >= 20.0 { score += 20; }
                else if param_b >= 12.0 { score += 12; }
                else { score -= 5; }
            } else {
                if param_b <= 10.0 { score += 8; }
                else if param_b <= 20.0 { score += 4; }
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
    }).collect();

    scored.sort_by(|a, b| b.1.cmp(&a.1));

    if let Some((best, score)) = scored.first() {
        tracing::info!(
            model = %best.model_uri,
            score = score,
            needs_tools = needs_tools,
            needs_reasoning = needs_reasoning,
            needs_json = needs_json,
            persona = persona.unwrap_or("none"),
            "Auto-selected model for task"
        );
        Some(best.model_uri.clone())
    } else {
        None
    }
}
