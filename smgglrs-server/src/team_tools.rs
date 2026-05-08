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
use smgglrs_agent::AuditSink;
use std::collections::HashMap;
use std::sync::{atomic::{AtomicU32, Ordering}, Mutex};
use std::time::Instant;
use tokio::task::JoinHandle;

/// Adapter that implements smgglrs-agent's AuditSink using smgglrs-memory's AuditLog.
pub(crate) struct AuditLogSink(pub std::sync::Arc<smgglrs_memory::AuditLog>);

impl AuditSink for AuditLogSink {
    fn log_tool_call(
        &self, run_id: &str, agent_id: &str, iteration: u32,
        tool_name: &str, tool_args: &str, tool_result: &str, duration_ms: u64,
    ) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let entry = smgglrs_memory::AuditToolCall {
            run_id: run_id.to_string(),
            agent_id: agent_id.to_string(),
            iteration,
            timestamp_ms: now_ms,
            tool_name: tool_name.to_string(),
            tool_args: tool_args.to_string(),
            tool_result: tool_result.to_string(),
            duration_ms,
            acl_decision: None,
            ifc_label: None,
        };
        if let Err(e) = self.0.log_tool_call(&entry) {
            tracing::debug!(error = %e, "Failed to log tool call to audit");
        }
    }

    fn log_model_call(
        &self, run_id: &str, agent_id: &str, iteration: u32,
        model_name: &str, input_tokens: u32, output_tokens: u32, response_type: &str,
    ) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let entry = smgglrs_memory::AuditModelCall {
            run_id: run_id.to_string(),
            agent_id: agent_id.to_string(),
            iteration,
            timestamp_ms: now_ms,
            model_name: if model_name.is_empty() { None } else { Some(model_name.to_string()) },
            input_tokens,
            output_tokens,
            response_type: response_type.to_string(),
            reasoning_text: None,
        };
        if let Err(e) = self.0.log_model_call(&entry) {
            tracing::debug!(error = %e, "Failed to log model call to audit");
        }
    }
}

/// Default operations granted to teammates.
pub const DEFAULT_OPERATIONS: &[&str] = &["read", "search", "list"];

/// Default tools granted to teammates.
pub const DEFAULT_TOOLS: &[&str] = &[
    "file_tree", "file_grep", "file_read",
    "team_bb_publish", "team_bb_read", "team_bb_notifications",
    "models_list", "personas_list", "flow_escalate",
    "flow_status", "flow_result",
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
    /// Podman container ID when running in containerized mode.
    pub container_id: Option<String>,
    /// OpenShell sandbox ID when running in OpenShell mode.
    pub sandbox_id: Option<String>,
    /// Host path to the mounted workspace directory.
    pub workspace_path: Option<std::path::PathBuf>,
    /// Elapsed seconds at the time of the last `team_bb_notifications` call.
    /// `None` means the agent has never checked, so all entries are returned.
    pub last_bb_check: Option<u64>,
    pub iterations: Option<u32>,
    pub agent_tokens: Option<u32>,
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
    /// IFC data label — propagated to readers via taint-on-read.
    #[serde(default)]
    pub label: smgglrs_core::protocol::label::DataLabel,
}

/// Lightweight notification about a blackboard publish event.
/// Contains only the key and author — not the content.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BlackboardNotification {
    pub key: String,
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
            max_depth: 5,
            max_agents: 50,
            max_tokens: 5_000_000,
            timeout_secs: 1800,
            max_iterations: 200,
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
                container_id: None,
                sandbox_id: None,
                workspace_path: None,
                last_bb_check: None,
                iterations: None,
                agent_tokens: None,
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

    pub fn bb_publish(
        &self, team_id: &str, key: &str, value: &str, author: &str,
        label: smgglrs_core::protocol::label::DataLabel,
    ) {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(team) = teams.get_mut(team_id) {
            team.blackboard.retain(|e| e.key != key);
            team.blackboard.push(BlackboardEntry {
                key: key.to_string(),
                value: value.to_string(),
                author: author.to_string(),
                timestamp_secs: team.created_at.elapsed().as_secs(),
                label,
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

    /// Return blackboard entries published since the agent's last check,
    /// excluding entries authored by the agent itself. Advances the
    /// agent's `last_bb_check` timestamp so the next call only returns
    /// new entries.
    pub fn bb_notifications(
        &self,
        team_id: &str,
        agent_name: &str,
    ) -> Result<Vec<BlackboardNotification>, String> {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        let team = teams
            .get_mut(team_id)
            .ok_or_else(|| format!("Unknown team: {team_id}"))?;

        let now = team.created_at.elapsed().as_secs();

        // Find the teammate's last check timestamp.
        // `None` means never checked — return all entries.
        let since = team
            .teammates
            .get(agent_name)
            .and_then(|tm| tm.last_bb_check);

        let notifications: Vec<BlackboardNotification> = team
            .blackboard
            .iter()
            .filter(|e| {
                e.author != agent_name
                    && match since {
                        None => true,
                        Some(ts) => e.timestamp_secs > ts,
                    }
            })
            .map(|e| BlackboardNotification {
                key: e.key.clone(),
                author: e.author.clone(),
                timestamp_secs: e.timestamp_secs,
            })
            .collect();

        // Advance the timestamp
        if let Some(tm) = team.teammates.get_mut(agent_name) {
            tm.last_bb_check = Some(now);
        }

        Ok(notifications)
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

    pub fn set_container_id(&self, team_id: &str, teammate: &str, container_id: String) {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(team) = teams.get_mut(team_id) {
            if let Some(tm) = team.teammates.get_mut(teammate) {
                tm.container_id = Some(container_id);
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

    pub fn set_resolved_model(&self, team_id: &str, teammate: &str, model: &str) {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(team) = teams.get_mut(team_id) {
            if let Some(tm) = team.teammates.get_mut(teammate) {
                tm.model = model.to_string();
            }
        }
    }

    pub fn set_agent_metrics(&self, team_id: &str, teammate: &str, iterations: u32, tokens: u32) {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(team) = teams.get_mut(team_id) {
            if let Some(tm) = team.teammates.get_mut(teammate) {
                tm.iterations = Some(iterations);
                tm.agent_tokens = Some(tokens);
            }
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

        // Stop any running containers
        let containers: Vec<String> = team.teammates.values()
            .filter_map(|tm| tm.container_id.clone())
            .collect();
        if !containers.is_empty() {
            let names = containers.clone();
            tokio::spawn(async move {
                for name in names {
                    tracing::info!(container = %name, "Stopping agent container on shutdown");
                    let _ = tokio::process::Command::new("podman")
                        .args(["stop", "-t", "5", &name])
                        .output()
                        .await;
                }
            });
        }

        let agent_count = team.teammates.len() as u32;
        self.total_agents.fetch_sub(agent_count, Ordering::Relaxed);

        Ok(serde_json::json!({
            "team_id": team_id,
            "name": team.name,
            "members_removed": team.teammates.keys().collect::<Vec<_>>(),
            "tasks_aborted": aborted,
            "containers_stopped": containers,
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
        annotations: None,
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
        annotations: None,
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
        annotations: None,
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
        annotations: None,
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
        annotations: None,
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
        annotations: None,
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
        annotations: None,
    }
}

pub fn team_bb_notifications_def() -> ToolDefinition {
    ToolDefinition {
        name: "team_bb_notifications".to_string(),
        description: Some(
            "Check for new blackboard entries published by other teammates \
             since your last check. Returns key, author, and timestamp for \
             each new entry (not the content). Call team_bb_read on \
             interesting keys to retrieve the full value."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                ("team_id".to_string(), serde_json::json!({"type": "string"})),
            ])),
            required: Some(vec!["team_id".to_string()]),
        },
        annotations: None,
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
        annotations: None,
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
        annotations: None,
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
        annotations: None,
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
    label: smgglrs_core::protocol::label::DataLabel,
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
    reg.bb_publish(team_id, key, value, agent_name, label);
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

/// Handle team_bb_notifications tool call.
pub async fn handle_team_bb_notifications(
    args: serde_json::Value,
    reg: std::sync::Arc<TeamRegistry>,
    agent_name: &str,
) -> smgglrs_core::protocol::CallToolResult {
    use smgglrs_core::protocol::CallToolResult;

    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(id) => id, None => return CallToolResult::error("Missing team_id"),
    };
    match reg.bb_notifications(team_id, agent_name) {
        Ok(notifications) => {
            if notifications.is_empty() {
                CallToolResult::text("No new blackboard entries since last check.")
            } else {
                CallToolResult::text(
                    serde_json::to_string_pretty(&notifications).unwrap_or_default()
                )
            }
        }
        Err(e) => CallToolResult::error(e),
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
    /// Optional PII filter applied to model-generated reasoning text.
    /// When set, teammate agents filter their text output to prevent
    /// PII leaking through model reasoning even after tool results
    /// were redacted.
    pub pii_filter: Option<std::sync::Arc<smgglrs_core::safety::FilterPipeline>>,
    /// Audit log for recording teammate runs.
    pub audit_log: Option<std::sync::Arc<smgglrs_memory::AuditLog>>,
    /// Path to cognitive core directory on the host (for container mounts).
    pub cognitive_core_path: Option<String>,
    /// Shared model server endpoint (e.g. `http://127.0.0.1:PORT/v1`).
    /// When set, containerized agents use this instead of Ollama.
    pub model_server_url: Option<String>,
    /// Semaphore limiting concurrent GPU-bound agent executions.
    pub gpu_semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    /// Whether to use containerized agent execution via Podman.
    pub containerized: bool,
    /// Container image for agent sandboxes.
    pub agent_image: String,
    /// Memory limit per container (e.g., "2g").
    pub container_memory: String,
    /// CPU limit per container (e.g., "2").
    pub container_cpus: String,
    /// PID limit per container.
    pub container_pids: u32,
    /// Optional embedding model for query-aware tool output compression.
    pub embedding_model: Option<std::sync::Arc<dyn smgglrs_model::ModelBackend>>,
    /// OpenShell compute driver gRPC endpoint (e.g., "http://[::1]:50051").
    /// When set, agents are spawned via OpenShell instead of Podman.
    pub openshell_gateway: Option<String>,
    /// Shared exec state for routing exec_run calls to the correct sandbox.
    pub exec_state: Option<std::sync::Arc<smgglrs_tools_exec::ExecModule>>,
    /// Workspace provider for populating agent sandbox workspaces.
    pub workspace_provider: Option<std::sync::Arc<dyn crate::workspace::WorkspaceProvider>>,
}

/// Check if Podman is available on this system.
pub fn is_podman_available() -> bool {
    std::process::Command::new("podman")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Spawn a teammate agent in a Podman container.
///
/// The agent binary (`smgglrs-agent`) reads its configuration from
/// environment variables and communicates with the gateway over HTTP.
/// The container uses `slirp4netns` networking so it can reach the
/// host gateway and model server via `10.0.2.2`.
///
/// **Security note on SMGGLRS_TOKEN**: The token passed to the container
/// is NOT the server's root token. It is a short-lived delegated token
/// minted via `build_delegated_payload` with:
/// - Scoped operations: only the teammate's allowed operations
/// - Scoped tools: only the teammate's allowed tools
/// - TTL: matches the team's `timeout_secs` (container deadline)
/// - Delegation chain: traceable back to the root payload via parent nonce
///
/// A compromised container can only call the specific tools granted to
/// that teammate, and the token expires when the team times out.
fn spawn_containerized_agent(
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
    let root_payload = ctx.root_payload.clone();
    let smgglrs_addr = ctx.smgglrs_addr.clone();
    let model_server_url = ctx.model_server_url.clone();
    let agent_image = ctx.agent_image.clone();
    let container_memory = ctx.container_memory.clone();
    let container_cpus = ctx.container_cpus.clone();
    let container_pids = ctx.container_pids;
    let gpu_semaphore = std::sync::Arc::clone(&ctx.gpu_semaphore);
    let cognitive_core_path = ctx.cognitive_core_path.clone();
    let audit_log = ctx.audit_log.clone();
    let team_id = team_id.to_string();
    let teammate_id = teammate_id.to_string();
    let message = message.to_string();

    tokio::spawn(async move {
        let deadline = std::time::Duration::from_secs(timeout_secs);
        let timeout_reg = reg.clone();
        let timeout_team = team_id.clone();
        let timeout_task = teammate_id.clone();

        let result = tokio::time::timeout(deadline, async {
            // Acquire GPU semaphore before running
            let _permit = gpu_semaphore.acquire().await.unwrap();

            // Build scoped capability token
            let (tm_ops, tm_tools, tm_persona, teammate_model) = {
                let teams = reg.teams.lock().unwrap_or_else(|e| e.into_inner());
                teams.get(&team_id)
                    .and_then(|t| t.teammates.get(&teammate_id))
                    .map(|tm| (
                        tm.operations.clone(),
                        tm.tools.clone(),
                        tm.persona.clone(),
                        tm.model.clone(),
                    ))
                    .unwrap_or_else(|| (
                        DEFAULT_OPERATIONS.iter().map(|s| s.to_string()).collect(),
                        DEFAULT_TOOLS.iter().map(|s| s.to_string()).collect(),
                        None,
                        "auto".to_string(),
                    ))
            };

            let did = format!("did:teammate:{}:{}", team_id, teammate_id);
            let token = if let Some(ref root) = root_payload {
                match smgglrs_core::auth::capability::build_delegated_payload(
                    root, &did, tm_ops, tm_tools, 2, timeout_secs,
                ) {
                    Ok(payload) => match smgglrs_core::auth::capability::encode_token(&payload, signer.as_ref()) {
                        Ok(t) => t,
                        Err(e) => {
                            reg.set_failed(&team_id, &teammate_id, format!("Token error: {e}"));
                            return;
                        }
                    },
                    Err(e) => {
                        reg.set_failed(&team_id, &teammate_id, format!("Token delegation error: {e}"));
                        return;
                    }
                }
            } else {
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
                        reg.set_failed(&team_id, &teammate_id, format!("Token error: {e}"));
                        return;
                    }
                }
            };

            // Resolve model
            let mut model = teammate_model;
            if model == "auto" {
                if let Some(selected) = select_model_for_task(
                    &reg.model_cards, tm_persona.as_deref(), &message,
                ) {
                    model = selected;
                } else {
                    model = "granite3.3:8b".to_string();
                }
            }

            // Determine model endpoint: shared model server or host Ollama
            let model_endpoint = model_server_url.clone()
                .unwrap_or_else(|| "http://10.0.2.2:11434/v1".to_string());

            // Parse the gateway port from smgglrs_addr (e.g. "127.0.0.1:9315")
            let gateway_port = smgglrs_addr
                .rsplit(':')
                .next()
                .unwrap_or("9315");
            let gateway_url = format!("http://10.0.2.2:{gateway_port}/mcp");

            // Replace host addresses with container-visible 10.0.2.2
            let container_model_ep = model_endpoint
                .replace("127.0.0.1", "10.0.2.2")
                .replace("localhost", "10.0.2.2");

            let container_name = format!("smgglrs-agent-{}-{}", team_id, teammate_id);

            reg.set_resolved_model(&team_id, &teammate_id, &model);
            eprintln!("  [container] {} → model: {}, image: {}", teammate_id, model, agent_image);

            // Build persona env vars
            let persona_env: Vec<String> = if let Some(ref name) = tm_persona {
                vec![
                    "-e".to_string(), format!("SMGGLRS_PERSONA={name}"),
                ]
            } else {
                vec![]
            };

            // Mount cognitive core directory if persona is set and path is known
            let cognitive_mount: Vec<String> = if tm_persona.is_some() {
                if let Some(ref core_path) = cognitive_core_path {
                    vec![
                        "-v".to_string(),
                        format!("{core_path}:/cognitive_core:ro,Z"),
                        "-e".to_string(),
                        "SMGGLRS_COGNITIVE_CORE=/cognitive_core".to_string(),
                    ]
                } else {
                    vec![]
                }
            } else {
                vec![]
            };

            let mut cmd = tokio::process::Command::new("podman");
            cmd.arg("run")
                .arg("--rm")
                .arg("--name").arg(&container_name)
                .arg("--network=slirp4netns:allow_host_loopback=true")
                .arg(format!("--memory={container_memory}"))
                .arg(format!("--cpus={container_cpus}"))
                .arg(format!("--pids-limit={container_pids}"))
                .arg("--read-only")
                .arg("--security-opt=no-new-privileges")
                .arg("-e").arg(format!("SMGGLRS_ENDPOINT={gateway_url}"))
                .arg("-e").arg(format!("SMGGLRS_TOKEN={token}"))
                .arg("-e").arg(format!("SMGGLRS_MODEL_ENDPOINT={container_model_ep}"))
                .arg("-e").arg(format!("SMGGLRS_MODEL_NAME={model}"))
                .arg("-e").arg(format!("SMGGLRS_TASK={message}"))
                .arg("-e").arg(format!("SMGGLRS_MAX_ITERATIONS={max_iterations}"));

            for arg in &persona_env {
                cmd.arg(arg);
            }
            for arg in &cognitive_mount {
                cmd.arg(arg);
            }

            cmd.arg(&agent_image);

            // Record container name
            reg.set_container_id(&team_id, &teammate_id, container_name.clone());

            let output = cmd
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .await;

            match output {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);

                    if !output.status.success() {
                        tracing::error!(
                            team = %team_id, teammate = %teammate_id,
                            stderr = %stderr,
                            "Container agent failed"
                        );
                        reg.set_failed(&team_id, &teammate_id, format!("Container exited with error: {stderr}"));
                        return;
                    }

                    // Parse JSON output from the agent binary.
                    // The stdout may contain log lines before the JSON
                    // (tracing warnings from the tool loop). Find the
                    // first '{' to locate the JSON object.
                    let json_str = stdout.find('{')
                        .map(|i| &stdout[i..])
                        .unwrap_or(&stdout);
                    match serde_json::from_str::<serde_json::Value>(json_str) {
                        Ok(result) => {
                            let response = result.get("output")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let iterations = result.get("iterations")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            let tokens_in = result.get("tokens_in")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0) as u32;
                            let tokens_out = result.get("tokens_out")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0) as u32;

                            let total_tokens = tokens_in + tokens_out;
                            reg.add_tokens(&team_id, total_tokens);
                            reg.set_agent_metrics(&team_id, &teammate_id, iterations as u32, total_tokens);

                            tracing::info!(
                                team = %team_id, teammate = %teammate_id,
                                iterations = iterations,
                                tokens = total_tokens,
                                "Container teammate completed"
                            );

                            // Audit log
                            if let Some(ref audit) = audit_log {
                                let now_ms = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis() as i64;
                                let run_id = format!("tm-{team_id}-{teammate_id}");
                                let run = smgglrs_memory::AuditRun {
                                    run_id,
                                    agent_id: teammate_id.clone(),
                                    prompt: message.clone(),
                                    persona: tm_persona.clone(),
                                    model: model.clone(),
                                    started_at: now_ms - (deadline.as_millis() as i64),
                                    ended_at: Some(now_ms),
                                    teammates: vec![],
                                    final_report: Some(response.clone()),
                                    exit_reason: Some("completed".to_string()),
                                };
                                let _ = audit.begin_run(&run);
                            }

                            reg.set_output(&team_id, &teammate_id, response);
                        }
                        Err(e) => {
                            // If we can't parse JSON, use raw stdout as output
                            let raw = stdout.trim().to_string();
                            if !raw.is_empty() {
                                tracing::warn!(
                                    team = %team_id, teammate = %teammate_id,
                                    error = %e,
                                    "Could not parse container JSON output, using raw text"
                                );
                                reg.set_output(&team_id, &teammate_id, raw);
                            } else {
                                reg.set_failed(
                                    &team_id, &teammate_id,
                                    format!("Container produced no output. stderr: {stderr}"),
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(
                        team = %team_id, teammate = %teammate_id,
                        error = %e,
                        "Failed to run container"
                    );
                    reg.set_failed(&team_id, &teammate_id, format!("Podman exec error: {e}"));
                }
            }
        }).await;

        if result.is_err() {
            tracing::warn!(
                team = %timeout_team, teammate = %timeout_task,
                "Container teammate timed out after {timeout_secs}s"
            );
            // Try to stop the container on timeout
            let container_name = format!("smgglrs-agent-{}-{}", timeout_team, timeout_task);
            let _ = tokio::process::Command::new("podman")
                .args(["stop", "-t", "5", &container_name])
                .output()
                .await;
            timeout_reg.set_failed(&timeout_team, &timeout_task, format!("Timed out after {timeout_secs}s"));
        }
    })
}

/// Spawn a teammate agent inside an OpenShell sandbox.
///
/// Uses the OpenShell compute driver to create a sandbox running
/// `smgglrs-agent`. Workspace is mounted at `/workspace` read-write.
/// The sandbox_id is registered in ExecState so the agent can call
/// `exec_run` to execute commands inside the sandbox.
fn spawn_openshell_agent(
    ctx: &TeammateSpawnContext,
    team_id: &str,
    teammate_id: &str,
    message: &str,
    max_iterations: usize,
    timeout_secs: u64,
    _generates_tasks: bool,
) -> tokio::task::JoinHandle<()> {
    let reg = std::sync::Arc::clone(&ctx.team_registry);
    let signer = std::sync::Arc::clone(&ctx.signer);
    let root_payload = ctx.root_payload.clone();
    let smgglrs_addr = ctx.smgglrs_addr.clone();
    let gateway_url = ctx.openshell_gateway.clone().unwrap();
    let agent_image = ctx.agent_image.clone();
    let exec_state = ctx.exec_state.as_ref().map(std::sync::Arc::clone);
    let workspace_provider = ctx.workspace_provider.as_ref().map(std::sync::Arc::clone);
    let gpu_semaphore = std::sync::Arc::clone(&ctx.gpu_semaphore);
    let cognitive_core_path = ctx.cognitive_core_path.clone();
    let model_server_url = ctx.model_server_url.clone();
    let team_id = team_id.to_string();
    let teammate_id = teammate_id.to_string();
    let message = message.to_string();

    tokio::spawn(async move {
        let deadline = std::time::Duration::from_secs(timeout_secs);
        let timeout_reg = reg.clone();
        let timeout_team = team_id.clone();
        let timeout_task = teammate_id.clone();

        let result = tokio::time::timeout(deadline, async {
            let _permit = gpu_semaphore.acquire().await.unwrap();

            // Build scoped capability token (same as Podman path)
            let (tm_ops, tm_tools, tm_persona, teammate_model) = {
                let teams = reg.teams.lock().unwrap_or_else(|e| e.into_inner());
                teams.get(&team_id)
                    .and_then(|t| t.teammates.get(&teammate_id))
                    .map(|tm| (
                        tm.operations.clone(),
                        tm.tools.clone(),
                        tm.persona.clone(),
                        tm.model.clone(),
                    ))
                    .unwrap_or_else(|| (
                        DEFAULT_OPERATIONS.iter().map(|s| s.to_string()).collect(),
                        DEFAULT_TOOLS.iter().map(|s| s.to_string()).collect(),
                        None,
                        "auto".to_string(),
                    ))
            };

            let did = format!("did:teammate:{}:{}", team_id, teammate_id);
            let token = if let Some(ref root) = root_payload {
                match smgglrs_core::auth::capability::build_delegated_payload(
                    root, &did, tm_ops, tm_tools, 2, timeout_secs,
                ) {
                    Ok(payload) => match smgglrs_core::auth::capability::encode_token(&payload, signer.as_ref()) {
                        Ok(t) => t,
                        Err(e) => {
                            reg.set_failed(&team_id, &teammate_id, format!("Token error: {e}"));
                            return;
                        }
                    },
                    Err(e) => {
                        reg.set_failed(&team_id, &teammate_id, format!("Token delegation error: {e}"));
                        return;
                    }
                }
            } else {
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
                        reg.set_failed(&team_id, &teammate_id, format!("Token error: {e}"));
                        return;
                    }
                }
            };

            // Resolve model
            let mut model = teammate_model;
            if model == "auto" {
                if let Some(selected) = select_model_for_task(
                    &reg.model_cards, tm_persona.as_deref(), &message,
                ) {
                    model = selected;
                } else {
                    model = "granite3.3:8b".to_string();
                }
            }

            let model_endpoint = model_server_url.clone()
                .unwrap_or_else(|| "http://10.0.2.2:11434/v1".to_string());

            let gateway_port = smgglrs_addr
                .rsplit(':')
                .next()
                .unwrap_or("9315");
            let mcp_url = format!("http://10.0.2.2:{gateway_port}/mcp");

            reg.set_resolved_model(&team_id, &teammate_id, &model);
            eprintln!("  [openshell] {} → model: {}, image: {}", teammate_id, model, agent_image);

            // Prepare workspace
            let workspace_dir = tempfile::tempdir().ok();
            if let (Some(ref provider), Some(ref ws_dir)) = (&workspace_provider, &workspace_dir) {
                if let Err(e) = provider.populate(ws_dir.path()) {
                    reg.set_failed(&team_id, &teammate_id, format!("Workspace populate error: {e}"));
                    return;
                }
            }

            // Build mounts
            let mut mounts = Vec::new();
            if let Some(ref ws_dir) = workspace_dir {
                mounts.push(smgglrs_model_runtime::openshell::Mount {
                    source: ws_dir.path().to_string_lossy().to_string(),
                    target: "/workspace".to_string(),
                    read_only: false,
                });
            }
            if let Some(ref core_path) = cognitive_core_path {
                if tm_persona.is_some() {
                    mounts.push(smgglrs_model_runtime::openshell::Mount {
                        source: core_path.clone(),
                        target: "/cognitive_core".to_string(),
                        read_only: true,
                    });
                }
            }

            // Build env vars
            let mut env = std::collections::HashMap::new();
            env.insert("SMGGLRS_ENDPOINT".to_string(), mcp_url);
            env.insert("SMGGLRS_TOKEN".to_string(), token);
            env.insert("SMGGLRS_MODEL_ENDPOINT".to_string(), model_endpoint);
            env.insert("SMGGLRS_MODEL_NAME".to_string(), model);
            env.insert("SMGGLRS_TASK".to_string(), message.clone());
            env.insert("SMGGLRS_MAX_ITERATIONS".to_string(), max_iterations.to_string());
            if tm_persona.is_some() {
                if let Some(ref name) = tm_persona {
                    env.insert("SMGGLRS_PERSONA".to_string(), name.clone());
                    env.insert("SMGGLRS_COGNITIVE_CORE".to_string(), "/cognitive_core".to_string());
                }
            }

            // Build sandbox labels
            let mut labels = std::collections::HashMap::new();
            labels.insert("runtime".to_string(), "agent".to_string());
            labels.insert("purpose".to_string(), "teammate".to_string());
            labels.insert("team".to_string(), team_id.clone());
            labels.insert("agent".to_string(), teammate_id.clone());

            let request = smgglrs_model_runtime::openshell::CreateSandboxRequest {
                labels,
                supervisor: Some(smgglrs_model_runtime::openshell::SupervisorConfig {
                    entrypoint: "smgglrs-agent".to_string(),
                    args: vec![],
                    env,
                    mounts,
                }),
            };

            // Connect to OpenShell compute driver
            let channel = match tonic::transport::Channel::from_shared(gateway_url.clone()) {
                Ok(c) => match c.connect().await {
                    Ok(ch) => ch,
                    Err(e) => {
                        reg.set_failed(&team_id, &teammate_id, format!("OpenShell connect error: {e}"));
                        return;
                    }
                },
                Err(e) => {
                    reg.set_failed(&team_id, &teammate_id, format!("OpenShell channel error: {e}"));
                    return;
                }
            };

            let mut client = smgglrs_model_runtime::openshell::ComputeDriverClient::new(channel);

            // Create sandbox
            let resp = match client.create_sandbox(request).await {
                Ok(r) => r.into_inner(),
                Err(e) => {
                    reg.set_failed(&team_id, &teammate_id, format!("CreateSandbox error: {e}"));
                    return;
                }
            };

            let sandbox_id = resp.sandbox_id.clone();

            // Record sandbox info
            {
                let mut teams = reg.teams.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(team) = teams.get_mut(&team_id) {
                    if let Some(tm) = team.teammates.get_mut(&teammate_id) {
                        tm.sandbox_id = Some(sandbox_id.clone());
                        if let Some(ref ws_dir) = workspace_dir {
                            tm.workspace_path = Some(ws_dir.path().to_path_buf());
                        }
                    }
                }
            }

            // Register sandbox for exec_run routing
            if let Some(ref exec) = exec_state {
                exec.state().register_sandbox(did.clone(), sandbox_id.clone());
            }

            // Wait for sandbox to be running
            let mut attempts = 0;
            loop {
                attempts += 1;
                if attempts > 120 {
                    reg.set_failed(&team_id, &teammate_id, "Sandbox failed to start (timeout)".to_string());
                    let _ = client.destroy_sandbox(
                        smgglrs_model_runtime::openshell::DestroySandboxRequest {
                            sandbox_id: sandbox_id.clone(),
                        },
                    ).await;
                    return;
                }

                match client.sandbox_status(
                    smgglrs_model_runtime::openshell::SandboxStatusRequest {
                        sandbox_id: sandbox_id.clone(),
                    },
                ).await {
                    Ok(status) => {
                        let state = status.into_inner().state;
                        if state == smgglrs_model_runtime::openshell::SandboxState::Running as i32 {
                            break;
                        }
                        if state == smgglrs_model_runtime::openshell::SandboxState::Failed as i32 {
                            reg.set_failed(&team_id, &teammate_id, "Sandbox entered failed state".to_string());
                            let _ = client.destroy_sandbox(
                                smgglrs_model_runtime::openshell::DestroySandboxRequest {
                                    sandbox_id: sandbox_id.clone(),
                                },
                            ).await;
                            return;
                        }
                    }
                    Err(e) => {
                        reg.set_failed(&team_id, &teammate_id, format!("SandboxStatus error: {e}"));
                        return;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }

            {
                let mut teams = reg.teams.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(team) = teams.get_mut(&team_id) {
                    if let Some(tm) = team.teammates.get_mut(&teammate_id) {
                        tm.status = "working".to_string();
                    }
                }
            }

            // Wait for sandbox to complete (agent finishes its ReAct loop)
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                match client.sandbox_status(
                    smgglrs_model_runtime::openshell::SandboxStatusRequest {
                        sandbox_id: sandbox_id.clone(),
                    },
                ).await {
                    Ok(status) => {
                        let state = status.into_inner().state;
                        if state == smgglrs_model_runtime::openshell::SandboxState::Stopped as i32
                            || state == smgglrs_model_runtime::openshell::SandboxState::Failed as i32
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            // Collect workspace results
            if let (Some(ref provider), Some(ref ws_dir)) = (&workspace_provider, &workspace_dir) {
                match provider.collect(ws_dir.path()) {
                    Ok(result) => {
                        let summary = format!(
                            "Workspace: {} files",
                            result.files.len(),
                        );
                        reg.set_output(&team_id, &teammate_id, summary);
                    }
                    Err(e) => {
                        reg.set_output(&team_id, &teammate_id, format!("Done (workspace collect error: {e})"));
                    }
                }
            } else {
                reg.set_output(&team_id, &teammate_id, "Done".to_string());
            }

            // Cleanup: destroy sandbox and deregister exec state
            let _ = client.destroy_sandbox(
                smgglrs_model_runtime::openshell::DestroySandboxRequest {
                    sandbox_id: sandbox_id.clone(),
                },
            ).await;
            if let Some(ref exec) = exec_state {
                exec.state().remove_sandbox(&did);
            }
        })
        .await;

        if result.is_err() {
            tracing::warn!(
                team = %timeout_team, teammate = %timeout_task,
                "OpenShell teammate timed out after {timeout_secs}s"
            );
            timeout_reg.set_failed(&timeout_team, &timeout_task, format!("Timed out after {timeout_secs}s"));
        }
    })
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
    // OpenShell path: preferred when gateway is configured
    if ctx.openshell_gateway.is_some() {
        return spawn_openshell_agent(
            ctx, team_id, teammate_id, message,
            max_iterations, timeout_secs, generates_tasks,
        );
    }

    // Containerized path: spawn agent in a Podman container
    if ctx.containerized && is_podman_available() {
        return spawn_containerized_agent(
            ctx, team_id, teammate_id, message,
            max_iterations, timeout_secs, generates_tasks,
        );
    }

    // In-process path (fallback)
    let reg = std::sync::Arc::clone(&ctx.team_registry);
    let signer = std::sync::Arc::clone(&ctx.signer);
    let forge = ctx.forge.clone();
    let root_payload = ctx.root_payload.clone();
    let pii_filter = ctx.pii_filter.clone();
    let audit_log = ctx.audit_log.clone();
    let embedding_model = ctx.embedding_model.clone();
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

            reg.set_resolved_model(&team_id, &teammate_id, &teammate_model);
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
                            .force_tool_iterations(1)
                            .temperature(0.3)
                            .max_tokens(8192);
                        // Note: generates_tasks schema enforcement is NOT
                        // applied here. Ollama can't handle format + tools
                        // simultaneously, and ignores format on large prompts.
                        // The resilient parser in parse_planner_tasks()
                        // recovers valid JSON from malformed model output.
                        if let Some(ref filter) = pii_filter {
                            builder = builder.pii_filter(std::sync::Arc::clone(filter));
                        }
                        if let Some(ref embed) = embedding_model {
                            builder = builder.embedding_model(std::sync::Arc::clone(embed));
                        }
                        if let Some(ref audit) = audit_log {
                            let sink: smgglrs_agent::SharedAuditSink =
                                std::sync::Arc::new(AuditLogSink(std::sync::Arc::clone(audit)));
                            builder = builder.audit_sink(sink);
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
                    reg.set_agent_metrics(&team_id, &teammate_id, result.iterations as u32, tokens);
                    tracing::info!(
                        team = %team_id, to = %teammate_id,
                        iterations = result.iterations,
                        tokens = tokens,
                        "Teammate completed"
                    );
                    // Record teammate run in audit log
                    if let Some(ref audit) = audit_log {
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as i64;
                        let run_id = format!("tm-{team_id}-{teammate_id}");
                        let run = smgglrs_memory::AuditRun {
                            run_id: run_id.clone(),
                            agent_id: teammate_id.clone(),
                            prompt: message.clone(),
                            persona: tm_persona.clone(),
                            model: teammate_model.clone(),
                            started_at: now_ms - (deadline.as_millis() as i64),
                            ended_at: Some(now_ms),
                            teammates: vec![],
                            final_report: Some(result.response.clone()),
                            exit_reason: Some("completed".to_string()),
                        };
                        if let Err(e) = audit.begin_run(&run) {
                            tracing::warn!(run_id = %run_id, error = %e, "Failed to record teammate run in audit");
                        }
                    }
                    reg.set_output(&team_id, &teammate_id, result.response);
                }
                Err(e) => {
                    tracing::error!(team = %team_id, to = %teammate_id, error = %e, "Teammate failed");
                    // Record failed teammate run in audit log
                    if let Some(ref audit) = audit_log {
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as i64;
                        let run_id = format!("tm-{team_id}-{teammate_id}");
                        let run = smgglrs_memory::AuditRun {
                            run_id,
                            agent_id: teammate_id.clone(),
                            prompt: message.clone(),
                            persona: tm_persona.clone(),
                            model: teammate_model.clone(),
                            started_at: now_ms - (deadline.as_millis() as i64),
                            ended_at: Some(now_ms),
                            teammates: vec![],
                            final_report: None,
                            exit_reason: Some(format!("failed: {e}")),
                        };
                        let _ = audit.begin_run(&run);
                    }
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
                // Prefer 12-20B for specialist tasks (fits in GPU with
                // concurrent KV caches). ≥20B is penalized because model
                // swapping under concurrent load can hang the GPU.
                if param_b >= 12.0 && param_b <= 20.0 { score += 20; }
                else if param_b >= 20.0 { score += 5; }
                else { score -= 50; } // ≤10B models can't reliably call tools via Ollama
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registry() -> TeamRegistry {
        TeamRegistry::new()
    }

    #[test]
    fn bb_notifications_returns_entries_from_others() {
        let reg = test_registry();
        let tid = reg.create_team("t", None, "lead", 0, TeamBudget::default()).unwrap();
        reg.add_teammate(&tid, "alice", None, "m", "local", vec![], vec![]).unwrap();
        reg.add_teammate(&tid, "bob", None, "m", "local", vec![], vec![]).unwrap();

        // Alice publishes
        reg.bb_publish(&tid, "finding-1", "data", "alice", smgglrs_core::protocol::label::DataLabel::TRUSTED_PUBLIC);

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
        let tid = reg.create_team("t", None, "lead", 0, TeamBudget::default()).unwrap();
        reg.add_teammate(&tid, "alice", None, "m", "local", vec![], vec![]).unwrap();
        reg.add_teammate(&tid, "bob", None, "m", "local", vec![], vec![]).unwrap();

        reg.bb_publish(&tid, "k1", "v1", "alice", smgglrs_core::protocol::label::DataLabel::TRUSTED_PUBLIC);

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
        let tid = reg.create_team("t", None, "lead", 0, TeamBudget::default()).unwrap();
        reg.add_teammate(&tid, "alice", None, "m", "local", vec![], vec![]).unwrap();
        reg.add_teammate(&tid, "bob", None, "m", "local", vec![], vec![]).unwrap();
        reg.add_teammate(&tid, "carol", None, "m", "local", vec![], vec![]).unwrap();

        reg.bb_publish(&tid, "k1", "v1", "alice", smgglrs_core::protocol::label::DataLabel::TRUSTED_PUBLIC);
        reg.bb_publish(&tid, "k2", "v2", "carol", smgglrs_core::protocol::label::DataLabel::TRUSTED_PUBLIC);
        reg.bb_publish(&tid, "k3", "v3", "alice", smgglrs_core::protocol::label::DataLabel::TRUSTED_PUBLIC);

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
        let tid = reg.create_team("t", None, "lead", 0, TeamBudget::default()).unwrap();
        reg.add_teammate(&tid, "alice", None, "m", "local", vec![], vec![]).unwrap();

        reg.bb_publish(&tid, "k1", "v1", "alice", smgglrs_core::protocol::label::DataLabel::TRUSTED_PUBLIC);

        let notifs = reg.bb_notifications(&tid, "outsider").unwrap();
        // outsider sees alice's entry (since=0)
        assert_eq!(notifs.len(), 1);
    }
}
