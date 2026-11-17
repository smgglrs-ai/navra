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

use navra_agent::AuditSink;
use navra_core::protocol::ToolDefinition;
use navra_protocol::compat::{CallToolResultExt, tool_input_schema};
use std::collections::HashMap;
use std::sync::{
    Mutex,
    atomic::{AtomicU32, Ordering},
};
use std::time::Instant;
use tokio::task::JoinHandle;

/// Adapter that implements navra-agent's AuditSink using navra-memory's AuditLog.
pub(crate) struct AuditLogSink(pub std::sync::Arc<navra_memory::AuditLog>);

impl AuditSink for AuditLogSink {
    fn log_tool_call(
        &self,
        run_id: &str,
        agent_id: &str,
        iteration: u32,
        tool_name: &str,
        tool_args: &str,
        tool_result: &str,
        duration_ms: u64,
        trace_id: Option<&str>,
    ) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let entry = navra_memory::AuditToolCall {
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
            trace_id: trace_id.map(|s| s.to_string()),
        };
        if let Err(e) = self.0.log_tool_call(&entry) {
            tracing::debug!(error = %e, "Failed to log tool call to audit");
        }
    }

    fn log_model_call(
        &self,
        run_id: &str,
        agent_id: &str,
        iteration: u32,
        model_name: &str,
        input_tokens: u32,
        output_tokens: u32,
        response_type: &str,
    ) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let entry = navra_memory::AuditModelCall {
            run_id: run_id.to_string(),
            agent_id: agent_id.to_string(),
            iteration,
            timestamp_ms: now_ms,
            model_name: if model_name.is_empty() {
                None
            } else {
                Some(model_name.to_string())
            },
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
    "file_tree",
    "file_grep",
    "file_read",
    "team_bb_publish",
    "team_bb_read",
    "team_bb_notifications",
    "models_list",
    "personas_list",
    "flow_escalate",
    "flow_status",
    "flow_result",
];

/// A teammate in the team.
#[derive(Debug, Clone)]
pub struct Teammate {
    pub name: String,
    pub persona: Option<String>,
    pub model: String,
    pub locality: String, // "local", "remote", "auto"
    pub operations: Vec<String>,
    pub tools: Vec<String>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub force_tool_iterations: Option<usize>,
    pub status: String,
    pub task: Option<String>,
    pub output: Option<String>,
    pub created_at: Instant,
    /// Podman container ID when running in containerized mode.
    pub container_id: Option<String>,
    /// OpenShell sandbox ID when running in OpenShell mode.
    pub sandbox_id: Option<String>,
    /// Kubernetes Sandbox name when spawned via SandboxClaim adoption
    /// (warm pool). The adopted pod keeps its pool-generated name,
    /// which is how the task endpoint maps an adoption poll to this
    /// teammate.
    pub k8s_sandbox: Option<String>,
    /// Host path to the mounted workspace directory.
    pub workspace_path: Option<std::path::PathBuf>,
    /// Elapsed seconds at the time of the last `team_bb_notifications` call.
    /// `None` means the agent has never checked, so all entries are returned.
    pub last_bb_check: Option<u64>,
    pub iterations: Option<u32>,
    pub agent_tokens: Option<u32>,
    /// Signal handle for cooperative interruption of in-process agents.
    pub signal_handle: Option<navra_agent::SignalHandle>,
}

/// Re-export the composite model card from the hub.
pub use navra_model_hub::ModelCard;

/// A blackboard entry shared across the team.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlackboardEntry {
    pub key: String,
    pub value: String,
    pub author: String,
    pub timestamp_secs: u64,
    /// IFC data label — propagated to readers via taint-on-read.
    #[serde(default)]
    pub label: navra_core::protocol::label::DataLabel,
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
    /// Operation classification per tool, injected after server build.
    tool_operations: Mutex<HashMap<String, navra_mcp::ToolOperation>>,
    /// Persistence path (NAVRA-198). When set, every persisted-state
    /// mutation writes a snapshot here (write-through) and
    /// `load_or_new` restores from it. Only the coordinator and
    /// standalone gateways set this; workers keep scratch registries.
    persist_path: Option<std::path::PathBuf>,
}

// ── Persistence (NAVRA-198) ───────────────────────────────────────
//
// The registry is a low-churn structure (teams, teammates,
// blackboard), so a whole-registry JSON snapshot written through on
// every mutation is sufficient — no WAL, no per-entry journal.
// Transient state (task JoinHandles, SignalHandles) is not
// persisted; the sandbox→teammate mappings ARE, so results
// published via POST /api/agent/result still route after a
// coordinator restart.

/// Serializable mirror of [`Teammate`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TeammateSnapshot {
    name: String,
    persona: Option<String>,
    model: String,
    locality: String,
    operations: Vec<String>,
    tools: Vec<String>,
    temperature: Option<f32>,
    max_tokens: Option<u32>,
    force_tool_iterations: Option<usize>,
    status: String,
    task: Option<String>,
    output: Option<String>,
    container_id: Option<String>,
    sandbox_id: Option<String>,
    k8s_sandbox: Option<String>,
    workspace_path: Option<std::path::PathBuf>,
    last_bb_check: Option<u64>,
    iterations: Option<u32>,
    agent_tokens: Option<u32>,
}

impl From<&Teammate> for TeammateSnapshot {
    fn from(tm: &Teammate) -> Self {
        Self {
            name: tm.name.clone(),
            persona: tm.persona.clone(),
            model: tm.model.clone(),
            locality: tm.locality.clone(),
            operations: tm.operations.clone(),
            tools: tm.tools.clone(),
            temperature: tm.temperature,
            max_tokens: tm.max_tokens,
            force_tool_iterations: tm.force_tool_iterations,
            status: tm.status.clone(),
            task: tm.task.clone(),
            output: tm.output.clone(),
            container_id: tm.container_id.clone(),
            sandbox_id: tm.sandbox_id.clone(),
            k8s_sandbox: tm.k8s_sandbox.clone(),
            workspace_path: tm.workspace_path.clone(),
            last_bb_check: tm.last_bb_check,
            iterations: tm.iterations,
            agent_tokens: tm.agent_tokens,
        }
    }
}

impl From<TeammateSnapshot> for Teammate {
    fn from(s: TeammateSnapshot) -> Self {
        Self {
            name: s.name,
            persona: s.persona,
            model: s.model,
            locality: s.locality,
            operations: s.operations,
            tools: s.tools,
            temperature: s.temperature,
            max_tokens: s.max_tokens,
            force_tool_iterations: s.force_tool_iterations,
            status: s.status,
            task: s.task,
            output: s.output,
            created_at: Instant::now(),
            container_id: s.container_id,
            sandbox_id: s.sandbox_id,
            k8s_sandbox: s.k8s_sandbox,
            workspace_path: s.workspace_path,
            last_bb_check: None, // restart returns all notifications (safe superset)
            iterations: s.iterations,
            agent_tokens: s.agent_tokens,
            signal_handle: None, // transient
        }
    }
}

/// Serializable mirror of [`Team`].
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct TeamSnapshot {
    team_id: String,
    name: String,
    description: Option<String>,
    lead: String,
    depth: u32,
    budget: TeamBudget,
    teammates: Vec<TeammateSnapshot>,
    blackboard: Vec<BlackboardEntry>,
    tokens_used: u32,
    /// Wall-clock creation time (Unix seconds); re-derived to
    /// Instant on load for timeout math.
    created_at_unix: i64,
}

/// Whole-registry snapshot.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct RegistrySnapshot {
    next_id: u64,
    total_agents: u32,
    teams: Vec<TeamSnapshot>,
}

/// Infrastructure tools always included in teammate allowlists.
const INFRA_TOOLS: &[&str] = &[
    "team_bb_publish",
    "team_bb_read",
    "team_bb_notifications",
    "models_list",
    "personas_list",
    "flow_escalate",
    "flow_status",
    "flow_result",
];

impl TeamRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_models(mut self, cards: Vec<ModelCard>) -> Self {
        self.model_cards = cards;
        self
    }

    /// Enable write-through persistence to `path`. (Currently used
    /// only by tests and external embedders; the server wires
    /// persistence via `load_or_new`.)
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn with_persistence(mut self, path: std::path::PathBuf) -> Self {
        self.persist_path = Some(path);
        self
    }

    /// Load a registry from its snapshot (when present and valid)
    /// and keep persisting to `path`. A missing or corrupt snapshot
    /// starts empty — persistence failures never block startup, but
    /// are logged loudly.
    pub fn load_or_new(path: &std::path::Path) -> Self {
        let mut reg = Self {
            persist_path: Some(path.to_path_buf()),
            ..Default::default()
        };
        reg.persist_path = Some(path.to_path_buf());

        match std::fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str::<RegistrySnapshot>(&content) {
                Ok(snap) => {
                    let now_unix = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    let mut teams = HashMap::new();
                    for t in snap.teams {
                        // Re-derive the Instant clock from wall time.
                        // Teams older than process uptime (always,
                        // after a restart) lose exact timeout
                        // arithmetic — clamp to now, which restarts
                        // their timeout budget.
                        let elapsed = (now_unix - t.created_at_unix).max(0) as u64;
                        let created_at = Instant::now()
                            .checked_sub(std::time::Duration::from_secs(elapsed))
                            .unwrap_or_else(Instant::now);
                        teams.insert(
                            t.team_id.clone(),
                            Team {
                                team_id: t.team_id,
                                name: t.name,
                                description: t.description,
                                lead: t.lead,
                                depth: t.depth,
                                budget: t.budget,
                                teammates: t
                                    .teammates
                                    .into_iter()
                                    .map(|s| (s.name.clone(), Teammate::from(s)))
                                    .collect(),
                                blackboard: t.blackboard,
                                tokens_used: AtomicU32::new(t.tokens_used),
                                created_at,
                                task_handles: HashMap::new(),
                            },
                        );
                    }
                    let team_count = teams.len();
                    let agent_count = snap.total_agents;
                    *reg.next_id.lock().unwrap_or_else(|e| e.into_inner()) = snap.next_id;
                    reg.total_agents.store(snap.total_agents, Ordering::Relaxed);
                    *reg.teams.lock().unwrap_or_else(|e| e.into_inner()) = teams;
                    tracing::info!(
                        teams = team_count,
                        agents = agent_count,
                        path = %path.display(),
                        "TeamRegistry restored from snapshot"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %path.display(),
                        "TeamRegistry snapshot unreadable — starting empty"
                    );
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    "TeamRegistry snapshot unreadable — starting empty"
                );
            }
        }
        reg
    }

    /// Write the snapshot. MUST be called while holding the `teams`
    /// lock (takes the map by reference — no re-locking, no
    /// deadlock). Failures are logged, never fatal to the mutation.
    fn persist(&self, teams: &HashMap<String, Team>) {
        let Some(path) = &self.persist_path else {
            return;
        };
        let next_id = *self.next_id.lock().unwrap_or_else(|e| e.into_inner());
        let snap = RegistrySnapshot {
            next_id,
            total_agents: self.total_agents.load(Ordering::Relaxed),
            teams: teams
                .values()
                .map(|t| TeamSnapshot {
                    team_id: t.team_id.clone(),
                    name: t.name.clone(),
                    description: t.description.clone(),
                    lead: t.lead.clone(),
                    depth: t.depth,
                    budget: t.budget.clone(),
                    teammates: t.teammates.values().map(TeammateSnapshot::from).collect(),
                    blackboard: t.blackboard.clone(),
                    tokens_used: t.tokens_used.load(Ordering::Relaxed),
                    created_at_unix: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64,
                })
                .collect(),
        };
        let json = match serde_json::to_string(&snap) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!(error = %e, "TeamRegistry snapshot serialization failed");
                return;
            }
        };
        // Atomic write: temp file + rename, so a crash mid-write
        // never corrupts the previous snapshot.
        let tmp = path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp, json).and_then(|_| std::fs::rename(&tmp, path)) {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "TeamRegistry snapshot write failed"
            );
        }
    }

    pub fn set_tool_operations(&self, ops: HashMap<String, navra_mcp::ToolOperation>) {
        *self
            .tool_operations
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = ops;
    }

    pub fn default_tools_for_operations(&self, operations: &[String]) -> Vec<String> {
        let ops = self
            .tool_operations
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if ops.is_empty() {
            return DEFAULT_TOOLS.iter().map(|s| s.to_string()).collect();
        }
        let wants_write = operations
            .iter()
            .any(|o| matches!(o.as_str(), "write" | "edit" | "delete"));
        let mut tools: Vec<String> = ops
            .iter()
            .filter(|(_, op)| match op {
                navra_mcp::ToolOperation::Read => true,
                navra_mcp::ToolOperation::Write => wants_write,
                navra_mcp::ToolOperation::Deny => false,
            })
            .map(|(name, _)| name.clone())
            .collect();
        for infra in INFRA_TOOLS {
            let s = infra.to_string();
            if !tools.contains(&s) {
                tools.push(s);
            }
        }
        tools.sort();
        tools
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

        // Scope the id guard: persist() re-locks next_id while the
        // teams lock is held, so the two must never be held
        // simultaneously here.
        let team_id = {
            let mut id = self.next_id.lock().unwrap_or_else(|e| e.into_inner());
            *id += 1;
            format!("team-{}", *id)
        };

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

        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        teams.insert(team_id.clone(), team);
        self.persist(&teams);

        Ok(team_id)
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub fn add_teammate(
        &self,
        team_id: &str,
        name: &str,
        persona: Option<&str>,
        model: &str,
        locality: &str,
        operations: Vec<String>,
        tools: Vec<String>,
        temperature: Option<f32>,
        max_tokens: Option<u32>,
        force_tool_iterations: Option<usize>,
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
                temperature,
                max_tokens,
                force_tool_iterations,
                status: "idle".to_string(),
                task: None,
                output: None,
                created_at: Instant::now(),
                container_id: None,
                sandbox_id: None,
                k8s_sandbox: None,
                workspace_path: None,
                last_bb_check: None,
                iterations: None,
                agent_tokens: None,
                signal_handle: None,
            },
        );

        self.total_agents.fetch_add(1, Ordering::Relaxed);
        self.persist(&teams);
        Ok(())
    }

    /// Store a signal handle for a teammate (for cooperative interruption).
    pub fn store_signal_handle(
        &self,
        team_id: &str,
        teammate: &str,
        handle: navra_agent::SignalHandle,
    ) {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(team) = teams.get_mut(team_id)
            && let Some(tm) = team.teammates.get_mut(teammate)
        {
            tm.signal_handle = Some(handle);
        }
    }

    /// Send a signal to a teammate's running agent.
    pub fn send_signal(
        &self,
        team_id: &str,
        teammate: &str,
        signal: navra_agent::AgentSignal,
    ) -> Result<(), String> {
        let teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        let team = teams
            .get(team_id)
            .ok_or_else(|| format!("Unknown team: {team_id}"))?;
        let tm = team
            .teammates
            .get(teammate)
            .ok_or_else(|| format!("Unknown teammate: {teammate}"))?;
        match &tm.signal_handle {
            Some(handle) => {
                handle.send(signal);
                Ok(())
            }
            None => Err(format!(
                "No signal handle for {teammate} (not an in-process agent)"
            )),
        }
    }

    pub fn send_message(&self, team_id: &str, to: &str, message: &str) -> Result<(), String> {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        let team = teams
            .get_mut(team_id)
            .ok_or_else(|| format!("Unknown team: {team_id}"))?;

        // Check timeout
        if team.created_at.elapsed().as_secs() > team.budget.timeout_secs {
            return Err(format!(
                "Team timeout exceeded ({}s)",
                team.budget.timeout_secs
            ));
        }

        let teammate = team
            .teammates
            .get_mut(to)
            .ok_or_else(|| format!("Unknown teammate: {to}"))?;

        teammate.task = Some(message.to_string());
        teammate.status = "working".to_string();
        self.persist(&teams);
        Ok(())
    }

    pub fn bb_publish(
        &self,
        team_id: &str,
        key: &str,
        value: &str,
        author: &str,
        label: navra_core::protocol::label::DataLabel,
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
            self.persist(&teams);
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
        if let Some(team) = teams.get_mut(team_id)
            && let Some(tm) = team.teammates.get_mut(teammate)
        {
            tm.container_id = Some(container_id);
        }
        self.persist(&teams);
    }

    /// Record the adopted Kubernetes Sandbox name for a teammate
    /// spawned via warm-pool claim. Must be set before the adopted
    /// pod's next task poll so the gateway can route its adoption
    /// request to this teammate.
    pub fn set_k8s_sandbox(&self, team_id: &str, teammate: &str, sandbox: String) {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(team) = teams.get_mut(team_id)
            && let Some(tm) = team.teammates.get_mut(teammate)
        {
            tm.k8s_sandbox = Some(sandbox);
        }
        self.persist(&teams);
    }

    /// Resolve `(team_id, teammate_id)` for a teammate spawned in the
    /// given Kubernetes Sandbox (warm-pool adoption lookup).
    pub fn teammate_by_k8s_sandbox(&self, sandbox: &str) -> Option<(String, String)> {
        let teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        for team in teams.values() {
            for (mate_id, tm) in &team.teammates {
                if tm.k8s_sandbox.as_deref() == Some(sandbox) {
                    return Some((team.team_id.clone(), mate_id.clone()));
                }
            }
        }
        None
    }

    /// The adopted Kubernetes Sandbox name for a teammate, if it was
    /// spawned via warm-pool claim.
    pub fn k8s_sandbox_of(&self, team_id: &str, teammate: &str) -> Option<String> {
        let teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        teams
            .get(team_id)?
            .teammates
            .get(teammate)?
            .k8s_sandbox
            .clone()
    }

    /// Capabilities for minting a teammate's delegated token:
    /// `(operations, tools, ttl_secs)` — the ttl is the team's
    /// timeout budget, matching the spawn paths.
    pub fn teammate_caps(
        &self,
        team_id: &str,
        teammate: &str,
    ) -> Option<(Vec<String>, Vec<String>, u64)> {
        let teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        let team = teams.get(team_id)?;
        let tm = team.teammates.get(teammate)?;
        Some((
            tm.operations.clone(),
            tm.tools.clone(),
            team.budget.timeout_secs,
        ))
    }

    pub fn set_output(&self, team_id: &str, teammate: &str, output: String) {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(team) = teams.get_mut(team_id)
            && let Some(tm) = team.teammates.get_mut(teammate)
        {
            tm.output = Some(output);
            tm.status = "done".to_string();
        }
        self.persist(&teams);
    }

    pub fn set_failed(&self, team_id: &str, teammate: &str, error: String) {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(team) = teams.get_mut(team_id)
            && let Some(tm) = team.teammates.get_mut(teammate)
        {
            tm.output = Some(error);
            tm.status = "failed".to_string();
        }
        self.persist(&teams);
    }

    pub fn add_tokens(&self, team_id: &str, tokens: u32) {
        let teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(team) = teams.get(team_id) {
            team.tokens_used.fetch_add(tokens, Ordering::Relaxed);
        }
        self.persist(&teams);
    }

    pub fn set_resolved_model(&self, team_id: &str, teammate: &str, model: &str) {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(team) = teams.get_mut(team_id)
            && let Some(tm) = team.teammates.get_mut(teammate)
        {
            tm.model = model.to_string();
        }
        self.persist(&teams);
    }

    pub fn set_agent_metrics(&self, team_id: &str, teammate: &str, iterations: u32, tokens: u32) {
        let mut teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(team) = teams.get_mut(team_id)
            && let Some(tm) = team.teammates.get_mut(teammate)
        {
            tm.iterations = Some(iterations);
            tm.agent_tokens = Some(tokens);
        }
        self.persist(&teams);
    }

    /// Task spec served to a teammate over the task-delivery endpoint
    /// (`GET /api/agent/task`). Contains everything the spawn paths
    /// would otherwise bake into the Sandbox env: the task itself,
    /// the resolved model, persona, and iteration/temperature
    /// settings. Endpoints are not included — they are deployment
    /// constants the pod already knows (pool-baked env).
    ///
    /// Returns `None` when the team or teammate is unknown, and a
    /// spec with `task: null` when no task has been delivered yet
    /// (the agent should keep polling).
    pub fn task_spec(&self, team_id: &str, teammate: &str) -> Option<serde_json::Value> {
        let teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        let team = teams.get(team_id)?;
        let tm = team.teammates.get(teammate)?;
        Some(serde_json::json!({
            "team_id": team.team_id,
            "teammate": tm.name,
            "task": tm.task,
            "model": tm.model,
            "persona": tm.persona,
            "max_iterations": team.budget.max_iterations,
            "temperature": tm.temperature,
            "max_tokens": tm.max_tokens,
            "status": tm.status,
        }))
    }

    /// Accept a teammate result published over HTTP
    /// (`POST /api/agent/result`). Mirrors the transitions the k8s
    /// log-collector performs: token accounting, agent metrics, and
    /// output storage — preferring blackboard `findings/<teammate>`
    /// over the posted output, exactly like the collector.
    pub fn submit_result(&self, team_id: &str, teammate: &str, result: &serde_json::Value) {
        let tokens_in = result
            .get("tokens_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let tokens_out = result
            .get("tokens_out")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let iterations = result
            .get("iterations")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let total_tokens = tokens_in.saturating_add(tokens_out);

        self.add_tokens(team_id, total_tokens);
        self.set_agent_metrics(team_id, teammate, iterations, total_tokens);

        if result
            .get("error")
            .and_then(|e| e.as_str())
            .is_some_and(|e| !e.is_empty())
        {
            let error = result["error"].as_str().unwrap_or_default().to_string();
            self.set_failed(team_id, teammate, error);
            return;
        }

        // Prefer blackboard findings over the posted output (same
        // rule as the k8s collector).
        let bb_key = format!("findings/{teammate}");
        let final_output = self.bb_read(team_id, &bb_key).map(|e| e.value).or_else(|| {
            result
                .get("output")
                .and_then(|o| o.as_str())
                .map(String::from)
        });
        match final_output {
            Some(output) => self.set_output(team_id, teammate, output),
            None => self.set_failed(
                team_id,
                teammate,
                "Result published without output and no blackboard findings".to_string(),
            ),
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
        teams
            .get(team_id)
            .and_then(|t| t.teammates.get(teammate))
            .map(|tm| tm.status.clone())
    }

    pub fn get_teammate_output(&self, team_id: &str, teammate: &str) -> Option<String> {
        let teams = self.teams.lock().unwrap_or_else(|e| e.into_inner());
        teams
            .get(team_id)
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

        // Send Terminate signal to all in-process agents before aborting
        for (name, tm) in &team.teammates {
            if let Some(ref handle) = tm.signal_handle {
                tracing::info!(team = team_id, teammate = %name, "Sending Terminate signal on shutdown");
                handle.send(navra_agent::AgentSignal::Terminate);
            }
        }

        // Abort all running teammate tasks
        let aborted: Vec<String> = team.task_handles.drain()
            .map(|(name, handle)| {
                tracing::info!(team = team_id, teammate = %name, "Aborting teammate task on shutdown");
                handle.abort();
                name
            })
            .collect();

        // Stop any running containers
        let containers: Vec<String> = team
            .teammates
            .values()
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
        self.persist(&teams);

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
    ToolDefinition::new(
        "team_create",
        "Create a team of agent teammates with a shared blackboard. \
             Returns a team_id. Teammates can communicate via blackboard \
             (team_bb_publish/team_bb_read) and can create subteams \
             for recursive decomposition (bounded by max_depth).",
        tool_input_schema(
            Some(HashMap::from([
                (
                    "name".to_string(),
                    serde_json::json!({"type": "string", "description": "Team name"}),
                ),
                (
                    "description".to_string(),
                    serde_json::json!({"type": "string", "description": "What this team will accomplish"}),
                ),
                (
                    "max_depth".to_string(),
                    serde_json::json!({"type": "integer", "description": "Max subteam nesting depth (default: 2)"}),
                ),
                (
                    "max_agents".to_string(),
                    serde_json::json!({"type": "integer", "description": "Max total agents across team tree (default: 10)"}),
                ),
                (
                    "max_tokens".to_string(),
                    serde_json::json!({"type": "integer", "description": "Max total tokens across team tree (default: 500000)"}),
                ),
                (
                    "timeout_secs".to_string(),
                    serde_json::json!({"type": "integer", "description": "Team timeout in seconds (default: 600)"}),
                ),
                (
                    "max_iterations".to_string(),
                    serde_json::json!({"type": "integer", "description": "Max ReAct iterations per teammate (default: 50)"}),
                ),
            ])),
            Some(vec!["name".to_string()]),
        ),
    )
}

pub fn team_add_def() -> ToolDefinition {
    ToolDefinition::new(
        "team_add",
        "Add a teammate to a team. Teammates are full agents with \
             scoped tool access and can publish findings to the shared \
             blackboard. Specify locality: 'local' for sensitive data \
             (on-device model), 'remote' for complex reasoning (cloud API), \
             'auto' for IFC-based selection.\n\n\
             Use 'operations' and 'tools' to control what the teammate \
             can do. Operations are capability-level permissions (e.g. \
             'read', 'search', 'list', 'write', 'git.commit'). Tools \
             are the specific MCP tools the teammate can call. Both \
             default to a safe read-only set if omitted.",
        tool_input_schema(
            Some(HashMap::from([
                ("team_id".to_string(), serde_json::json!({"type": "string"})),
                (
                    "name".to_string(),
                    serde_json::json!({"type": "string", "description": "Teammate name (unique within team)"}),
                ),
                (
                    "persona".to_string(),
                    serde_json::json!({"type": "string", "description": "Persona name from cognitive core"}),
                ),
                (
                    "model".to_string(),
                    serde_json::json!({"type": "string", "description": "Model name from models_list (e.g. 'granite3.3:8b'). Use fast/small models for file reading tasks, large models only for synthesis. Defaults to 'auto' (smallest available)."}),
                ),
                (
                    "locality".to_string(),
                    serde_json::json!({"type": "string", "enum": ["local", "remote", "auto"], "description": "'local' = data stays on device, 'remote' = cloud API, 'auto' = IFC decides"}),
                ),
                (
                    "operations".to_string(),
                    serde_json::json!({"type": "array", "items": {"type": "string"}, "description": "Allowed operations (default: ['read', 'search', 'list'])"}),
                ),
                (
                    "tools".to_string(),
                    serde_json::json!({"type": "array", "items": {"type": "string"}, "description": "Allowed MCP tools (default: auto-detected from server)"}),
                ),
                (
                    "temperature".to_string(),
                    serde_json::json!({"type": "number", "description": "Model temperature (0.0 = deterministic, 1.0 = creative). Omit to use model default."}),
                ),
                (
                    "max_tokens".to_string(),
                    serde_json::json!({"type": "integer", "description": "Max output tokens per response. Omit for unlimited (recommended for local models)."}),
                ),
                (
                    "force_tool_iterations".to_string(),
                    serde_json::json!({"type": "integer", "description": "Force tool calls for this many initial iterations before allowing text-only response. Default: 1."}),
                ),
            ])),
            Some(vec!["team_id".to_string(), "name".to_string()]),
        ),
    )
}

pub fn team_message_def() -> ToolDefinition {
    ToolDefinition::new(
        "team_message",
        "Send a task to a teammate. The teammate runs asynchronously \
             with full tool access (file_tree, file_grep, file_read) and \
             can publish findings to the team's shared blackboard. \
             Use team_status to check progress, team_result to read output.",
        tool_input_schema(
            Some(HashMap::from([
                ("team_id".to_string(), serde_json::json!({"type": "string"})),
                (
                    "to".to_string(),
                    serde_json::json!({"type": "string", "description": "Teammate name, or '*' for broadcast"}),
                ),
                (
                    "message".to_string(),
                    serde_json::json!({"type": "string", "description": "Task description"}),
                ),
            ])),
            Some(vec![
                "team_id".to_string(),
                "to".to_string(),
                "message".to_string(),
            ]),
        ),
    )
}

pub fn team_status_def() -> ToolDefinition {
    ToolDefinition::new(
        "team_status",
        "Check team status: teammate progress, blackboard keys, \
             token usage, and budget remaining.",
        tool_input_schema(
            Some(HashMap::from([(
                "team_id".to_string(),
                serde_json::json!({"type": "string"}),
            )])),
            Some(vec!["team_id".to_string()]),
        ),
    )
}

pub fn team_result_def() -> ToolDefinition {
    ToolDefinition::new(
        "team_result",
        "Read a teammate's output.",
        tool_input_schema(
            Some(HashMap::from([
                ("team_id".to_string(), serde_json::json!({"type": "string"})),
                (
                    "teammate".to_string(),
                    serde_json::json!({"type": "string"}),
                ),
            ])),
            Some(vec!["team_id".to_string(), "teammate".to_string()]),
        ),
    )
}

pub fn team_bb_publish_def() -> ToolDefinition {
    ToolDefinition::new(
        "team_bb_publish",
        "Publish a finding or data to the team's shared blackboard. \
             Other teammates can read it via team_bb_read. The lead can \
             read all entries via team_status (shows keys) and team_bb_read.",
        tool_input_schema(
            Some(HashMap::from([
                ("team_id".to_string(), serde_json::json!({"type": "string"})),
                (
                    "key".to_string(),
                    serde_json::json!({"type": "string", "description": "Entry key (e.g., 'auth-findings', 'unwrap-count')"}),
                ),
                (
                    "value".to_string(),
                    serde_json::json!({"type": "string", "description": "Entry value (findings, data, etc.)"}),
                ),
            ])),
            Some(vec![
                "team_id".to_string(),
                "key".to_string(),
                "value".to_string(),
            ]),
        ),
    )
}

pub fn team_bb_read_def() -> ToolDefinition {
    ToolDefinition::new(
        "team_bb_read",
        "Read an entry from the team's shared blackboard.",
        tool_input_schema(
            Some(HashMap::from([
                ("team_id".to_string(), serde_json::json!({"type": "string"})),
                (
                    "key".to_string(),
                    serde_json::json!({"type": "string", "description": "Entry key to read"}),
                ),
            ])),
            Some(vec!["team_id".to_string(), "key".to_string()]),
        ),
    )
}

pub fn team_bb_notifications_def() -> ToolDefinition {
    ToolDefinition::new(
        "team_bb_notifications",
        "Check for new blackboard entries published by other teammates \
             since your last check. Returns key, author, and timestamp for \
             each new entry (not the content). Call team_bb_read on \
             interesting keys to retrieve the full value.",
        tool_input_schema(
            Some(HashMap::from([(
                "team_id".to_string(),
                serde_json::json!({"type": "string"}),
            )])),
            Some(vec!["team_id".to_string()]),
        ),
    )
}

pub fn team_shutdown_def() -> ToolDefinition {
    ToolDefinition::new(
        "team_shutdown",
        "Shut down a team. Shows final stats (tokens used, findings count). \
             You MUST call this before producing your final response.",
        tool_input_schema(
            Some(HashMap::from([(
                "team_id".to_string(),
                serde_json::json!({"type": "string"}),
            )])),
            Some(vec!["team_id".to_string()]),
        ),
    )
}

pub fn agent_signal_def() -> ToolDefinition {
    ToolDefinition::new(
        "agent_signal",
        "Send a cooperative signal to a running teammate agent. \
             Signals: 'interrupt' (cancel and return partial result), \
             'terminate' (graceful shutdown after current iteration), \
             'pause' (stop until resumed), 'resume' (continue after pause). \
             Only works for in-process agents.",
        tool_input_schema(
            Some(HashMap::from([
                ("team_id".to_string(), serde_json::json!({"type": "string"})),
                (
                    "agent_id".to_string(),
                    serde_json::json!({"type": "string", "description": "Name of the teammate to signal"}),
                ),
                (
                    "signal".to_string(),
                    serde_json::json!({
                        "type": "string",
                        "enum": ["interrupt", "terminate", "pause", "resume"],
                        "description": "Signal to send"
                    }),
                ),
            ])),
            Some(vec![
                "team_id".to_string(),
                "agent_id".to_string(),
                "signal".to_string(),
            ]),
        ),
    )
}

/// Handle agent_signal tool call.
pub async fn handle_agent_signal(
    args: serde_json::Value,
    registry: std::sync::Arc<TeamRegistry>,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return CallToolResult::error_msg("Missing team_id"),
    };
    let agent_id = match args.get("agent_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return CallToolResult::error_msg("Missing agent_id"),
    };
    let signal_str = match args.get("signal").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return CallToolResult::error_msg("Missing signal"),
    };

    let signal = match signal_str {
        "interrupt" => navra_agent::AgentSignal::Interrupt,
        "terminate" => navra_agent::AgentSignal::Terminate,
        "pause" => navra_agent::AgentSignal::Pause,
        "resume" => navra_agent::AgentSignal::Resume,
        other => return CallToolResult::error_msg(format!("Unknown signal: {other}")),
    };

    match registry.send_signal(team_id, agent_id, signal) {
        Ok(()) => {
            tracing::info!(
                team = team_id,
                agent = agent_id,
                signal = signal_str,
                "Signal delivered to agent"
            );
            CallToolResult::success(vec![navra_core::protocol::Content::text(format!(
                "Signal '{signal_str}' delivered to {agent_id}"
            ))])
        }
        Err(e) => CallToolResult::error_msg(e),
    }
}

pub fn models_list_def() -> ToolDefinition {
    ToolDefinition::new(
        "models_list",
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
             - Check runtime.by_task if available — real data beats operator assumptions",
        tool_input_schema(None, None),
    )
}

pub fn personas_list_def() -> ToolDefinition {
    ToolDefinition::new(
        "personas_list",
        "List available specialist personas from the cognitive core. \
             Each persona has a name, display name, core mandate, and \
             heuristic modules. Use persona names in the `persona` field \
             of team_add to assign specialist behavior to teammates.",
        tool_input_schema(None, None),
    )
}

// --- Handler functions ---

/// Handle team_create tool call.
pub async fn handle_team_create(
    args: serde_json::Value,
    reg: std::sync::Arc<TeamRegistry>,
    budget_cfg: &crate::config::BudgetConfig,
    agent_name: &str,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    let name = args
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unnamed");
    let desc = args.get("description").and_then(|v| v.as_str());
    let budget = TeamBudget {
        max_depth: args
            .get("max_depth")
            .and_then(|v| v.as_u64())
            .unwrap_or(budget_cfg.max_depth as u64) as u32,
        max_agents: args
            .get("max_agents")
            .and_then(|v| v.as_u64())
            .unwrap_or(budget_cfg.max_agents as u64) as u32,
        max_tokens: args
            .get("max_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(500_000),
        timeout_secs: args
            .get("timeout_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(budget_cfg.timeout_secs),
        max_iterations: args
            .get("max_iterations")
            .and_then(|v| v.as_u64())
            .unwrap_or(budget_cfg.max_iterations as u64) as usize,
    };
    match reg.create_team(name, desc, agent_name, 0, budget) {
        Ok(team_id) => {
            tracing::info!(team_id = %team_id, name = name, lead = %agent_name, "Team created");
            CallToolResult::text(format!("Team created.\nteam_id: {team_id}\nname: {name}"))
        }
        Err(e) => CallToolResult::error_msg(e),
    }
}

/// Handle team_add tool call.
pub async fn handle_team_add(
    args: serde_json::Value,
    reg: std::sync::Arc<TeamRegistry>,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return CallToolResult::error_msg("Missing team_id"),
    };
    let name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return CallToolResult::error_msg("Missing name"),
    };
    let persona = args.get("persona").and_then(|v| v.as_str());
    let model = args.get("model").and_then(|v| v.as_str()).unwrap_or("auto");
    let locality = args
        .get("locality")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");

    let operations: Vec<String> = args
        .get("operations")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| DEFAULT_OPERATIONS.iter().map(|s| s.to_string()).collect());

    let tools: Vec<String> = args
        .get("tools")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| reg.default_tools_for_operations(&operations));

    let temperature = args
        .get("temperature")
        .and_then(|v| v.as_f64())
        .map(|v| v as f32);
    let max_tokens = args
        .get("max_tokens")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    let force_tool_iterations = args
        .get("force_tool_iterations")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize);

    match reg.add_teammate(
        team_id,
        name,
        persona,
        model,
        locality,
        operations.clone(),
        tools.clone(),
        temperature,
        max_tokens,
        force_tool_iterations,
    ) {
        Ok(()) => {
            tracing::info!(team = team_id, name = name, persona = ?persona, model = model, locality = locality, operations = ?operations, tools = ?tools, "Teammate added");
            CallToolResult::text(format!(
                "Added '{name}' to team (persona: {}, model: {model}, locality: {locality}, operations: {operations:?}, tools: {tools:?})",
                persona.unwrap_or("default"),
            ))
        }
        Err(e) => CallToolResult::error_msg(e),
    }
}

/// Handle team_status tool call.
pub async fn handle_team_status(
    args: serde_json::Value,
    reg: std::sync::Arc<TeamRegistry>,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return CallToolResult::error_msg("Missing team_id"),
    };
    match reg.get_status(team_id) {
        Some(status) => {
            CallToolResult::text(serde_json::to_string_pretty(&status).unwrap_or_default())
        }
        None => CallToolResult::error_msg(format!("Unknown team: {team_id}")),
    }
}

/// Handle team_result tool call.
pub async fn handle_team_result(
    args: serde_json::Value,
    reg: std::sync::Arc<TeamRegistry>,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return CallToolResult::error_msg("Missing team_id"),
    };
    let teammate = match args.get("teammate").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return CallToolResult::error_msg("Missing teammate"),
    };
    match reg.get_result(team_id, teammate) {
        Some(result) => {
            CallToolResult::text(serde_json::to_string_pretty(&result).unwrap_or_default())
        }
        None => CallToolResult::error_msg(format!("No result from '{teammate}'")),
    }
}

/// Handle team_shutdown tool call.
pub async fn handle_team_shutdown(
    args: serde_json::Value,
    reg: std::sync::Arc<TeamRegistry>,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return CallToolResult::error_msg("Missing team_id"),
    };
    match reg.shutdown(team_id) {
        Ok(info) => {
            tracing::info!(team = team_id, "Team shut down");
            CallToolResult::text(serde_json::to_string_pretty(&info).unwrap_or_default())
        }
        Err(e) => CallToolResult::error_msg(e),
    }
}

/// Handle team_bb_publish tool call.
pub async fn handle_team_bb_publish(
    args: serde_json::Value,
    reg: std::sync::Arc<TeamRegistry>,
    agent_name: &str,
    label: navra_core::protocol::label::DataLabel,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return CallToolResult::error_msg("Missing team_id"),
    };
    let key = match args.get("key").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => return CallToolResult::error_msg("Missing key"),
    };
    let value = match args.get("value").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return CallToolResult::error_msg("Missing value"),
    };
    reg.bb_publish(team_id, key, value, agent_name, label);
    CallToolResult::text(format!("Published '{key}' to team blackboard"))
}

/// Handle team_bb_read tool call.
pub async fn handle_team_bb_read(
    args: serde_json::Value,
    reg: std::sync::Arc<TeamRegistry>,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return CallToolResult::error_msg("Missing team_id"),
    };
    let key = match args.get("key").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => return CallToolResult::error_msg("Missing key"),
    };
    match reg.bb_read(team_id, key) {
        Some(entry) => {
            CallToolResult::text(serde_json::to_string_pretty(&entry).unwrap_or_default())
        }
        None => CallToolResult::error_msg(format!("No blackboard entry: {key}")),
    }
}

/// Handle team_bb_notifications tool call.
pub async fn handle_team_bb_notifications(
    args: serde_json::Value,
    reg: std::sync::Arc<TeamRegistry>,
    agent_name: &str,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;

    let team_id = match args.get("team_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return CallToolResult::error_msg("Missing team_id"),
    };
    match reg.bb_notifications(team_id, agent_name) {
        Ok(notifications) => {
            if notifications.is_empty() {
                CallToolResult::text("No new blackboard entries since last check.")
            } else {
                CallToolResult::text(
                    serde_json::to_string_pretty(&notifications).unwrap_or_default(),
                )
            }
        }
        Err(e) => CallToolResult::error_msg(e),
    }
}

/// Handle models_list tool call.
pub async fn handle_models_list(cards: Vec<ModelCard>) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;
    let enriched: Vec<serde_json::Value> = cards
        .iter()
        .filter(|c| {
            c.agentic.has_metadata()
                || c.vendor
                    .tasks
                    .iter()
                    .any(|t| t == "chat" || t == "text-generation")
        })
        .map(|c| {
            let mut v = serde_json::to_value(c).unwrap_or_default();
            if let Some(obj) = v.as_object_mut() {
                obj.insert(
                    "name".to_string(),
                    serde_json::Value::String(c.inference_name().to_string()),
                );
            }
            v
        })
        .collect();
    CallToolResult::text(serde_json::to_string_pretty(&enriched).unwrap_or_default())
}

/// Handle personas_list tool call.
pub async fn handle_personas_list(
    data: Vec<serde_json::Value>,
) -> navra_core::protocol::CallToolResult {
    use navra_core::protocol::CallToolResult;
    CallToolResult::text(serde_json::to_string_pretty(&data).unwrap_or_default())
}

// Re-export items moved to sibling modules so `crate::team_tools::X` paths keep working.
pub use crate::agent_spawn::{TeammateSpawnContext, is_podman_available, spawn_teammate_agent};
pub use crate::model_selection::handle_team_message;

#[cfg(test)]
mod persistence_tests {
    use super::*;

    fn reg_with_persistence(dir: &tempfile::TempDir) -> TeamRegistry {
        TeamRegistry::load_or_new(&dir.path().join("teams.json"))
    }

    #[test]
    fn snapshot_roundtrip_preserves_state() {
        let dir = tempfile::tempdir().unwrap();
        let reg = reg_with_persistence(&dir);

        let team = reg
            .create_team("e2e", Some("desc"), "lead", 0, TeamBudget::default())
            .unwrap();
        reg.add_teammate(
            &team,
            "worker",
            Some("analyst"),
            "granite3.3:8b",
            "local",
            vec!["read".to_string()],
            vec![],
            Some(0.2),
            None,
            None,
        )
        .unwrap();
        reg.send_message(&team, "worker", "do the thing").unwrap();
        reg.bb_publish(
            &team,
            "findings/worker",
            "found 3 issues",
            "worker",
            navra_core::protocol::label::DataLabel::TRUSTED_PUBLIC,
        );
        reg.set_k8s_sandbox(&team, "worker", "navra-agents-abc12".to_string());
        reg.set_output(&team, "worker", "final report".to_string());
        reg.add_tokens(&team, 4242);

        // "Restart": load a fresh registry from the same path.
        let restored = reg_with_persistence(&dir);

        // Team, teammate, task, output survive.
        let result = restored.get_result(&team, "worker").unwrap();
        assert_eq!(result["status"], "done");
        assert_eq!(result["output"], "final report");

        // Blackboard survives (with values).
        let entry = restored.bb_read(&team, "findings/worker").unwrap();
        assert_eq!(entry.value, "found 3 issues");

        // The sandbox → teammate mapping survives: a post-restart
        // POST /api/agent/result still routes.
        assert_eq!(
            restored.teammate_by_k8s_sandbox("navra-agents-abc12"),
            Some((team.clone(), "worker".to_string()))
        );

        // Token accounting survives.
        let status = restored.get_status(&team).unwrap();
        assert_eq!(status["tokens_used"], 4242);

        // Task survives (redelivery after restart).
        let spec = restored.task_spec(&team, "worker").unwrap();
        assert_eq!(spec["task"], "do the thing");

        // Team ids continue without collision after restore.
        let team2 = restored
            .create_team("next", None, "lead", 0, TeamBudget::default())
            .unwrap();
        assert_ne!(team, team2);
        // And the restored agent budget accounts for the prior teammate.
        assert_eq!(
            restored.get_status(&team).unwrap()["members"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn shutdown_persists_team_removal() {
        let dir = tempfile::tempdir().unwrap();
        let reg = reg_with_persistence(&dir);
        let team = reg
            .create_team("t", None, "lead", 0, TeamBudget::default())
            .unwrap();
        reg.shutdown(&team).unwrap();

        let restored = reg_with_persistence(&dir);
        assert!(restored.get_status(&team).is_none());
    }

    #[test]
    fn missing_snapshot_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let reg = reg_with_persistence(&dir);
        assert!(reg.get_status("team-1").is_none());
    }

    #[test]
    fn corrupt_snapshot_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("teams.json");
        std::fs::write(&path, "not json").unwrap();
        let reg = TeamRegistry::load_or_new(&path);
        assert!(reg.get_status("team-1").is_none());
    }

    #[test]
    fn persistence_off_is_noop() {
        // Default registries (tests, workers) never touch the disk.
        let reg = TeamRegistry::default();
        let team = reg
            .create_team("t", None, "lead", 0, TeamBudget::default())
            .unwrap();
        reg.add_teammate(
            &team,
            "w",
            None,
            "m",
            "local",
            vec![],
            vec![],
            None,
            None,
            None,
        )
        .unwrap();
        reg.set_output(&team, "w", "out".to_string());
        assert_eq!(reg.get_teammate_output(&team, "w").as_deref(), Some("out"));
    }

    #[test]
    fn restored_notification_cursor_resets_safely() {
        // After restore, last_bb_check is None → bb_notifications
        // returns all entries (a safe superset, never a gap).
        let dir = tempfile::tempdir().unwrap();
        let reg = reg_with_persistence(&dir);
        let team = reg
            .create_team("t", None, "lead", 0, TeamBudget::default())
            .unwrap();
        reg.add_teammate(
            &team,
            "w",
            None,
            "m",
            "local",
            vec![],
            vec![],
            None,
            None,
            None,
        )
        .unwrap();
        reg.bb_publish(
            &team,
            "note",
            "hello",
            "lead",
            navra_core::protocol::label::DataLabel::TRUSTED_PUBLIC,
        );

        let restored = reg_with_persistence(&dir);
        let notes = restored.bb_notifications(&team, "w").unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].key, "note");
    }
}
