use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Agents,
    Audit,
    Models,
    Flows,
    Safety,
}

impl Tab {
    pub const ALL: [Tab; 6] = [
        Tab::Dashboard,
        Tab::Agents,
        Tab::Audit,
        Tab::Models,
        Tab::Flows,
        Tab::Safety,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Agents => "Agents",
            Tab::Audit => "Audit",
            Tab::Models => "Models",
            Tab::Flows => "Flows",
            Tab::Safety => "Safety",
        }
    }

    pub fn index(self) -> usize {
        Tab::ALL.iter().position(|&t| t == self).unwrap_or(0)
    }

    pub fn next(self) -> Tab {
        let i = (self.index() + 1) % Tab::ALL.len();
        Tab::ALL[i]
    }

    pub fn prev(self) -> Tab {
        let i = (self.index() + Tab::ALL.len() - 1) % Tab::ALL.len();
        Tab::ALL[i]
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ServerStatus {
    pub name: String,
    pub version: String,
    pub status: String,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub personas: Vec<String>,
    #[serde(default)]
    pub crates: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProcessSnapshot {
    pub name: String,
    pub permissions: String,
    pub did: Option<String>,
    pub ring: Option<u8>,
    #[serde(default)]
    pub call_count: u64,
    #[serde(default)]
    pub denied_count: u64,
    #[serde(default)]
    pub uptime_secs: u64,
    #[serde(default)]
    pub idle_secs: u64,
    #[serde(default)]
    pub active_calls: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SysStatus {
    #[serde(default)]
    pub agents: Vec<ProcessSnapshot>,
    #[serde(default)]
    pub session_count: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ModelInfo {
    pub name: String,
    #[serde(default)]
    pub task: String,
    #[serde(default)]
    pub backend: String,
    pub source: Option<String>,
    pub runtime: Option<String>,
    pub context_size: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct BlackboxEntry {
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub timestamp_ms: u64,
    #[serde(default)]
    pub agent_name: String,
    #[serde(default)]
    pub agent_permissions: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub tool_args: String,
    #[serde(default)]
    pub tool_result: String,
    #[serde(default)]
    pub outcome: String,
    #[serde(default)]
    pub duration_us: u64,
    #[serde(default)]
    pub ifc_label: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuditResponse {
    #[serde(default)]
    pub entries: Vec<BlackboxEntry>,
    #[serde(default)]
    pub total: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FlowInfo {
    pub name: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub tasks: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FlowRunSummary {
    #[serde(default)]
    pub flow_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub elapsed_secs: f64,
    #[serde(default)]
    pub node_count: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SafetyMetrics {
    #[serde(default)]
    pub total_scans: u64,
    #[serde(default)]
    pub pii_detected: u64,
    #[serde(default)]
    pub pii_redacted: u64,
    #[serde(default)]
    pub pii_blocked: u64,
    #[serde(default)]
    pub by_category: std::collections::HashMap<String, u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    Filter,
}

pub struct AppState {
    pub tab: Tab,
    pub input_mode: InputMode,
    pub filter_text: String,
    pub connected: bool,
    pub last_error: Option<String>,

    pub server_status: Option<ServerStatus>,
    pub sys_status: Option<SysStatus>,
    pub models: Vec<ModelInfo>,
    pub audit: AuditResponse,
    pub flows: Vec<FlowInfo>,
    pub flow_runs: Vec<FlowRunSummary>,
    pub safety: Option<SafetyMetrics>,

    pub table_offset: usize,
    pub selected_row: usize,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            tab: Tab::Dashboard,
            input_mode: InputMode::Normal,
            filter_text: String::new(),
            connected: false,
            last_error: None,
            server_status: None,
            sys_status: None,
            models: Vec::new(),
            audit: AuditResponse::default(),
            flows: Vec::new(),
            flow_runs: Vec::new(),
            safety: None,
            table_offset: 0,
            selected_row: 0,
        }
    }
}

impl AppState {
    pub fn reset_selection(&mut self) {
        self.table_offset = 0;
        self.selected_row = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_cycling() {
        let t = Tab::Dashboard;
        assert_eq!(t.next(), Tab::Agents);
        assert_eq!(Tab::Safety.next(), Tab::Dashboard);
        assert_eq!(Tab::Dashboard.prev(), Tab::Safety);
    }

    #[test]
    fn tab_index_roundtrip() {
        for tab in Tab::ALL {
            assert_eq!(Tab::ALL[tab.index()], tab);
        }
    }
}
