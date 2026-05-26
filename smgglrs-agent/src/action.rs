//! Typed agent action model for classification, risk assessment, and audit.

use serde_json::Value;

/// Typed agent action — classifies what a tool call does.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentAction {
    /// Read a file.
    FileRead {
        /// Path to the file.
        path: String,
    },
    /// Write a file.
    FileWrite {
        /// Path to the file.
        path: String,
    },
    /// Edit a file.
    FileEdit {
        /// Path to the file.
        path: String,
    },
    /// Delete a file.
    FileDelete {
        /// Path to the file.
        path: String,
    },
    /// Search files.
    FileSearch {
        /// Search query.
        query: String,
    },
    /// Check git status.
    GitStatus {
        /// Repository path.
        repo: String,
    },
    /// View git diff.
    GitDiff {
        /// Repository path.
        repo: String,
    },
    /// Create a git commit.
    GitCommit {
        /// Repository path.
        repo: String,
        /// Commit message.
        message: String,
    },
    /// Search via RAG.
    RagSearch {
        /// Search query.
        query: String,
    },
    /// Store to memory.
    MemoryStore {
        /// Memory kind.
        kind: String,
    },
    /// Query memory.
    MemoryQuery {
        /// Search query.
        query: String,
    },
    /// Create a team.
    TeamCreate {
        /// Team name.
        name: String,
    },
    /// Send a team message.
    TeamMessage {
        /// Team identifier.
        team: String,
        /// Target agent.
        target: String,
    },
    /// Start a flow.
    FlowStart {
        /// Flow name.
        flow: String,
    },
    /// Call an MCP tool not matching any known pattern.
    McpToolCall {
        /// Tool name.
        tool: String,
    },
    /// Unrecognised tool.
    Unknown {
        /// Tool name.
        tool: String,
    },
}

/// Risk level of an agent action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// No risk (read-only observation).
    None,
    /// Low risk (search, query).
    Low,
    /// Medium risk (file write, edit).
    Medium,
    /// High risk (delete, commit).
    High,
    /// Critical risk (flow start, team creation).
    Critical,
}

/// Record of a completed agent action.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ActionRecord {
    /// Classified action.
    pub action: AgentAction,
    /// Whether the tool call succeeded.
    pub success: bool,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Truncated preview of tool output.
    pub output_preview: String,
}

fn str_field(args: &Value, key: &str) -> String {
    args.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

impl AgentAction {
    /// Classify a tool call by name and arguments.
    pub fn classify(tool_name: &str, args: &Value) -> Self {
        match tool_name {
            "file_read" => Self::FileRead {
                path: str_field(args, "path"),
            },
            "file_write" => Self::FileWrite {
                path: str_field(args, "path"),
            },
            "file_edit" => Self::FileEdit {
                path: str_field(args, "path"),
            },
            "file_delete" => Self::FileDelete {
                path: str_field(args, "path"),
            },
            "file_search" | "file_find" => Self::FileSearch {
                query: str_field(args, "query"),
            },
            "git_status" => Self::GitStatus {
                repo: str_field(args, "repo"),
            },
            "git_diff" => Self::GitDiff {
                repo: str_field(args, "repo"),
            },
            "git_commit" => Self::GitCommit {
                repo: str_field(args, "repo"),
                message: str_field(args, "message"),
            },
            "rag_search" | "rag_query" => Self::RagSearch {
                query: str_field(args, "query"),
            },
            "memory_store" => Self::MemoryStore {
                kind: str_field(args, "kind"),
            },
            "memory_query" | "memory_search" => Self::MemoryQuery {
                query: str_field(args, "query"),
            },
            "team_create" => Self::TeamCreate {
                name: str_field(args, "name"),
            },
            "team_message" | "team_send" => Self::TeamMessage {
                team: str_field(args, "team"),
                target: str_field(args, "target"),
            },
            "flow_start" | "flow_run" => Self::FlowStart {
                flow: str_field(args, "flow"),
            },
            _ if tool_name.starts_with("file_")
                || tool_name.starts_with("git_")
                || tool_name.starts_with("rag_")
                || tool_name.starts_with("memory_")
                || tool_name.starts_with("team_")
                || tool_name.starts_with("flow_") =>
            {
                Self::McpToolCall {
                    tool: tool_name.to_string(),
                }
            }
            _ => Self::Unknown {
                tool: tool_name.to_string(),
            },
        }
    }

    /// Whether this action is read-only (no side effects).
    pub fn is_read_only(&self) -> bool {
        matches!(
            self,
            Self::FileRead { .. }
                | Self::FileSearch { .. }
                | Self::GitStatus { .. }
                | Self::GitDiff { .. }
                | Self::RagSearch { .. }
                | Self::MemoryQuery { .. }
        )
    }

    /// Risk level of this action.
    pub fn risk_level(&self) -> RiskLevel {
        match self {
            Self::FileRead { .. } | Self::GitStatus { .. } | Self::GitDiff { .. } => {
                RiskLevel::None
            }
            Self::FileSearch { .. } | Self::RagSearch { .. } | Self::MemoryQuery { .. } => {
                RiskLevel::Low
            }
            Self::FileWrite { .. } | Self::FileEdit { .. } | Self::MemoryStore { .. } => {
                RiskLevel::Medium
            }
            Self::FileDelete { .. } | Self::GitCommit { .. } => RiskLevel::High,
            Self::TeamCreate { .. } | Self::TeamMessage { .. } | Self::FlowStart { .. } => {
                RiskLevel::Critical
            }
            Self::McpToolCall { .. } | Self::Unknown { .. } => RiskLevel::Medium,
        }
    }

    /// Human-readable summary of this action.
    pub fn user_friendly_name(&self) -> String {
        match self {
            Self::FileRead { path } => format!("Read file: {path}"),
            Self::FileWrite { path } => format!("Write file: {path}"),
            Self::FileEdit { path } => format!("Edit file: {path}"),
            Self::FileDelete { path } => format!("Delete file: {path}"),
            Self::FileSearch { query } => format!("Search files: {query}"),
            Self::GitStatus { repo } => format!("Git status: {repo}"),
            Self::GitDiff { repo } => format!("Git diff: {repo}"),
            Self::GitCommit { repo, message } => format!("Git commit in {repo}: {message}"),
            Self::RagSearch { query } => format!("RAG search: {query}"),
            Self::MemoryStore { kind } => format!("Store memory: {kind}"),
            Self::MemoryQuery { query } => format!("Query memory: {query}"),
            Self::TeamCreate { name } => format!("Create team: {name}"),
            Self::TeamMessage { team, target } => format!("Message {target} in {team}"),
            Self::FlowStart { flow } => format!("Start flow: {flow}"),
            Self::McpToolCall { tool } => format!("MCP tool: {tool}"),
            Self::Unknown { tool } => format!("Unknown tool: {tool}"),
        }
    }
    /// Extract the tool name and arguments for recipe compilation.
    ///
    /// Returns `(tool_name, arguments_json)` for actions that map to
    /// a single tool call. Returns `None` for actions that don't have
    /// a direct tool call mapping.
    pub fn tool_call_parts(&self) -> Option<(String, serde_json::Value)> {
        match self {
            Self::FileRead { path } => Some(("file_read".into(), serde_json::json!({"path": path}))),
            Self::FileWrite { path } => Some(("file_write".into(), serde_json::json!({"path": path}))),
            Self::FileEdit { path } => Some(("file_edit".into(), serde_json::json!({"path": path}))),
            Self::FileDelete { path } => Some(("file_delete".into(), serde_json::json!({"path": path}))),
            Self::FileSearch { query } => Some(("file_search".into(), serde_json::json!({"query": query}))),
            Self::GitStatus { repo } => Some(("git_status".into(), serde_json::json!({"repo": repo}))),
            Self::GitDiff { repo } => Some(("git_diff".into(), serde_json::json!({"repo": repo}))),
            Self::GitCommit { repo, message } => Some(("git_commit".into(), serde_json::json!({"repo": repo, "message": message}))),
            Self::RagSearch { query } => Some(("rag_search".into(), serde_json::json!({"query": query}))),
            Self::MemoryStore { kind } => Some(("memory_store".into(), serde_json::json!({"kind": kind}))),
            Self::MemoryQuery { query } => Some(("memory_query".into(), serde_json::json!({"query": query}))),
            Self::McpToolCall { tool } => Some((tool.clone(), serde_json::json!({}))),
            Self::Unknown { tool } => Some((tool.clone(), serde_json::json!({}))),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classify_file_read() {
        let action = AgentAction::classify("file_read", &json!({"path": "/tmp/foo.rs"}));
        assert!(matches!(action, AgentAction::FileRead { ref path } if path == "/tmp/foo.rs"));
        assert!(action.is_read_only());
        assert_eq!(action.risk_level(), RiskLevel::None);
    }

    #[test]
    fn classify_file_write() {
        let action = AgentAction::classify("file_write", &json!({"path": "/tmp/bar.rs"}));
        assert!(matches!(action, AgentAction::FileWrite { .. }));
        assert!(!action.is_read_only());
        assert_eq!(action.risk_level(), RiskLevel::Medium);
    }

    #[test]
    fn classify_file_delete() {
        let action = AgentAction::classify("file_delete", &json!({"path": "/tmp/x"}));
        assert!(matches!(action, AgentAction::FileDelete { .. }));
        assert_eq!(action.risk_level(), RiskLevel::High);
    }

    #[test]
    fn classify_git_commit() {
        let action =
            AgentAction::classify("git_commit", &json!({"repo": "/repo", "message": "fix"}));
        assert!(
            matches!(action, AgentAction::GitCommit { ref repo, ref message }
            if repo == "/repo" && message == "fix")
        );
        assert!(!action.is_read_only());
        assert_eq!(action.risk_level(), RiskLevel::High);
    }

    #[test]
    fn classify_git_status() {
        let action = AgentAction::classify("git_status", &json!({"repo": "."}));
        assert!(action.is_read_only());
        assert_eq!(action.risk_level(), RiskLevel::None);
    }

    #[test]
    fn classify_rag_search() {
        let action = AgentAction::classify("rag_search", &json!({"query": "auth"}));
        assert!(action.is_read_only());
        assert_eq!(action.risk_level(), RiskLevel::Low);
    }

    #[test]
    fn classify_team_create() {
        let action = AgentAction::classify("team_create", &json!({"name": "reviewers"}));
        assert_eq!(action.risk_level(), RiskLevel::Critical);
    }

    #[test]
    fn classify_flow_start() {
        let action = AgentAction::classify("flow_start", &json!({"flow": "deploy"}));
        assert_eq!(action.risk_level(), RiskLevel::Critical);
    }

    #[test]
    fn classify_unknown_tool() {
        let action = AgentAction::classify("custom_thing", &json!({}));
        assert!(matches!(action, AgentAction::Unknown { ref tool } if tool == "custom_thing"));
        assert_eq!(action.risk_level(), RiskLevel::Medium);
    }

    #[test]
    fn classify_known_prefix_unknown_suffix() {
        let action = AgentAction::classify("git_log", &json!({}));
        assert!(matches!(action, AgentAction::McpToolCall { ref tool } if tool == "git_log"));
    }

    #[test]
    fn user_friendly_names() {
        let action = AgentAction::classify("file_read", &json!({"path": "/etc/hosts"}));
        assert_eq!(action.user_friendly_name(), "Read file: /etc/hosts");

        let action = AgentAction::classify("git_commit", &json!({"repo": ".", "message": "init"}));
        assert_eq!(action.user_friendly_name(), "Git commit in .: init");
    }

    #[test]
    fn missing_args_default_to_empty() {
        let action = AgentAction::classify("file_read", &json!({}));
        assert!(matches!(action, AgentAction::FileRead { ref path } if path.is_empty()));
    }
}
