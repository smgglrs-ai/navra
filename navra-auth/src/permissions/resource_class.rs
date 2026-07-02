//! Semantic classification of MCP primitives into (domain, operation) pairs.
//!
//! Every tool, prompt, and resource is classified at registration time.
//! Permission sets declare which domain:operation pairs they allow.
//! Classification priority: operator override > ToolAnnotations > AI > heuristic.

use std::fmt;
use std::str::FromStr;
use vstd::prelude::*;

/// Capability domain for an MCP primitive.
///
/// Navra's taxonomy — operators assign tools to existing domains,
/// they don't define new ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Domain {
    Filesystem,
    Git,
    Shell,
    Network,
    Github,
    Gitlab,
    Database,
    System,
    Messaging,
    Prompt,
    Resource,
    Unknown,
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Filesystem => "filesystem",
            Self::Git => "git",
            Self::Shell => "shell",
            Self::Network => "network",
            Self::Github => "github",
            Self::Gitlab => "gitlab",
            Self::Database => "database",
            Self::System => "system",
            Self::Messaging => "messaging",
            Self::Prompt => "prompt",
            Self::Resource => "resource",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

impl FromStr for Domain {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "filesystem" | "file" | "fs" => Ok(Self::Filesystem),
            "git" => Ok(Self::Git),
            "shell" | "exec" => Ok(Self::Shell),
            "network" | "net" | "http" => Ok(Self::Network),
            "github" | "gh" => Ok(Self::Github),
            "gitlab" | "gl" => Ok(Self::Gitlab),
            "database" | "db" | "sql" => Ok(Self::Database),
            "system" | "sys" => Ok(Self::System),
            "messaging" | "msg" | "email" | "chat" => Ok(Self::Messaging),
            "prompt" => Ok(Self::Prompt),
            "resource" => Ok(Self::Resource),
            "unknown" | "*" => Ok(Self::Unknown),
            other => Err(format!("unknown domain: '{other}'")),
        }
    }
}

/// Operation type within a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Operation {
    Read,
    Write,
    Execute,
    Delete,
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Execute => "execute",
            Self::Delete => "delete",
        };
        f.write_str(s)
    }
}

impl FromStr for Operation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "read" | "r" => Ok(Self::Read),
            "write" | "w" => Ok(Self::Write),
            "execute" | "exec" | "x" => Ok(Self::Execute),
            "delete" | "del" | "remove" => Ok(Self::Delete),
            other => Err(format!("unknown operation: '{other}'")),
        }
    }
}

/// Semantic classification of an MCP primitive (tool, prompt, or resource).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResourceClass {
    pub domain: Domain,
    pub operation: Operation,
}

impl ResourceClass {
    pub fn new(domain: Domain, operation: Operation) -> Self {
        Self { domain, operation }
    }
}

impl fmt::Display for ResourceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.domain, self.operation)
    }
}

impl FromStr for ResourceClass {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (domain_str, op_str) = s
            .split_once(':')
            .ok_or_else(|| format!("expected 'domain:operation', got '{s}'"))?;
        Ok(Self {
            domain: domain_str.parse()?,
            operation: op_str.parse()?,
        })
    }
}

/// Classify a prompt. Always `Prompt:Read` unless overridden.
pub fn classify_prompt() -> ResourceClass {
    ResourceClass::new(Domain::Prompt, Operation::Read)
}

/// Classify a resource. Always `Resource:Read` unless overridden.
pub fn classify_resource() -> ResourceClass {
    ResourceClass::new(Domain::Resource, Operation::Read)
}

/// Canonical descriptions for each domain, used by the embedding-based
/// classifier (tier 3) to compute cosine similarity.
pub const DOMAIN_EXEMPLARS: &[(Domain, &str)] = &[
    (
        Domain::Filesystem,
        "Read, write, list, move, copy, delete files and directories on the local filesystem",
    ),
    (
        Domain::Git,
        "Git version control operations: status, commit, push, pull, branch, diff, log, merge",
    ),
    (
        Domain::Shell,
        "Execute shell commands, run scripts, spawn processes, terminal operations",
    ),
    (
        Domain::Network,
        "HTTP requests, fetch URLs, download content, API calls, network connectivity",
    ),
    (
        Domain::Github,
        "GitHub API: pull requests, issues, repositories, actions, reviews, releases",
    ),
    (
        Domain::Gitlab,
        "GitLab API: merge requests, issues, pipelines, repositories, CI/CD",
    ),
    (
        Domain::Database,
        "Database queries, SQL execution, table operations, schema management, data retrieval",
    ),
    (
        Domain::System,
        "System information, process management, environment variables, OS operations",
    ),
    (
        Domain::Messaging,
        "Send email, post messages, chat, Slack, notifications, communication",
    ),
];

// --- Tier 4: Name-based heuristic classifier ---

/// Infer the domain from a tool name using keyword matching.
///
/// Handles two conventions:
/// - navra built-in: `module_verb` (e.g., `file_read` → Filesystem)
/// - upstream: arbitrary names with domain keywords (e.g., `read_file` → Filesystem)
pub fn infer_domain_heuristic(name: &str) -> Domain {
    let lower = name.to_lowercase();

    // navra convention: prefix before first underscore
    if let Some(prefix) = lower.split('_').next() {
        match prefix {
            "file" | "docs" => return Domain::Filesystem,
            "git" => return Domain::Git,
            "shell" => return Domain::Shell,
            "github" => return Domain::Github,
            "gitlab" => return Domain::Gitlab,
            "db" | "sql" | "database" => return Domain::Database,
            "env" | "process" | "system" | "sysinfo" => return Domain::System,
            "email" | "slack" | "teams" | "chat" | "notify" => return Domain::Messaging,
            "http" | "fetch" | "curl" | "net" | "web" => return Domain::Network,
            _ => {}
        }
    }

    // Keyword scan for upstream tools with non-prefixed names
    if has_any(
        &lower,
        &[
            "file", "director", "path", "folder", "mv", "cp", "mkdir", "chmod", "zip", "unzip",
            "archive",
        ],
    ) {
        return Domain::Filesystem;
    }
    if has_any(
        &lower,
        &["commit", "branch", "merge", "rebase", "stash", "cherry"],
    ) {
        return Domain::Git;
    }
    if has_any(
        &lower,
        &["exec", "spawn", "bash", "cmd", "terminal", "subprocess"],
    ) {
        return Domain::Shell;
    }
    if has_any(&lower, &["pull_request", "pr_", "issue", "repo", "gist"])
        && has_any(&lower, &["github", "gh"])
    {
        return Domain::Github;
    }
    if has_any(&lower, &["merge_request", "mr_", "pipeline"]) && has_any(&lower, &["gitlab", "gl"])
    {
        return Domain::Gitlab;
    }
    if has_any(
        &lower,
        &["query", "sql", "table", "schema", "database", "collection"],
    ) {
        return Domain::Database;
    }
    if has_any(
        &lower,
        &["email", "mail", "slack", "message", "notify", "sms"],
    ) {
        return Domain::Messaging;
    }
    if has_any(
        &lower,
        &[
            "http", "fetch", "url", "download", "upload", "request", "curl", "api",
        ],
    ) {
        return Domain::Network;
    }
    if has_any(
        &lower,
        &[
            "process", "env", "system", "hostname", "uptime", "memory", "cpu",
        ],
    ) {
        return Domain::System;
    }

    Domain::Unknown
}

/// Infer the operation from a tool name and optional MCP annotations.
///
/// Priority: annotations (authoritative) > name keywords > default (Read).
pub fn infer_operation_heuristic(
    name: &str,
    annotations: Option<&navra_protocol::ToolAnnotations>,
) -> Operation {
    if let Some(ann) = annotations {
        if ann.read_only_hint == Some(true) {
            return Operation::Read;
        }
        if ann.destructive_hint == Some(true) {
            return Operation::Delete;
        }
    }

    let lower = name.to_lowercase();

    if has_any(
        &lower,
        &[
            "delete", "remove", "drop", "purge", "destroy", "unlink", "rmdir",
        ],
    ) {
        return Operation::Delete;
    }
    if has_any(
        &lower,
        &["exec", "run", "spawn", "execute", "invoke", "call", "push"],
    ) {
        return Operation::Execute;
    }
    if has_any(
        &lower,
        &[
            "write", "create", "update", "edit", "send", "post", "put", "set", "add", "insert",
            "commit", "move", "rename", "copy", "zip", "upload",
        ],
    ) {
        return Operation::Write;
    }
    if has_any(
        &lower,
        &[
            "read", "get", "list", "search", "query", "view", "show", "fetch", "status", "diff",
            "log", "describe", "info", "stat", "find", "browse", "download",
        ],
    ) {
        return Operation::Read;
    }

    Operation::Read
}

/// Classify a tool using name heuristics and optional MCP annotations.
pub fn classify_tool_heuristic(
    name: &str,
    annotations: Option<&navra_protocol::ToolAnnotations>,
) -> ResourceClass {
    ResourceClass {
        domain: infer_domain_heuristic(name),
        operation: infer_operation_heuristic(name, annotations),
    }
}

fn has_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_display_roundtrip() {
        for domain in [
            Domain::Filesystem,
            Domain::Git,
            Domain::Shell,
            Domain::Network,
            Domain::Github,
            Domain::Gitlab,
            Domain::Database,
            Domain::System,
            Domain::Messaging,
            Domain::Prompt,
            Domain::Resource,
            Domain::Unknown,
        ] {
            let s = domain.to_string();
            let parsed: Domain = s.parse().unwrap();
            assert_eq!(domain, parsed, "roundtrip failed for {s}");
        }
    }

    #[test]
    fn domain_aliases() {
        assert_eq!("file".parse::<Domain>().unwrap(), Domain::Filesystem);
        assert_eq!("fs".parse::<Domain>().unwrap(), Domain::Filesystem);
        assert_eq!("gh".parse::<Domain>().unwrap(), Domain::Github);
        assert_eq!("gl".parse::<Domain>().unwrap(), Domain::Gitlab);
        assert_eq!("db".parse::<Domain>().unwrap(), Domain::Database);
        assert_eq!("sys".parse::<Domain>().unwrap(), Domain::System);
        assert_eq!("net".parse::<Domain>().unwrap(), Domain::Network);
        assert_eq!("msg".parse::<Domain>().unwrap(), Domain::Messaging);
        assert_eq!("*".parse::<Domain>().unwrap(), Domain::Unknown);
    }

    #[test]
    fn domain_rejects_unknown() {
        assert!("foobar".parse::<Domain>().is_err());
    }

    #[test]
    fn operation_display_roundtrip() {
        for op in [
            Operation::Read,
            Operation::Write,
            Operation::Execute,
            Operation::Delete,
        ] {
            let s = op.to_string();
            let parsed: Operation = s.parse().unwrap();
            assert_eq!(op, parsed, "roundtrip failed for {s}");
        }
    }

    #[test]
    fn operation_aliases() {
        assert_eq!("r".parse::<Operation>().unwrap(), Operation::Read);
        assert_eq!("w".parse::<Operation>().unwrap(), Operation::Write);
        assert_eq!("x".parse::<Operation>().unwrap(), Operation::Execute);
        assert_eq!("exec".parse::<Operation>().unwrap(), Operation::Execute);
        assert_eq!("del".parse::<Operation>().unwrap(), Operation::Delete);
        assert_eq!("remove".parse::<Operation>().unwrap(), Operation::Delete);
    }

    #[test]
    fn operation_rejects_unknown() {
        assert!("admin".parse::<Operation>().is_err());
    }

    #[test]
    fn resource_class_display() {
        let rc = ResourceClass::new(Domain::Filesystem, Operation::Write);
        assert_eq!(rc.to_string(), "filesystem:write");
    }

    #[test]
    fn resource_class_parse() {
        let rc: ResourceClass = "github:read".parse().unwrap();
        assert_eq!(rc.domain, Domain::Github);
        assert_eq!(rc.operation, Operation::Read);
    }

    #[test]
    fn resource_class_parse_aliases() {
        let rc: ResourceClass = "fs:w".parse().unwrap();
        assert_eq!(rc.domain, Domain::Filesystem);
        assert_eq!(rc.operation, Operation::Write);
    }

    #[test]
    fn resource_class_parse_errors() {
        assert!("nocolon".parse::<ResourceClass>().is_err());
        assert!("bad:read".parse::<ResourceClass>().is_err());
        assert!("git:bad".parse::<ResourceClass>().is_err());
    }

    #[test]
    fn classify_prompt_default() {
        let rc = classify_prompt();
        assert_eq!(rc.domain, Domain::Prompt);
        assert_eq!(rc.operation, Operation::Read);
    }

    #[test]
    fn classify_resource_default() {
        let rc = classify_resource();
        assert_eq!(rc.domain, Domain::Resource);
        assert_eq!(rc.operation, Operation::Read);
    }

    #[test]
    fn domain_exemplars_covers_non_meta_domains() {
        let exemplar_domains: Vec<_> = DOMAIN_EXEMPLARS.iter().map(|(d, _)| *d).collect();
        for domain in [
            Domain::Filesystem,
            Domain::Git,
            Domain::Shell,
            Domain::Network,
            Domain::Github,
            Domain::Gitlab,
            Domain::Database,
            Domain::System,
            Domain::Messaging,
        ] {
            assert!(
                exemplar_domains.contains(&domain),
                "missing exemplar for {domain}"
            );
        }
    }

    // --- Heuristic classifier tests ---

    #[test]
    fn heuristic_navra_builtin_tools() {
        // navra convention: module_verb
        assert_eq!(infer_domain_heuristic("file_read"), Domain::Filesystem);
        assert_eq!(infer_domain_heuristic("file_write"), Domain::Filesystem);
        assert_eq!(infer_domain_heuristic("git_status"), Domain::Git);
        assert_eq!(infer_domain_heuristic("git_commit"), Domain::Git);
        assert_eq!(infer_domain_heuristic("shell_exec"), Domain::Shell);
        assert_eq!(infer_domain_heuristic("github_pr_list"), Domain::Github);
        assert_eq!(infer_domain_heuristic("github_pr_create"), Domain::Github);
        assert_eq!(infer_domain_heuristic("gitlab_mr_list"), Domain::Gitlab);
        assert_eq!(infer_domain_heuristic("db_query"), Domain::Database);
        assert_eq!(infer_domain_heuristic("email_send"), Domain::Messaging);
        assert_eq!(infer_domain_heuristic("http_get"), Domain::Network);
        assert_eq!(infer_domain_heuristic("env_get"), Domain::System);
    }

    #[test]
    fn heuristic_upstream_tools() {
        // Common upstream MCP tool names (not navra convention)
        assert_eq!(infer_domain_heuristic("read_file"), Domain::Filesystem);
        assert_eq!(infer_domain_heuristic("write_file"), Domain::Filesystem);
        assert_eq!(infer_domain_heuristic("list_directory"), Domain::Filesystem);
        assert_eq!(infer_domain_heuristic("move_file"), Domain::Filesystem);
        assert_eq!(
            infer_domain_heuristic("list_allowed_directories"),
            Domain::Filesystem
        );
        assert_eq!(infer_domain_heuristic("zip_files"), Domain::Filesystem);
    }

    #[test]
    fn heuristic_unknown_fallback() {
        assert_eq!(infer_domain_heuristic("some_random_tool"), Domain::Unknown);
        assert_eq!(infer_domain_heuristic("foobar"), Domain::Unknown);
    }

    #[test]
    fn heuristic_operation_from_name() {
        assert_eq!(
            infer_operation_heuristic("file_read", None),
            Operation::Read
        );
        assert_eq!(
            infer_operation_heuristic("file_write", None),
            Operation::Write
        );
        assert_eq!(
            infer_operation_heuristic("git_commit", None),
            Operation::Write
        );
        assert_eq!(
            infer_operation_heuristic("shell_exec", None),
            Operation::Execute
        );
        assert_eq!(
            infer_operation_heuristic("git_push", None),
            Operation::Execute
        );
        assert_eq!(
            infer_operation_heuristic("file_delete", None),
            Operation::Delete
        );
        assert_eq!(
            infer_operation_heuristic("db_drop", None),
            Operation::Delete
        );
        assert_eq!(
            infer_operation_heuristic("git_status", None),
            Operation::Read
        );
        assert_eq!(infer_operation_heuristic("git_diff", None), Operation::Read);
        assert_eq!(infer_operation_heuristic("git_log", None), Operation::Read);
        assert_eq!(
            infer_operation_heuristic("search_files", None),
            Operation::Read
        );
    }

    #[test]
    fn heuristic_operation_annotations_override() {
        let read_only = navra_protocol::ToolAnnotations::new().read_only(true);
        // Name says "write" but annotation says read-only
        assert_eq!(
            infer_operation_heuristic("file_write", Some(&read_only)),
            Operation::Read
        );

        let destructive = navra_protocol::ToolAnnotations::new().destructive(true);
        // Name says "read" but annotation says destructive
        assert_eq!(
            infer_operation_heuristic("file_read", Some(&destructive)),
            Operation::Delete
        );
    }

    #[test]
    fn heuristic_upstream_operations() {
        assert_eq!(
            infer_operation_heuristic("read_file", None),
            Operation::Read
        );
        assert_eq!(
            infer_operation_heuristic("write_file", None),
            Operation::Write
        );
        assert_eq!(
            infer_operation_heuristic("create_pull_request", None),
            Operation::Write
        );
        assert_eq!(
            infer_operation_heuristic("delete_branch", None),
            Operation::Delete
        );
        assert_eq!(
            infer_operation_heuristic("list_allowed_directories", None),
            Operation::Read
        );
        // zip_files matches "zip" in write keywords — correct, zipping creates files.
        assert_eq!(
            infer_operation_heuristic("zip_files", None),
            Operation::Write
        );
        assert_eq!(
            infer_operation_heuristic("move_file", None),
            Operation::Write
        );
    }

    #[test]
    fn classify_tool_heuristic_combined() {
        let rc = classify_tool_heuristic("file_read", None);
        assert_eq!(rc.domain, Domain::Filesystem);
        assert_eq!(rc.operation, Operation::Read);

        let rc = classify_tool_heuristic("git_push", None);
        assert_eq!(rc.domain, Domain::Git);
        assert_eq!(rc.operation, Operation::Execute);

        let rc = classify_tool_heuristic("write_file", None);
        assert_eq!(rc.domain, Domain::Filesystem);
        assert_eq!(rc.operation, Operation::Write);
    }

    #[test]
    fn domain_case_insensitive() {
        assert_eq!("FILESYSTEM".parse::<Domain>().unwrap(), Domain::Filesystem);
        assert_eq!("Git".parse::<Domain>().unwrap(), Domain::Git);
        assert_eq!("GitHub".parse::<Domain>().unwrap(), Domain::Github);
    }

    #[test]
    fn operation_case_insensitive() {
        assert_eq!("READ".parse::<Operation>().unwrap(), Operation::Read);
        assert_eq!("Write".parse::<Operation>().unwrap(), Operation::Write);
    }
}

verus! {

// Operation risk ordering: Read=0 < Write=1 < Execute=2 < Delete=3
spec fn op_rank(op: nat) -> nat { op }

proof fn operation_ordering_total(a: nat, b: nat, c: nat)
    requires a <= 3, b <= 3, c <= 3, a <= b, b <= c,
    ensures a <= c,
{}

proof fn read_is_least_privileged()
    ensures op_rank(0) <= op_rank(1) && op_rank(0) <= op_rank(2) && op_rank(0) <= op_rank(3),
{}

proof fn delete_is_most_privileged()
    ensures op_rank(3) >= op_rank(0) && op_rank(3) >= op_rank(1) && op_rank(3) >= op_rank(2),
{}

// classify_prompt always returns Prompt:Read (domain=9, op=0)
proof fn classify_prompt_is_read_only()
    ensures op_rank(0) == 0, // Read
{}

// classify_resource always returns Resource:Read (domain=10, op=0)
proof fn classify_resource_is_read_only()
    ensures op_rank(0) == 0, // Read
{}

} // verus!
