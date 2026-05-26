use serde::{Deserialize, Serialize};

/// MCP permission negotiation extension.
///
/// Adds four JSON-RPC methods to MCP:
/// - `permissions/request` — server requests elevated permissions from client
/// - `permissions/grant` — client grants the permission
/// - `permissions/deny` — client denies the permission
/// - `permissions/list` — list current permission grants for a session

// --- Scope ---

/// What the permission request covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum PermissionScope {
    /// Access to a filesystem path with specific operations.
    PathAccess {
        path: String,
        operations: Vec<String>,
    },
    /// Access to a specific tool by name.
    ToolAccess {
        #[serde(rename = "toolName")]
        tool_name: String,
    },
    /// Access to a resource by URI.
    ResourceAccess { uri: String },
}

// --- Request ---

/// A permission request from server to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequestParams {
    /// Unique ID for this request (UUID string).
    pub id: String,
    /// What permission is being requested.
    pub scope: PermissionScope,
    /// Human-readable reason for the request.
    pub reason: String,
    /// Optional duration in seconds. If None, grant lasts for the session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<u64>,
}

/// Result of a permissions/request call (acknowledgement).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequestResult {
    /// The request ID, echoed back.
    pub id: String,
    /// Status: "pending", "granted", "denied".
    pub status: String,
}

// --- Grant ---

/// Client grants a permission request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionGrantParams {
    /// The request ID being granted.
    pub request_id: String,
}

/// Result of a permissions/grant call.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionGrantResult {
    /// The request ID.
    pub request_id: String,
    /// The granted scope.
    pub scope: PermissionScope,
    /// When the grant expires (Unix timestamp), if time-bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Who granted the permission.
    pub granted_by: String,
}

// --- Deny ---

/// Client denies a permission request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionDenyParams {
    /// The request ID being denied.
    pub request_id: String,
    /// Optional reason for denial.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Result of a permissions/deny call.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionDenyResult {
    /// The request ID.
    pub request_id: String,
}

// --- List ---

/// Parameters for permissions/list (currently empty, session-scoped).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermissionListParams {}

/// A single active grant in the list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionGrantEntry {
    /// The original request ID.
    pub request_id: String,
    /// The granted scope.
    pub scope: PermissionScope,
    /// When the grant expires (Unix timestamp), if time-bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    /// Who granted the permission.
    pub granted_by: String,
}

/// Result of a permissions/list call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionListResult {
    pub grants: Vec<PermissionGrantEntry>,
}

// --- Capability advertisement ---

/// Server capability for permission negotiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionsCapability {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_permission_scope_path() {
        let scope = PermissionScope::PathAccess {
            path: "/home/user/project".to_string(),
            operations: vec!["read".to_string(), "write".to_string()],
        };
        let json = serde_json::to_value(&scope).unwrap();
        assert_eq!(json["type"], "pathAccess");
        assert_eq!(json["path"], "/home/user/project");
        assert_eq!(json["operations"][0], "read");
    }

    #[test]
    fn serialize_permission_scope_tool() {
        let scope = PermissionScope::ToolAccess {
            tool_name: "git_push".to_string(),
        };
        let json = serde_json::to_value(&scope).unwrap();
        assert_eq!(json["type"], "toolAccess");
        assert_eq!(json["toolName"], "git_push");
    }

    #[test]
    fn serialize_permission_scope_resource() {
        let scope = PermissionScope::ResourceAccess {
            uri: "file:///home/user/doc.md".to_string(),
        };
        let json = serde_json::to_value(&scope).unwrap();
        assert_eq!(json["type"], "resourceAccess");
        assert_eq!(json["uri"], "file:///home/user/doc.md");
    }

    #[test]
    fn roundtrip_permission_request() {
        let req = PermissionRequestParams {
            id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            scope: PermissionScope::PathAccess {
                path: "/tmp/data".to_string(),
                operations: vec!["write".to_string()],
            },
            reason: "Need write access to save results".to_string(),
            duration_secs: Some(3600),
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: PermissionRequestParams = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, req.id);
        assert_eq!(decoded.duration_secs, Some(3600));
    }

    #[test]
    fn roundtrip_permission_grant() {
        let grant = PermissionGrantParams {
            request_id: "req-123".to_string(),
        };
        let json = serde_json::to_string(&grant).unwrap();
        let decoded: PermissionGrantParams = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.request_id, "req-123");
    }

    #[test]
    fn roundtrip_permission_deny() {
        let deny = PermissionDenyParams {
            request_id: "req-456".to_string(),
            reason: Some("Not authorized".to_string()),
        };
        let json = serde_json::to_string(&deny).unwrap();
        let decoded: PermissionDenyParams = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.request_id, "req-456");
        assert_eq!(decoded.reason.unwrap(), "Not authorized");
    }

    #[test]
    fn deny_without_reason() {
        let deny = PermissionDenyParams {
            request_id: "req-789".to_string(),
            reason: None,
        };
        let json = serde_json::to_value(&deny).unwrap();
        assert!(json.get("reason").is_none());
    }

    #[test]
    fn roundtrip_permission_list_result() {
        let result = PermissionListResult {
            grants: vec![PermissionGrantEntry {
                request_id: "req-1".to_string(),
                scope: PermissionScope::ToolAccess {
                    tool_name: "file_write".to_string(),
                },
                expires_at: Some(1700000000),
                granted_by: "user".to_string(),
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        let decoded: PermissionListResult = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.grants.len(), 1);
        assert_eq!(decoded.grants[0].request_id, "req-1");
    }

    #[test]
    fn request_without_duration() {
        let req = PermissionRequestParams {
            id: "req-no-dur".to_string(),
            scope: PermissionScope::ToolAccess {
                tool_name: "shell_exec".to_string(),
            },
            reason: "Need shell access".to_string(),
            duration_secs: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("durationSecs").is_none());
    }

    #[test]
    fn grant_result_serialization() {
        let result = PermissionGrantResult {
            request_id: "req-g1".to_string(),
            scope: PermissionScope::PathAccess {
                path: "/data".to_string(),
                operations: vec!["read".to_string()],
            },
            expires_at: None,
            granted_by: "operator".to_string(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["requestId"], "req-g1");
        assert_eq!(json["grantedBy"], "operator");
        assert!(json.get("expiresAt").is_none());
    }

    #[test]
    fn deserialize_scope_variants() {
        let path_json = r#"{"type":"pathAccess","path":"/tmp","operations":["read"]}"#;
        let scope: PermissionScope = serde_json::from_str(path_json).unwrap();
        assert!(matches!(scope, PermissionScope::PathAccess { .. }));

        let tool_json = r#"{"type":"toolAccess","toolName":"git_push"}"#;
        let scope: PermissionScope = serde_json::from_str(tool_json).unwrap();
        assert!(matches!(scope, PermissionScope::ToolAccess { .. }));

        let res_json = r#"{"type":"resourceAccess","uri":"file:///doc.md"}"#;
        let scope: PermissionScope = serde_json::from_str(res_json).unwrap();
        assert!(matches!(scope, PermissionScope::ResourceAccess { .. }));
    }
}
