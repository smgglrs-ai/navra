//! A2UI (Agent-to-User Interface) protocol support (NAVRA-146).
//!
//! Provides validation and helpers for Google's A2UI declarative JSON
//! UI protocol. A2UI payloads use MIME type `application/a2ui+json`
//! and can be delivered via MCP tool results or resources.

use serde::{Deserialize, Serialize};

pub const A2UI_MIME_TYPE: &str = "application/a2ui+json";
pub const A2UI_URI_SCHEME: &str = "a2ui://";
pub const A2UI_VERSION: &str = "v0.9";

/// A2UI message envelope (top-level array element).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2uiMessage {
    pub version: String,
    #[serde(rename = "createSurface", skip_serializing_if = "Option::is_none")]
    pub create_surface: Option<A2uiSurface>,
    #[serde(rename = "updateSurface", skip_serializing_if = "Option::is_none")]
    pub update_surface: Option<A2uiSurfaceUpdate>,
}

/// A2UI surface creation payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2uiSurface {
    pub surface_id: String,
    #[serde(default)]
    pub components: Vec<serde_json::Value>,
}

/// A2UI surface update payload (data model delta).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2uiSurfaceUpdate {
    pub surface_id: String,
    #[serde(default)]
    pub data: serde_json::Value,
}

/// Validation error for A2UI payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum A2uiValidationError {
    InvalidJson(String),
    NotArray,
    EmptyArray,
    MissingVersion { index: usize },
    UnsupportedVersion { index: usize, version: String },
    NoSurfaceAction { index: usize },
    MissingSurfaceId { index: usize },
}

impl std::fmt::Display for A2uiValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJson(e) => write!(f, "invalid A2UI JSON: {e}"),
            Self::NotArray => write!(f, "A2UI payload must be a JSON array"),
            Self::EmptyArray => write!(f, "A2UI payload array is empty"),
            Self::MissingVersion { index } => {
                write!(f, "A2UI message[{index}] missing 'version' field")
            }
            Self::UnsupportedVersion { index, version } => {
                write!(f, "A2UI message[{index}] unsupported version: {version}")
            }
            Self::NoSurfaceAction { index } => {
                write!(
                    f,
                    "A2UI message[{index}] has neither createSurface nor updateSurface"
                )
            }
            Self::MissingSurfaceId { index } => {
                write!(f, "A2UI message[{index}] surface missing surfaceId")
            }
        }
    }
}

/// Validate an A2UI JSON payload string.
///
/// Checks:
/// - Valid JSON array
/// - Each element has `version` field matching supported versions
/// - Each element has `createSurface` or `updateSurface`
/// - Surface actions have `surfaceId`
pub fn validate(payload: &str) -> Result<Vec<A2uiMessage>, A2uiValidationError> {
    let value: serde_json::Value = serde_json::from_str(payload)
        .map_err(|e| A2uiValidationError::InvalidJson(e.to_string()))?;

    let arr = value.as_array().ok_or(A2uiValidationError::NotArray)?;
    if arr.is_empty() {
        return Err(A2uiValidationError::EmptyArray);
    }

    let mut messages = Vec::with_capacity(arr.len());

    for (i, item) in arr.iter().enumerate() {
        let version = item
            .get("version")
            .and_then(|v| v.as_str())
            .ok_or(A2uiValidationError::MissingVersion { index: i })?;

        if !version.starts_with("v0.") && !version.starts_with("v1.") {
            return Err(A2uiValidationError::UnsupportedVersion {
                index: i,
                version: version.to_string(),
            });
        }

        let has_create = item.get("createSurface").is_some();
        let has_update = item.get("updateSurface").is_some();

        if !has_create && !has_update {
            return Err(A2uiValidationError::NoSurfaceAction { index: i });
        }

        if has_create {
            let surface = item.get("createSurface").unwrap();
            if surface.get("surfaceId").and_then(|v| v.as_str()).is_none() {
                return Err(A2uiValidationError::MissingSurfaceId { index: i });
            }
        }
        if has_update {
            let surface = item.get("updateSurface").unwrap();
            if surface.get("surfaceId").and_then(|v| v.as_str()).is_none() {
                return Err(A2uiValidationError::MissingSurfaceId { index: i });
            }
        }

        let msg: A2uiMessage = serde_json::from_value(item.clone())
            .map_err(|e| A2uiValidationError::InvalidJson(e.to_string()))?;
        messages.push(msg);
    }

    Ok(messages)
}

/// Check if a MIME type is A2UI.
pub fn is_a2ui_mime(mime: &str) -> bool {
    mime == A2UI_MIME_TYPE
}

/// Check if a URI uses the A2UI scheme.
pub fn is_a2ui_uri(uri: &str) -> bool {
    uri.starts_with(A2UI_URI_SCHEME)
}

/// Extract all text strings from an A2UI payload for safety scanning.
///
/// Walks the JSON tree and collects all string values, which may
/// contain user-visible text that needs PII filtering.
pub fn extract_text_fields(payload: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
        return vec![];
    };
    let mut texts = Vec::new();
    collect_strings(&value, &mut texts);
    texts
}

fn collect_strings(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => {
            if !s.is_empty()
                && !s.starts_with("v0.")
                && !s.starts_with("v1.")
                && s != "text"
                && s != "button"
                && s != "input"
                && s != "container"
                && s != "card"
            {
                out.push(s.clone());
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_strings(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                if key == "version" || key == "type" || key == "surfaceId" {
                    continue;
                }
                collect_strings(val, out);
            }
        }
        _ => {}
    }
}

/// Create an A2UI resource content entry for embedding in tool results.
pub fn resource_content(surface_id: &str, payload: &str) -> crate::ResourceContent {
    crate::ResourceContent::TextResourceContents {
        uri: format!("{A2UI_URI_SCHEME}dynamic-ui/{surface_id}"),
        mime_type: Some(A2UI_MIME_TYPE.to_string()),
        text: payload.to_string(),
        meta: None,
    }
}

/// Create a Content::Resource entry containing an A2UI payload.
pub fn embedded_content(surface_id: &str, payload: &str) -> crate::Content {
    crate::Content::resource(crate::ResourceContent::TextResourceContents {
        uri: format!("{A2UI_URI_SCHEME}dynamic-ui/{surface_id}"),
        mime_type: Some(A2UI_MIME_TYPE.to_string()),
        text: payload.to_string(),
        meta: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_payload() -> String {
        serde_json::json!([{
            "version": "v0.9",
            "createSurface": {
                "surfaceId": "recipe-card",
                "components": [
                    {"type": "text", "content": "Hello world"},
                    {"type": "button", "label": "Click me"}
                ]
            }
        }])
        .to_string()
    }

    #[test]
    fn validate_valid_payload() {
        let result = validate(&valid_payload());
        assert!(result.is_ok());
        let messages = result.unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].version, "v0.9");
        let surface = messages[0].create_surface.as_ref().unwrap();
        assert_eq!(surface.surface_id, "recipe-card");
        assert_eq!(surface.components.len(), 2);
    }

    #[test]
    fn validate_update_surface() {
        let payload = serde_json::json!([{
            "version": "v0.9",
            "updateSurface": {
                "surfaceId": "score-board",
                "data": {"score": 42}
            }
        }])
        .to_string();

        let messages = validate(&payload).unwrap();
        assert_eq!(messages.len(), 1);
        let update = messages[0].update_surface.as_ref().unwrap();
        assert_eq!(update.surface_id, "score-board");
    }

    #[test]
    fn validate_multiple_messages() {
        let payload = serde_json::json!([
            {
                "version": "v0.9",
                "createSurface": {"surfaceId": "a", "components": []}
            },
            {
                "version": "v0.9",
                "updateSurface": {"surfaceId": "b", "data": {}}
            }
        ])
        .to_string();

        let messages = validate(&payload).unwrap();
        assert_eq!(messages.len(), 2);
    }

    #[test]
    fn validate_not_array() {
        let err = validate(r#"{"version": "v0.9"}"#).unwrap_err();
        assert_eq!(err, A2uiValidationError::NotArray);
    }

    #[test]
    fn validate_empty_array() {
        let err = validate("[]").unwrap_err();
        assert_eq!(err, A2uiValidationError::EmptyArray);
    }

    #[test]
    fn validate_missing_version() {
        let payload = serde_json::json!([{
            "createSurface": {"surfaceId": "x", "components": []}
        }])
        .to_string();

        let err = validate(&payload).unwrap_err();
        assert!(matches!(
            err,
            A2uiValidationError::MissingVersion { index: 0 }
        ));
    }

    #[test]
    fn validate_unsupported_version() {
        let payload = serde_json::json!([{
            "version": "v99.0",
            "createSurface": {"surfaceId": "x", "components": []}
        }])
        .to_string();

        let err = validate(&payload).unwrap_err();
        assert!(matches!(
            err,
            A2uiValidationError::UnsupportedVersion { index: 0, .. }
        ));
    }

    #[test]
    fn validate_no_surface_action() {
        let payload = serde_json::json!([{"version": "v0.9"}]).to_string();
        let err = validate(&payload).unwrap_err();
        assert!(matches!(
            err,
            A2uiValidationError::NoSurfaceAction { index: 0 }
        ));
    }

    #[test]
    fn validate_missing_surface_id() {
        let payload = serde_json::json!([{
            "version": "v0.9",
            "createSurface": {"components": []}
        }])
        .to_string();

        let err = validate(&payload).unwrap_err();
        assert!(matches!(
            err,
            A2uiValidationError::MissingSurfaceId { index: 0 }
        ));
    }

    #[test]
    fn validate_invalid_json() {
        let err = validate("not json").unwrap_err();
        assert!(matches!(err, A2uiValidationError::InvalidJson(_)));
    }

    #[test]
    fn is_a2ui_mime_check() {
        assert!(is_a2ui_mime("application/a2ui+json"));
        assert!(!is_a2ui_mime("application/json"));
        assert!(!is_a2ui_mime("text/html"));
    }

    #[test]
    fn is_a2ui_uri_check() {
        assert!(is_a2ui_uri("a2ui://dynamic-ui/recipe-card"));
        assert!(is_a2ui_uri("a2ui://static/config-form"));
        assert!(!is_a2ui_uri("https://example.com"));
        assert!(!is_a2ui_uri("navra://proc"));
    }

    #[test]
    fn extract_text_fields_from_payload() {
        let texts = extract_text_fields(&valid_payload());
        assert!(texts.contains(&"Hello world".to_string()));
        assert!(texts.contains(&"Click me".to_string()));
        // version, type, and surfaceId strings should be excluded
        assert!(!texts.iter().any(|t| t == "v0.9"));
        assert!(!texts.iter().any(|t| t == "text"));
        assert!(!texts.iter().any(|t| t == "button"));
    }

    #[test]
    fn extract_text_fields_invalid_json() {
        let texts = extract_text_fields("not json");
        assert!(texts.is_empty());
    }

    #[test]
    fn resource_content_creates_correct_uri() {
        let rc = resource_content("recipe-card", "[{}]");
        match rc {
            crate::ResourceContent::TextResourceContents {
                uri,
                mime_type,
                text,
                ..
            } => {
                assert_eq!(uri, "a2ui://dynamic-ui/recipe-card");
                assert_eq!(mime_type.as_deref(), Some("application/a2ui+json"));
                assert_eq!(text, "[{}]");
            }
            _ => panic!("expected TextResourceContents"),
        }
    }

    #[test]
    fn embedded_content_wraps_in_resource() {
        let content = embedded_content("my-surface", "[{}]");
        if let Some(res) = content.raw.as_resource() {
            match &res.resource {
                crate::ResourceContent::TextResourceContents { uri, mime_type, .. } => {
                    assert_eq!(uri, "a2ui://dynamic-ui/my-surface");
                    assert_eq!(mime_type.as_deref(), Some("application/a2ui+json"));
                }
                _ => panic!("expected TextResourceContents"),
            }
        } else {
            panic!("expected Resource content");
        }
    }

    #[test]
    fn a2ui_message_roundtrip() {
        let msg = A2uiMessage {
            version: "v0.9".to_string(),
            create_surface: Some(A2uiSurface {
                surface_id: "test".to_string(),
                components: vec![serde_json::json!({"type": "text", "content": "hi"})],
            }),
            update_surface: None,
        };

        let json = serde_json::to_string(&msg).unwrap();
        let parsed: A2uiMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, "v0.9");
        assert_eq!(parsed.create_surface.unwrap().surface_id, "test");
    }

    #[test]
    fn v1_version_accepted() {
        let payload = serde_json::json!([{
            "version": "v1.0",
            "createSurface": {"surfaceId": "x", "components": []}
        }])
        .to_string();

        assert!(validate(&payload).is_ok());
    }
}
