//! Tool definitions and tool choice types.

use serde::{Deserialize, Serialize};

/// A function tool the model can call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FunctionTool {
    /// Always "function".
    #[serde(rename = "type")]
    pub kind: String,
    /// Function name.
    pub name: String,
    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema for the function parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
    /// Whether to enforce strict schema validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
}

impl FunctionTool {
    /// Create a new function tool.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            kind: "function".to_string(),
            name: name.into(),
            description: Some(description.into()),
            parameters: None,
            strict: None,
        }
    }

    /// Set the JSON Schema for parameters.
    pub fn with_parameters(mut self, schema: serde_json::Value) -> Self {
        self.parameters = Some(schema);
        self
    }

    /// Enable strict schema validation.
    pub fn strict(mut self) -> Self {
        self.strict = Some(true);
        self
    }
}

/// Tool choice — controls whether and how the model uses tools.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ToolChoice {
    /// Simple mode: "none", "auto", or "required".
    Mode(ToolChoiceMode),
    /// Force a specific function.
    Function {
        #[serde(rename = "type")]
        kind: String,
        name: String,
    },
    /// Restrict to a subset of tools.
    Allowed(AllowedTools),
}

/// Simple tool choice mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ToolChoiceMode {
    None,
    Auto,
    Required,
}

/// Restrict the model to a subset of available tools.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AllowedTools {
    #[serde(rename = "type")]
    pub kind: String,
    pub tools: Vec<AllowedToolRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<ToolChoiceMode>,
}

/// Reference to a specific tool in allowed_tools.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AllowedToolRef {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
}

// --- Helpers ---

impl ToolChoice {
    pub fn auto() -> Self {
        Self::Mode(ToolChoiceMode::Auto)
    }

    pub fn none() -> Self {
        Self::Mode(ToolChoiceMode::None)
    }

    pub fn required() -> Self {
        Self::Mode(ToolChoiceMode::Required)
    }

    /// Force a specific function by name.
    pub fn function(name: impl Into<String>) -> Self {
        Self::Function {
            kind: "function".to_string(),
            name: name.into(),
        }
    }

    /// Restrict to specific tool names.
    pub fn allowed(names: &[&str], mode: ToolChoiceMode) -> Self {
        Self::Allowed(AllowedTools {
            kind: "allowed_tools".to_string(),
            tools: names
                .iter()
                .map(|n| AllowedToolRef {
                    kind: "function".to_string(),
                    name: n.to_string(),
                })
                .collect(),
            mode: Some(mode),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_tool_roundtrip() {
        let tool = FunctionTool::new("get_weather", "Get current weather")
            .with_parameters(serde_json::json!({
                "type": "object",
                "properties": {
                    "city": { "type": "string" }
                },
                "required": ["city"]
            }));
        let json = serde_json::to_string(&tool).unwrap();
        let parsed: FunctionTool = serde_json::from_str(&json).unwrap();
        assert_eq!(tool, parsed);
    }

    #[test]
    fn tool_choice_auto_serde() {
        let choice = ToolChoice::auto();
        let json = serde_json::to_string(&choice).unwrap();
        assert_eq!(json, "\"auto\"");
    }

    #[test]
    fn tool_choice_function_serde() {
        let choice = ToolChoice::function("get_weather");
        let json = serde_json::to_string(&choice).unwrap();
        assert!(json.contains("\"type\":\"function\""));
        assert!(json.contains("\"name\":\"get_weather\""));
    }

    #[test]
    fn allowed_tools_roundtrip() {
        let choice = ToolChoice::allowed(&["search", "read"], ToolChoiceMode::Auto);
        let json = serde_json::to_string(&choice).unwrap();
        assert!(json.contains("\"type\":\"allowed_tools\""));
        let parsed: ToolChoice = serde_json::from_str(&json).unwrap();
        assert_eq!(choice, parsed);
    }
}
