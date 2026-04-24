//! Content types for input and output.

use serde::{Deserialize, Serialize};

// --- Input content (user → model) ---

/// Content in a user, system, or developer message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum InputContent {
    #[serde(rename = "input_text")]
    Text(InputTextContent),
    #[serde(rename = "input_image")]
    Image(InputImageContent),
    #[serde(rename = "input_file")]
    File(InputFileContent),
    #[serde(rename = "input_video")]
    Video(InputVideoContent),
}

/// Plain text input content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InputTextContent {
    pub text: String,
}

/// Image input content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InputImageContent {
    pub image_url: String,
    #[serde(default)]
    pub detail: Option<ImageDetail>,
}

/// File input content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InputFileContent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_data: Option<String>,
}

/// Video input content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InputVideoContent {
    pub video_url: String,
}

/// Image detail level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ImageDetail {
    Low,
    High,
    Auto,
}

// --- Output content (model → user) ---

/// Content in an assistant message output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum OutputContent {
    #[serde(rename = "output_text")]
    Text(OutputTextContent),
    #[serde(rename = "refusal")]
    Refusal(RefusalContent),
}

/// Text output with optional annotations and logprobs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutputTextContent {
    pub text: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub annotations: Vec<Annotation>,
}

/// URL citation annotation on output text.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Annotation {
    #[serde(rename = "type")]
    pub annotation_type: String,
    pub url: String,
    pub title: String,
    pub start_index: usize,
    pub end_index: usize,
}

/// Model refusal content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RefusalContent {
    pub refusal: String,
}

// --- Helpers ---

impl InputContent {
    /// Create a text input content.
    pub fn text(s: impl Into<String>) -> Self {
        Self::Text(InputTextContent { text: s.into() })
    }

    /// Create an image input content.
    pub fn image(url: impl Into<String>) -> Self {
        Self::Image(InputImageContent {
            image_url: url.into(),
            detail: None,
        })
    }
}

impl OutputContent {
    /// Create a text output content.
    pub fn text(s: impl Into<String>) -> Self {
        Self::Text(OutputTextContent {
            text: s.into(),
            annotations: Vec::new(),
        })
    }

    /// Extract text content, returning empty string for refusals.
    pub fn as_text(&self) -> &str {
        match self {
            Self::Text(t) => &t.text,
            Self::Refusal(r) => &r.refusal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_text_roundtrip() {
        let content = InputContent::text("hello");
        let json = serde_json::to_string(&content).unwrap();
        assert!(json.contains("\"type\":\"input_text\""));
        assert!(json.contains("\"text\":\"hello\""));
        let parsed: InputContent = serde_json::from_str(&json).unwrap();
        assert_eq!(content, parsed);
    }

    #[test]
    fn output_text_roundtrip() {
        let content = OutputContent::text("response");
        let json = serde_json::to_string(&content).unwrap();
        assert!(json.contains("\"type\":\"output_text\""));
        let parsed: OutputContent = serde_json::from_str(&json).unwrap();
        assert_eq!(content, parsed);
    }

    #[test]
    fn image_detail_serde() {
        let detail = ImageDetail::High;
        let json = serde_json::to_string(&detail).unwrap();
        assert_eq!(json, "\"high\"");
    }

    #[test]
    fn refusal_roundtrip() {
        let content = OutputContent::Refusal(RefusalContent {
            refusal: "I cannot help with that".to_string(),
        });
        let json = serde_json::to_string(&content).unwrap();
        assert!(json.contains("\"type\":\"refusal\""));
        let parsed: OutputContent = serde_json::from_str(&json).unwrap();
        assert_eq!(content, parsed);
    }
}
