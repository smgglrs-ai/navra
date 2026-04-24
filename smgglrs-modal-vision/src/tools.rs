//! Vision module tools for smgglrs.
//!
//! Provides image understanding: describe, OCR, visual QA, screen capture.
//! Requires a vision-capable model (e.g., Granite Vision, Gemma 4).
//!
//! Tools:
//! - `vision_describe` — describe an image file
//! - `vision_ocr` — extract text from an image
//! - `vision_ask` — answer a question about an image
//! - `vision_screen` — capture screen and describe or OCR it

use crate::screenshot;
use smgglrs_core::auth::CallContext;
use smgglrs_core::models::{GenerateRequest, ImageInput, ModelBackend};
use smgglrs_core::permissions::{PermissionEngine, PermissionResult};
use smgglrs_core::protocol::{CallToolResult, ToolDefinition, ToolInputSchema};
use smgglrs_core::{Module, ToolHandler};
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Vision module for image understanding.
pub struct VisionModule {
    state: Arc<VisionState>,
}

struct VisionState {
    /// Vision model (Granite Vision, Gemma 4, etc.)
    vision_model: Arc<dyn ModelBackend>,
    perm_engine: Arc<PermissionEngine>,
}

impl VisionModule {
    pub fn new(vision_model: Arc<dyn ModelBackend>, perm_engine: Arc<PermissionEngine>) -> Self {
        Self {
            state: Arc::new(VisionState { vision_model, perm_engine }),
        }
    }
}

impl Module for VisionModule {
    fn name(&self) -> &str {
        "vision"
    }

    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
        let s = self.state.clone();
        vec![
            make_tool(describe_tool_def(), s.clone(), handle_describe),
            make_tool(ocr_tool_def(), s.clone(), handle_ocr),
            make_tool(ask_tool_def(), s.clone(), handle_ask),
            make_tool(screen_tool_def(), s.clone(), handle_screen),
        ]
    }
}

fn make_tool<F>(
    def: ToolDefinition,
    state: Arc<VisionState>,
    handler: fn(serde_json::Value, CallContext, Arc<VisionState>) -> F,
) -> (ToolDefinition, ToolHandler)
where
    F: Future<Output = CallToolResult> + Send + 'static,
{
    let h: ToolHandler = Arc::new(move |args, ctx| {
        let s = state.clone();
        Box::pin(handler(args, ctx, s))
    });
    (def, h)
}

// --- Tool definitions ---

fn describe_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "vision_describe".to_string(),
        description: Some("Describe the contents of an image file.".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([(
                "path".to_string(),
                serde_json::json!({"type": "string", "description": "Absolute path to image file"}),
            )])),
            required: Some(vec!["path".to_string()]),
        },
    }
}

fn ocr_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "vision_ocr".to_string(),
        description: Some(
            "Extract text from an image file using OCR. Returns the recognized text.".to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([(
                "path".to_string(),
                serde_json::json!({"type": "string", "description": "Absolute path to image file"}),
            )])),
            required: Some(vec!["path".to_string()]),
        },
    }
}

fn ask_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "vision_ask".to_string(),
        description: Some("Answer a question about an image file.".to_string()),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "path".to_string(),
                    serde_json::json!({"type": "string", "description": "Absolute path to image file"}),
                ),
                (
                    "question".to_string(),
                    serde_json::json!({"type": "string", "description": "Question about the image"}),
                ),
            ])),
            required: Some(vec!["path".to_string(), "question".to_string()]),
        },
    }
}

fn screen_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "vision_screen".to_string(),
        description: Some(
            "Capture a screenshot and describe or OCR it. Uses the XDG Desktop Portal \
             (works on Wayland and X11). May show a consent dialog."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([(
                "mode".to_string(),
                serde_json::json!({
                    "type": "string",
                    "description": "What to do with the screenshot: 'describe' (default) or 'ocr'",
                    "default": "describe"
                }),
            )])),
            required: None,
        },
    }
}

// --- Image loading ---

fn load_image(path: &Path) -> Result<ImageInput, String> {
    if !path.is_file() {
        return Err(format!("Not a file: {}", path.display()));
    }

    let data = std::fs::read(path)
        .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;

    let mime_type = match path.extension().and_then(|e| e.to_str()) {
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("bmp") => "image/bmp",
        Some("tiff" | "tif") => "image/tiff",
        Some("svg") => "image/svg+xml",
        _ => "image/png", // fallback
    };

    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&data);

    Ok(ImageInput {
        data: encoded,
        mime_type: mime_type.to_string(),
    })
}

fn resolve_path(raw: &str) -> Result<PathBuf, String> {
    let expanded = if raw.starts_with("~/") {
        match dirs::home_dir() {
            Some(home) => home.join(&raw[2..]),
            None => return Err("Cannot resolve home directory".to_string()),
        }
    } else {
        PathBuf::from(raw)
    };

    if !expanded.is_absolute() {
        return Err(format!("Path must be absolute: {raw}"));
    }

    expanded
        .canonicalize()
        .map_err(|e| format!("Cannot resolve path {raw}: {e}"))
}

// --- Permission check ---

fn check_perm(
    state: &VisionState,
    ctx: &CallContext,
    op: &str,
    path: &Path,
) -> Result<(), CallToolResult> {
    match state.perm_engine.check_with_capabilities(
        &ctx.agent.permissions, op, path, ctx.agent.capabilities.as_ref(),
    ) {
        PermissionResult::Allowed => Ok(()),
        PermissionResult::DeniedPath => Err(CallToolResult::error(format!(
            "Access denied: {}",
            path.display()
        ))),
        PermissionResult::DeniedOperation => Err(CallToolResult::error(format!(
            "Operation '{}' not permitted for agent '{}'",
            op, ctx.agent.name
        ))),
        PermissionResult::DeniedUnknown => Err(CallToolResult::error(format!(
            "Unknown permission set: {}",
            ctx.agent.permissions
        ))),
        PermissionResult::NeedsApproval => Err(CallToolResult::error(format!(
            "Approval required: {} on {}",
            op,
            path.display()
        ))),
    }
}

// --- Tool handlers ---

async fn handle_describe(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<VisionState>,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let path = match resolve_path(raw_path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(&state, &ctx, "read", &path) {
        return e;
    }

    let image = match load_image(&path) {
        Ok(img) => img,
        Err(e) => return CallToolResult::error(e),
    };

    let request = GenerateRequest {
        prompt: "Describe this image in detail.".to_string(),
        max_tokens: Some(1024),
        temperature: Some(0.2),
        system: None,
        images: vec![image],
    };

    match state.vision_model.generate(&request).await {
        Ok(response) => CallToolResult::text(response.text),
        Err(e) => CallToolResult::error(format!("Vision model failed: {e}")),
    }
}

async fn handle_ocr(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<VisionState>,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };

    let path = match resolve_path(raw_path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(&state, &ctx, "read", &path) {
        return e;
    }

    let image = match load_image(&path) {
        Ok(img) => img,
        Err(e) => return CallToolResult::error(e),
    };

    let request = GenerateRequest {
        prompt: "Extract all text from this image. Return only the text content, preserving layout where possible.".to_string(),
        max_tokens: Some(4096),
        temperature: Some(0.0),
        system: None,
        images: vec![image],
    };

    match state.vision_model.generate(&request).await {
        Ok(response) => CallToolResult::text(response.text),
        Err(e) => CallToolResult::error(format!("OCR failed: {e}")),
    }
}

async fn handle_ask(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<VisionState>,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };
    let question = match args.get("question").and_then(|v| v.as_str()) {
        Some(q) if !q.is_empty() => q,
        _ => return CallToolResult::error("Missing required parameter: question"),
    };

    let path = match resolve_path(raw_path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(&state, &ctx, "read", &path) {
        return e;
    }

    let image = match load_image(&path) {
        Ok(img) => img,
        Err(e) => return CallToolResult::error(e),
    };

    let request = GenerateRequest {
        prompt: question.to_string(),
        max_tokens: Some(1024),
        temperature: Some(0.2),
        system: None,
        images: vec![image],
    };

    match state.vision_model.generate(&request).await {
        Ok(response) => CallToolResult::text(response.text),
        Err(e) => CallToolResult::error(format!("Vision model failed: {e}")),
    }
}

async fn handle_screen(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<VisionState>,
) -> CallToolResult {
    if let Err(e) = check_perm(&state, &ctx, "read", Path::new("/")) {
        return e;
    }

    let mode = args
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("describe");

    // Capture screenshot via XDG portal
    let screenshot_path = match screenshot::capture_screen().await {
        Ok(path) => path,
        Err(e) => return CallToolResult::error(format!("Screen capture failed: {e}")),
    };

    let path = Path::new(&screenshot_path);
    // Verify screenshot is in a temp directory (prevent path injection from backend)
    let canonical = match path.canonicalize() {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(format!("Cannot resolve screenshot path: {e}")),
    };
    let in_tmp = canonical.starts_with("/tmp") || canonical.starts_with(std::env::temp_dir());
    if !in_tmp {
        return CallToolResult::error("Screenshot path outside temp directory");
    }
    let image = match load_image(&canonical) {
        Ok(img) => img,
        Err(e) => {
            // Clean up screenshot file
            let _ = std::fs::remove_file(&canonical);
            return CallToolResult::error(e);
        }
    };

    let prompt = match mode {
        "ocr" => "Extract all text from this screenshot. Return only the text content, preserving layout where possible.".to_string(),
        _ => "Describe what is shown on this screenshot.".to_string(),
    };

    let request = GenerateRequest {
        prompt,
        max_tokens: Some(2048),
        temperature: Some(0.2),
        system: None,
        images: vec![image],
    };

    let result = match state.vision_model.generate(&request).await {
        Ok(response) => CallToolResult::text(response.text),
        Err(e) => CallToolResult::error(format!("Vision model failed: {e}")),
    };

    // Clean up screenshot file
    let _ = std::fs::remove_file(&canonical);

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use smgglrs_core::auth::AgentIdentity;
    use smgglrs_core::models::{GenerateResponse, ModelBackend, ModelError};

    struct FakeVisionModel;
    impl ModelBackend for FakeVisionModel {
        fn generate(
            &self,
            req: &GenerateRequest,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<GenerateResponse, ModelError>> + Send + '_>,
        > {
            let has_images = !req.images.is_empty();
            Box::pin(async move {
                Ok(GenerateResponse {
                    text: if has_images {
                        "A cat sitting on a desk.".to_string()
                    } else {
                        "No image provided.".to_string()
                    },
                    prompt_tokens: Some(100),
                    completion_tokens: Some(10),
                })
            })
        }
    }

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("test", "dev"), "test")
    }

    #[test]
    fn module_provides_all_tools() {
        let model: Arc<dyn ModelBackend> = Arc::new(FakeVisionModel);
        let module = VisionModule::new(model, Arc::new(smgglrs_core::permissions::PermissionEngine::new()));

        assert_eq!(module.name(), "vision");
        let tools = module.tools();
        let names: Vec<_> = tools.iter().map(|(def, _)| def.name.as_str()).collect();
        assert!(names.contains(&"vision_describe"));
        assert!(names.contains(&"vision_ocr"));
        assert!(names.contains(&"vision_ask"));
        assert!(names.contains(&"vision_screen"));
        assert_eq!(tools.len(), 4);
    }

    #[tokio::test]
    async fn describe_rejects_missing_path() {
        let state = Arc::new(VisionState {
            vision_model: Arc::new(FakeVisionModel),
            perm_engine: Arc::new(smgglrs_core::permissions::PermissionEngine::new()),
        });
        let result = handle_describe(serde_json::json!({}), test_ctx(), state).await;
        assert!(result.is_error);
    }

    #[tokio::test]
    async fn ask_rejects_missing_question() {
        let state = Arc::new(VisionState {
            vision_model: Arc::new(FakeVisionModel),
            perm_engine: Arc::new(smgglrs_core::permissions::PermissionEngine::new()),
        });
        let result = handle_ask(
            serde_json::json!({"path": "/tmp/test.png"}),
            test_ctx(),
            state,
        )
        .await;
        assert!(result.is_error);
    }

    #[tokio::test]
    async fn describe_rejects_nonexistent_file() {
        let state = Arc::new(VisionState {
            vision_model: Arc::new(FakeVisionModel),
            perm_engine: Arc::new(smgglrs_core::permissions::PermissionEngine::new()),
        });
        let result = handle_describe(
            serde_json::json!({"path": "/nonexistent/image.png"}),
            test_ctx(),
            state,
        )
        .await;
        assert!(result.is_error);
    }
}
