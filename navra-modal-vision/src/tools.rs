//! Vision module tools for navra.
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
use navra_core::models::{GenerateRequest, ImageInput, ModelBackend};
use navra_core::permissions::{PermissionEngine, PermissionResult};
use navra_core::protocol::CallToolResult;
use navra_core::{Module, ToolHandler};
use navra_macros::tool;
use navra_auth::auth::CallContext;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Vision module for image understanding.
pub struct VisionModule {
    /// Vision model (Granite Vision, Gemma 4, etc.)
    vision_model: Arc<dyn ModelBackend>,
    perm_engine: Arc<PermissionEngine>,
}

impl VisionModule {
    pub fn new(vision_model: Arc<dyn ModelBackend>, perm_engine: Arc<PermissionEngine>) -> Self {
        Self {
            vision_model,
            perm_engine,
        }
    }
}

impl Module for VisionModule {
    fn name(&self) -> &str {
        "vision"
    }

    fn tools(&self) -> Vec<(navra_core::protocol::ToolDefinition, ToolHandler)> {
        let s = Arc::new(VisionState {
            vision_model: self.vision_model.clone(),
            perm_engine: self.perm_engine.clone(),
        });
        vec![
            handle_describe_handler(s.clone()),
            handle_ocr_handler(s.clone()),
            handle_ask_handler(s.clone()),
            handle_screen_handler(s.clone()),
        ]
    }
}

/// Internal shared state for tool handler closures.
struct VisionState {
    vision_model: Arc<dyn ModelBackend>,
    perm_engine: Arc<PermissionEngine>,
}

// --- Image loading ---

const MAX_IMAGE_SIZE: u64 = 100 * 1024 * 1024;

fn load_image(path: &Path) -> Result<ImageInput, String> {
    if !path.is_file() {
        return Err(format!("Not a file: {}", path.display()));
    }

    let meta =
        std::fs::metadata(path).map_err(|e| format!("Cannot stat {}: {e}", path.display()))?;
    if meta.len() > MAX_IMAGE_SIZE {
        return Err(format!(
            "Image too large ({} MB, max {} MB)",
            meta.len() / (1024 * 1024),
            MAX_IMAGE_SIZE / (1024 * 1024),
        ));
    }

    let data =
        std::fs::read(path).map_err(|e| format!("Failed to read {}: {e}", path.display()))?;

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
        &ctx.agent.permissions,
        op,
        path,
        ctx.agent.capabilities.as_ref(),
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

// --- Tool implementations ---

#[tool(
    name = "vision_describe",
    description = "Describe the contents of an image file."
)]
async fn handle_describe(
    #[arg(description = "Absolute path to image file")] path: String,
    ctx: CallContext,
    #[state] state: Arc<VisionState>,
) -> CallToolResult {
    let resolved = match resolve_path(&path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(&state, &ctx, "read", &resolved) {
        return e;
    }

    let image = match load_image(&resolved) {
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

#[tool(
    name = "vision_ocr",
    description = "Extract text from an image file using OCR. Returns the recognized text."
)]
async fn handle_ocr(
    #[arg(description = "Absolute path to image file")] path: String,
    ctx: CallContext,
    #[state] state: Arc<VisionState>,
) -> CallToolResult {
    let resolved = match resolve_path(&path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(&state, &ctx, "read", &resolved) {
        return e;
    }

    let image = match load_image(&resolved) {
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

#[tool(
    name = "vision_ask",
    description = "Answer a question about an image file."
)]
async fn handle_ask(
    #[arg(description = "Absolute path to image file")] path: String,
    #[arg(description = "Question about the image")] question: String,
    ctx: CallContext,
    #[state] state: Arc<VisionState>,
) -> CallToolResult {
    if question.is_empty() {
        return CallToolResult::error("Missing required parameter: question");
    }

    let resolved = match resolve_path(&path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(&state, &ctx, "read", &resolved) {
        return e;
    }

    let image = match load_image(&resolved) {
        Ok(img) => img,
        Err(e) => return CallToolResult::error(e),
    };

    let request = GenerateRequest {
        prompt: question,
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

#[tool(
    name = "vision_screen",
    description = "Capture a screenshot and describe or OCR it. Uses the XDG Desktop Portal (works on Wayland and X11). May show a consent dialog."
)]
async fn handle_screen(
    #[arg(
        description = "What to do with the screenshot: 'describe' (default) or 'ocr'",
        default = "describe"
    )]
    mode: Option<String>,
    ctx: CallContext,
    #[state] state: Arc<VisionState>,
) -> CallToolResult {
    if let Err(e) = check_perm(&state, &ctx, "read", Path::new("/")) {
        return e;
    }

    let mode = mode.as_deref().unwrap_or("describe");

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
    use navra_core::models::{GenerateResponse, ModelBackend, ModelError};
    use navra_core::permissions::{PathAcl, PermissionEngine};
    use navra_auth::auth::AgentIdentity;
    use std::collections::HashSet;
    use std::io::Write;

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

    fn test_perm_engine() -> Arc<PermissionEngine> {
        let mut engine = PermissionEngine::new();
        engine.add_permission_set(
            "dev".to_string(),
            PathAcl {
                ring: None,
                allow: vec!["/**".to_string()],
                deny: vec![],
                operations: ["read", "write"].into_iter().map(String::from).collect(),
                requires_approval: HashSet::new(),
            },
        );
        Arc::new(engine)
    }

    fn make_state() -> Arc<VisionState> {
        Arc::new(VisionState {
            vision_model: Arc::new(FakeVisionModel),
            perm_engine: test_perm_engine(),
        })
    }

    /// Minimal valid 1x1 white PNG (67 bytes).
    fn tiny_png() -> Vec<u8> {
        let mut buf = Vec::new();
        // PNG signature
        buf.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        // IHDR chunk (1x1, 8-bit grayscale)
        let ihdr_data: [u8; 13] = [
            0x00, 0x00, 0x00, 0x01, // width: 1
            0x00, 0x00, 0x00, 0x01, // height: 1
            0x08, // bit depth: 8
            0x00, // color type: grayscale
            0x00, // compression
            0x00, // filter
            0x00, // interlace
        ];
        let ihdr_crc = crc32(&[b"IHDR" as &[u8], &ihdr_data].concat());
        buf.extend_from_slice(&(13u32).to_be_bytes()); // length
        buf.extend_from_slice(b"IHDR");
        buf.extend_from_slice(&ihdr_data);
        buf.extend_from_slice(&ihdr_crc.to_be_bytes());
        // IDAT chunk (zlib-compressed single pixel: filter byte 0 + pixel value 0xFF)
        let idat_data: [u8; 10] = [
            0x78, 0x01, // zlib header (deflate, no dict)
            0x62, 0xF8, 0x0F, 0x00, // compressed data
            0x01, 0x01, 0x00, 0x00, // adler32
        ];
        let idat_crc = crc32(&[b"IDAT", &idat_data as &[u8]].concat());
        buf.extend_from_slice(&(idat_data.len() as u32).to_be_bytes());
        buf.extend_from_slice(b"IDAT");
        buf.extend_from_slice(&idat_data);
        buf.extend_from_slice(&idat_crc.to_be_bytes());
        // IEND chunk
        let iend_crc = crc32(b"IEND");
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(b"IEND");
        buf.extend_from_slice(&iend_crc.to_be_bytes());
        buf
    }

    /// CRC-32 for PNG chunks.
    fn crc32(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }

    // --- Module tests ---

    #[test]
    fn module_provides_all_tools() {
        let model: Arc<dyn ModelBackend> = Arc::new(FakeVisionModel);
        let module = VisionModule::new(model, test_perm_engine());

        assert_eq!(module.name(), "vision");
        let tools = module.tools();
        let names: Vec<_> = tools.iter().map(|(def, _)| def.name.as_str()).collect();
        assert!(names.contains(&"vision_describe"));
        assert!(names.contains(&"vision_ocr"));
        assert!(names.contains(&"vision_ask"));
        assert!(names.contains(&"vision_screen"));
        assert_eq!(tools.len(), 4);
    }

    // --- load_image tests ---

    #[test]
    fn load_image_valid_png() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.png");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&tiny_png()).unwrap();

        let result = load_image(&path);
        assert!(result.is_ok(), "load_image failed: {:?}", result.err());
        let img = result.unwrap();
        assert_eq!(img.mime_type, "image/png");
        assert!(!img.data.is_empty());

        // Verify data is valid base64
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD.decode(&img.data);
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap(), tiny_png());
    }

    #[test]
    fn load_image_rejects_directory() {
        let dir = tempfile::tempdir().unwrap();
        let result = load_image(dir.path());
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("Not a file"), "unexpected error: {msg}");
    }

    #[test]
    fn load_image_rejects_nonexistent() {
        let result = load_image(Path::new("/nonexistent/image.png"));
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("Not a file"), "unexpected error: {msg}");
    }

    #[test]
    fn load_image_rejects_oversized_file() {
        // Create a file that exceeds MAX_IMAGE_SIZE using a sparse file
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.png");
        let file = std::fs::File::create(&path).unwrap();
        // Set the file length to exceed the limit without writing actual data
        file.set_len(MAX_IMAGE_SIZE + 1).unwrap();

        let result = load_image(&path);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("too large"), "unexpected error: {msg}");
    }

    // --- MIME type detection ---

    #[test]
    fn mime_type_png() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.png");
        std::fs::write(&path, &tiny_png()).unwrap();
        assert_eq!(load_image(&path).unwrap().mime_type, "image/png");
    }

    #[test]
    fn mime_type_jpeg() {
        let dir = tempfile::tempdir().unwrap();
        for ext in &["jpg", "jpeg"] {
            let path = dir.path().join(format!("test.{ext}"));
            std::fs::write(&path, &tiny_png()).unwrap(); // content irrelevant for MIME check
            assert_eq!(load_image(&path).unwrap().mime_type, "image/jpeg");
        }
    }

    #[test]
    fn mime_type_gif() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.gif");
        std::fs::write(&path, &tiny_png()).unwrap();
        assert_eq!(load_image(&path).unwrap().mime_type, "image/gif");
    }

    #[test]
    fn mime_type_webp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.webp");
        std::fs::write(&path, &tiny_png()).unwrap();
        assert_eq!(load_image(&path).unwrap().mime_type, "image/webp");
    }

    #[test]
    fn mime_type_bmp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bmp");
        std::fs::write(&path, &tiny_png()).unwrap();
        assert_eq!(load_image(&path).unwrap().mime_type, "image/bmp");
    }

    #[test]
    fn mime_type_tiff() {
        let dir = tempfile::tempdir().unwrap();
        for ext in &["tiff", "tif"] {
            let path = dir.path().join(format!("test.{ext}"));
            std::fs::write(&path, &tiny_png()).unwrap();
            assert_eq!(load_image(&path).unwrap().mime_type, "image/tiff");
        }
    }

    #[test]
    fn mime_type_svg() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.svg");
        std::fs::write(&path, &tiny_png()).unwrap();
        assert_eq!(load_image(&path).unwrap().mime_type, "image/svg+xml");
    }

    #[test]
    fn mime_type_unknown_defaults_to_png() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.xyz");
        std::fs::write(&path, &tiny_png()).unwrap();
        assert_eq!(load_image(&path).unwrap().mime_type, "image/png");
    }

    // --- resolve_path tests ---

    #[test]
    fn resolve_path_rejects_relative() {
        let result = resolve_path("relative/path.png");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("must be absolute"), "unexpected error: {msg}");
    }

    #[test]
    fn resolve_path_rejects_bare_filename() {
        let result = resolve_path("image.png");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("must be absolute"), "unexpected error: {msg}");
    }

    #[test]
    fn resolve_path_handles_tilde_expansion() {
        // ~/some_path should be expanded. The path may not exist, so
        // canonicalize will fail, but the error should say "Cannot resolve"
        // not "must be absolute".
        let result = resolve_path("~/nonexistent_test_path_12345.png");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("Cannot resolve"), "unexpected error: {msg}");
    }

    #[test]
    fn resolve_path_absolute_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.png");
        std::fs::write(&path, b"data").unwrap();
        let resolved = resolve_path(path.to_str().unwrap());
        assert!(resolved.is_ok());
        assert!(resolved.unwrap().is_absolute());
    }

    #[test]
    fn resolve_path_nonexistent_absolute() {
        let result = resolve_path("/nonexistent/path/image.png");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("Cannot resolve"), "unexpected error: {msg}");
    }

    // --- screenshot path validation ---

    #[test]
    fn screenshot_path_must_be_in_tmp() {
        // Test the inline validation logic used in handle_screen:
        // canonical path must start with /tmp or std::env::temp_dir()
        let tmp = std::env::temp_dir();

        let valid_tmp = Path::new("/tmp/screenshot.png");
        let in_tmp = valid_tmp.starts_with("/tmp") || valid_tmp.starts_with(&tmp);
        assert!(in_tmp);

        let invalid = Path::new("/home/user/screenshot.png");
        let in_tmp = invalid.starts_with("/tmp") || invalid.starts_with(&tmp);
        assert!(!in_tmp);
    }

    // --- Tool handler tests ---

    #[tokio::test]
    async fn describe_rejects_missing_path() {
        let state = make_state();
        let (_, handler) = handle_describe_handler(state);
        let result = handler(serde_json::json!({}), test_ctx()).await;
        assert!(result.is_error);
    }

    #[tokio::test]
    async fn describe_rejects_nonexistent_file() {
        let state = make_state();
        let (_, handler) = handle_describe_handler(state);
        let result = handler(
            serde_json::json!({"path": "/nonexistent/image.png"}),
            test_ctx(),
        )
        .await;
        assert!(result.is_error);
    }

    #[tokio::test]
    async fn describe_rejects_relative_path() {
        let state = make_state();
        let (_, handler) = handle_describe_handler(state);
        let result = handler(
            serde_json::json!({"path": "relative/image.png"}),
            test_ctx(),
        )
        .await;
        assert!(result.is_error);
    }

    #[tokio::test]
    async fn describe_with_valid_image() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.png");
        std::fs::write(&path, &tiny_png()).unwrap();

        let state = make_state();
        let (_, handler) = handle_describe_handler(state);
        let result = handler(
            serde_json::json!({"path": path.to_str().unwrap()}),
            test_ctx(),
        )
        .await;
        assert!(!result.is_error, "describe should succeed with valid PNG");
    }

    #[tokio::test]
    async fn ocr_rejects_missing_path() {
        let state = make_state();
        let (_, handler) = handle_ocr_handler(state);
        let result = handler(serde_json::json!({}), test_ctx()).await;
        assert!(result.is_error);
    }

    #[tokio::test]
    async fn ocr_with_valid_image() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.png");
        std::fs::write(&path, &tiny_png()).unwrap();

        let state = make_state();
        let (_, handler) = handle_ocr_handler(state);
        let result = handler(
            serde_json::json!({"path": path.to_str().unwrap()}),
            test_ctx(),
        )
        .await;
        assert!(!result.is_error);
    }

    #[tokio::test]
    async fn ask_rejects_missing_question() {
        let state = make_state();
        let (_, handler) = handle_ask_handler(state);
        let result = handler(serde_json::json!({"path": "/tmp/test.png"}), test_ctx()).await;
        assert!(result.is_error);
    }

    #[tokio::test]
    async fn ask_rejects_empty_question() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.png");
        std::fs::write(&path, &tiny_png()).unwrap();

        let state = make_state();
        let (_, handler) = handle_ask_handler(state);
        let result = handler(
            serde_json::json!({"path": path.to_str().unwrap(), "question": ""}),
            test_ctx(),
        )
        .await;
        assert!(result.is_error);
    }

    #[tokio::test]
    async fn ask_rejects_missing_path() {
        let state = make_state();
        let (_, handler) = handle_ask_handler(state);
        let result = handler(serde_json::json!({"question": "What is this?"}), test_ctx()).await;
        assert!(result.is_error);
    }

    #[tokio::test]
    async fn ask_with_valid_image_and_question() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.png");
        std::fs::write(&path, &tiny_png()).unwrap();

        let state = make_state();
        let (_, handler) = handle_ask_handler(state);
        let result = handler(
            serde_json::json!({
                "path": path.to_str().unwrap(),
                "question": "What color is this?"
            }),
            test_ctx(),
        )
        .await;
        assert!(!result.is_error);
    }

    // --- Permission check tests ---

    #[tokio::test]
    async fn permission_check_is_called() {
        // Build a perm engine with a restrictive permission set that denies reads.
        // The "dev" permission set in the default engine allows reads,
        // so we use a non-existent permission set name to trigger DeniedUnknown.
        let state = Arc::new(VisionState {
            vision_model: Arc::new(FakeVisionModel),
            perm_engine: Arc::new(navra_core::permissions::PermissionEngine::new()),
        });
        let ctx = CallContext::new(
            AgentIdentity::new("restricted-agent", "nonexistent_perm_set"),
            "test",
        );

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.png");
        std::fs::write(&path, &tiny_png()).unwrap();

        let (_, handler) = handle_describe_handler(state);
        let result = handler(serde_json::json!({"path": path.to_str().unwrap()}), ctx).await;
        // With an unknown permission set, the engine should deny
        assert!(result.is_error);
    }

    // --- Tool definition tests ---

    #[test]
    fn describe_tool_def_has_required_path() {
        let def = handle_describe_tool_def();
        assert_eq!(def.name, "vision_describe");
        assert!(def.description.is_some());
        let required = def.input_schema.required.as_ref().unwrap();
        assert!(required.contains(&"path".to_string()));
    }

    #[test]
    fn ocr_tool_def_has_required_path() {
        let def = handle_ocr_tool_def();
        assert_eq!(def.name, "vision_ocr");
        let required = def.input_schema.required.as_ref().unwrap();
        assert!(required.contains(&"path".to_string()));
    }

    #[test]
    fn ask_tool_def_has_required_fields() {
        let def = handle_ask_tool_def();
        assert_eq!(def.name, "vision_ask");
        let required = def.input_schema.required.as_ref().unwrap();
        assert!(required.contains(&"path".to_string()));
        assert!(required.contains(&"question".to_string()));
    }

    #[test]
    fn screen_tool_def_has_no_required_fields() {
        let def = handle_screen_tool_def();
        assert_eq!(def.name, "vision_screen");
        assert!(def.input_schema.required.is_none());
    }
}
