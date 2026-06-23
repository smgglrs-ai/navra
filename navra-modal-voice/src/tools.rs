//! Voice module tools for navra.
//!
//! Provides speech I/O: microphone → ASR → text, text → TTS → speaker.
//!
//! Tools:
//! - `voice_listen` — record from microphone, transcribe to text
//! - `voice_speak` — synthesize text, play on speaker
//! - `voice_transcribe` — transcribe an audio file (no mic)
//! - `voice_status` — show audio device info and model availability

use crate::audio;
use navra_macros::tool;
use navra_mcp::auth::CallContext;
use navra_mcp::models::ModelBackend;
use navra_mcp::permissions::{PermissionEngine, PermissionResult};
use navra_mcp::protocol::CallToolResult;
use navra_protocol::compat::CallToolResultExt;
use navra_mcp::Module;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Voice module for speech I/O.
pub struct VoiceModule {
    state: Arc<VoiceState>,
}

pub(crate) struct VoiceState {
    /// ASR model (Whisper, Granite Speech, etc.)
    asr_model: Arc<dyn ModelBackend>,
    /// TTS model (Kokoro, Voxtral, etc.)
    tts_model: Arc<dyn ModelBackend>,
    /// VAD energy threshold (RMS). Default: 0.01
    vad_threshold: f32,
    /// Maximum recording duration.
    max_record_secs: u64,
    /// Silence duration after speech to stop recording.
    silence_timeout_ms: u64,
    /// Default voice for TTS.
    default_voice: Option<String>,
    perm_engine: Arc<PermissionEngine>,
}

impl VoiceModule {
    /// Create a new voice module with ASR and TTS models.
    pub fn new(
        asr_model: Arc<dyn ModelBackend>,
        tts_model: Arc<dyn ModelBackend>,
        perm_engine: Arc<PermissionEngine>,
    ) -> Self {
        Self {
            state: Arc::new(VoiceState {
                asr_model,
                tts_model,
                vad_threshold: 0.01,
                max_record_secs: 30,
                silence_timeout_ms: 1500,
                default_voice: None,
                perm_engine,
            }),
        }
    }

    /// Create with custom configuration.
    pub fn with_config(
        asr_model: Arc<dyn ModelBackend>,
        tts_model: Arc<dyn ModelBackend>,
        vad_threshold: f32,
        max_record_secs: u64,
        silence_timeout_ms: u64,
        default_voice: Option<String>,
        perm_engine: Arc<PermissionEngine>,
    ) -> Self {
        Self {
            state: Arc::new(VoiceState {
                asr_model,
                tts_model,
                vad_threshold,
                max_record_secs,
                silence_timeout_ms,
                default_voice,
                perm_engine,
            }),
        }
    }
}

impl Module for VoiceModule {
    fn name(&self) -> &str {
        "voice"
    }

    fn tools(&self) -> Vec<(navra_mcp::protocol::ToolDefinition, navra_mcp::ToolHandler)> {
        let s = self.state.clone();
        vec![
            handle_listen_handler(s.clone()),
            handle_speak_handler(s.clone()),
            handle_transcribe_handler(s.clone()),
            handle_status_handler(s.clone()),
        ]
    }
}

// --- Tool implementations ---

#[tool(
    name = "voice_listen",
    description = "Record audio from the microphone and transcribe it to text. Automatically stops when silence is detected after speech."
)]
async fn handle_listen(
    #[arg(description = "Language hint (ISO 639-1, e.g. 'en', 'fr'). Auto-detect if omitted.")]
    language: Option<String>,
    #[arg(description = "Maximum recording duration in seconds (default: 30)")] max_seconds: Option<
        u64,
    >,
    ctx: CallContext,
    #[state] state: Arc<VoiceState>,
) -> CallToolResult {
    if let Err(e) = check_perm(&state, &ctx, "read", Path::new("/")) {
        return e;
    }

    let max_secs = max_seconds.unwrap_or(state.max_record_secs);

    tracing::info!("Recording from microphone (max {max_secs}s)...");

    // Record audio
    let audio = match audio::record(
        std::time::Duration::from_secs(max_secs),
        state.vad_threshold,
        std::time::Duration::from_millis(state.silence_timeout_ms),
    )
    .await
    {
        Ok(samples) => samples,
        Err(e) => return CallToolResult::error_msg(format!("Recording failed: {e}")),
    };

    if audio.is_empty() {
        return CallToolResult::text("No audio recorded.");
    }

    let duration_secs = audio.len() as f64 / 16000.0;
    tracing::info!("Recorded {:.1}s, transcribing...", duration_secs);

    // Transcribe
    let request = navra_mcp::models::TranscribeRequest { audio, language };
    match state.asr_model.transcribe(&request).await {
        Ok(response) => {
            let mut output = response.text.clone();
            if let Some(lang) = &response.language {
                output.push_str(&format!("\n\n_Detected language: {lang}_"));
            }
            CallToolResult::text(output)
        }
        Err(e) => CallToolResult::error_msg(format!("Transcription failed: {e}")),
    }
}

#[tool(
    name = "voice_speak",
    description = "Synthesize text to speech and play it on the speaker."
)]
async fn handle_speak(
    #[arg(description = "Text to speak")] text: String,
    #[arg(description = "Voice identifier (backend-specific). Uses default if omitted.")]
    voice: Option<String>,
    ctx: CallContext,
    #[state] state: Arc<VoiceState>,
) -> CallToolResult {
    if let Err(e) = check_perm(&state, &ctx, "write", Path::new("/")) {
        return e;
    }

    if text.is_empty() {
        return CallToolResult::error_msg("Missing required parameter: text");
    }
    let voice = voice.or_else(|| state.default_voice.clone());

    // Synthesize
    let request = navra_mcp::models::SynthesizeRequest {
        text: text.to_string(),
        voice,
    };
    let response = match state.tts_model.synthesize(&request).await {
        Ok(r) => r,
        Err(e) => return CallToolResult::error_msg(format!("Speech synthesis failed: {e}")),
    };

    if response.audio.is_empty() {
        return CallToolResult::error_msg("TTS produced no audio");
    }

    let duration_secs = response.audio.len() as f64 / response.sample_rate as f64;

    // Play audio
    if let Err(e) = audio::play(response.audio, response.sample_rate).await {
        return CallToolResult::error_msg(format!("Playback failed: {e}"));
    }

    CallToolResult::text(format!("Spoke {:.1}s of audio.", duration_secs))
}

#[tool(
    name = "voice_transcribe",
    description = "Transcribe an audio file to text. Supports WAV files (16-bit PCM)."
)]
async fn handle_transcribe(
    #[arg(description = "Absolute path to audio file")] path: String,
    #[arg(description = "Language hint (ISO 639-1). Auto-detect if omitted.")] language: Option<
        String,
    >,
    ctx: CallContext,
    #[state] state: Arc<VoiceState>,
) -> CallToolResult {
    let resolved = match resolve_path(&path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error_msg(e),
    };

    if let Err(e) = check_perm(&state, &ctx, "read", &resolved) {
        return e;
    }

    // Read WAV file
    let audio = match read_wav_file(&resolved) {
        Ok(samples) => samples,
        Err(e) => return CallToolResult::error_msg(format!("Failed to read audio file: {e}")),
    };

    if audio.is_empty() {
        return CallToolResult::error_msg("Audio file is empty");
    }

    let duration_secs = audio.len() as f64 / 16000.0;
    tracing::info!(path = %resolved.display(), duration = duration_secs, "Transcribing audio file");

    let request = navra_mcp::models::TranscribeRequest { audio, language };
    match state.asr_model.transcribe(&request).await {
        Ok(response) => {
            let mut output = response.text.clone();
            if let Some(lang) = &response.language {
                output.push_str(&format!("\n\n_Detected language: {lang}_"));
            }
            CallToolResult::text(output)
        }
        Err(e) => CallToolResult::error_msg(format!("Transcription failed: {e}")),
    }
}

#[tool(
    name = "voice_status",
    description = "Show audio device information and model availability."
)]
async fn handle_status(ctx: CallContext, #[state] state: Arc<VoiceState>) -> CallToolResult {
    if let Err(e) = check_perm(&state, &ctx, "read", Path::new("/")) {
        return e;
    }

    let info = audio::device_info();

    let mut output = String::from("Voice Module Status:\n\n");
    output.push_str(&format!("Audio host: {}\n", info.host));
    output.push_str(&format!(
        "Input:  {}\n",
        info.input_device.as_deref().unwrap_or("(none)")
    ));
    if let Some(rate) = info.input_sample_rate {
        output.push_str(&format!("  Sample rate: {} Hz\n", rate));
    }
    output.push_str(&format!(
        "Output: {}\n",
        info.output_device.as_deref().unwrap_or("(none)")
    ));
    if let Some(rate) = info.output_sample_rate {
        output.push_str(&format!("  Sample rate: {} Hz\n", rate));
    }

    CallToolResult::text(output)
}

// --- Path helpers ---

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
    state: &VoiceState,
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
        PermissionResult::NeedsApproval => {
            tracing::info!(op, path = %path.display(), agent = %ctx.agent.name, "Approval required");
            Err(CallToolResult::error_msg("Approval required".to_string()))
        }
        other => {
            tracing::info!(op, path = %path.display(), agent = %ctx.agent.name, result = ?other, "Permission denied");
            Err(CallToolResult::error_msg("Permission denied".to_string()))
        }
    }
}

/// Read a WAV file and return 16kHz mono f32 PCM samples.
fn read_wav_file(path: &std::path::Path) -> Result<Vec<f32>, String> {
    let data = std::fs::read(path).map_err(|e| format!("Cannot read {}: {e}", path.display()))?;

    // Minimal WAV parser — supports 16-bit PCM mono/stereo
    if data.len() < 44 || &data[0..4] != b"RIFF" || &data[8..12] != b"WAVE" {
        return Err("Not a valid WAV file".to_string());
    }

    // Find "fmt " chunk
    let mut pos = 12;
    let mut sample_rate = 0u32;
    let mut channels = 0u16;
    let mut bits_per_sample = 0u16;

    while pos + 8 <= data.len() {
        let chunk_id = &data[pos..pos + 4];
        let chunk_size =
            u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
                as usize;

        if chunk_id == b"fmt " && chunk_size >= 16 {
            let fmt_start = pos + 8;
            let audio_format = u16::from_le_bytes([data[fmt_start], data[fmt_start + 1]]);
            if audio_format != 1 {
                return Err(format!(
                    "Unsupported WAV format: {audio_format} (only PCM supported)"
                ));
            }
            channels = u16::from_le_bytes([data[fmt_start + 2], data[fmt_start + 3]]);
            sample_rate = u32::from_le_bytes([
                data[fmt_start + 4],
                data[fmt_start + 5],
                data[fmt_start + 6],
                data[fmt_start + 7],
            ]);
            bits_per_sample = u16::from_le_bytes([data[fmt_start + 14], data[fmt_start + 15]]);
        }

        if chunk_id == b"data" {
            let data_start = pos + 8;
            let data_end = (data_start + chunk_size).min(data.len());
            let audio_data = &data[data_start..data_end];

            if bits_per_sample != 16 {
                return Err(format!(
                    "Unsupported bit depth: {bits_per_sample} (only 16-bit supported)"
                ));
            }

            // Convert 16-bit PCM to f32
            let mut samples: Vec<f32> = audio_data
                .chunks_exact(2)
                .map(|chunk| {
                    let sample = i16::from_le_bytes([chunk[0], chunk[1]]);
                    sample as f32 / 32768.0
                })
                .collect();

            // Convert to mono
            if channels == 2 {
                samples = samples
                    .chunks(2)
                    .map(|pair| {
                        if pair.len() == 2 {
                            (pair[0] + pair[1]) / 2.0
                        } else {
                            pair[0]
                        }
                    })
                    .collect();
            }

            // Resample to 16kHz
            if sample_rate != 16000 {
                samples = crate::audio::resample(&samples, sample_rate, 16000);
            }

            return Ok(samples);
        }

        pos += 8 + chunk_size;
        // Align to 2-byte boundary
        if chunk_size % 2 != 0 {
            pos += 1;
        }
    }

    Err("No data chunk found in WAV file".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use navra_mcp::auth::AgentIdentity;
    use navra_mcp::models::{
        ModelBackend, ModelError, SynthesizeRequest, SynthesizeResponse, TranscribeRequest,
        TranscribeResponse,
    };
    use navra_mcp::permissions::PathAcl;
    use std::collections::HashSet;

    fn test_perm_engine() -> PermissionEngine {
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
        engine
    }

    struct FakeAsrModel;
    impl ModelBackend for FakeAsrModel {
        fn transcribe(
            &self,
            _req: &TranscribeRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<TranscribeResponse, ModelError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async {
                Ok(TranscribeResponse {
                    text: "Hello world".to_string(),
                    language: Some("en".to_string()),
                })
            })
        }
    }

    struct FakeTtsModel;
    impl ModelBackend for FakeTtsModel {
        fn synthesize(
            &self,
            _req: &SynthesizeRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<SynthesizeResponse, ModelError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async {
                Ok(SynthesizeResponse {
                    audio: vec![0.0; 16000],
                    sample_rate: 16000,
                })
            })
        }
    }

    fn test_ctx() -> CallContext {
        CallContext::new(AgentIdentity::new("test", "dev"), "test")
    }

    fn test_state() -> Arc<VoiceState> {
        let asr: Arc<dyn ModelBackend> = Arc::new(FakeAsrModel);
        let tts: Arc<dyn ModelBackend> = Arc::new(FakeTtsModel);
        Arc::new(VoiceState {
            asr_model: asr,
            tts_model: tts,
            vad_threshold: 0.01,
            max_record_secs: 30,
            silence_timeout_ms: 1500,
            default_voice: None,
            perm_engine: Arc::new(test_perm_engine()),
        })
    }

    #[test]
    fn module_provides_all_tools() {
        let asr: Arc<dyn ModelBackend> = Arc::new(FakeAsrModel);
        let tts: Arc<dyn ModelBackend> = Arc::new(FakeTtsModel);
        let module = VoiceModule::new(
            asr,
            tts,
            Arc::new(navra_mcp::permissions::PermissionEngine::new()),
        );

        assert_eq!(module.name(), "voice");
        let tools = module.tools();
        let names: Vec<_> = tools.iter().map(|(def, _)| &*def.name).collect();
        assert!(names.contains(&"voice_listen"));
        assert!(names.contains(&"voice_speak"));
        assert!(names.contains(&"voice_transcribe"));
        assert!(names.contains(&"voice_status"));
        assert_eq!(tools.len(), 4);
    }

    #[tokio::test]
    async fn status_shows_device_info() {
        let state = test_state();
        let (_, handler) = handle_status_handler(state);
        let result = handler(serde_json::json!({}), test_ctx()).await;
        assert!(result.is_error != Some(true));
        let t = result.content[0].raw.as_text().expect("expected text content");
        assert!(t.text.contains("Voice Module Status"));
        assert!(t.text.contains("Audio host"));
    }

    #[tokio::test]
    async fn transcribe_rejects_missing_path() {
        let state = test_state();
        let (_, handler) = handle_transcribe_handler(state);
        let result = handler(serde_json::json!({}), test_ctx()).await;
        assert!(result.is_error == Some(true));
    }

    #[tokio::test]
    async fn speak_rejects_empty_text() {
        let state = test_state();
        let (_, handler) = handle_speak_handler(state);
        let result = handler(serde_json::json!({}), test_ctx()).await;
        assert!(result.is_error == Some(true));
    }
}
