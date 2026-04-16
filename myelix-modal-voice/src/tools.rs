//! Voice module tools for mcpd.
//!
//! Provides speech I/O: microphone → ASR → text, text → TTS → speaker.
//!
//! Tools:
//! - `voice_listen` — record from microphone, transcribe to text
//! - `voice_speak` — synthesize text, play on speaker
//! - `voice_transcribe` — transcribe an audio file (no mic)
//! - `voice_status` — show audio device info and model availability

use crate::audio;
use myelix_core::auth::CallContext;
use myelix_core::models::ModelBackend;
use myelix_core::permissions::{PermissionEngine, PermissionResult};
use myelix_core::protocol::{CallToolResult, ToolDefinition, ToolInputSchema};
use myelix_core::{Module, ToolHandler};
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Voice module for speech I/O.
pub struct VoiceModule {
    state: Arc<VoiceState>,
}

struct VoiceState {
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

    fn tools(&self) -> Vec<(ToolDefinition, ToolHandler)> {
        let s = self.state.clone();
        vec![
            make_tool(listen_tool_def(), s.clone(), handle_listen),
            make_tool(speak_tool_def(), s.clone(), handle_speak),
            make_tool(transcribe_tool_def(), s.clone(), handle_transcribe),
            make_tool(status_tool_def(), s.clone(), handle_status),
        ]
    }
}

fn make_tool<F>(
    def: ToolDefinition,
    state: Arc<VoiceState>,
    handler: fn(serde_json::Value, CallContext, Arc<VoiceState>) -> F,
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

fn listen_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "voice_listen".to_string(),
        description: Some(
            "Record audio from the microphone and transcribe it to text. \
             Automatically stops when silence is detected after speech."
                .to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "language".to_string(),
                    serde_json::json!({"type": "string", "description": "Language hint (ISO 639-1, e.g. 'en', 'fr'). Auto-detect if omitted."}),
                ),
                (
                    "max_seconds".to_string(),
                    serde_json::json!({"type": "integer", "description": "Maximum recording duration in seconds (default: 30)"}),
                ),
            ])),
            required: None,
        },
    }
}

fn speak_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "voice_speak".to_string(),
        description: Some(
            "Synthesize text to speech and play it on the speaker.".to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "text".to_string(),
                    serde_json::json!({"type": "string", "description": "Text to speak"}),
                ),
                (
                    "voice".to_string(),
                    serde_json::json!({"type": "string", "description": "Voice identifier (backend-specific). Uses default if omitted."}),
                ),
            ])),
            required: Some(vec!["text".to_string()]),
        },
    }
}

fn transcribe_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "voice_transcribe".to_string(),
        description: Some(
            "Transcribe an audio file to text. Supports WAV files (16-bit PCM).".to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: Some(HashMap::from([
                (
                    "path".to_string(),
                    serde_json::json!({"type": "string", "description": "Absolute path to audio file"}),
                ),
                (
                    "language".to_string(),
                    serde_json::json!({"type": "string", "description": "Language hint (ISO 639-1). Auto-detect if omitted."}),
                ),
            ])),
            required: Some(vec!["path".to_string()]),
        },
    }
}

fn status_tool_def() -> ToolDefinition {
    ToolDefinition {
        name: "voice_status".to_string(),
        description: Some(
            "Show audio device information and model availability.".to_string(),
        ),
        input_schema: ToolInputSchema {
            schema_type: "object".to_string(),
            properties: None,
            required: None,
        },
    }
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
    match state.perm_engine.check(&ctx.agent.permissions, op, path) {
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

async fn handle_listen(
    args: serde_json::Value,
    _ctx: CallContext,
    state: Arc<VoiceState>,
) -> CallToolResult {
    let language = args.get("language").and_then(|v| v.as_str()).map(String::from);
    let max_secs = args
        .get("max_seconds")
        .and_then(|v| v.as_u64())
        .unwrap_or(state.max_record_secs);

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
        Err(e) => return CallToolResult::error(format!("Recording failed: {e}")),
    };

    if audio.is_empty() {
        return CallToolResult::text("No audio recorded.");
    }

    let duration_secs = audio.len() as f64 / 16000.0;
    tracing::info!("Recorded {:.1}s, transcribing...", duration_secs);

    // Transcribe
    let request = myelix_core::models::TranscribeRequest {
        audio,
        language,
    };
    match state.asr_model.transcribe(&request).await {
        Ok(response) => {
            let mut output = response.text.clone();
            if let Some(lang) = &response.language {
                output.push_str(&format!("\n\n_Detected language: {lang}_"));
            }
            CallToolResult::text(output)
        }
        Err(e) => CallToolResult::error(format!("Transcription failed: {e}")),
    }
}

async fn handle_speak(
    args: serde_json::Value,
    _ctx: CallContext,
    state: Arc<VoiceState>,
) -> CallToolResult {
    let text = match args.get("text").and_then(|v| v.as_str()) {
        Some(t) if !t.is_empty() => t,
        _ => return CallToolResult::error("Missing required parameter: text"),
    };
    let voice = args
        .get("voice")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| state.default_voice.clone());

    // Synthesize
    let request = myelix_core::models::SynthesizeRequest {
        text: text.to_string(),
        voice,
    };
    let response = match state.tts_model.synthesize(&request).await {
        Ok(r) => r,
        Err(e) => return CallToolResult::error(format!("Speech synthesis failed: {e}")),
    };

    if response.audio.is_empty() {
        return CallToolResult::error("TTS produced no audio");
    }

    let duration_secs = response.audio.len() as f64 / response.sample_rate as f64;

    // Play audio
    if let Err(e) = audio::play(response.audio, response.sample_rate).await {
        return CallToolResult::error(format!("Playback failed: {e}"));
    }

    CallToolResult::text(format!("Spoke {:.1}s of audio.", duration_secs))
}

async fn handle_transcribe(
    args: serde_json::Value,
    ctx: CallContext,
    state: Arc<VoiceState>,
) -> CallToolResult {
    let raw_path = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return CallToolResult::error("Missing required parameter: path"),
    };
    let language = args.get("language").and_then(|v| v.as_str()).map(String::from);

    let path = match resolve_path(raw_path) {
        Ok(p) => p,
        Err(e) => return CallToolResult::error(e),
    };

    if let Err(e) = check_perm(&state, &ctx, "read", &path) {
        return e;
    }

    // Read WAV file
    let audio = match read_wav_file(&path) {
        Ok(samples) => samples,
        Err(e) => return CallToolResult::error(format!("Failed to read audio file: {e}")),
    };

    if audio.is_empty() {
        return CallToolResult::error("Audio file is empty");
    }

    let duration_secs = audio.len() as f64 / 16000.0;
    tracing::info!(path = %path.display(), duration = duration_secs, "Transcribing audio file");

    let request = myelix_core::models::TranscribeRequest { audio, language };
    match state.asr_model.transcribe(&request).await {
        Ok(response) => {
            let mut output = response.text.clone();
            if let Some(lang) = &response.language {
                output.push_str(&format!("\n\n_Detected language: {lang}_"));
            }
            CallToolResult::text(output)
        }
        Err(e) => CallToolResult::error(format!("Transcription failed: {e}")),
    }
}

async fn handle_status(
    _args: serde_json::Value,
    _ctx: CallContext,
    _state: Arc<VoiceState>,
) -> CallToolResult {
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
        let chunk_size = u32::from_le_bytes([
            data[pos + 4],
            data[pos + 5],
            data[pos + 6],
            data[pos + 7],
        ]) as usize;

        if chunk_id == b"fmt " && chunk_size >= 16 {
            let fmt_start = pos + 8;
            let audio_format =
                u16::from_le_bytes([data[fmt_start], data[fmt_start + 1]]);
            if audio_format != 1 {
                return Err(format!("Unsupported WAV format: {audio_format} (only PCM supported)"));
            }
            channels =
                u16::from_le_bytes([data[fmt_start + 2], data[fmt_start + 3]]);
            sample_rate = u32::from_le_bytes([
                data[fmt_start + 4],
                data[fmt_start + 5],
                data[fmt_start + 6],
                data[fmt_start + 7],
            ]);
            bits_per_sample =
                u16::from_le_bytes([data[fmt_start + 14], data[fmt_start + 15]]);
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
    use myelix_core::auth::AgentIdentity;
    use myelix_core::models::{
        ModelBackend, ModelError, SynthesizeRequest, SynthesizeResponse, TranscribeRequest,
        TranscribeResponse,
    };

    struct FakeAsrModel;
    impl ModelBackend for FakeAsrModel {
        fn transcribe(
            &self,
            _req: &TranscribeRequest,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<TranscribeResponse, ModelError>> + Send + '_>,
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
            Box<dyn std::future::Future<Output = Result<SynthesizeResponse, ModelError>> + Send + '_>,
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

    #[test]
    fn module_provides_all_tools() {
        let asr: Arc<dyn ModelBackend> = Arc::new(FakeAsrModel);
        let tts: Arc<dyn ModelBackend> = Arc::new(FakeTtsModel);
        let module = VoiceModule::new(asr, tts, Arc::new(myelix_core::permissions::PermissionEngine::new()));

        assert_eq!(module.name(), "voice");
        let tools = module.tools();
        let names: Vec<_> = tools.iter().map(|(def, _)| def.name.as_str()).collect();
        assert!(names.contains(&"voice_listen"));
        assert!(names.contains(&"voice_speak"));
        assert!(names.contains(&"voice_transcribe"));
        assert!(names.contains(&"voice_status"));
        assert_eq!(tools.len(), 4);
    }

    #[tokio::test]
    async fn status_shows_device_info() {
        let asr: Arc<dyn ModelBackend> = Arc::new(FakeAsrModel);
        let tts: Arc<dyn ModelBackend> = Arc::new(FakeTtsModel);
        let state = Arc::new(VoiceState {
            asr_model: asr,
            tts_model: tts,
            vad_threshold: 0.01,
            max_record_secs: 30,
            silence_timeout_ms: 1500,
            default_voice: None,
            perm_engine: Arc::new(myelix_core::permissions::PermissionEngine::new()),
        });

        let result = handle_status(serde_json::json!({}), test_ctx(), state).await;
        assert!(!result.is_error);
        match &result.content[0] {
            myelix_core::protocol::Content::Text(t) => {
                assert!(t.text.contains("Voice Module Status"));
                assert!(t.text.contains("Audio host"));
            }
        }
    }

    #[tokio::test]
    async fn transcribe_rejects_missing_path() {
        let asr: Arc<dyn ModelBackend> = Arc::new(FakeAsrModel);
        let tts: Arc<dyn ModelBackend> = Arc::new(FakeTtsModel);
        let state = Arc::new(VoiceState {
            asr_model: asr,
            tts_model: tts,
            vad_threshold: 0.01,
            max_record_secs: 30,
            silence_timeout_ms: 1500,
            default_voice: None,
            perm_engine: Arc::new(myelix_core::permissions::PermissionEngine::new()),
        });

        let result = handle_transcribe(serde_json::json!({}), test_ctx(), state).await;
        assert!(result.is_error);
    }

    #[tokio::test]
    async fn speak_rejects_empty_text() {
        let asr: Arc<dyn ModelBackend> = Arc::new(FakeAsrModel);
        let tts: Arc<dyn ModelBackend> = Arc::new(FakeTtsModel);
        let state = Arc::new(VoiceState {
            asr_model: asr,
            tts_model: tts,
            vad_threshold: 0.01,
            max_record_secs: 30,
            silence_timeout_ms: 1500,
            default_voice: None,
            perm_engine: Arc::new(myelix_core::permissions::PermissionEngine::new()),
        });

        let result = handle_speak(serde_json::json!({}), test_ctx(), state).await;
        assert!(result.is_error);
    }
}
