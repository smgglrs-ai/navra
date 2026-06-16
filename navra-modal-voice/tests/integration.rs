//! Integration tests for navra-modal-voice public API.
//!
//! Tests VoiceModule construction, tool definitions, and audio utilities.

use navra_mcp::models::{
    ModelBackend, ModelError, SynthesizeRequest, SynthesizeResponse, TranscribeRequest,
    TranscribeResponse,
};
use navra_mcp::permissions::PermissionEngine;
use navra_mcp::Module;
use navra_modal_voice::audio;
use navra_modal_voice::VoiceModule;
use std::sync::Arc;

// =====================================================================
// Helpers
// =====================================================================

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

fn build_voice_module() -> VoiceModule {
    let asr: Arc<dyn ModelBackend> = Arc::new(FakeAsrModel);
    let tts: Arc<dyn ModelBackend> = Arc::new(FakeTtsModel);
    VoiceModule::new(asr, tts, Arc::new(PermissionEngine::new()))
}

// =====================================================================
// 1. Module construction and naming
// =====================================================================

#[test]
fn module_name_is_voice() {
    let module = build_voice_module();
    assert_eq!(module.name(), "voice");
}

// =====================================================================
// 2. Tool definitions: count and names
// =====================================================================

#[test]
fn module_registers_four_tools() {
    let module = build_voice_module();
    let tools = module.tools();
    assert_eq!(tools.len(), 4);
}

#[test]
fn module_registers_expected_tool_names() {
    let module = build_voice_module();
    let tools = module.tools();
    let names: Vec<&str> = tools.iter().map(|(def, _)| def.name.as_str()).collect();

    let expected = [
        "voice_listen",
        "voice_speak",
        "voice_transcribe",
        "voice_status",
    ];
    for name in &expected {
        assert!(names.contains(name), "Missing tool: {name}");
    }
}

#[test]
fn all_tool_names_prefixed_with_voice() {
    let module = build_voice_module();
    let tools = module.tools();
    for (def, _) in &tools {
        assert!(
            def.name.starts_with("voice_"),
            "Tool '{}' does not start with 'voice_'",
            def.name
        );
    }
}

// =====================================================================
// 3. Tool definition schemas
// =====================================================================

#[test]
fn all_tools_have_descriptions_and_object_schema() {
    let module = build_voice_module();
    let tools = module.tools();
    for (def, _) in &tools {
        assert!(
            def.description.is_some(),
            "Tool '{}' missing description",
            def.name
        );
        assert_eq!(def.input_schema.schema_type, "object");
    }
}

#[test]
fn speak_tool_requires_text() {
    let module = build_voice_module();
    let tools = module.tools();
    let speak = tools.iter().find(|(d, _)| d.name == "voice_speak").unwrap();
    let required = speak.0.input_schema.required.as_ref().unwrap();
    assert!(required.contains(&"text".to_string()));
}

#[test]
fn transcribe_tool_requires_path() {
    let module = build_voice_module();
    let tools = module.tools();
    let transcribe = tools
        .iter()
        .find(|(d, _)| d.name == "voice_transcribe")
        .unwrap();
    let required = transcribe.0.input_schema.required.as_ref().unwrap();
    assert!(required.contains(&"path".to_string()));
}

#[test]
fn listen_tool_has_no_required_params() {
    let module = build_voice_module();
    let tools = module.tools();
    let listen = tools
        .iter()
        .find(|(d, _)| d.name == "voice_listen")
        .unwrap();
    assert!(listen.0.input_schema.required.is_none());
}

// =====================================================================
// 4. Audio utilities
// =====================================================================

#[test]
fn device_info_does_not_panic() {
    let info = audio::device_info();
    assert!(!info.host.is_empty());
}

#[test]
fn with_config_constructor_works() {
    let asr: Arc<dyn ModelBackend> = Arc::new(FakeAsrModel);
    let tts: Arc<dyn ModelBackend> = Arc::new(FakeTtsModel);
    let module = VoiceModule::with_config(
        asr,
        tts,
        0.02,
        60,
        2000,
        Some("af_heart".to_string()),
        Arc::new(PermissionEngine::new()),
    );
    assert_eq!(module.name(), "voice");
    assert_eq!(module.tools().len(), 4);
}
