# navra-modal-voice

Voice I/O module for the navra gateway (ASR + TTS).

## Overview

Provides speech input and output through the gateway. Uses cpal for
audio device access (microphone capture and speaker playback). On
Linux with PipeWire, cpal uses the ALSA backend which routes through
PipeWire transparently.

ASR and TTS inference are delegated to the `ModelBackend` trait
(`transcribe` / `synthesize` methods).

## Key types

- `VoiceModule` -- implements `Module` trait, registers voice tools
- `audio` module -- microphone capture and speaker playback via cpal
  - `DeviceInfo` -- available audio device information
  - Capture/playback functions for 16kHz mono f32 PCM

## Tools

| Tool | Description |
|---|---|
| `voice_listen` | Record audio from microphone with VAD and silence detection |
| `voice_transcribe` | Transcribe audio to text (ASR) |
| `voice_speak` | Synthesize text to speech and play through speaker (TTS) |

## Configuration

```toml
[modules.voice]
enabled = true
asr_model = "asr"         # model name in [models.*]
tts_model = "tts"         # model name in [models.*]
vad_threshold = 0.01      # voice activity detection energy threshold
max_record_secs = 30
silence_timeout_ms = 1500
```

## Dependency layer

```
navra-core
    |
navra-modal-voice
```

## Reference

See [DESIGN.md](../DESIGN.md) for the modality architecture and
[MODELS.md](../MODELS.md) for ASR/TTS model support.
