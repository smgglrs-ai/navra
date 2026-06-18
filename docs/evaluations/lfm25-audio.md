# LFM2.5-Audio-1.5B-ONNX Evaluation for navra-modal-voice

Evaluation of Liquid AI's LFM2.5-Audio-1.5B as a unified ASR+TTS
replacement for the current two-model voice pipeline (Whisper +
Kokoro).

## Verdict: Reject (license incompatibility)

LFM2.5-Audio is technically impressive — a single 1.5B model that
handles both ASR and TTS with 5 ONNX components. However, the
LFM 1.0 License restricts commercial use to companies under $10M
annual revenue, making it incompatible with navra's intended
deployment at Red Hat/IBM.

## Technical Assessment

### Architecture

6 ONNX components for end-to-end speech:
1. **Audio Encoder** — Conformer encoder, mel spectrogram → features
2. **Audio Embedding** — Codebook indices → continuous representations
3. **Decoder** — LFM2 backbone, generates text or audio tokens
4. **Vocoder Depthformer** — 8 autoregressive codebook predictions
5. **Audio Detokenizer** — Neural vocoder STFT, codes → waveform
6. **Text Embeddings** — Token-to-embedding lookup (binary files)

### Capabilities

- **ASR**: 16kHz input, 128-bin mel spectrogram
- **TTS**: 24kHz output, 8 codebooks × 2049 tokens
- **Interleaved**: Mixed text and audio I/O
- **Quantization**: FP32, FP16, Q4 (~1.5GB), Q8

### Comparison with Current Pipeline

| Aspect | Whisper + Kokoro | LFM2.5-Audio |
|--------|-----------------|--------------|
| Models | 2 (ASR + TTS) | 1 (unified) |
| ONNX files | 2 | 5 components |
| Total size (Q4) | ~200MB + ~80MB | ~1.5GB |
| Pipeline complexity | Simple (transcribe → synthesize) | Complex (multi-component orchestration) |
| License | MIT + Apache 2.0 | LFM 1.0 ($10M cap) |

### Integration Complexity

Loading 5 separate ONNX sessions and orchestrating them (KV cache
management, autoregressive codebook generation, mode switching)
is significantly more complex than the current pipeline. Each
component has different input/output tensors and the inference
loop requires mode-switching logic (text vs audio tokens).

## License Analysis

The [LFM Open License v1.0](https://www.liquid.ai/lfm-license)
is based on Apache 2.0 but adds a commercial use limitation:

> If your company's revenue exceeds $10 million USD, your right
> to use the model for commercial purposes ends.

This makes LFM2.5-Audio incompatible with Red Hat/IBM deployment.
Research and nonprofit use is unrestricted.

## Recommendation

**Reject** for the following reasons (in priority order):

1. **License**: $10M revenue cap blocks commercial use at Red Hat/IBM
2. **Complexity**: 5-component orchestration vs 2 simple models
3. **Size**: 1.5GB (Q4) vs ~280MB for Whisper + Kokoro
4. **Maturity**: 173 downloads, limited community adoption

The current Whisper (MIT) + Kokoro (Apache 2.0) pipeline remains
the best option for navra-modal-voice.

### Future Considerations

- If Liquid AI releases under Apache 2.0, re-evaluate
- If a community ONNX export of Moshi/KAME appears (Apache 2.0),
  evaluate as alternative unified model (NAVRA-022)
- Granite 4.0 1B Speech (Apache 2.0) for ASR upgrade is already
  in the GPU tier table

## References

- Model: https://huggingface.co/LiquidAI/LFM2.5-Audio-1.5B-ONNX
- License: https://www.liquid.ai/lfm-license
- License docs: https://docs.liquid.ai/lfm/getting-started/model-license
