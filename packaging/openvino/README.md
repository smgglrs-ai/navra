# OpenVINO 2026.1.0 RPM Build

RPM spec for building OpenVINO 2026.1.0 with GenAI on Fedora 44.

## Why

Fedora 44 ships OpenVINO 2025.1.0. We need 2026.1.0 for:

- **OpenVINO GenAI** — LLM pipelines with EAGLE-3 speculative
  decoding, sparse attention, KV cache eviction, NPU LLM generation
- **NF4 quantization on NPU** — Lunar Lake native, better quality
  than INT4_SYM
- **MoE model support** (GA) — Qwen3-30B-A3B, Gemma 4 26B-A4B
- **OpenVINO backend for llama.cpp** (preview)

## What the spec does

Based on the Fedora 44 spec for 2025.1.0 (by Ali Erdinc Koroglu).
Key additions:

1. Version bump 2025.1.0 → 2026.1.0, SO version 2510 → 2610
2. OpenVINO GenAI built via `OPENVINO_EXTRA_MODULES`
3. OpenVINO Tokenizers built as extra module (GenAI dependency)
4. New subpackages: `openvino-genai`, `openvino-genai-devel`,
   `python3-openvino-genai`, `python3-openvino-tokenizers`

## TODO before building

The spec has placeholder `COMMIT` hashes for bundled dependencies.
These must be resolved from the 2026.1.0 tag's `.gitmodules`:

```bash
# Clone and check submodule pins
git clone --branch 2026.1.0 --depth 1 \
  https://github.com/openvinotoolkit/openvino.git
cd openvino
git submodule status

# Record the commit for each:
#   src/plugins/intel_cpu/thirdparty/onednn    → Source3
#   src/plugins/intel_cpu/thirdparty/mlas      → Source4
#   src/plugins/intel_npu/thirdparty/level-zero-ext → Source5
# etc.
```

Also needed:

- Identify the `npu_compiler` release tag for 2026.1.0
- Check if gcc 15 `cstdint` patches are still needed
- Verify GenAI shared library names (`libopenvino_genai.so.*`)
- Check if `dependencies.cmake` needs updating
- Verify `openvino-fedora.patch` still applies

## Build

```bash
# Install build deps
sudo dnf builddep openvino.spec

# Build in mock (recommended)
mock -r fedora-44-x86_64 --rebuild openvino-2026.1.0-1.fc44.src.rpm

# Or build locally
rpmbuild -ba openvino.spec
```

## References

- [OpenVINO 2026.1.0 release](https://github.com/openvinotoolkit/openvino/releases/tag/2026.1.0)
- [OpenVINO build on Linux](https://github.com/openvinotoolkit/openvino/blob/master/docs/dev/build_linux.md)
- [OpenVINO CMake options](https://github.com/openvinotoolkit/openvino/blob/master/docs/dev/cmake_options_for_custom_compilation.md)
- [OpenVINO GenAI build](https://github.com/openvinotoolkit/openvino.genai/blob/master/src/docs/BUILD.md)
- [Fedora openvino package](https://packages.fedoraproject.org/pkgs/openvino/openvino/)
