# OpenVINO GenAI 2026.1.0.0 RPM Build

Standalone RPM spec for OpenVINO GenAI on Fedora 44.

Built against installed `openvino-devel >= 2026.1.0`, tracks the
GenAI release cycle independently (2026.1.0.0, 2026.1.1.0, etc.).

## Patches

Two patches needed for Fedora 44 (GCC 16 + pybind11 3.x):

- **genai-pybind11-keep-alive.patch** — pybind11 >= 2.13 rejects
  `keep_alive` on `def_readwrite`. Wrap in `py::cpp_function`.
- **genai-gguf-format-template.patch** — GCC 16 with
  `-fvisibility=hidden` strips template instantiation from `.so`.
  Move `format()` template definition from `.cpp` to header.

Both patches are submitted upstream and can be dropped when
a GenAI release includes the fixes.

## Subpackages

| Package | Contents |
|---|---|
| `openvino-genai` | `libopenvino_genai.so`, `libopenvino_genai_c.so` |
| `openvino-genai-devel` | Headers, CMake config |
| `python3-openvino-genai` | Python bindings (LLMPipeline, etc.) |
| `python3-openvino-tokenizers` | HuggingFace tokenizer conversion |

## Build

```bash
dnf builddep openvino-genai.spec
rpmbuild -ba openvino-genai.spec
```

## TODO

- Add `openvino_tokenizers` source tarball (submodule not in GitHub
  release archive)
- Verify library install paths after first successful rpmbuild
- Confirm `setupvars.sh` location for the build environment
- Test in mock

## References

- [OpenVINO GenAI](https://github.com/openvinotoolkit/openvino.genai)
- [GenAI build docs](https://github.com/openvinotoolkit/openvino.genai/blob/master/src/docs/BUILD.md)
