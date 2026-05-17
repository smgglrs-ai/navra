# OpenVINO 2026.1.0 RPM Build

RPM spec for building OpenVINO 2026.1.0 core on Fedora 44.

GenAI is in a separate package: see `../openvino-genai/`.

## Changes from Fedora 2025.1.0

- Version bump to 2026.1.0, SO version 2510 -> 2610
- GenAI removed (separate spec with its own release cycle)
- NPU compiler updated to npu_ud_2026_12_1_rc1
- gcc 15 cstdint patches dropped (upstreamed in 2026.1.0)
- KeepConstsPrecision typo fix dropped (fixed upstream)
- Submodule commit hashes resolved from 2026.1.0 tag

## Files

| File | Purpose |
|---|---|
| `openvino.spec` | Main RPM spec |
| `dependencies.cmake` | Replacement thirdparty CMake (from Fedora SRPM) |
| `pyproject.toml` | Python package metadata |
| `npu-compiler-thirdparty-CMakeLists.txt` | Replacement CMakeLists for npu_compiler thirdparty |
| `openvino-fedora.patch` | Install paths, disable docs/tools/scripts subdirs |
| `npu-level-zero.patch` | Remove bundled yaml-cpp, use system package |
| `npu-compiler-disable-git.patch` | Replace git rev-parse with static hash |
| `npu-compiler-fix-install.patch` | Remove CHANGES.txt/README.md install |
| `npu-compiler-vpux-driver-compiler.patch` | Fix library and header install paths |

## Build

```bash
dnf builddep openvino.spec
spectool -g openvino.spec   # download sources
rpmbuild -ba openvino.spec
```

## TODO

- Test build in mock
- Verify openvino-fedora.patch applies cleanly (line offsets may have shifted)
- Verify npu-compiler patches against actual extracted source

## References

- [OpenVINO 2026.1.0 release](https://github.com/openvinotoolkit/openvino/releases/tag/2026.1.0)
- [Fedora openvino package](https://packages.fedoraproject.org/pkgs/openvino/openvino/)
- [NPU compiler npu_ud_2026_12_1_rc1](https://github.com/openvinotoolkit/npu_compiler/releases/tag/npu_ud_2026_12_1_rc1)
