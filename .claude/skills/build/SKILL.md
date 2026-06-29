---
name: build
description: Build navra (ORT auto-bundled via download-binaries feature)
---

Build the project. ONNX Runtime is bundled automatically.

## Usage

- If the user specifies a crate, build only that crate with `-p <crate>`
- If the user says "release", add `--release`
- If the user specifies features, add `--features <features>`
- Default: build the full workspace

## Commands

Full workspace:

```bash
cargo build
```

Single crate:

```bash
cargo build -p <crate>
```

Release build:

```bash
cargo build --release
```

With features (e.g., otel):

```bash
cargo build --features <features>
```

## Notes

- Read the full build output — warnings are important even on success
- Report any new warnings introduced by the build
