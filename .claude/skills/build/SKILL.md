---
name: build
description: Build navra with ONNX Runtime environment variables
---

Build the project with the required ONNX Runtime environment variables.

## Usage

- If the user specifies a crate, build only that crate with `-p <crate>`
- If the user says "release", add `--release`
- If the user specifies features, add `--features <features>`
- Default: build the full workspace

## Commands

Full workspace:

```bash
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo build
```

Single crate:

```bash
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo build -p <crate>
```

Release build:

```bash
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo build --release
```

With features (e.g., otel):

```bash
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo build --features <features>
```

## Notes

- Read the full build output — warnings are important even on success
- Report any new warnings introduced by the build
