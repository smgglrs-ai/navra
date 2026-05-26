---
name: test
description: Run smgglrs tests with ONNX Runtime environment variables
---

Run tests with the required ONNX Runtime environment variables.

## Usage

- If the user specifies a crate, test only that crate
- If the user says "all" or "everything", test the full workspace
- Otherwise, infer the relevant crate from recent context

## Commands

Single crate:

```bash
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p <crate>
```

Full workspace:

```bash
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test --workspace
```

E2e tests (require Ollama running):

```bash
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test -p smgglrs-server --test e2e
```

## Notes

- Always read the full test output — exit code 0 does not guarantee
  all tests passed when using `--workspace`
- Report the test count summary from the output
