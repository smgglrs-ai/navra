---
name: check
description: Run fmt + clippy + check in one pass with ONNX Runtime environment variables
---

Pre-commit sanity check: format verification, linting, and type checking.

## Usage

- If the user specifies a crate, check only that crate
- Default: check the full workspace
- Run all three steps sequentially — stop and report on first failure

## Commands

Run in this order:

1. Format check:

```bash
cargo fmt --check
```

2. Clippy (deny warnings):

```bash
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo clippy --workspace --all-targets -- -D warnings
```

3. Type check:

```bash
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo check --workspace
```

For a single crate, replace `--workspace` with `-p <crate>`.

## Notes

- If fmt check fails, run `cargo fmt` to fix, then continue
- Report all clippy warnings even if the command succeeds
- This does NOT run tests — use `/test` for that
