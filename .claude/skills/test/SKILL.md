---
name: test
description: Run navra tests with just (serialized server tests, ORT auto-bundled)
---

Run tests using `just` commands (preferred) or `cargo test` directly.

## Usage

- If the user specifies a crate, test only that crate
- If the user says "all" or "everything", test the full workspace
- Otherwise, infer the relevant crate from recent context

## Commands

Single crate:

```bash
just test-crate <crate>
```

Full workspace:

```bash
just test
```

E2e tests (require Ollama running):

```bash
cargo test -p navra-server --test e2e
```

## Notes

- Always read the full test output — exit code 0 does not guarantee
  all tests passed when using `--workspace`
- Report the test count summary from the output
