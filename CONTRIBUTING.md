# Contributing to navra

Thank you for your interest in contributing to navra.

## Getting Started

### Prerequisites

- Rust stable (1.75+)
- ONNX Runtime (`onnxruntime-devel` on Fedora)
- Linux (systemd + D-Bus for full functionality)

### Build

```bash
export ORT_LIB_PATH=/usr/lib64
export ORT_PREFER_DYNAMIC_LINK=1
cargo build
```

### Run Tests

```bash
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo test --workspace
```

See [TESTING.md](TESTING.md) for per-crate details and e2e test
prerequisites.

## How to Contribute

### Reporting Bugs

Open a [GitHub issue](https://github.com/smgglrs-ai/navra/issues)
with:

- Steps to reproduce
- Expected behavior
- Actual behavior
- navra version (`cargo run -- --version`)
- OS and ONNX Runtime version

### Security Vulnerabilities

Do **not** open a public issue. See [SECURITY.md](SECURITY.md) for
the responsible disclosure process.

### Pull Requests

1. Fork the repository and create a branch from `main`.
2. Make your changes. Follow the conventions below.
3. Add tests. All PRs must maintain or improve test coverage.
4. Run `cargo fmt` and `cargo clippy` before pushing.
5. Open a PR against `main` with a clear description of what and why.

## Conventions

### Commit Messages

Use imperative mood, present tense:

```
fix(security): prevent path traversal in canonicalize()
feat(rag): add cross-encoder reranking with batching
docs(readme): add quickstart for Goose integration
```

Prefix with the affected area: `fix(crate)`, `feat(crate)`,
`docs(area)`, `test(crate)`, `chore(area)`.

### Sign-Off

All commits must include a `Signed-off-by` line (Developer
Certificate of Origin). Use `git commit -s`:

```
Signed-off-by: Your Name <your@email.com>
```

This certifies that you have the right to submit the work under
the project's license.

### Code Style

- Run `cargo fmt` before committing.
- Run `cargo clippy` and fix all warnings.
- Follow existing patterns in the crate you're modifying.
- No comments unless the *why* is non-obvious.
- Tool names are prefixed with module name: `file_read`, `git_status`.
- Config fields use `snake_case` in TOML.

### Error Handling

- Modules return `CallToolResult::error(msg)` for user-facing errors.
- Infrastructure code uses `anyhow::Result`.
- Model loading failures are logged and skipped (graceful degradation).

### Testing

- Unit tests live in `#[cfg(test)] mod tests` at the bottom of each
  file.
- Integration tests go in `tests/` directories per crate.
- All async tests use `#[tokio::test]`.
- See [TESTING.md](TESTING.md) for the full test suite structure.

### Adding a Module

1. Create a crate implementing the `Module` trait (from `navra-core`).
2. Add the dependency in `navra-server/Cargo.toml`.
3. Add a config struct in `config.rs`.
4. Wire it in `main.rs` behind a config gate.

### Adding a Tool

Use the `#[tool]` proc macro from `navra-macros`:

```rust
#[navra::tool(name = "file_read", description = "Read a file")]
async fn file_read(
    #[arg(description = "Path to the file")] path: String,
    ctx: CallContext,
) -> CallToolResult {
    // ...
}
```

Or define `ToolDefinition` and handler manually. See
[CLAUDE.md](CLAUDE.md#adding-a-tool) for details.

## Releases

navra uses [git-cliff](https://git-cliff.org/) for changelog
generation and GitHub Actions for release automation.

### Cutting a release

```bash
# Preview the changelog for the next version
git-cliff --unreleased --strip header

# Tag the release
git tag -s v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

The `release.yml` workflow will:
1. Generate release notes from conventional commits since the last tag
2. Create a GitHub Release with the notes
3. Build a Linux x86_64 binary and attach it as an artifact
4. Update CHANGELOG.md on main

### Version numbering

navra is pre-1.0. Versions follow `0.MINOR.PATCH`:
- Bump MINOR for new features or breaking changes
- Bump PATCH for bug fixes

## Architecture

Read [DESIGN.md](DESIGN.md) for the full architecture, and
[CLAUDE.md](CLAUDE.md) for the workspace layout and dependency
layering.

## License

By contributing, you agree that your contributions will be licensed
under the [Apache License, Version 2.0](LICENSE).
