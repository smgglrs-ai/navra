# Evaluation: rust-mcp-filesystem as upstream MCP server

**Item:** NAVRA-076
**Date:** 2026-06-12
**Repo:** https://github.com/rust-mcp-stack/rust-mcp-filesystem
**Version evaluated:** 0.4.2 (2026-05-18)
**License:** MIT

## Verdict: ADOPT

rust-mcp-filesystem is a strong fit for navra agent deployments. It
provides comprehensive filesystem operations with security-by-default,
plugs directly into navra's upstream MCP infrastructure, and produces a
single static binary suitable for distroless containers.

## Evaluation criteria

### 1. MCP protocol version compatibility

| | navra | rust-mcp-filesystem |
|---|---|---|
| Current | 2025-03-26 | 2025-11-25 |
| Target | 2026-07-28 | — |

**Compatible.** MCP protocol negotiation is backwards-compatible. The
upstream server speaks 2025-11-25 and downgrades for older clients.
navra sends 2025-03-26 during `initialize` — this will work. When
NAVRA-018 ships (2026-07-28 default flip), we'll need to verify
rust-mcp-filesystem has updated too, or that their backward compat
handles 2026-07-28 gracefully. Low risk — the project tracks MCP spec
actively.

### 2. Tool coverage

24 tools across read and write operations:

**Read (17):** read_text_file, read_multiple_text_files, read_media_file,
read_multiple_media_files, head_file, tail_file, read_file_lines,
directory_tree, list_directory, list_directory_with_sizes, get_file_info,
search_files (glob), search_files_content (text/regex),
find_empty_directories, find_duplicate_files, calculate_directory_size,
list_allowed_directories.

**Write (7):** write_file, edit_file (line-based with diff preview),
create_directory, move_file, zip_files, unzip_file, zip_directory.

**Assessment:** Exceeds requirements. The search_files_content tool with
regex support is particularly useful for agent code analysis tasks.
zip/unzip operations are a bonus for artifact handling. The `edit_file`
tool supports dry-run mode and replaceAll — good for safe agent edits.

### 3. Security model

**Directory sandboxing:** Strict. All paths validated against an
allowlist. Path normalization, `~` expansion, `starts_with()` checks.
Access violations return descriptive errors.

**Symlink prevention:** Full path component checking via
`contains_symlink()`. Detects symlinks at each level using
`fs::symlink_metadata()`. Blocks access if symlink target escapes
allowed directories.

**Read-only default:** Enabled by default. Write requires explicit
`-w` / `--allow-write` flag or `ALLOW_WRITE` env var. Write tools
check `require_write_access()` at runtime.

**Tool disabling:** `--disable-tools` flag allows removing specific
tools. Useful for least-privilege: disable write_file and move_file
for read-only agents.

**Assessment:** Strong. The security model aligns with navra's
defense-in-depth approach. Directory sandboxing + symlink prevention +
read-only default is a solid foundation.

### 4. Policy integration with navra

navra layers its own security on top of upstream tools via three
mechanisms:

1. **ToolScanner** (navra-auth): Scans upstream tool definitions during
   discovery. Can block tools with `ScanVerdict::Malicious` or warn
   with `ScanVerdict::Suspicious`. rust-mcp-filesystem's clean tool
   definitions will pass scanning.

2. **Permission system**: navra's per-agent permission rules apply to
   all tools regardless of source. An agent with `read-only` permissions
   won't be able to call `write_file` even if the upstream allows it.

3. **IFC labels**: navra's information flow control labels propagate
   through upstream tool calls. File content read from a
   `confidentiality: high` context will be tainted accordingly.

**Gap:** navra doesn't currently pass directory restrictions to the
upstream. The directory scoping happens at the rust-mcp-filesystem
level via CLI args / container mounts. This is actually fine — it's
defense-in-depth: navra controls *which agents* can call *which tools*,
and rust-mcp-filesystem controls *which directories* those tools can
access.

**Configuration example:**
```toml
[[upstream]]
name = "filesystem"
transport = "stdio"
command = ["rust-mcp-filesystem", "/workspace", "/tmp/scratch"]
```

For read-only agents:
```toml
[[upstream]]
name = "filesystem-ro"
transport = "stdio"
command = ["rust-mcp-filesystem", "/workspace"]
# no -w flag → read-only
```

For write-capable agents:
```toml
[[upstream]]
name = "filesystem-rw"
transport = "stdio"
command = ["rust-mcp-filesystem", "-w", "/workspace", "/tmp/scratch"]
```

### 5. Performance under concurrent agent access

**Architecture:** Each upstream MCP connection is a separate stdio
process. Multiple agents each get their own rust-mcp-filesystem
instance. No shared state, no contention.

**I/O:** Async Tokio throughout. Parallel processing with Rayon for
heavy operations (duplicate file detection). Streaming Base64 encoding
with 8KB buffers for media files.

**Assessment:** Excellent. The one-process-per-agent model avoids
concurrency issues entirely. Each agent's filesystem operations are
isolated. The only shared resource is the actual filesystem, which is
the OS's job to handle.

### 6. Container deployment pattern

**Recommended: separate process managed by the gateway, NOT inside the
agent container.**

rust-mcp-filesystem must run outside the agent's trust boundary.
Placing it inside the agent container defeats the security model:
the agent would have direct filesystem access bypassing the gateway's
permission/IFC/safety pipeline, and could tamper with the MCP server's
configuration.

Correct architecture:
- **Agent container** (`FROM scratch`): navra-agent only, connects to
  gateway via `NAVRA_ENDPOINT`
- **Gateway** (host or container): navra, spawns rust-mcp-filesystem
  as an upstream MCP server via stdio, enforces all policy
- **Filesystem MCP** (host process or sidecar container):
  rust-mcp-filesystem with directory mounts scoped by the orchestrator

Gateway configuration:
```toml
[[upstream]]
name = "filesystem"
transport = "stdio"
command = ["rust-mcp-filesystem", "/workspace"]
# no -w flag → read-only by default
```

## Risks and mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Protocol version drift after NAVRA-018 | Low | Monitor upstream releases; project tracks MCP spec |
| `--enable-roots` allows directory escape | Medium | Never enable roots in agent deployments |
| zip operations could exhaust disk | Low | Container volume limits; disable zip tools for untrusted agents |

## Dependencies for NAVRA-075

This evaluation confirms rust-mcp-filesystem is suitable for the
distroless container deployment (NAVRA-075). Key decisions for that
work item:

1. **Separate process** managed by the gateway, not inside the agent container
2. **Two upstream configs**: `filesystem-ro` (default) and
   `filesystem-rw` (opt-in per agent)
3. **Disable zip tools** in production unless explicitly needed
4. **Never enable `--enable-roots`** in containerized deployments
