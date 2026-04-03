# mcpd

Secure MCP gateway daemon for Linux desktops. Rust workspace.

## Build

Requires ONNX Runtime installed system-wide (Fedora: `onnxruntime-devel`).

```bash
# Build
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo build

# Run
ORT_LIB_PATH=/usr/lib64 ORT_PREFER_DYNAMIC_LINK=1 cargo run -- serve
```

These environment variables are required because `ort` is configured
with `default-features = false` (no bundled download) and the system
package only provides shared libraries.

## Workspace

| Crate | Role |
|---|---|
| `mcpd-core` | MCP framework, auth, permissions, safety, transports, upstream proxy |
| `mcpd-server` | Binary: CLI, config, module wiring, systemd, tray |
| `mcpd-mod-docs` | Document tools, SQLite FTS5 + sqlite-vec |
| `mcpd-mod-git` | Git tools |
