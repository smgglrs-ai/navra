# navra

**Secure MCP gateway for AI agents.**

navra is a user-level daemon that sits between AI agents and local
resources. It aggregates built-in tool modules and upstream MCP
servers behind a unified security layer with authentication, path
ACLs, content safety filtering, Information Flow Control, and a
hash-chained audit log.

```text
AI Agent (Claude Code, Goose, custom agents, ...)
    |
    |  MCP Streamable HTTP + SSE
    v
navra (gateway)
    |-- Auth (BLAKE3 tokens, capability tokens, DID:key)
    |-- Permission engine (deny-wins ACLs, tool rules, Cedar)
    |-- Hook pipeline (pre/post tool-call)
    |-- Safety filters (regex + ML + NER)
    |-- Built-in modules (file, git, exec, RAG, voice, vision)
    |-- Upstream MCP servers (proxied, safety-filtered)
    v
Desktop (D-Bus notifications, system tray, systemd)
```

## Key Numbers

| Metric | Value |
|---|---|
| Workspace crates | 22 |
| Tests | 2400+ |
| Kani formal proofs | 138 |
| TLA+ specifications | 6 |
| MCP spec coverage | 39/39 |
| OWASP ASI controls | 10/10 |

## What navra is Not

- **Not an agent framework** — navra secures agents, it does not
  build them
- **Not a model server** — navra routes to models but does not
  serve them at scale
- **Not a marketplace** — navra discovers tools via registries
  but does not curate them

## License

[Apache License 2.0](https://github.com/smgglrs-ai/navra/blob/main/LICENSE)
