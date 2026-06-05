# navra-tools-exec

Command execution module for navra. Runs commands inside OpenShell
sandboxes or directly on the host, with configurable timeouts and
output capture.

## Tools

| Tool | Description |
|---|---|
| `exec_run` | Execute a shell command with timeout, working directory, and environment variables |

## Isolation modes

When `navra-model-runtime` is available, commands can run inside
sandboxed environments:

- **Direct** -- execute on the host (default)
- **Podman** -- execute inside a container
- **OpenShell** -- execute inside an OpenShell sandbox

The isolation mode is determined by the server configuration and
the agent's permission level.

## Configuration

Enable in `config.toml`:

```toml
[modules.exec]
enabled = true
```

## Dependency layer

```
navra-core + navra-model-runtime
    |
navra-tools-exec
```
