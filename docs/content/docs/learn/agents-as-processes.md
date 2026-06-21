+++
title = "5. Agents as Processes"
description = "The OS analogy made concrete — mapping process isolation concepts to AI agent security boundaries."
weight = 50
template = "docs/page.html"

[extra]
part = "os-security"
toc = true
+++

## What you already know

You know what an AI agent is: a program that receives a task, calls tools to get information, and produces a result. You have probably used Claude Code, Cursor, or a similar coding assistant. You noticed that it reads files, runs commands, and writes code — not by magic, but by making explicit tool calls through a protocol.

From Part I, you also know this is dangerous. An agent that can read any file and call any tool is an agent that can exfiltrate your SSH keys or overwrite your production config. The question is: how do you constrain it?

Operating systems solved this problem decades ago. Not for AI agents, but for programs — ordinary executables competing for CPU, memory, and I/O on a shared machine. The constraints they invented translate almost perfectly to agents. This chapter builds that translation table.


## What a process is

Every program running on your Linux machine is a process. When you type `ls` in a terminal, the kernel creates a new process. That process gets:

| Property | What it is | Why it matters |
|----------|-----------|----------------|
| **PID** | A unique integer (e.g., 31742) | The kernel tracks every process by its PID |
| **Credentials** | UID, GID, supplementary groups | Determine what the process can access |
| **File descriptors** | Handles to open files, sockets, pipes | The process can only read/write what it has opened |
| **Memory space** | Virtual address range | Process A cannot read Process B's memory |
| **Capability set** | Linux capabilities (e.g., `CAP_NET_BIND_SERVICE`) | Fine-grained permissions beyond the UID model |

The critical insight: none of these are self-reported. The process does not tell the kernel "I am user root." The kernel assigns credentials at creation time and enforces them at every system call.

A process that calls `open("/etc/shadow", O_RDONLY)` does not get to decide whether it can read that file. The kernel checks the process's UID/GID against the file's permission bits. If the check fails, the process gets `EACCES` — and there is nothing it can do about it.


## What an agent is

Now look at an AI agent connecting to navra:

| OS Process | AI Agent | navra Implementation |
|-----------|----------|---------------------|
| PID | Session ID | UUID assigned at `initialize` |
| Credentials (UID/GID) | Auth token | BLAKE3-hashed bearer token, verified on every request |
| File descriptors | Tool access | `tools/list` returns only tools the agent is allowed to see |
| Memory space | Context window | The agent's conversation history, isolated per session |
| Capability set | Capability token | `CapabilityToken` with paths, operations, tools, ring level |

The parallel is not metaphorical. Each row represents a real enforcement boundary in both systems.


## Session as process creation

When an agent connects to navra and sends `initialize`, the gateway does exactly what a kernel does on `fork()`:

1. **Assign an identity.** The kernel assigns a PID; navra assigns a UUID session ID.

2. **Verify credentials.** The kernel inherits the parent's UID/GID; navra extracts the bearer token from the `Authorization` header and hashes it with BLAKE3 to look up the agent's identity.

3. **Set the capability set.** Linux processes inherit a capability bounding set; navra resolves the agent's permission set name and loads its ACLs, operations, tool rules, and safety profile.

4. **Allocate isolated state.** Linux gives the process a virtual address space; navra creates a session with its own taint tracker, value store, and context label.

After `initialize`, the agent is "running" — it can call `tools/list` and `tools/call` just as a process can call `read()` and `write()`. But every call goes through the kernel.


## The system call boundary

In an OS, programs do not touch hardware directly. They ask the kernel, and the kernel decides whether to allow it. The interface between userland and kernel is the system call boundary.

In navra, the equivalent is `handle_call_tool()`. Every tool call from every agent passes through this single function. Here is what it checks, in order:

```
Agent calls: tools/call { name: "file_write", arguments: { path: "~/.ssh/id_rsa", content: "..." } }

                            handle_call_tool()
                                   |
                    1. Is the server paused?           --> "Server is paused"
                    2. Rate limit check                --> "Rate limit exceeded"
                    3. Capability token tool globs     --> "tool not in grants"
                    4. Per-tool permission rules        --> "tool is blocked"
                    5. Operations-based check           --> "write not permitted"
                    6. Domain classification gate       --> "domain denied"
                    7. Path ACL (deny-wins)             --> "path blocked by ACL"
                    8. IFC taint check                  --> "tainted write denied"
                    9. Pre-hooks (may block/modify)     --> hook decision
                   10. >>> Execute tool handler <<<
                   11. IFC label assignment
                   12. Post-hooks (safety filters)
                   13. Blackbox audit record
```

A process that tries to `open("/etc/shadow")` hits one check — file permissions. An agent that tries to `file_write("~/.ssh/id_rsa")` hits eight checks before the handler even runs. This is not an accident. AI agents are less trustworthy than compiled programs, so the enforcement is denser.


## Credential lifecycle

In an OS, credentials follow a strict lifecycle. They are assigned at process creation, inherited by child processes (potentially reduced), and destroyed when the process exits. At no point does the process choose its own credentials.

navra follows the same pattern:

**Creation.** The operator registers an agent in `config.toml`:

```toml
[[agents]]
name = "claude-code"
token_hash = "20a8c34a..."  # BLAKE3 hash of the agent's bearer token
permissions = "developer"
```

The agent's token is generated offline via `navra token generate`. The gateway stores only the hash. When the agent connects, it sends the raw token in the `Authorization` header. The gateway hashes the incoming token with BLAKE3 and compares it to the stored hash. If it matches, the agent gets the `developer` permission set.

**Inheritance.** When a leader agent spawns a specialist, it delegates a capability token. The specialist inherits a subset of the leader's permissions — fewer tools, narrower paths, shorter TTL. It cannot inherit more than the parent has. This is covered in detail in Chapter 6.

**Termination.** When the agent disconnects or the session times out, the session state is destroyed. The taint tracker, value store, and all per-session state are cleaned up. Any capability tokens the agent delegated continue to exist independently (they have their own TTLs), but the session that created them is gone.

This lifecycle prevents a class of bugs where stale credentials accumulate. A long-running agent does not build up permissions over time. Each session starts fresh with exactly the permissions configured by the operator.


## Isolation between agents

Two processes on the same Linux machine cannot read each other's memory. The MMU (memory management unit) hardware enforces this — there is no software workaround.

Two agents connected to navra get a similar guarantee, enforced in software:

- **Session state is not shared.** Agent A's taint tracker, value store, and context label are separate objects. There is no API for one agent to query another's session.

- **Tool results are scoped.** When Agent A calls `file_read`, the result is returned only to Agent A. Agent B does not see it.

- **Capability tokens are non-transferable.** Agent A's token grants `file_*` tools on `~/Code/**`. Even if Agent A somehow communicated the token string to Agent B, Agent B's session would not inherit Agent A's grants — the token is bound to the session.

The one place agents can interact is through shared tools — if Agent A writes a file and Agent B reads it, information flows between them. This is exactly analogous to two processes sharing a file on disk. navra handles this case with information flow control, covered in Chapter 8.


## What happens on a denied call

When an OS process makes a system call that fails a permission check, the kernel returns an error code and the process continues running. It does not crash. It does not get more permissions. It just gets told "no."

navra works the same way. When a tool call is denied, the agent receives an error response:

```json
{
  "content": [
    { "type": "text", "text": "Permission denied: tool 'git_push' is blocked" }
  ],
  "isError": true
}
```

The agent can decide what to do with this information. Most LLM-based agents will try an alternative approach, ask the user for help, or report that they cannot complete the task. The denied call is also recorded in the blackbox audit log with the agent name, tool name, arguments, and timestamp.

This non-fatal denial pattern is important for two reasons:

1. **Graceful degradation.** An agent that encounters a permission boundary does not crash. It can still use the tools it is allowed to use. A coding agent denied `git_push` can still write code, run tests, and commit locally.

2. **Audit trail.** Every denied call is evidence of either a misconfiguration (the agent needs a permission it does not have) or a security event (the agent is trying something it should not). The operator can review the blackbox to distinguish between the two.


## The untrusted process model

Here is the key philosophical difference between navra and most AI platforms: navra treats every agent as an untrusted process.

Most platforms trust the agent by default and add restrictions as an afterthought:
- "Allow all tools, but deny these dangerous ones"
- "Allow all paths, but block `/etc`"
- "Trust the system prompt to keep the agent in line"

navra inverts this:
- Tools are invisible until the permission set grants them
- Paths are inaccessible until an allow rule matches
- The system prompt is irrelevant to security enforcement

This is the same shift that happened in operating systems. Early systems (MS-DOS, classic Mac OS) ran every program with full hardware access. Modern systems (Linux, Windows NT) run every program in a restricted sandbox by default, granting permissions explicitly.

The reason is the same in both cases: you cannot predict what a program (or an agent) will do. A coding assistant that worked flawlessly for months might encounter a prompt injection in a document it reads and suddenly try to exfiltrate credentials. The only defense is enforcement that does not depend on the agent behaving correctly.


## Why this matters for what comes next

The OS analogy is not just a teaching device. It is a design framework. Each of the next four chapters maps a specific OS security mechanism to its navra equivalent:

| OS Concept | navra Concept | Chapter |
|-----------|--------------|---------|
| Capability-based security | `CapabilityToken` | 6 |
| Protection rings | Ring 0/1/2 with deny-wins | 7 |
| Information flow control | Bell-LaPadula taint tracking | 8 |
| Microkernel architecture | Small trusted computing base | 9 |

These are not analogies bolted on after the fact. navra was designed around these concepts from the beginning. The `CapabilityPayload` struct has a `ring` field. The `TaintTracker` implements a formal lattice join. The crate boundary between `navra-auth` and `navra-tools-file` mirrors the kernel/userland split.

Understanding the OS model gives you a mental framework for reasoning about agent security that extends far beyond navra. Every AI security system will eventually reinvent these concepts, because the problem — constraining untrusted code running on shared infrastructure — is the same problem operating systems have been solving since the 1960s.

The difference is maturity. Operating systems have had fifty years to refine these patterns. AI agent platforms are just starting. By mapping the well-understood OS concepts directly to agent security, navra avoids reinventing solutions to problems that were solved before most of us were born.


## What's next

Chapter 6 digs into the first mechanism: [capability-based security](../capabilities/). You will see how a token can carry its own permissions, how those permissions can be narrowed but never widened, and why this matters when a leader agent delegates work to specialists.
