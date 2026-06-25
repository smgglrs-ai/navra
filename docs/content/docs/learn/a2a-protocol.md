+++
title = "19. Agent-to-Agent Protocol"
description = "A2A enables inter-agent communication through task delegation. Agent Cards for discovery, task lifecycle for coordination, and navra as the bridge between MCP tool calls and A2A task delegation."
weight = 190
template = "docs/page.html"

[extra]
part = "protocol"
toc = true
+++

## What you already know

You know how MCP handles communication between an agent and a tool server -- JSON-RPC requests, the three primitives, and navra's chokepoint pipeline. But MCP is designed for a single agent talking to a single server. What happens when an agent needs to delegate work to another agent?

## The problem MCP doesn't solve

Consider a scenario: an agent is reviewing code and finds a bug. It wants to delegate the fix to a specialized coding agent, then review the result when the coding agent is done. MCP cannot express this. MCP's `tools/call` is synchronous from the agent's perspective -- call a tool, get a result. There is no concept of "submit a task and check back later" or "hand off to another agent."

This is where A2A (Agent-to-Agent) comes in. A2A is a protocol designed by Google for inter-agent communication. Where MCP defines agent-to-tool interactions, A2A defines agent-to-agent interactions.

## Agent Cards: discovery

Before agents can talk to each other, they need to find each other. A2A uses Agent Cards for discovery. An Agent Card is a JSON document published at a well-known URL (`/.well-known/agent.json`) that describes what an agent can do:

```json
{
  "name": "code-reviewer",
  "description": "Reviews code for correctness, security, and style",
  "url": "https://agent.example.com/a2a",
  "version": "1.0.0",
  "protocolVersion": "0.2.5",
  "capabilities": {
    "streaming": true,
    "pushNotifications": false,
    "stateTransitionHistory": true
  },
  "defaultInputModes": ["text/plain"],
  "defaultOutputModes": ["text/plain"],
  "skills": [
    {
      "id": "review-rust",
      "name": "Rust Code Review",
      "description": "Reviews Rust code for correctness and idiomatic style",
      "tags": ["rust", "code-review"]
    }
  ]
}
```

The Agent Card tells potential callers: this agent reviews code, it supports streaming, it has a skill for Rust code review, and you can reach it at this URL. Think of it like a DNS SRV record combined with a capability manifest.

navra can optionally include a DID (Decentralized Identifier) in its Agent Card. This is a cryptographic identity -- a `did:key:` URI derived from a public key -- that other agents can use to verify they're talking to the right agent.

## Task lifecycle

A2A organizes work around tasks. A task has a lifecycle with defined states:

```
submitted --> working --> completed
                     \--> failed
                     \--> canceled
```

A requesting agent creates a task:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tasks/send",
  "params": {
    "id": "task-abc-123",
    "message": {
      "role": "user",
      "parts": [
        {
          "type": "text",
          "text": "Review this Rust function for off-by-one errors:\n\nfn get_slice(data: &[u8], start: usize, len: usize) -> &[u8] {\n    &data[start..start + len]\n}\n"
        }
      ]
    }
  }
}
```

The receiving agent processes the task, optionally sending progress updates while in the `working` state. When done, it transitions to `completed` with a result:

```json
{
  "status": {
    "state": "completed",
    "message": {
      "role": "agent",
      "parts": [
        {
          "type": "text",
          "text": "The function has a potential panic: if start + len exceeds data.len(), the slice operation will panic at runtime. Use data.get(start..start+len).ok_or(...)? or add a bounds check."
        }
      ]
    }
  }
}
```

The requesting agent can check task status (`tasks/get`), cancel a task (`tasks/cancel`), or send follow-up messages (`tasks/send` to an existing task ID).

## How navra bridges MCP and A2A

navra speaks both protocols. On the MCP side, it's a tool server. On the A2A side, it can both delegate tasks to other agents and receive tasks from them.

The bridge works in both directions:

**MCP to A2A**: An agent connected via MCP calls a tool that triggers A2A delegation. For example, if navra's tool list includes `delegate_review`, calling that tool creates an A2A task on a configured review agent. navra handles the task lifecycle, waits for completion (or streams progress), and returns the result as a tool call result.

**A2A to MCP**: An external agent sends an A2A task to navra. navra converts the task into a sequence of MCP tool calls, executes them through its chokepoint pipeline, and returns the aggregated result as an A2A task completion.

In both cases, navra's security pipeline applies. A delegated task is subject to the same ACL checks, IFC enforcement, and blackbox recording as a direct tool call. An external agent cannot bypass navra's security by sending tasks instead of tool calls.

## Task artifacts

A2A tasks can include artifacts -- structured outputs that are more than just text messages. An artifact might be a code patch, a generated file, or a structured report:

```json
{
  "artifacts": [
    {
      "name": "review-report",
      "parts": [
        {
          "type": "text",
          "text": "## Review Summary\n\n1 critical issue found: bounds check missing..."
        }
      ]
    }
  ]
}
```

Artifacts are part of the task completion, separate from the conversational messages. This distinction lets the receiving agent extract structured results without parsing natural language responses.

## Streaming and long-running tasks

Unlike MCP's synchronous `tools/call`, A2A tasks can run for minutes or hours. The `tasks/sendSubscribe` method sets up a streaming connection (using Server-Sent Events) where the working agent sends progress updates:

```
event: status
data: {"state": "working", "message": {"role": "agent", "parts": [{"type": "text", "text": "Analyzing 47 source files..."}]}}

event: status
data: {"state": "working", "message": {"role": "agent", "parts": [{"type": "text", "text": "Found 3 potential issues, verifying..."}]}}

event: status
data: {"state": "completed", "message": {"role": "agent", "parts": [{"type": "text", "text": "Review complete. See artifacts for detailed report."}]}}
```

This makes A2A suitable for complex, multi-step tasks that would time out under MCP's request-response model.

## Security considerations

A2A introduces new security surfaces that MCP alone does not have:

- **Agent identity**: How do you verify that an Agent Card is authentic? navra uses DID-based identity, but the A2A spec does not mandate it.
- **Task isolation**: A task from agent A should not be able to access data from agent B's tasks. navra enforces session isolation through IFC labels.
- **Delegation chains**: If agent A delegates to agent B, which delegates to agent C, each hop must maintain IFC properties. Taint propagates through the chain -- if A's context is untrusted, B's task inherits that label, and C cannot write to trusted destinations.

These are not fully solved problems in the A2A specification. navra adds its own enforcement, but inter-agent security is an active area of development across the ecosystem.

## What's next

We have covered the protocols navra speaks. In Part V, we shift from "how it works" to "how we know it works" -- starting with bounded model checking using Kani, where the Rust compiler and a SAT solver prove that security properties hold for all possible inputs.
