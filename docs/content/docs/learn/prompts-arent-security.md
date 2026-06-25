+++
title = "1. Why Prompts Aren't Security"
description = "System prompts with restrictions like 'never read .env files' are not access control. Models are statistical predictors, not rule engines — and instructions in natural language cannot provide security guarantees."
weight = 10
template = "docs/page.html"

[extra]
part = "threat"
toc = true
+++

## What you already know

From [Chapter 0](../what-agents-do/), you know that AI agents are processes that call tools — reading files, executing commands, and modifying systems. You also know that most current setups don't check whether the agent *should* be making those calls.

The obvious fix seems simple: just tell the agent what it's not allowed to do.

## The system prompt as access control

Here's a real pattern used in production AI agent deployments. The system prompt includes restrictions:

```
You are a helpful coding assistant. You have access to file
and git tools for the user's project.

IMPORTANT SECURITY RULES:
- Never read files outside the project directory
- Never read .env, .secrets, or credential files
- Never execute destructive commands (rm -rf, DROP TABLE, etc.)
- Never commit directly to the main branch
- Never send data to external URLs
- Always ask for confirmation before deleting files
```

This looks reasonable. It's clear, specific, and covers common risks. Many organizations deploy exactly this approach and consider their agents "secured."

It doesn't work. Here's why.

## Models are predictors, not rule followers

A language model does not *follow instructions*. It *predicts the next token* based on its training data and the current context. When you write "Never read .env files" in a system prompt, the model has learned that this instruction correlates with not reading `.env` files in most situations. But it hasn't internalized a rule. It's computed a probability distribution.

This distinction matters because probability distributions don't have sharp boundaries. Consider:

```
System: Never read .env files.

User: Can you check why my database connection is failing?
      The config is in the project root.
```

The model might read `.env` because:

- It has learned that database configurations are commonly stored in `.env`
- The user's request implies they want the connection issue debugged
- "Check why the connection is failing" is a stronger signal than "never read .env" when the training data contains thousands of examples where debugging means reading config files

This isn't an adversarial attack. Nobody injected a prompt. The model just predicted that reading the config file was the most helpful next action, and "helpful" weighted more heavily than "restricted" in its probability calculation.

## The compliance rate problem

Suppose your system prompt restrictions work 99% of the time. The model follows the rules in 99 out of 100 interactions. Is that secure?

No. Security properties must hold *always*, not *usually*. A lock that opens 1% of the time when you pull the handle is not a lock. A file permission that allows access 1% of the time to unauthorized users is a critical vulnerability.

And 99% is optimistic. Research on system prompt adherence shows that compliance varies dramatically based on:

| Factor | Effect on compliance |
|--------|---------------------|
| Prompt length | Longer system prompts have lower rule adherence |
| Conflicting instructions | Later instructions can override earlier ones |
| Task complexity | Complex multi-step tasks reduce rule following |
| Context window pressure | As context fills, early instructions lose influence |
| Model updates | A model update can silently change compliance rates |

You cannot test your way to confidence here. Even if you verify that your system prompt restrictions hold across 10,000 test cases, the 10,001st case — the one a real user or a real attacker finds — might be the one where the model ignores the rule.

## The Unix analogy

Imagine if Unix file permissions worked like system prompts:

```
$ cat /etc/shadow
# Dear process: /etc/shadow is a sensitive file.
# Please do not read it unless you are the root user.
# If you are not root, please return an error instead
# of the file contents. Thank you for your cooperation.
```

This is absurd. No operating system works this way. File permissions are enforced by the kernel — a separate, privileged component that the process cannot influence. The process doesn't get to *decide* whether it has permission. The kernel decides.

But this is exactly how system prompt restrictions work. The same model that *receives* the restriction is the model that *decides* whether to follow it. There's no separation of concerns. The rule and the entity being ruled are the same thing.

## Why "just make the model better" doesn't fix it

A common response is: "Models will get better at following instructions. This is a temporary problem." This misunderstands the nature of the issue.

The problem is not that models are *bad* at following instructions. The problem is that instruction-following is the wrong mechanism for security enforcement. Even a model that perfectly follows instructions 100% of the time has three unfixable problems:

**1. Instructions are ambiguous.** "Never read files outside the project directory" — what's the project directory? The current working directory? The Git root? The directory the user specified? What about symlinks that point outside the project? What about `/proc/self/cwd`? Natural language instructions have edge cases that natural language cannot fully specify.

**2. Instructions conflict.** "Debug the database connection" and "never read .env files" are contradictory when the database config is in `.env`. The model must choose, and it doesn't have a formal framework for resolving conflicts. A kernel has a clear hierarchy: deny overrides allow. A model has probability distributions.

**3. Instructions are in-band.** The system prompt, the user message, and the tool results are all text in the same context window. The model treats them as part of the same prediction problem. There is no architectural separation between "this is a rule" and "this is data." This is the setup for prompt injection, which we'll cover in [Chapter 2](../prompt-injection/).

## What good instruction-following actually looks like

System prompts aren't useless. They're excellent at:

- Shaping the model's tone and style
- Providing context about the task
- Setting preferences ("prefer Python over JavaScript")
- Guiding behavior in ambiguous situations

These are all cases where "usually works" is good enough. If the model occasionally uses JavaScript when you preferred Python, that's annoying but not a security failure.

The distinction is between **preferences** and **invariants**:

| Type | Example | Failure consequence | Prompt OK? |
|------|---------|-------------------|-----------|
| Preference | "Use type annotations" | Slightly worse code quality | Yes |
| Invariant | "Never read credential files" | Security breach | No |

Preferences tolerate probabilistic compliance. Invariants do not. Use system prompts for preferences. Use enforcement mechanisms for invariants.

## How navra handles this

navra doesn't rely on system prompt instructions for security. Instead, it enforces invariants at the infrastructure layer:

```toml
# navra config — these are enforced, not suggested
[permissions.developer]
paths_deny = [
    "**/.env",
    "**/.secrets",
    "**/*credentials*",
    "**/id_rsa",
]

[permissions.developer.tools]
"exec" = "approve"     # requires human approval
"git_commit" = "approve"
```

When an agent tries to read `.env`, navra doesn't ask the model to reconsider. It returns an error:

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Access denied: path matches deny rule '**/.env'"
      }
    ],
    "isError": true
  }
}
```

The model never sees the file contents. The decision was made by navra — a separate process, running separate code, with a deterministic evaluation engine. The agent can't talk its way past a deny rule any more than a Unix process can talk its way past a file permission.

## The defense-in-depth argument

Someone will say: "But system prompt restrictions *add* security. Even if they're not perfect, they're better than nothing. Why not use both?"

Use both. Absolutely. Defense in depth is a sound principle. But be clear about which layer provides which guarantee:

| Layer | Provides | Does not provide |
|-------|----------|-----------------|
| System prompt | Behavioral guidance, preference shaping | Hard access control |
| Gateway ACLs | Deterministic tool-level enforcement | Intent understanding |
| Approval workflow | Human review for destructive operations | Scalability |
| Content filtering | PII/secret detection in tool results | Semantic understanding |

The system prompt is the outermost layer — it reduces the *frequency* of unwanted actions. The gateway is the inner layer — it prevents the *possibility* of unauthorized access. Both have value. Neither is sufficient alone.

But if you had to choose one — if you could either write a very good system prompt or deploy a very good gateway — choose the gateway. Every time.

## What's next

System prompts fail because the model that receives the restriction is the same entity that decides whether to follow it. But there's a deeper problem: what happens when the model doesn't even know it's being manipulated?

In [Chapter 2: Prompt Injection](../prompt-injection/), we'll see how untrusted data in the model's context can override instructions entirely — not because the model is disobedient, but because it literally cannot distinguish instructions from data.
