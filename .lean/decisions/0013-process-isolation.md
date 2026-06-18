# ADR-0013: Module Process-Level Isolation

## Status

Accepted

## Context

navra modules run as in-process trait objects. This is fast but
couples module stability to the gateway process.

## Decision

navra modules should evolve toward process-level isolation (like a
real micro-kernel) rather than staying as in-process trait objects.
In-process mode stays as the fast default; process isolation is
the hardened deployment mode.

## Rationale

Reinforces the micro-kernel narrative. Enables higher fault isolation
— a crashing RAG module does not take down the gateway. Also enables
independent scaling and deployment of crates as standalone services
(e.g., navra-rag already has a Unix socket server mode).

## Consequences

- When adding or refactoring modules, design them as independently
  deployable processes that communicate via IPC.
- In-process mode remains the fast default for development and
  single-machine deployments.
- Process isolation is the hardened deployment mode for production.
