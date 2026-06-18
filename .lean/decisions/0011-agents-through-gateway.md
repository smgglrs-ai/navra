# ADR-0011: Agents Must Route Through Gateway

## Status

Accepted

## Context

Containerized agents need to access LLM model backends (Ollama, etc.)
for inference. They could connect directly to the model backend or
route through navra's gateway endpoint.

## Decision

Agents MUST connect through navra's `/v1/chat/completions` endpoint
(port 9315), never directly to Ollama or any model backend.

## Rationale

Going through the gateway ensures RAG augmentation, safety filtering,
hook pipeline, capability token enforcement, and all security layers.
Direct Ollama access bypasses the entire security model — which is
the whole point of navra.

## Consequences

- Agent configs, Dockerfiles, and docs must point to navra's endpoint.
- If an agent bypasses the gateway, it is a bug.
- Permission tokens for delegated agents inherit from the parent,
  with the planner creating subsets when tighter access is needed.
- Agents get a model serving endpoint, not model downloads.
