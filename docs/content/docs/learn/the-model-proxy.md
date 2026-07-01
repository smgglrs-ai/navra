+++
title = "The Model Proxy"
description = "navra sits between agents and frontier models — not just tools. PII filtering, credential isolation, audit logging, and safety enforcement apply to every model call, covering the trust boundary that providers cannot see."
weight = 185
template = "docs/page.html"

[extra]
part = "protocol"
toc = true
+++

## What you already know

You know that navra proxies tool calls through a single chokepoint where ACLs, IFC, content filtering, and blackbox recording are enforced ([Chapter 17](../the-chokepoint/)). You know it does the same for upstream MCP servers ([Chapter 18](../upstream-and-proxy/)). Now we cover the third leg: navra also sits between the agent and the **model** itself.

## The gap in frontier model security

Frontier model providers — Anthropic, OpenAI, Google — run safety systems on their side. They filter harmful outputs, detect abuse patterns, and enforce usage policies. These systems are good at what they can see: the content of the API request and response.

But they cannot see what happens on your machine. They don't know:

- What files the agent just read before crafting the prompt
- Whether the prompt contains your employees' names, your customers' addresses, or your database credentials
- Whether the response will be piped into a tool that executes shell commands
- Which agent is making the request, what permissions it has, or whether it's operating under a compromised prompt
- Whether the model's output will be stored in a shared context that other agents read

The provider sees an API call. You see the full pipeline: what went in, what came out, where it's going next, and who asked for it. This is the local trust boundary — and it's invisible to the provider.

## What the model proxy does

navra exposes two model proxy endpoints:

- `/v1/chat/completions` — OpenAI Chat Completions format
- `/v1/messages` — Anthropic Messages API format

Both pass through the same security pipeline. The agent connects to navra instead of connecting to the model provider directly. navra authenticates the agent, applies safety controls, forwards the request, inspects the response, and returns it to the agent.

```
Agent                  navra                     Model Provider
  │                      │                            │
  │── model request ────▶│                            │
  │                      │── authenticate agent       │
  │                      │── safety-filter inbound     │
  │                      │── inject persona (if any)   │
  │                      │                            │
  │                      │── forward request ────────▶│
  │                      │◀──────────── response ─────│
  │                      │                            │
  │                      │── safety-filter outbound    │
  │                      │── record to blackbox        │
  │                      │── meter tokens              │
  │                      │                            │
  │◀── filtered response │                            │
```

The agent and the provider both see a normal API interaction. Neither knows the other is mediated.

## PII filtering on prompts

This is the most consequential capability. When an agent sends a message to a frontier model, the prompt may contain data from tool results: file contents, search results, database records, user input. Any of this can contain PII.

Without navra, that PII goes directly to the model provider's API. The provider's logs may retain it. The model may echo it. Regulatory frameworks (GDPR, CCPA) apply to any PII that leaves your infrastructure.

With navra, inbound messages pass through the same privacy pipeline that filters tool results:

1. **Regex detectors** scan for structured PII: credit card numbers, SSNs, email addresses, phone numbers, IBANs, IP addresses. These run in microseconds.

2. **NER model** scans for unstructured PII: person names, organization names, locations. This catches "Please update John Miller's account in the Portland office" — PII that no regex would find.

3. **Privacy classifier** scores the overall text for privacy risk, catching patterns that individual detectors miss.

If a finding exceeds the configured threshold, navra either redacts the content (replacing PII with `[REDACTED:category]`) or blocks the request entirely. The model provider never receives the original PII.

This filtering is format-aware. For the Anthropic Messages API, navra iterates content blocks — text blocks are scanned, tool_use and tool_result blocks are inspected, image blocks are passed through. For OpenAI format, navra scans the `content` field of user and system messages. The filtering preserves the wire format exactly; only text content is modified.

## Outbound response filtering

The model's response passes through the same pipeline in reverse. If the model generates text containing PII — whether echoed from the prompt, hallucinated, or retrieved from its training data — navra catches it before the agent sees it.

Outbound filtering is particularly important for multi-agent systems. If Agent A asks a model to summarize a dataset and the model includes a customer's phone number in the summary, that phone number would propagate to Agent B, Agent C, and every downstream consumer of the summary. Outbound filtering at the model proxy layer stops the propagation at the source.

## Credential isolation

The agent authenticates to navra with a navra-issued token. navra authenticates to the model provider with the provider's credentials. These are completely separate:

- The agent's token (`mcd_...`) is a BLAKE3-hashed bearer token stored in navra's config. It identifies the agent and maps to a permission set.
- The provider's credential is either an API key (for direct Anthropic/OpenAI) or an OAuth token from Google Application Default Credentials (for Vertex AI).

The agent never sees the provider credential. If an agent is compromised — through prompt injection or a bug — the attacker gets a navra token that can only do what the permission set allows. They don't get the Anthropic API key, the Google OAuth refresh token, or any other upstream credential.

For Vertex AI specifically, navra reads the Application Default Credentials file, performs the OAuth token refresh over HTTPS, and caches the access token until 60 seconds before expiry. The refresh token never leaves navra's memory. The access token is never sent to the agent.

## Per-agent audit trail

Every model proxy request is recorded in navra's append-only, hash-chained blackbox:

- Which agent made the request
- What permission set was active
- What model was called
- The first 500 characters of the response
- Request duration
- Token usage (input, output, cached)

This audit trail is critical for:

**Cost attribution.** When multiple agents share an API key, the provider's billing shows aggregate usage. navra's metrics show per-agent token consumption, so you know which agent is burning through your Opus quota.

**Incident investigation.** If a model produces harmful output, the blackbox shows what went in (after safety filtering) and what came out (before delivery to the agent). Combined with the tool call audit, you have a complete timeline: what the agent read, what it sent to the model, what the model said, and what the agent did next.

**Compliance evidence.** Regulatory frameworks require evidence that PII processing is controlled and auditable. The blackbox provides machine-readable proof that every model interaction was authenticated, filtered, and recorded.

## Concurrency and quota controls

Model API calls are expensive. A runaway agent loop can burn thousands of dollars in minutes. navra applies the same concurrency and rate limiting to model proxy requests as it does to tool calls:

- **Per-agent concurrency limits** prevent a single agent from monopolizing the model. If `max_concurrent = 3`, the fourth concurrent request gets a `rate_limit_error`.
- **Token metering** tracks input, output, and cached tokens per agent. The metrics are available for alerting and dashboarding.

These controls share the same semaphore and quota engine as tool calls. An agent's total resource consumption — tools plus model calls — is bounded by a single configuration.

## Persona injection

navra's cognitive core can inject persona system prompts into model requests. When an agent sends an `x-persona` header (or includes a `persona:` prefix in the system prompt), navra assembles the persona's full system prompt and prepends it to the request.

This is useful for operators who want consistent agent behavior across models. A "code reviewer" persona carries the same instructions whether the backend is Claude, GPT-4, or a local Llama model. The persona is managed in navra's config, not hardcoded in the agent.

For the Anthropic Messages API, persona injection uses the top-level `system` field (either prepending to an existing string or inserting a text block at the beginning of an array). For OpenAI format, it inserts a system message at position 0.

## Streaming

Both proxy endpoints support streaming pass-through. When the agent sets `stream: true`, navra forwards the SSE event stream from the provider directly to the agent without buffering the full response.

There is a tradeoff: streaming responses bypass outbound safety filtering. The privacy pipeline requires the complete response text to run NER and classification models. Per-chunk filtering would miss patterns that span chunk boundaries. navra logs the streaming request for audit purposes but does not filter individual chunks.

If outbound filtering is critical for your deployment, disable streaming in the agent configuration. The agent receives the complete response after filtering, with slightly higher latency.

## Vertex AI specifics

For Vertex AI upstreams, navra handles several translation details that the Anthropic SDK normally manages:

- **URL construction.** The Anthropic Messages API uses a single endpoint (`/v1/messages`). Vertex AI requires a per-model URL with the format `projects/{id}/locations/{region}/publishers/anthropic/models/{model}:rawPredict`. navra constructs this dynamically from the model field in the request body.

- **Streaming URL.** Vertex uses `:streamRawPredict` for streaming and `:rawPredict` for non-streaming. navra selects the correct suffix automatically.

- **Body transformation.** Vertex requires `anthropic_version` in the request body (not just the header) and expects the `model` field to be absent (it's in the URL). navra moves the model to the URL and inserts the version.

- **Authentication.** Vertex uses Google OAuth, not API keys. navra obtains and caches tokens from Application Default Credentials.

These details are invisible to the agent. The agent sends a standard Anthropic Messages API request; navra translates it for Vertex.

## The complete picture

With the model proxy, navra covers both sides of the agent:

```
                         navra
                    ┌─────────────────┐
                    │                 │
Tools/MCP ◀────────│   Chokepoint    │◀──────── Agent
Servers            │   Pipeline      │
                    │                 │
Model    ◀─────────│   Model Proxy   │
Providers          │   Pipeline      │
                    │                 │
                    └─────────────────┘
```

Every input to the agent (tool results) and every output from the agent (model prompts) passes through navra's security pipeline. Every external service the agent talks to — whether it's a file server, a database MCP server, or a frontier model API — is mediated, authenticated, filtered, and audited.

This is the security architecture that no single component can provide on its own:

- The **model provider** filters at the API level but can't see your local data or agent permissions.
- The **MCP server** executes tools but can't enforce cross-server policies or filter content.
- The **agent framework** orchestrates work but trusts whatever the model and tools return.
- **navra** sits at the intersection of all three, enforcing policy where the data actually flows.

## What's next

navra handles tool calls within a single agent-server connection and model calls to external providers. But agents sometimes need to delegate tasks to other agents. In the next chapter, we look at the Agent-to-Agent (A2A) protocol and how navra bridges the two protocols.
