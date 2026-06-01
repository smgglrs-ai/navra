# Agent & Tool Discovery — Landscape and Implications for navra

Research captured April 2026. This document surveys the emerging
discovery mechanisms for AI agents and tools, and outlines how navra
could participate in (and benefit from) this layer.

## The Problem

Today, connecting an AI agent to tools or other agents requires manual
configuration — endpoint URLs, transport types, authentication details,
all hardcoded in config files. There is no standard way for a client to
ask "what MCP servers exist on this network?" or "what agents can help
me with task X?" without already knowing where to look.

This is the discovery problem, and three complementary layers are
converging to solve it.

## Layer 1: DNS Discovery — "Where is the agent?"

### AID (Agent Identity & Discovery)

IETF Internet-Draft `draft-nemethi-aid-agent-identity-discovery-00`
(published March 2026, expires September 2026).

AID is intentionally minimal: a single DNS TXT record at
`_agent.<domain>` that points to an agent's endpoint and declares
its protocol. After discovery, richer protocols (MCP, A2A) take over.

**Record format** — semicolon-delimited key=value pairs:

```
_agent.example.com. 300 IN TXT "v=aid1;u=https://api.example.com/mcp;p=mcp;a=pat;s=Example AI Tools"
```

| Key | Name    | Required | Description                               |
|-----|---------|----------|-------------------------------------------|
| `v` | version | yes      | Must be `aid1`                            |
| `u` | uri     | yes      | HTTPS URL or local package locator        |
| `p` | proto   | yes      | Protocol token (see below)                |
| `a` | auth    | no       | Auth hint: none, pat, apikey, oauth2_code, mtls, ... |
| `s` | desc    | no       | Human-readable description (<=60 bytes)   |
| `d` | docs    | no       | Documentation URL                         |
| `e` | dep     | no       | ISO 8601 deprecation timestamp            |
| `k` | pka     | no       | Ed25519 public key (multibase-encoded)    |
| `i` | kid     | no       | Key rotation ID (required when `k` present) |

**Protocol tokens** — AID is protocol-agnostic:

| Token     | Protocol                    | URI scheme  |
|-----------|-----------------------------|-------------|
| `mcp`     | Model Context Protocol      | `https://`  |
| `a2a`     | Agent-to-Agent Protocol     | `https://`  |
| `openapi` | OpenAPI                     | `https://`  |
| `grpc`    | gRPC over HTTP/2 or HTTP/3  | `https://`  |
| `graphql` | GraphQL over HTTP           | `https://`  |
| `websocket` | WebSocket                 | `wss://`    |
| `local`   | Local execution             | `docker:`, `npx:`, `pip:` |
| `zeroconf`| mDNS/DNS-SD                 | `zeroconf:` |
| `ucp`     | Universal Commerce Protocol | `https://`  |

**Local execution example:**

```
_agent.grafana.com. 300 IN TXT "v=aid1;u=docker:grafana/mcp:latest;p=local;a=pat;s=Run Grafana agent locally"
```

**Endpoint proof (PKA):** Optional Ed25519 HTTP Message Signatures
(RFC 9421) to cryptographically verify that the endpoint belongs to
the domain. DNSSEC is recommended but not required.

**Fallback:** When DNS TXT records are unavailable (e.g., shared
hosting), clients can query `GET https://<domain>/.well-known/agent`
for equivalent JSON.

**Specification:** https://aid.agentcommunity.org/docs/specification
**IETF draft:** https://datatracker.ietf.org/doc/draft-nemethi-aid-agent-identity-discovery/

### Competing DNS Approaches

Two other IETF drafts exist in this space:

- **DNS-AID** (`draft-mozleywilliams-dnsop-dnsaid-00`): Uses SVCB
  records under structured namespaces like `_a2a._agents.example.com`.
  Richer than TXT but requires more DNS infrastructure. Supports
  mDNS/DNS-SD for local network discovery.

- **DNS-Native Agent Naming** (`draft-cui-dns-native-agent-naming-resolution-00`):
  FQDN-based agent identity with SVCB records and cryptographic keys
  published via DNS TXT.

AID is the simplest and most deployable of the three.

## Layer 2: Agent Discovery — "What can it do as a peer?"

### A2A Agent Cards

The Agent-to-Agent (A2A) protocol, created by Google and donated to
the Linux Foundation in June 2025, defines how agents discover and
communicate with each other.

The central discovery mechanism is the **Agent Card**: a JSON document
published at `/.well-known/agent-card.json` that declares:

- Agent name, description, and provider
- Skills (capabilities the agent offers)
- Supported modalities (text, audio, video)
- Streaming support
- Authentication requirements
- Protocol version and endpoint URL

**Agent Cards enable dynamic discovery.** A planning agent can query
an Agent Card registry to find capable sub-agents without hardcoded
knowledge. This is the mechanism that makes A2A suitable for enterprise
environments where specialized agents are deployed and updated
independently.

A2A v1.0 shipped with gRPC transport, **signed Agent Cards**
(cryptographic identity verification), and multi-tenancy support.

**Key distinction from MCP:** A2A treats agents as opaque peers that
delegate tasks to each other. MCP treats servers as transparent tool
providers. They are complementary — in Google's reference architecture,
inter-agent communication is A2A, tool invocation is MCP.

**Protocol:** https://github.com/a2aproject/A2A
**Announcement:** https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/

### ACP Merger

IBM's Agent Communication Protocol (ACP) merged into A2A under the
Linux Foundation in 2025. ACP's notable contribution was **metadata
embedded in distribution packages**, enabling discovery even when
agents are not running (scale-to-zero). This capability carries
forward into A2A.

## Layer 3: Tool Discovery — "What tools does it expose?"

### MCP Server Cards (In Progress)

The MCP project is developing **Server Cards**: structured metadata
documents exposed at `/.well-known/mcp.json`. Server Cards allow
clients to learn a server's capabilities, authentication requirements,
and available tools **without completing the full initialize handshake**.

This solves a real friction point — today, MCP clients must complete
the full JSON-RPC initialization sequence just to discover what tools
are available. Server Cards enable:

- Autoconfiguration
- Static security validation
- Registry crawling
- UI hydration with reduced latency

**Timeline:** Spec Enhancement Proposals (SEPs) targeting Q1 2026
finalization for the June 2026 specification release.

**Roadmap:** https://modelcontextprotocol.io/development/roadmap

### MCP Registry

The official MCP Registry (`registry.modelcontextprotocol.io`) is an
open catalog and API for publicly available MCP servers. It provides:

- Centralized discovery (self-reported server metadata)
- OpenAPI specification for sub-registries
- Community moderation (flag spam, malicious code, impersonation)
- Public and private sub-registry support

The **GitHub MCP Registry** auto-syncs from the community registry,
creating a unified discovery path. Developers self-publish MCP servers
to the OSS MCP Community Registry and they appear in both.

**Registry:** https://registry.modelcontextprotocol.io
**GitHub Registry:** https://github.blog/ai-and-ml/github-copilot/meet-the-github-mcp-registry-the-fastest-way-to-discover-mcp-servers/

## The Converging Stack

```
┌─────────────────────────────────────────────────┐
│          DNS Discovery (AID / DNS-AID)           │  "Where is the agent?"
│  _agent.example.com TXT → endpoint + protocol    │
├─────────────────────────────────────────────────┤
│        Agent Discovery (A2A Agent Cards)         │  "What can it do as a peer?"
│  /.well-known/agent-card.json → skills, auth     │
├─────────────────────────────────────────────────┤
│        Tool Discovery (MCP Server Cards)         │  "What tools does it expose?"
│  /.well-known/mcp.json → tools, resources        │
├─────────────────────────────────────────────────┤
│      Agent Communication (A2A, JSON-RPC 2.0)     │  "Delegate a task"
├─────────────────────────────────────────────────┤
│      Tool Invocation (MCP, Streamable HTTP)      │  "Call a tool"
└─────────────────────────────────────────────────┘
```

The layers do not compete. AID finds the endpoint, A2A negotiates
agent-level capabilities, MCP handles tool-level interaction. Each
protocol stays in its lane.

## Governance

All major protocols are now under the **Agentic AI Foundation (AAIF)**,
a directed fund under the Linux Foundation, co-founded by Anthropic,
Block, and OpenAI in December 2025.

| Protocol | Origin    | Contribution |
|----------|-----------|--------------|
| MCP      | Anthropic | Donated Dec 2025 |
| A2A      | Google    | Donated Jun 2025 |
| ACP      | IBM       | Merged into A2A  |
| goose    | Block     | Contributed      |
| AGENTS.md| OpenAI    | Contributed      |

As of April 2026, AAIF has grown to **170 members** across three tiers.

### MCP Dev Summit Findings (April 2026)

At the MCP Dev Summit in New York (April 6, 2026), maintainers from
Anthropic, AWS, Microsoft, and OpenAI shared key updates:

- **MCP fastest-growing standard ever**: RedMonk reports MCP achieved
  in ~13 weeks the adoption level Docker took ~13 months to reach.
- **Auth in active flux**: Authorization is the most actively changing
  part of the MCP spec. Maintainers are collaborating with Okta on
  authentication improvements.
- **Gateway validation**: "Gateways, registries, sandboxing,
  interceptors must evolve alongside the protocol" (David Soria Para,
  Anthropic). This directly validates navra's gateway architecture.
- **MCP should stay narrow**: Nick Cooper (OpenAI): "MCP should stay
  narrow — connecting AI to data sources. Identity, observability,
  and governance should come in as other projects" under AAIF.
- **AAIF accepting new project proposals**: github.com/aaif/project-proposals
  — first accepted projects should set the right direction.
- **MCP + A2A**: "Not directly competing. Approaches slightly
  different at the moment, but we are open to anything that makes the
  industry easier to work with through open standards."
- **Anti-pattern**: Don't just wrap 500 API endpoints as MCP tools.
  Design the MCP interface for agents as a new consumer class, not
  just another developer. Quality differs vastly between careful
  designs and naive API wrappers.

## Implications for navra

navra sits at the intersection of these layers — it is both an MCP
server (exposing tools to agents) and an MCP client (aggregating
upstream servers). This makes it a natural point for discovery
integration on both sides.

### Downstream: Make navra Discoverable

1. **MCP Server Card** — Serve `/.well-known/mcp.json` on the HTTP
   transport, advertising the aggregated tool set, auth requirements,
   and server capabilities. This lets clients autoconfigure without a
   full handshake.

2. **AID DNS record** — Publish an `_agent` TXT record pointing to
   the navra endpoint with `p=mcp`. For local-only deployments, the
   `.well-known/agent` JSON fallback works over the Unix socket or
   localhost TCP.

3. **A2A Agent Card** — If navra evolves toward A2A support, serve
   `/.well-known/agent-card.json` describing the combined capabilities
   of all upstream servers as skills.

### Upstream: Discover MCP Servers Dynamically

Today, upstream servers are manually configured in `config.toml`.
Discovery mechanisms could supplement this:

1. **AID lookup** — Given a domain, query `_agent.<domain>` to find
   MCP endpoints automatically. This could replace or augment the
   `[[upstream]]` config entries.

2. **Registry queries** — Query the MCP Registry API to discover
   servers matching specific tool categories or capabilities.

3. **Local network discovery** — Use mDNS/DNS-SD (the `zeroconf`
   protocol token in AID) to discover MCP servers on the local
   network. This is particularly relevant for navra's desktop-first
   deployment model.

### Security Considerations

- **AID PKA** aligns with navra's security posture — Ed25519 endpoint
  proof ensures discovered endpoints are legitimate.
- **Signed A2A Agent Cards** provide cryptographic identity verification
  for agent-to-agent scenarios.
- **MCP Server Cards** are static metadata and do not bypass navra's
  auth/ACL/safety layers — they describe capabilities, not grant access.
- Auto-discovered upstream servers should still be subject to the same
  per-tool rules, path ACLs, and content safety filters as manually
  configured ones.

## Key References

- AID Specification: https://aid.agentcommunity.org/docs/specification
- AID IETF Draft: https://datatracker.ietf.org/doc/draft-nemethi-aid-agent-identity-discovery/
- DNS-AID IETF Draft: https://www.ietf.org/archive/id/draft-mozleywilliams-dnsop-dnsaid-00.html
- MCP Roadmap: https://modelcontextprotocol.io/development/roadmap
- MCP 2026 Roadmap Blog: https://blog.modelcontextprotocol.io/posts/2026-mcp-roadmap/
- MCP Registry: https://blog.modelcontextprotocol.io/posts/2025-09-08-mcp-registry-preview/
- A2A Protocol: https://github.com/a2aproject/A2A
- A2A Announcement: https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/
- ACP (IBM): https://research.ibm.com/projects/agent-communication-protocol
- Protocol Ecosystem Map 2026: https://www.digitalapplied.com/blog/ai-agent-protocol-ecosystem-map-2026-mcp-a2a-acp-ucp
