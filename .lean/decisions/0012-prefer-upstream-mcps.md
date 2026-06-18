# ADR-0012: Prefer Upstream MCP Servers Over Custom Modules

## Status

Accepted

## Context

navra could build custom tool modules for every service (GitHub,
GitLab, Jira, Google Workspace) or use existing MCP servers as
upstreams.

## Decision

Use existing MCP servers as upstreams before building custom navra
modules. Service-specific access control (token scopes, folder ACLs,
method denylists, read-only mode) belongs in the MCP server, not
in navra.

## Rationale

navra is a gateway, not a framework. Domain logic and service-specific
ACLs belong in upstream MCP servers. Building custom modules for every
service defeats the gateway architecture and duplicates safety
mechanisms that upstream servers already provide.

Reference pattern: mcp-google-workspace (TOML policy file + OAuth2
scopes handle safety at the server level, letting the gateway focus
on cross-cutting concerns).

## Consequences

- When a new integration is requested, search for existing MCP servers first.
- Only build a navra module when no MCP exists or when gateway-level
  features (PII detection, IFC taint tracking, audit logging) need deep
  integration that proxying cannot provide.
- NAVRA-045/046/047 were closed as wont_do under this decision.
- navra-tools-github is flagged for removal (NAVRA-072).
