+++
title = "OpenAPI Bridge"
description = "Expose any REST API as MCP tools by pointing navra at an OpenAPI spec."
weight = 30
template = "docs/page.html"

[extra]
toc = true
+++

The OpenAPI bridge (`navra-openapi`) converts an OpenAPI 3.x
specification into MCP tools automatically. Point navra at a spec
URL or file, and every operation with an `operationId` becomes a
callable tool -- with typed parameters, method annotations, and
authentication handled transparently.

## How it works

1. navra fetches the OpenAPI spec (JSON or YAML, local or remote)
2. Each operation with an `operationId` becomes an MCP tool
3. Path/query parameters and request bodies become tool input properties
4. HTTP method determines tool annotations (read-only, destructive, idempotent)
5. When an agent calls the tool, navra builds the HTTP request and returns the response

Tool names are prefixed with the upstream name and sanitized:
`operationId: listPets` on upstream `petstore` becomes tool
`petstore_listpets`.

## Configuration

Add an OpenAPI upstream in `config.toml`:

```toml
[[upstream]]
name = "petstore"
openapi = "https://petstore.example.com/v1/openapi.json"

# Or a local file:
# openapi = "/etc/navra/specs/petstore.json"
```

### Authentication

#### Bearer token

```toml
[[upstream]]
name = "github"
openapi = "https://raw.githubusercontent.com/.../openapi.json"

[upstream.auth]
bearer = "ghp_your_token_here"
```

#### API key (header or query)

```toml
[[upstream]]
name = "weather"
openapi = "/etc/navra/specs/weather.json"

[upstream.auth.api_key]
name = "X-API-Key"
value = "your_api_key"
location = "header"   # or "query"
```

#### Basic auth

```toml
[[upstream]]
name = "internal"
openapi = "/etc/navra/specs/internal.json"

[upstream.auth.basic]
username = "admin"
password = "secret"
```

#### OAuth 2.0

navra supports OAuth 2.0 Authorization Code (with PKCE) and Client
Credentials flows. Tokens are cached, automatically refreshed on
expiry, and retried on 401/403.

```toml
[[upstream]]
name = "crm"
openapi = "https://crm.example.com/openapi.json"

[upstream.auth.oauth]
client_id = "navra-client"
client_secret = "your-secret"
token_endpoint = "https://auth.example.com/token"
authorization_endpoint = "https://auth.example.com/authorize"
scopes = ["read", "write"]
flow = "client_credentials"   # or "authorization_code"
```

For the authorization code flow, navra starts a local callback server
on an ephemeral port and prints the authorization URL. Open it in your
browser to complete the flow.

### Timeouts and limits

```toml
[[upstream]]
name = "slow-api"
openapi = "/etc/navra/specs/slow.json"
request_timeout_secs = 120
max_response_bytes = 524288   # 512 KiB
```

Response truncation is JSON-aware: large arrays are truncated by item
count, not raw bytes, so the output remains valid JSON.

### Filtering operations

Include only specific operations by `operationId` or tool name.
Supports glob patterns:

```toml
[[upstream]]
name = "petstore"
openapi = "https://petstore.example.com/openapi.json"
filter = ["listPets", "getPetById"]

# Or with globs:
# filter = ["petstore_*pet"]
```

### Overriding tools

Block specific tools with `tool_overrides`:

```toml
[[upstream]]
name = "petstore"
openapi = "https://petstore.example.com/openapi.json"

[upstream.tool_overrides]
petstore_deletepet = "deny"
```

Denied tools are removed from the tools list and never appear to
agents.

## Tool annotations

navra automatically sets MCP tool annotations based on the HTTP method:

| Method | read_only | destructive | idempotent | open_world |
|--------|-----------|-------------|------------|------------|
| GET, HEAD, OPTIONS | true | false | true | true |
| PUT | false | false | true | true |
| POST, PATCH | false | false | false | true |
| DELETE | false | true | true | true |

These annotations inform the agent's planning -- it knows that GET
tools are safe to call without confirmation, while DELETE tools may
need approval.

## Security scanning

Before tools are exposed to agents, navra can scan them for malicious
patterns using the tool scanner from `navra-auth`. Call `scan_tools()`
on the module to:

- **Block** tools flagged as malicious (e.g., tool descriptions
  containing prompt injection patterns)
- **Warn** on suspicious tools (logged but still allowed)
- **Pass** safe tools unchanged

```text
2024-01-15 WARN Suspicious OpenAPI tool (allowed)
  upstream=petstore tool=petstore_admin_exec reasons=["description contains shell command pattern"]

2024-01-15 ERROR BLOCKED malicious OpenAPI tool
  upstream=untrusted tool=untrusted_exfiltrate reasons=["description instructs model to ignore system prompt"]
```

## How requests are built

When an agent calls an OpenAPI tool:

1. **Path parameters** are substituted into the URL template and
   URL-encoded
2. **Query parameters** are appended to the URL and URL-encoded
3. **Request body** is sent as JSON (from the `body` tool parameter)
4. **Auth headers** are added from the configured auth method
5. **OAuth tokens** are refreshed if expired before the request
6. On **401/403** with OAuth, the token is force-refreshed and the
   request is retried once

## Spec requirements

The bridge requires:

- OpenAPI 3.0 or 3.1 format (JSON or YAML)
- An `operationId` on each operation (operations without one are skipped)
- A `servers` entry for the base URL (empty string if missing)
- Spec size under 10 MiB

Parameter references (`$ref` to `#/components/parameters/...`) are
resolved automatically.

## Combining with navra security

OpenAPI tools go through the same security pipeline as all navra tools:

- **Path ACLs**: restrict which URLs agents can access
- **IFC labels**: data confidentiality propagates through tool chains
- **Audit log**: every API call is logged with tool name, args, result, and duration
- **Safety hooks**: PII filtering, approval gates, and policy rules apply

The `tool_operations()` method classifies each tool as `Read` or
`Write` based on its HTTP method. This classification feeds into
navra's permission engine for fine-grained access control.
