# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in navra, please report it
responsibly. **Do not open a public GitHub issue.**

Email: **security@smgglrs.ai**

Include:

- Description of the vulnerability
- Steps to reproduce
- Affected component (crate name, module, or configuration)
- Impact assessment (what an attacker could achieve)

## Response Timeline

| Stage | Target |
|---|---|
| Acknowledgment | 48 hours |
| Initial assessment | 5 business days |
| Fix or mitigation | 30 days (critical), 90 days (other) |
| Public disclosure | After fix is released |

We will coordinate disclosure timing with you. If you want credit
in the advisory, let us know your preferred name/handle.

## Scope

The following are in scope:

- Authentication bypass (BLAKE3 tokens, capability tokens, DID:key)
- Permission engine bypass (path ACLs, tool rules, Cedar policies)
- Information Flow Control violations (label bypass, taint escape)
- Content safety filter bypass (regex, ML, NER pipelines)
- Path traversal past canonicalization
- Audit log tampering or omission
- Upstream MCP server proxy vulnerabilities
- Hook pipeline injection
- Memory or knowledge store data leakage

The following are out of scope:

- Denial of service via resource exhaustion (file descriptors, memory)
- Vulnerabilities in upstream MCP servers themselves (report to their maintainers)
- Social engineering
- Issues requiring physical access to the machine

## Security Architecture

navra enforces security at the gateway layer with multiple defense
mechanisms. For a detailed description of the security model, see
[DESIGN.md](DESIGN.md#security).

Key properties verified with formal methods:

- **138 Kani proofs** covering ACL evaluation, capability delegation,
  token verification, and IFC lattice operations
- **6 TLA+ specifications** covering flow concurrency, taint
  propagation, and deny-wins ACL semantics
- **Bell-LaPadula no-read-up** verified for IFC label enforcement
- **OWASP ASI 10/10** controls covered

See [formal/PROOF_MAP.md](formal/PROOF_MAP.md) for the full
verification artifact map.

## Supported Versions

navra is pre-1.0. Security fixes are applied to the `main` branch.
There are no stable release branches yet.

| Version | Supported |
|---|---|
| main (HEAD) | Yes |
| Older commits | No |
