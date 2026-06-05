<p align="center">
  <img src="https://raw.githubusercontent.com/smgglrs-ai/navra/main/assets/logo/logo-192.png" alt="smgglrs ai" width="96" />
</p>

<h3 align="center">smgglrs ai</h3>

<p align="center">
  Infrastructure for trustworthy AI agents
</p>

---

We build open-source security and orchestration tools for the
[MCP](https://modelcontextprotocol.io/) ecosystem. Our focus is
gateway-enforced security — authentication, access control,
content safety, and audit — so that AI agents can be trusted with
real-world tools.

### navra

Our flagship project. A secure MCP gateway daemon for Linux that
sits between AI agents and local resources.

- 22-crate Rust workspace
- Deny-wins ACLs with path canonicalization
- Information Flow Control with Bell-LaPadula verification
- In-process ML safety filters (ONNX, no GPU required)
- 138 Kani proofs, 6 TLA+ specs, OWASP ASI 10/10
- Multi-agent flows with IFC-gated mesh communication

**[Repository](https://github.com/smgglrs-ai/navra)** ·
**[Documentation](https://github.com/smgglrs-ai/navra/blob/main/CONFIG.md)** ·
**[Why navra?](https://github.com/smgglrs-ai/navra/blob/main/WHY-NAVRA.md)**

### Research

We publish peer-reviewed research on AI agent security:

- [Gateway-enforced IFC for AI agents](https://github.com/smgglrs-ai/navra/blob/main/docs/papers/security-gateway.md) — 138 Kani proofs, adversarial evaluation
- [Formal verification artifacts](https://github.com/smgglrs-ai/navra/blob/main/formal/PROOF_MAP.md) — TLA+ to Rust traceability

---

<p align="center">
  Apache-2.0 · Built in Rust
</p>
