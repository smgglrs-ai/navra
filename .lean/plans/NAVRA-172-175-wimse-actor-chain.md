# NAVRA-172 + NAVRA-175: WIMSE/SPIFFE Identity & Actor-Chain Delegation

## Context

navra's identity system currently supports DID:key (self-sovereign), BLAKE3 bearer tokens (local), capability tokens (Ed25519 signed with delegation), OAuth 2.1, and ID-JAG (enterprise JWT). However, both IETF agent identity drafts (AIMS and WIMSE AI Agent Identity) mandate WIMSE/SPIFFE identifiers — navra needs native support to be interoperable with the emerging enterprise agent identity ecosystem.

NAVRA-172 adds WIMSE/SPIFFE as a first-class identity type alongside DID:key. NAVRA-175 adds Uber-style actor-chain JWT tracking for multi-agent delegation lineage.

## Existing infrastructure to reuse

- **`OpenShellAuthenticator`** (`navra-auth/src/auth/openshell.rs`) — already verifies SPIFFE JWT-SVIDs via trust bundles. Has `verify_spiffe_jwt()`, `spiffe_id` field on claims, and a `spiffe_id_becomes_did` test. This is the foundation for NAVRA-172.
- **`CapabilityPayload`** (`navra-auth/src/auth/capability.rs`) — already has `obo: Option<OboIdentity>` and `parent: Option<[u8; 16]>` for delegation chains. Actor-chain (NAVRA-175) extends this.
- **`OAuthProvider::exchange_token`** (`navra-auth/src/auth/oauth.rs`) — already implements RFC 8693 token exchange with OBO identity embedding. Actor-chain JWT is the next step.
- **`ChainAuthenticator`** (`navra-auth/src/auth/chain.rs`) — composable auth chain. WIMSE authenticator slots in.
- **`AgentIdentity`** (`navra-auth/src/auth/mod.rs`) — has `did: Option<String>` field. WIMSE identifiers go here.

## NAVRA-172: WIMSE/SPIFFE Identity Support

### Step 1: Add `WimseIdentity` type

New file: `navra-auth/src/auth/wimse.rs`

```rust
pub struct WimseIdentity {
    /// SPIFFE ID (e.g., "spiffe://example.org/agent/analyst")
    pub spiffe_id: String,
    /// WIMSE workload identifier (may differ from SPIFFE ID)
    pub workload_id: Option<String>,
    /// Owner identity — the human or org this agent acts for (AIMS dual-identity)
    pub owner: Option<OwnerIdentity>,
}

pub struct OwnerIdentity {
    pub sub: String,
    pub iss: String,
    pub org: Option<String>,
}
```

This mirrors the AIMS draft's dual-identity model: agent identity (SPIFFE ID) + owner identity (human/org).

### Step 2: Add `WimseAuthenticator`

In `navra-auth/src/auth/wimse.rs`:

Accepts `Authorization: Bearer <JWT>` where the JWT contains:
- `sub`: SPIFFE ID (`spiffe://...`)
- `iss`: Identity provider
- `aud`: navra gateway identifier
- `wimse_id`: WIMSE workload identifier (optional)
- `owner`: nested claim with owner identity (AIMS dual-identity)
- `act_chain`: actor chain (for NAVRA-175, optional)

Verification:
1. Decode JWT header → get `kid`
2. Fetch JWKS from configured providers (reuse `JwksCache` from `openshell.rs`)
3. Verify signature
4. Validate `iss` against trusted provider list
5. Validate `aud` matches gateway identity
6. Check expiry
7. Map to `AgentIdentity` with `did` = SPIFFE ID

Config:
```json
{
  "wimse_auth": {
    "enabled": true,
    "trusted_providers": [
      {
        "name": "corporate-spire",
        "issuer": "https://spire.corp.example.com",
        "jwks_uri": "https://spire.corp.example.com/keys",
        "audience": "spiffe://example.org/navra",
        "default_permissions": "enterprise"
      }
    ],
    "accept_spiffe_svid": true
  }
}
```

### Step 3: Extend `AgentIdentity` with WIMSE fields

Add to `AgentIdentity` in `navra-auth/src/auth/mod.rs`:
```rust
pub wimse: Option<WimseIdentity>,
```

This is in addition to `did: Option<String>` — agents can have both (bridged identities).

### Step 4: Add WIMSE → DID bridging

Utility function in `wimse.rs`:
```rust
pub fn spiffe_to_did(spiffe_id: &str) -> String {
    // spiffe://example.org/agent/analyst → did:web:example.org:agent:analyst
    format!("did:web:{}", spiffe_id
        .strip_prefix("spiffe://").unwrap_or(spiffe_id)
        .replace('/', ":"))
}
```

This lets capability tokens reference WIMSE agents by DID when the underlying identity is SPIFFE.

### Step 5: Wire into `ChainAuthenticator`

In `navra-server/src/setup/auth.rs`, add `WimseAuthenticator` to the chain when `wimse_auth` is configured. Insert before ID-JAG and after capability auth.

Add `wimse_auth: Option<WimseAuthConfig>` to `ServerConfig`.

**Commit: "feat(auth): add WIMSE/SPIFFE identity support (NAVRA-172)"**

## NAVRA-175: Actor-Chain JWT Delegation

### Step 6: Define `ActorChainEntry`

In `navra-auth/src/auth/capability.rs`:
```rust
pub struct ActorChainEntry {
    pub sub: String,       // Agent identity (SPIFFE ID or DID)
    pub agent_id: String,  // Unique agent instance identifier
    pub iat: u64,          // When this agent joined the chain
    pub permissions: String, // Permission set at this level
}
```

### Step 7: Add `act_chain` to `CapabilityPayload`

Add to `CapabilityPayload`:
```rust
#[serde(default, skip_serializing_if = "Vec::is_empty")]
pub act_chain: Vec<ActorChainEntry>,
```

### Step 8: Chain extension on delegation

Modify `build_delegated_payload()` (or add a new function) in `capability.rs`:

When agent A delegates to agent B through the gateway:
1. Clone parent's `act_chain`
2. Append new entry for agent A (the delegator)
3. Set in the child payload

This gives agent B's token a complete lineage of who delegated what.

### Step 9: Chain-aware authorization

Add to the authorization path in `navra-core/src/server/handlers.rs`:

When evaluating tool calls, the permission system can now check:
- "Only allow if chain includes an agent with permissions X"
- "Deny if chain depth exceeds N"
- "Require chain to originate from a WIMSE-identified agent"

Config via permission set:
```json
{
  "chain_policy": {
    "max_depth": 5,
    "require_wimse_root": false,
    "required_ancestors": []
  }
}
```

### Step 10: Actor-chain in flow delegation

In `navra-server/src/flow_execution.rs` and `agent_spawn.rs`:

When a flow spawns a sub-agent, extend the actor chain in the delegated capability token. The flow node's identity becomes an entry in the chain.

**Commit: "feat(auth): add actor-chain JWT delegation tracking (NAVRA-175)"**

## Step 11: Blackbox audit integration

Log `act_chain` in blackbox entries so the audit trail shows the full delegation lineage for every tool call. Add `act_chain: Option<Vec<ActorChainEntry>>` to `BlackboxEntry`.

**Same commit as Step 10.**

## File Change Summary

| Area | Files | Nature |
|---|---|---|
| WIMSE identity | New `navra-auth/src/auth/wimse.rs` | Core new module |
| Agent identity | `navra-auth/src/auth/mod.rs` | Add `wimse` field |
| Capability tokens | `navra-auth/src/auth/capability.rs` | Add `act_chain` field + chain extension |
| Config | `navra-server/src/config/server.rs` | Add `wimse_auth` section |
| Auth wiring | `navra-server/src/setup/auth.rs` | Wire WIMSE into chain |
| Flow delegation | `navra-server/src/flow_execution.rs`, `agent_spawn.rs` | Extend chain on spawn |
| Server handlers | `navra-core/src/server/handlers.rs` | Chain-aware auth checks |
| Blackbox | `navra-core/src/blackbox.rs` | Log act_chain |
| Tests | `navra-auth/src/auth/wimse.rs`, `capability.rs` | Unit + integration |

## Verification

1. `cargo test -p navra-auth` — all existing tests pass + new WIMSE/chain tests
2. `just test-workspace` — no regressions
3. Verify: WIMSE JWT with SPIFFE ID authenticates and maps to correct permissions
4. Verify: capability token delegation appends to actor chain
5. Verify: chain depth limit enforced
6. Verify: blackbox entries include actor chain
7. Verify: existing DID:key and BLAKE3 auth unchanged
