---------------------- MODULE CapabilityDelegation ----------------------
(* Capability token delegation model for smgglrs.

   Proves that delegated tokens can only narrow parent permissions:
   ring attenuation, expiry attenuation, operation/credential subset.
   Transitive attenuation composes across delegation chains.

   Maps to smgglrs-security/src/auth/capability.rs (validate_delegation). *)

EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    MaxRing,        \* Highest ring level (e.g., 3)
    AllOperations,  \* Set of all possible operations
    AllCredentials, \* Set of all possible credentials
    MaxDepth        \* Maximum delegation chain depth

(* ---- Token structure ---- *)

Token == [
    ring: 0..MaxRing,
    exp: 0..1000,
    operations: SUBSET AllOperations,
    credentials: SUBSET AllCredentials,
    nonce: Nat,
    parent_nonce: Nat \cup {-1}  \* -1 = root (no parent)
]

VARIABLES
    tokens,             \* Set of valid tokens
    next_nonce          \* Monotonic nonce counter

vars == <<tokens, next_nonce>>

(* ---- Initial state: one root token ---- *)

Init ==
    /\ tokens = {[
        ring |-> 0,
        exp |-> 1000,
        operations |-> AllOperations,
        credentials |-> AllCredentials,
        nonce |-> 0,
        parent_nonce |-> -1
       ]}
    /\ next_nonce = 1

(* ---- Delegation action ---- *)

Delegate(parent, child_ring, child_exp, child_ops, child_creds) ==
    /\ parent \in tokens
    \* Attenuation preconditions (from validate_delegation)
    /\ child_ring >= parent.ring
    /\ child_exp <= parent.exp
    /\ child_ops \subseteq parent.operations
    /\ child_creds \subseteq parent.credentials
    /\ Cardinality(tokens) < 10  \* bound state space
    /\ LET child == [
            ring |-> child_ring,
            exp |-> child_exp,
            operations |-> child_ops,
            credentials |-> child_creds,
            nonce |-> next_nonce,
            parent_nonce |-> parent.nonce
           ]
       IN
        /\ tokens' = tokens \cup {child}
        /\ next_nonce' = next_nonce + 1

(* ---- State machine ---- *)

Next ==
    \E p \in tokens :
    \E r \in 0..MaxRing :
    \E e \in 0..1000 :
    \E ops \in SUBSET AllOperations :
    \E creds \in SUBSET AllCredentials :
        Delegate(p, r, e, ops, creds)

Spec == Init /\ [][Next]_vars

(* ---- Safety invariants ---- *)

(* Every child has ring >= its parent *)
NoRingEscalation ==
    \A child \in tokens : child.parent_nonce # -1 =>
        \A parent \in tokens : parent.nonce = child.parent_nonce =>
            child.ring >= parent.ring

(* Every child expires no later than its parent *)
NoExpiryExtension ==
    \A child \in tokens : child.parent_nonce # -1 =>
        \A parent \in tokens : parent.nonce = child.parent_nonce =>
            child.exp <= parent.exp

(* Every child's operations are a subset of its parent *)
NoOperationEscalation ==
    \A child \in tokens : child.parent_nonce # -1 =>
        \A parent \in tokens : parent.nonce = child.parent_nonce =>
            child.operations \subseteq parent.operations

(* Every child's credentials are a subset of its parent *)
NoCredentialEscalation ==
    \A child \in tokens : child.parent_nonce # -1 =>
        \A parent \in tokens : parent.nonce = child.parent_nonce =>
            child.credentials \subseteq parent.credentials

(* Transitive: grandchild is at most as privileged as grandparent *)
TransitiveAttenuation ==
    \A gc \in tokens : gc.parent_nonce # -1 =>
    \A child \in tokens : child.nonce = gc.parent_nonce /\ child.parent_nonce # -1 =>
    \A parent \in tokens : parent.nonce = child.parent_nonce =>
        /\ gc.ring >= parent.ring
        /\ gc.exp <= parent.exp
        /\ gc.operations \subseteq parent.operations
        /\ gc.credentials \subseteq parent.credentials

=========================================================================
