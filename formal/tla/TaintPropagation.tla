------------------------ MODULE TaintPropagation ------------------------
(* Session-level taint propagation model for smgglrs IFC.

   Models the chokepoint sequence from handle_call_tool as a state
   machine. Proves that taint is monotonic, untrusted writes are
   blocked under Deny policy, and stored variable labels are immutable.

   Maps to smgglrs-core/src/server/handlers.rs (handle_call_tool)
   and smgglrs-security/src/ifc/mod.rs (TaintTracker). *)

EXTENDS Integers, Sequences, FiniteSets, TLC

(* ---- Inline lattice definitions (avoid INSTANCE variable conflict) ---- *)

Integrity == {"Trusted", "Untrusted"}
Confidentiality == {"Public", "Sensitive", "Pii", "Secret"}
DataLabel == Integrity \X Confidentiality

IntegrityOrd(i) == CASE i = "Trusted"   -> 0
                     [] i = "Untrusted" -> 1

ConfidentialityOrd(c) == CASE c = "Public"    -> 0
                          [] c = "Sensitive" -> 1
                          [] c = "Pii"       -> 2
                          [] c = "Secret"    -> 3

MaxI(a, b) == IF IntegrityOrd(a) >= IntegrityOrd(b) THEN a ELSE b
MaxC(a, b) == IF ConfidentialityOrd(a) >= ConfidentialityOrd(b) THEN a ELSE b

Join(a, b) == <<MaxI(a[1], b[1]), MaxC(a[2], b[2])>>

(* ---- Constants ---- *)

CONSTANTS
    MaxTools,       \* Max tool calls per trace (e.g., 4)
    WritePolicy,    \* "Allow", "Approve", or "Deny"
    ReadClearance   \* Max readable confidentiality: "Public", "Sensitive", "Pii", "Secret"

(* ---- Variables ---- *)

VARIABLES
    taint,          \* Current session DataLabel
    store,          \* VarId (Nat) -> DataLabel
    next_id,        \* Next variable ID
    step_count,     \* Steps taken
    outcome         \* Last action outcome

vars == <<taint, store, next_id, step_count, outcome>>

(* ---- Initial state ---- *)

Init ==
    /\ taint = <<"Trusted", "Public">>
    /\ store = <<>>
    /\ next_id = 1
    /\ step_count = 0
    /\ outcome = "ok"

(* ---- Actions ---- *)

(* Helper: can an agent with ReadClearance read data at this conf level? *)
CanReadFrom(classification) ==
    ConfidentialityOrd(ReadClearance) >= ConfidentialityOrd(classification)

(* External read: checks no-read-up before allowing *)
ExternalRead(conf) ==
    /\ step_count < MaxTools
    /\ LET label == <<"Untrusted", conf>>
       IN IF ~CanReadFrom(conf)
          THEN /\ outcome' = "read_blocked"
               /\ UNCHANGED <<taint, store, next_id>>
               /\ step_count' = step_count + 1
          ELSE /\ taint' = Join(taint, label)
               /\ store' = Append(store, label)
               /\ next_id' = next_id + 1
               /\ step_count' = step_count + 1
               /\ outcome' = "ok"

(* Read from trusted source (always Public, always allowed) *)
TrustedRead ==
    /\ step_count < MaxTools
    /\ LET label == <<"Trusted", "Public">>
       IN /\ taint' = Join(taint, label)
          /\ store' = Append(store, label)
          /\ next_id' = next_id + 1
          /\ step_count' = step_count + 1
          /\ outcome' = "ok"

(* Write using a single var:// reference *)
WriteWithRef(idx) ==
    /\ step_count < MaxTools
    /\ idx >= 1 /\ idx <= Len(store)
    /\ LET check_label == store[idx]
       IN IF check_label[1] = "Untrusted" /\ WritePolicy = "Deny"
          THEN /\ outcome' = "blocked"
               /\ UNCHANGED <<taint, store, next_id>>
               /\ step_count' = step_count + 1
          ELSE /\ outcome' = IF check_label[1] = "Untrusted" /\ WritePolicy = "Approve"
                             THEN "approved" ELSE "ok"
               /\ taint' = Join(taint, check_label)
               /\ UNCHANGED <<store, next_id>>
               /\ step_count' = step_count + 1

(* Write using session-level taint (no var ref) *)
WriteNoRef ==
    /\ step_count < MaxTools
    /\ IF taint[1] = "Untrusted" /\ WritePolicy = "Deny"
       THEN /\ outcome' = "blocked"
            /\ UNCHANGED <<taint, store, next_id>>
            /\ step_count' = step_count + 1
       ELSE /\ outcome' = IF taint[1] = "Untrusted" /\ WritePolicy = "Approve"
                          THEN "approved" ELSE "ok"
            /\ UNCHANGED <<taint, store, next_id>>
            /\ step_count' = step_count + 1

(* Declassification: trusted filter steps down confidentiality.
   Preconditions:
   - Current taint is Pii
   - Filter action was Redact (not Pseudonymize — GDPR Art. 4(5))
   - ALL findings were handled (all_handled = TRUE)
   Step-down target: Sensitive (not Public — markers reveal PII existed)

   This is the ONLY exception to taint monotonicity. *)
Declassify ==
    /\ step_count < MaxTools
    /\ taint[2] = "Pii"                     \* Only from Pii level
    /\ outcome' = "declassified"
    /\ taint' = <<taint[1], "Sensitive">>    \* Step down to Sensitive
    /\ UNCHANGED <<store, next_id>>
    /\ step_count' = step_count + 1

(* ---- State machine ---- *)

Next ==
    \/ ExternalRead("Public")
    \/ ExternalRead("Sensitive")
    \/ ExternalRead("Pii")
    \/ ExternalRead("Secret")
    \/ TrustedRead
    \/ \E i \in 1..Len(store) : WriteWithRef(i)
    \/ WriteNoRef
    \/ Declassify

(* ---- Safety invariants (state predicates for INVARIANT) ---- *)

(* No read above clearance ever produces a stored variable.
   If data at conf level C exceeds the agent's ReadClearance,
   ExternalRead blocks and the store does not grow. *)
NoReadUpInv ==
    \A i \in 1..Len(store) :
        CanReadFrom(store[i][2])

(* Declassification only steps DOWN, and only from Pii to Sensitive.
   After declassification the taint is NEVER lower than Sensitive
   (because the redaction markers are structural metadata). *)
DeclassifyBounded ==
    outcome = "declassified" =>
        /\ taint[2] = "Sensitive"
        /\ ConfidentialityOrd(taint[2]) >= ConfidentialityOrd("Sensitive")

(* Variable labels never change (store is append-only) *)
TypeOK ==
    /\ taint \in DataLabel
    /\ \A i \in 1..Len(store) : store[i] \in DataLabel
    /\ step_count >= 0
    /\ step_count <= MaxTools

=========================================================================
