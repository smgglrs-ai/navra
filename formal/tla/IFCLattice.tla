--------------------------- MODULE IFCLattice ---------------------------
(* Core lattice definitions for smgglrs IFC.

   Defines the 8-element DataLabel lattice (2 integrity × 4 confidentiality)
   and proves algebraic properties: commutativity, associativity,
   idempotency, monotonicity of join, and Bell-LaPadula no-write-down.

   These properties are also verified exhaustively on the Rust
   implementation via Kani bounded model checking (see PROOF_MAP.md).

   TLC checks all ASSUME statements at startup by exhaustive enumeration
   over the finite domains. *)

EXTENDS Integers, TLC

(* ---- Type definitions ---- *)

Integrity == {"Trusted", "Untrusted"}

Confidentiality == {"Public", "Sensitive", "Pii", "Secret"}

DataLabel == Integrity \X Confidentiality

(* ---- Ordering ---- *)

IntegrityOrd(i) == CASE i = "Trusted"   -> 0
                     [] i = "Untrusted" -> 1

ConfidentialityOrd(c) == CASE c = "Public"    -> 0
                          [] c = "Sensitive" -> 1
                          [] c = "Pii"       -> 2
                          [] c = "Secret"    -> 3

(* ---- Lattice join: element-wise max ---- *)

MaxIntegrity(a, b) == IF IntegrityOrd(a) >= IntegrityOrd(b) THEN a ELSE b

MaxConfidentiality(a, b) == IF ConfidentialityOrd(a) >= ConfidentialityOrd(b) THEN a ELSE b

Join(a, b) == <<MaxIntegrity(a[1], b[1]), MaxConfidentiality(a[2], b[2])>>

(* ---- Bell-LaPadula no-write-down ---- *)

CanWriteTo(label, target) == ConfidentialityOrd(label[2]) <= ConfidentialityOrd(target)

(* ---- Properties (checked exhaustively by TLC at startup) ---- *)

ASSUME \A a, b \in DataLabel : Join(a, b) = Join(b, a)

ASSUME \A a, b, c \in DataLabel : Join(Join(a, b), c) = Join(a, Join(b, c))

ASSUME \A a \in DataLabel : Join(a, a) = a

ASSUME \A a, b \in DataLabel :
    /\ IntegrityOrd(Join(a, b)[1]) >= IntegrityOrd(a[1])
    /\ ConfidentialityOrd(Join(a, b)[2]) >= ConfidentialityOrd(a[2])
    /\ IntegrityOrd(Join(a, b)[1]) >= IntegrityOrd(b[1])
    /\ ConfidentialityOrd(Join(a, b)[2]) >= ConfidentialityOrd(b[2])

ASSUME \A a, b \in DataLabel : \A t \in Confidentiality :
    (~CanWriteTo(a, t) \/ ~CanWriteTo(b, t)) =>
        ~CanWriteTo(Join(a, b), t)

ASSUME \A a \in DataLabel : \A b, c \in Confidentiality :
    (CanWriteTo(a, b) /\ ConfidentialityOrd(b) <= ConfidentialityOrd(c)) =>
        CanWriteTo(a, c)

(* ---- Trivial spec (TLC requires Init/Next) ---- *)

VARIABLE dummy
Init == dummy = TRUE
Next == UNCHANGED dummy

=========================================================================
