------------------------ MODULE SessionIsolation ------------------------
(* Proves that session taint labels are isolated: absorbing a label
   in one session does not affect any other session.

   Maps to smgglrs-core/src/session.rs (InMemorySessionBackend). *)

EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Sessions,       \* Set of session IDs (e.g., {"s1", "s2", "s3"})
    MaxSteps        \* Max steps per session

VARIABLES
    labels,         \* Function: session ID -> DataLabel (as integer 0..7)
    step_count

vars == <<labels, step_count>>

Init ==
    /\ labels = [s \in Sessions |-> 0]  \* All sessions start at TRUSTED_PUBLIC (0)
    /\ step_count = 0

(* Absorb a label into one session (lattice join = max) *)
Absorb(session, new_label) ==
    /\ step_count < MaxSteps
    /\ session \in Sessions
    /\ new_label \in 0..7
    /\ labels' = [labels EXCEPT ![session] = IF new_label > labels[session]
                                             THEN new_label
                                             ELSE labels[session]]
    /\ step_count' = step_count + 1

Next ==
    \E s \in Sessions : \E l \in 0..7 : Absorb(s, l)

(* ---- Invariants ---- *)

(* No session's label is affected by another session's absorb.
   After absorbing into session S, all other sessions are unchanged. *)
SessionsIsolated ==
    [][
        \A s1, s2 \in Sessions :
            s1 # s2 =>
                (labels'[s1] # labels[s1] => labels'[s2] = labels[s2])
    ]_labels

(* Each session's label only increases (monotonicity per session) *)
PerSessionMonotonicity ==
    [][\A s \in Sessions : labels'[s] >= labels[s]]_labels

=========================================================================
