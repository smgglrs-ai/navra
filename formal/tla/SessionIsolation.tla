------------------------ MODULE SessionIsolation ------------------------
(* Proves that session taint labels are isolated: absorbing a label
   in one session does not affect any other session.

   Also models expiration races: a session cannot be expired while a
   tool call is in flight, preventing stale/missing label reads.

   Maps to navra-core/src/session.rs (InMemorySessionBackend). *)

EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    Sessions,       \* Set of session IDs (e.g., {"s1", "s2", "s3"})
    MaxSteps        \* Max steps per session

VARIABLES
    labels,         \* Function: session ID -> DataLabel (as integer 0..7)
    active,         \* Set of currently active (non-expired) sessions
    in_flight,      \* Set of sessions with in-flight tool calls
    step_count

vars == <<labels, active, in_flight, step_count>>

Init ==
    /\ labels = [s \in Sessions |-> 0]  \* All sessions start at TRUSTED_PUBLIC (0)
    /\ active = Sessions                \* All sessions start active
    /\ in_flight = {}                   \* No in-flight calls initially
    /\ step_count = 0

(* Absorb a label into one session (lattice join = max) *)
Absorb(session, new_label) ==
    /\ step_count < MaxSteps
    /\ session \in active
    /\ new_label \in 0..7
    /\ labels' = [labels EXCEPT ![session] = IF new_label > labels[session]
                                             THEN new_label
                                             ELSE labels[session]]
    /\ step_count' = step_count + 1
    /\ UNCHANGED <<active, in_flight>>

(* Begin a tool call — reads the session's label *)
ToolCall(session) ==
    /\ session \in active
    /\ session \notin in_flight
    /\ step_count < MaxSteps
    /\ in_flight' = in_flight \union {session}
    /\ step_count' = step_count + 1
    /\ UNCHANGED <<labels, active>>

(* Complete a tool call *)
ToolCallComplete(session) ==
    /\ session \in in_flight
    /\ in_flight' = in_flight \ {session}
    /\ UNCHANGED <<labels, active, step_count>>

(* Expire a session — only if no tool call is in flight *)
Expire(session) ==
    /\ session \in active
    /\ session \notin in_flight
    /\ active' = active \ {session}
    /\ UNCHANGED <<labels, in_flight, step_count>>

Next ==
    \E s \in Sessions :
        \/ \E l \in 0..7 : Absorb(s, l)
        \/ ToolCall(s)
        \/ ToolCallComplete(s)
        \/ Expire(s)

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

(* A session with an in-flight tool call is never expired *)
InFlightNeverExpired ==
    \A s \in Sessions : s \in in_flight => s \in active

(* Every in-flight session has a valid label *)
ToolCallReadsValidLabel ==
    \A s \in in_flight : s \in active /\ labels[s] \in 0..7

=========================================================================
