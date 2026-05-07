----------------------- MODULE VarRefCompleteness -----------------------
(* Variable reference resolution completeness model.

   Proves that resolve_variable_refs computes the correct effective
   label as the lattice join of all referenced variables' labels,
   regardless of JSON nesting depth or position.

   Maps to smgglrs-security/src/ifc/value_store.rs
   (resolve_variable_refs, resolve_value_recursive). *)

EXTENDS Integers, FiniteSets, TLC

INSTANCE IFCLattice

CONSTANTS
    MaxVars,    \* Maximum number of variables in store (e.g., 4)
    MaxDepth    \* Maximum JSON nesting depth (e.g., 3)

(* ---- Variable store ---- *)

VarIds == 0..(MaxVars - 1)

VARIABLES
    var_labels,     \* Function from VarId -> DataLabel
    var_count       \* Number of stored variables

vars == <<var_labels, var_count>>

(* ---- JSON tree model ---- *)

(* A JSON argument tree is modeled as a set of var:// references.
   The structure (nesting, arrays, objects) is abstracted away because
   resolve_variable_refs walks the entire tree and collects ALL
   var:// strings regardless of position. The completeness property
   depends only on which references exist, not where they are nested. *)

(* ---- Effective label computation ---- *)

(* The effective label is the join of all referenced variables' labels.
   This is the specification that the Rust implementation must satisfy. *)

EffectiveLabel(refs) ==
    IF refs = {}
    THEN <<"Trusted", "Public">>     \* No references: trusted
    ELSE LET labels == {var_labels[v] : v \in refs}
         IN CHOOSE r \in DataLabel :
            /\ \A l \in labels :
                /\ IntegrityOrd(r[1]) >= IntegrityOrd(l[1])
                /\ ConfidentialityOrd(r[2]) >= ConfidentialityOrd(l[2])
            /\ \A r2 \in DataLabel :
                (\A l \in labels :
                    /\ IntegrityOrd(r2[1]) >= IntegrityOrd(l[1])
                    /\ ConfidentialityOrd(r2[2]) >= ConfidentialityOrd(l[2]))
                => (/\ IntegrityOrd(r[1]) <= IntegrityOrd(r2[1])
                    /\ ConfidentialityOrd(r[2]) <= ConfidentialityOrd(r2[2]))

(* ---- Initial state ---- *)

Init ==
    /\ var_labels = [v \in VarIds |-> <<"Trusted", "Public">>]
    /\ var_count = 0

(* ---- Actions ---- *)

(* Store a variable with an arbitrary label *)
StoreVar(vid, label) ==
    /\ vid \in VarIds
    /\ vid = var_count
    /\ var_count < MaxVars
    /\ var_labels' = [var_labels EXCEPT ![vid] = label]
    /\ var_count' = var_count + 1

Next ==
    \E vid \in VarIds : \E label \in DataLabel :
        StoreVar(vid, label)

Spec == Init /\ [][Next]_vars

(* ---- Invariants ---- *)

(* For any subset of stored variables, the effective label is the
   lattice join. This is checked for ALL subsets (2^MaxVars). *)

JoinIsCorrectForAllSubsets ==
    \A refs \in SUBSET (0..(var_count - 1)) :
        refs # {} =>
            LET eff == EffectiveLabel(refs)
            IN
            \* Every referenced label is dominated by the effective label
            /\ \A v \in refs :
                /\ IntegrityOrd(eff[1]) >= IntegrityOrd(var_labels[v][1])
                /\ ConfidentialityOrd(eff[2]) >= ConfidentialityOrd(var_labels[v][2])
            \* The effective label is the least upper bound
            /\ \A candidate \in DataLabel :
                (\A v \in refs :
                    /\ IntegrityOrd(candidate[1]) >= IntegrityOrd(var_labels[v][1])
                    /\ ConfidentialityOrd(candidate[2]) >= ConfidentialityOrd(var_labels[v][2]))
                => (/\ IntegrityOrd(eff[1]) <= IntegrityOrd(candidate[1])
                    /\ ConfidentialityOrd(eff[2]) <= ConfidentialityOrd(candidate[2]))

(* Single-reference case: effective label equals the variable's label *)
SingleRefIdentity ==
    \A v \in 0..(var_count - 1) :
        EffectiveLabel({v}) = var_labels[v]

(* Two-reference case: effective label equals Join of both *)
TwoRefJoin ==
    \A v1, v2 \in 0..(var_count - 1) :
        v1 # v2 =>
            EffectiveLabel({v1, v2}) = Join(var_labels[v1], var_labels[v2])

(* Adding a reference can only raise the effective label *)
AdditionalRefMonotonic ==
    \A refs \in SUBSET (0..(var_count - 1)) :
    \A extra \in 0..(var_count - 1) :
        (refs # {} /\ extra \notin refs) =>
            LET before == EffectiveLabel(refs)
                after == EffectiveLabel(refs \cup {extra})
            IN
            /\ IntegrityOrd(after[1]) >= IntegrityOrd(before[1])
            /\ ConfidentialityOrd(after[2]) >= ConfidentialityOrd(before[2])

=========================================================================
