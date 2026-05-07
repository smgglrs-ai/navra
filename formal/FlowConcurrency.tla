---- MODULE FlowConcurrency ----
\* Models the smgglrs flow DAG execution engine to verify
\* that the global container count never exceeds max_parallel.
\*
\* Actors:
\*   - DAG loop (main flow): spawns batches of tasks
\*   - Escalation handler: spawns subflow tasks independently
\*   - GPU semaphore: limits concurrent container permits
\*
\* Property to verify:
\*   RunningContainers <= MaxParallel (invariant)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    MaxParallel,    \* Max concurrent containers (default: 2)
    NumTasks,       \* Total tasks in the DAG
    NumSubflows     \* Max concurrent escalation subflows

VARIABLES
    \* Main flow state
    pending,        \* Set of pending task IDs
    running,        \* Set of currently running task IDs
    completed,      \* Set of completed task IDs
    \* Semaphore
    permits,        \* Available semaphore permits
    \* Subflow state
    subflow_running \* Set of subflow tasks currently running

vars == <<pending, running, completed, permits, subflow_running>>

TypeOK ==
    /\ pending \subseteq 1..NumTasks
    /\ running \subseteq 1..NumTasks
    /\ completed \subseteq 1..NumTasks
    /\ permits \in 0..MaxParallel
    /\ subflow_running \subseteq (NumTasks+1)..(NumTasks+NumTasks)

Init ==
    /\ pending = 1..NumTasks
    /\ running = {}
    /\ completed = {}
    /\ permits = MaxParallel
    /\ subflow_running = {}

\* Main flow: spawn a task (acquire permit)
SpawnTask ==
    /\ pending /= {}
    /\ permits > 0
    /\ Cardinality(running) < MaxParallel
    /\ \E t \in pending :
        /\ pending' = pending \ {t}
        /\ running' = running \union {t}
        /\ permits' = permits - 1
        /\ UNCHANGED <<completed, subflow_running>>

\* Main flow: task completes (release permit)
CompleteTask ==
    /\ running /= {}
    /\ \E t \in running :
        /\ running' = running \ {t}
        /\ completed' = completed \union {t}
        /\ permits' = permits + 1
        /\ UNCHANGED <<pending, subflow_running>>

\* Escalation: spawn a subflow task (acquire permit)
SpawnSubflow ==
    /\ permits > 0
    /\ \E t \in (NumTasks+1)..(NumTasks+NumTasks) :
        /\ t \notin subflow_running
        /\ subflow_running' = subflow_running \union {t}
        /\ permits' = permits - 1
        /\ UNCHANGED <<pending, running, completed>>

\* Escalation: subflow task completes (release permit)
CompleteSubflow ==
    /\ subflow_running /= {}
    /\ \E t \in subflow_running :
        /\ subflow_running' = subflow_running \ {t}
        /\ permits' = permits + 1
        /\ UNCHANGED <<pending, running, completed>>

Next ==
    \/ SpawnTask
    \/ CompleteTask
    \/ SpawnSubflow
    \/ CompleteSubflow

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

\* ========================================
\* SAFETY PROPERTIES
\* ========================================

\* The core invariant: total running containers never exceeds MaxParallel
ConcurrencyBound ==
    Cardinality(running) + Cardinality(subflow_running) <= MaxParallel

\* Permits are always non-negative
PermitsNonNegative ==
    permits >= 0

\* Permits + running = MaxParallel (conservation)
PermitConservation ==
    permits + Cardinality(running) + Cardinality(subflow_running) = MaxParallel

\* ========================================
\* LIVENESS PROPERTIES
\* ========================================

\* All tasks eventually complete
AllTasksComplete ==
    <>(completed = 1..NumTasks)

\* No deadlock: if tasks remain, progress is possible
NoDeadlock ==
    [](pending /= {} => <>(Cardinality(completed) > Cardinality(completed)))

====
