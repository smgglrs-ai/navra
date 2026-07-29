//! Integration tests for mesh communication primitives.
//!
//! Tests cross-primitive interactions: IFC propagation across mailbox
//! and blackboard, back-edge lifecycle with conditional re-execution,
//! concurrent blackboard access, and TOML deserialization of mesh config.

use navra_auth::ifc::TaintTracker;
use navra_flow::{
    BackEdgeTracker, Blackboard, ConditionalEdge, EdgeCondition, FlowError, MailboxRegistry,
    TaskResult, TaskStatus,
};
use navra_protocol::label::{Confidentiality, DataLabel};

// ── TOML deserialization of mesh config ──

#[test]
fn flow_toml_deserializes_mesh_config() {
    let toml_str = r#"
[flow]
name = "mesh"
entry = "a"
mailbox_capacity = 32
blackboard_capacity = 128

[[flow.nodes]]
id = "a"
endpoint = "http://localhost:3000/mcp"
model_url = "http://localhost:11434/v1"
model_name = "granite3.3:8b"
clearance = "sensitive"

[[flow.nodes]]
id = "b"
endpoint = "http://localhost:3000/mcp"
model_url = "http://localhost:11434/v1"
model_name = "granite3.3:8b"
clearance = "public"
"#;
    let def: navra_flow::FlowDefinition = toml::from_str(toml_str).unwrap();
    assert_eq!(def.flow.mailbox_capacity, Some(32));
    assert_eq!(def.flow.blackboard_capacity, Some(128));
    assert_eq!(def.flow.nodes[0].clearance.as_deref(), Some("sensitive"));
    assert_eq!(def.flow.nodes[1].clearance.as_deref(), Some("public"));
}

#[test]
fn dag_toml_deserializes_back_edges() {
    let toml_str = r#"
[dag]
name = "iterative_audit"
blackboard_capacity = 64

[[dag.tasks]]
id = "analyze"
specialist = "analyst"
mandate = "Analyze the codebase"

[[dag.tasks]]
id = "fix"
specialist = "developer"
mandate = "Fix the issues"
depends_on = ["analyze"]

[[dag.tasks.back_edges]]
target = "analyze"
condition = "score_below:70"
max_iterations = 3
"#;
    let def: navra_flow::DagDefinition = toml::from_str(toml_str).unwrap();
    assert_eq!(def.dag.blackboard_capacity, Some(64));
    let be = &def.dag.tasks[1].back_edges[0];
    assert_eq!(be.target, "analyze");
    assert_eq!(be.condition, "score_below:70");
    assert_eq!(be.max_iterations, 3);
}

#[test]
fn back_edge_definition_defaults_to_always_with_3_iterations() {
    let toml_str = r#"
[dag]
name = "defaults"

[[dag.tasks]]
id = "a"
specialist = "dev"
mandate = "Do A"

[[dag.tasks]]
id = "b"
specialist = "dev"
mandate = "Do B"
depends_on = ["a"]

[[dag.tasks.back_edges]]
target = "a"
"#;
    let def: navra_flow::DagDefinition = toml::from_str(toml_str).unwrap();
    let be = &def.dag.tasks[1].back_edges[0];
    assert_eq!(be.condition, "always");
    assert_eq!(be.max_iterations, 3);
}

// ── Blackboard + Mailbox: cross-primitive IFC propagation ──

#[test]
fn tainted_blackboard_reader_cannot_post_to_public_mailbox() {
    // Scenario: agent reads sensitive data from blackboard, then tries
    // to post to a Public-clearance agent's mailbox. IFC must block.

    let bb = Blackboard::new(10);
    bb.publish(
        "vault",
        "credentials",
        serde_json::json!("secret"),
        DataLabel::UNTRUSTED_SENSITIVE,
    )
    .unwrap();

    // Agent reads sensitive entry → taint rises
    let mut taint = TaintTracker::new();
    bb.read("credentials", &mut taint).unwrap();
    assert_eq!(taint.level(), DataLabel::UNTRUSTED_SENSITIVE);

    // Now try to post via mailbox using the tainted label
    let ids = vec!["tainted_agent".to_string(), "clean_agent".to_string()];
    let reg = MailboxRegistry::new(&ids, 16);

    let err = reg
        .post("tainted_agent", taint.level(), "clean_agent", "leak".into())
        .unwrap_err();
    assert!(matches!(err, FlowError::IfcViolation { .. }));
}

#[test]
fn tainted_blackboard_reader_can_post_to_sensitive_mailbox() {
    // Same scenario, but target has Sensitive clearance → allowed.

    let bb = Blackboard::new(10);
    bb.publish(
        "vault",
        "credentials",
        serde_json::json!("secret"),
        DataLabel::UNTRUSTED_SENSITIVE,
    )
    .unwrap();

    let mut taint = TaintTracker::new();
    bb.read("credentials", &mut taint).unwrap();

    let ids = vec!["tainted_agent".to_string(), "secure_agent".to_string()];
    let mut reg = MailboxRegistry::new(&ids, 16);
    reg.set_clearance("secure_agent", Confidentiality::Sensitive);

    reg.post(
        "tainted_agent",
        taint.level(),
        "secure_agent",
        "sensitive data".into(),
    )
    .unwrap();

    let msg = reg.recv("secure_agent").unwrap();
    assert_eq!(msg.body.text(), "sensitive data");
    assert_eq!(msg.label, DataLabel::UNTRUSTED_SENSITIVE);
}

// ── Blackboard taint lattice walk ──

#[test]
fn blackboard_taint_rises_monotonically_through_multiple_reads() {
    let bb = Blackboard::new(10);

    bb.publish(
        "sys",
        "config",
        serde_json::json!("safe"),
        DataLabel::TRUSTED_PUBLIC,
    )
    .unwrap();
    bb.publish(
        "net",
        "external",
        serde_json::json!("from network"),
        DataLabel::UNTRUSTED_PUBLIC,
    )
    .unwrap();
    bb.publish(
        "vault",
        "secret",
        serde_json::json!("classified"),
        DataLabel::UNTRUSTED_SENSITIVE,
    )
    .unwrap();

    let mut taint = TaintTracker::new();
    assert_eq!(taint.level(), DataLabel::TRUSTED_PUBLIC);

    // Each read can only raise taint, never lower it
    bb.read("config", &mut taint).unwrap();
    assert_eq!(taint.level(), DataLabel::TRUSTED_PUBLIC);

    bb.read("external", &mut taint).unwrap();
    assert_eq!(taint.level(), DataLabel::UNTRUSTED_PUBLIC);

    bb.read("secret", &mut taint).unwrap();
    assert_eq!(taint.level(), DataLabel::UNTRUSTED_SENSITIVE);

    // Reading lower-level data doesn't reset taint
    bb.read("config", &mut taint).unwrap();
    assert_eq!(taint.level(), DataLabel::UNTRUSTED_SENSITIVE);
}

// ── Blackboard concurrent writes ──

#[test]
fn blackboard_handles_concurrent_writes_from_multiple_threads() {
    use std::sync::Arc;

    let bb = Arc::new(Blackboard::new(100));
    let mut handles = vec![];

    for i in 0..10 {
        let bb_clone = Arc::clone(&bb);
        handles.push(std::thread::spawn(move || {
            bb_clone
                .publish(
                    &format!("agent_{i}"),
                    &format!("key_{i}"),
                    serde_json::json!(i),
                    DataLabel::TRUSTED_PUBLIC,
                )
                .unwrap();
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(bb.len(), 10);
    for i in 0..10 {
        let mut taint = TaintTracker::new();
        let entry = bb.read(&format!("key_{i}"), &mut taint).unwrap();
        assert_eq!(entry.author, format!("agent_{i}"));
    }
}

// ── Blackboard concurrent stress (100 threads) ──

#[test]
fn stress_100_concurrent_blackboard_writes() {
    use std::collections::HashSet;
    use std::sync::Arc;

    let bb = Arc::new(Blackboard::new(1000));
    let handles: Vec<_> = (0..100)
        .map(|i| {
            let bb_clone = Arc::clone(&bb);
            std::thread::spawn(move || {
                bb_clone
                    .publish(
                        &format!("agent_{i}"),
                        &format!("key_{i}"),
                        serde_json::json!(i),
                        DataLabel::TRUSTED_PUBLIC,
                    )
                    .unwrap();
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread must not panic");
    }

    assert_eq!(bb.len(), 100);

    // Verify all 100 unique authors are present
    let snapshot = bb.snapshot();
    let authors: HashSet<&str> = snapshot.values().map(|e| e.author.as_str()).collect();
    assert_eq!(authors.len(), 100);
    for i in 0..100 {
        assert!(authors.contains(format!("agent_{i}").as_str()));
    }
}

// ── Back-edge lifecycle ──

#[test]
fn back_edge_activates_on_low_score_and_exhausts_at_max() {
    let edge = ConditionalEdge {
        from: "review".to_string(),
        to: "implement".to_string(),
        condition: EdgeCondition::ScoreBelow(80.0),
        max_iterations: 2,
    };

    let mut tracker = BackEdgeTracker::new();

    let result_low = TaskResult {
        task_id: "review".to_string(),
        status: TaskStatus::Complete,
        output: "Needs improvement".to_string(),
        prompt_tokens: 0,
        completion_tokens: 0,
        taint: DataLabel::TRUSTED_PUBLIC,
        validation_score: Some(50.0),
        validation_notes: vec!["Missing error handling".to_string()],
    };

    // Activates twice (max_iterations=2)
    assert!(tracker.should_activate(&edge, &result_low));
    tracker.record_activation("review", "implement");
    assert!(tracker.should_activate(&edge, &result_low));
    tracker.record_activation("review", "implement");

    // Exhausted
    assert!(!tracker.should_activate(&edge, &result_low));
}

#[test]
fn back_edge_does_not_activate_on_high_score() {
    let edge = ConditionalEdge {
        from: "review".to_string(),
        to: "implement".to_string(),
        condition: EdgeCondition::ScoreBelow(80.0),
        max_iterations: 5,
    };

    let tracker = BackEdgeTracker::new();

    let result_high = TaskResult {
        task_id: "review".to_string(),
        status: TaskStatus::Complete,
        output: "Looks good".to_string(),
        prompt_tokens: 0,
        completion_tokens: 0,
        taint: DataLabel::TRUSTED_PUBLIC,
        validation_score: Some(95.0),
        validation_notes: vec![],
    };

    assert!(!tracker.should_activate(&edge, &result_high));
}

#[test]
fn back_edge_output_contains_matches_error_patterns() {
    let edge = ConditionalEdge {
        from: "test".to_string(),
        to: "fix".to_string(),
        condition: EdgeCondition::OutputContains("FAILED".to_string()),
        max_iterations: 3,
    };

    let tracker = BackEdgeTracker::new();

    let result_fail = TaskResult {
        task_id: "test".to_string(),
        status: TaskStatus::Complete,
        output: "3 tests FAILED, 7 passed".to_string(),
        prompt_tokens: 0,
        completion_tokens: 0,
        taint: DataLabel::TRUSTED_PUBLIC,
        validation_score: Some(70.0),
        validation_notes: vec![],
    };
    assert!(tracker.should_activate(&edge, &result_fail));

    let result_pass = TaskResult {
        output: "10 tests passed".to_string(),
        ..result_fail
    };
    assert!(!tracker.should_activate(&edge, &result_pass));
}

// ── Mailbox multi-agent message ordering ──

#[test]
fn mailbox_preserves_message_order_from_multiple_senders() {
    let ids = vec![
        "alice".to_string(),
        "bob".to_string(),
        "carol".to_string(),
        "dave".to_string(),
    ];
    let reg = MailboxRegistry::new(&ids, 16);

    // Multiple agents post to dave in order
    reg.post("alice", DataLabel::TRUSTED_PUBLIC, "dave", "msg 1".into())
        .unwrap();
    reg.post("bob", DataLabel::TRUSTED_PUBLIC, "dave", "msg 2".into())
        .unwrap();
    reg.post("carol", DataLabel::TRUSTED_PUBLIC, "dave", "msg 3".into())
        .unwrap();

    let msgs = reg.recv_all("dave");
    assert_eq!(msgs.len(), 3);
    assert_eq!(msgs[0].sender, "alice");
    assert_eq!(msgs[0].body.text(), "msg 1");
    assert_eq!(msgs[1].sender, "bob");
    assert_eq!(msgs[1].body.text(), "msg 2");
    assert_eq!(msgs[2].sender, "carol");
    assert_eq!(msgs[2].body.text(), "msg 3");
}

// ── Mailbox: IFC labels propagate through messages ──

#[test]
fn mailbox_message_carries_sender_label() {
    let ids = vec!["sender".to_string(), "receiver".to_string()];
    let mut reg = MailboxRegistry::new(&ids, 16);
    reg.set_clearance("receiver", Confidentiality::Sensitive);

    // Send with UNTRUSTED_SENSITIVE label
    reg.post(
        "sender",
        DataLabel::UNTRUSTED_SENSITIVE,
        "receiver",
        "tainted data".into(),
    )
    .unwrap();

    let msg = reg.recv("receiver").unwrap();
    assert_eq!(msg.label, DataLabel::UNTRUSTED_SENSITIVE);
    // Receiver knows the message is tainted and can absorb it
    let mut taint = TaintTracker::new();
    taint.absorb(msg.label);
    assert_eq!(taint.level(), DataLabel::UNTRUSTED_SENSITIVE);
}

// ── DAG + IFC: taint propagation through multi-step flows ──

#[test]
fn tainted_dag_node_write_blocked_by_ifc() {
    // Scenario: Agent A publishes untrusted-sensitive data to the blackboard.
    // Agent B reads it (absorbs taint), then tries to publish to a
    // Public-clearance mailbox. IFC must block the write.

    let bb = Blackboard::new(10);

    // Step 1: Agent A publishes sensitive data to the blackboard
    bb.publish(
        "agent_a",
        "analysis_result",
        serde_json::json!({"findings": "sensitive internal data"}),
        DataLabel::UNTRUSTED_SENSITIVE,
    )
    .unwrap();

    // Step 2: Agent B reads from the blackboard, absorbing taint
    let mut agent_b_taint = TaintTracker::new();
    assert_eq!(agent_b_taint.level(), DataLabel::TRUSTED_PUBLIC);

    let entry = bb.read("analysis_result", &mut agent_b_taint).unwrap();
    assert_eq!(entry.author, "agent_a");
    assert_eq!(agent_b_taint.level(), DataLabel::UNTRUSTED_SENSITIVE);

    // Step 3: Agent B attempts to post to Agent C's Public mailbox
    let ids = vec![
        "agent_b".to_string(),
        "agent_c_public".to_string(),
    ];
    let reg = MailboxRegistry::new(&ids, 16);
    // agent_c_public has default Public clearance

    let err = reg
        .post(
            "agent_b",
            agent_b_taint.level(),
            "agent_c_public",
            "processed result".into(),
        )
        .unwrap_err();
    assert!(matches!(err, FlowError::IfcViolation { .. }));
}

#[test]
fn taint_propagation_through_blackboard_chain() {
    // Scenario: taint flows transitively through a chain of agents.
    // Agent A publishes with Untrusted label.
    // Agent B reads (absorbs taint), processes, publishes its own result.
    // Agent C reads Agent B's output.
    // Verify Agent C's taint tracker is also tainted (transitivity).

    let bb = Blackboard::new(20);

    // Step 1: Agent A publishes untrusted-sensitive data
    bb.publish(
        "agent_a",
        "raw_input",
        serde_json::json!("user-supplied sensitive data"),
        DataLabel::UNTRUSTED_SENSITIVE,
    )
    .unwrap();

    // Step 2: Agent B reads from blackboard, absorbing taint
    let mut agent_b_taint = TaintTracker::new();
    bb.read("raw_input", &mut agent_b_taint).unwrap();
    assert_eq!(agent_b_taint.level(), DataLabel::UNTRUSTED_SENSITIVE);

    // Agent B processes the data and publishes its result.
    // The published label carries Agent B's taint level.
    bb.publish(
        "agent_b",
        "processed_output",
        serde_json::json!("processed: user-supplied data"),
        agent_b_taint.level(),
    )
    .unwrap();

    // Step 3: Agent C reads Agent B's output
    let mut agent_c_taint = TaintTracker::new();
    assert_eq!(agent_c_taint.level(), DataLabel::TRUSTED_PUBLIC);

    let entry = bb.read("processed_output", &mut agent_c_taint).unwrap();
    assert_eq!(entry.author, "agent_b");

    // Transitivity: Agent C is now tainted even though it never
    // directly read Agent A's data
    assert_eq!(agent_c_taint.level(), DataLabel::UNTRUSTED_SENSITIVE);

    // Step 4: Verify Agent C cannot post to a Public-clearance mailbox
    // The Sensitive confidentiality cannot write down to Public clearance.
    let ids = vec![
        "agent_c".to_string(),
        "clean_agent".to_string(),
    ];
    let reg = MailboxRegistry::new(&ids, 16);

    let err = reg
        .post(
            "agent_c",
            agent_c_taint.level(),
            "clean_agent",
            "should be blocked".into(),
        )
        .unwrap_err();
    assert!(matches!(err, FlowError::IfcViolation { .. }));
}
