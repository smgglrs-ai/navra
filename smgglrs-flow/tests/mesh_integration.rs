//! Integration tests for mesh communication primitives.
//!
//! Tests cross-primitive interactions: IFC propagation across mailbox
//! and blackboard, back-edge lifecycle with conditional re-execution,
//! concurrent blackboard access, and TOML deserialization of mesh config.

use smgglrs_flow::{
    BackEdgeTracker, Blackboard, ConditionalEdge, EdgeCondition, FlowError, MailboxRegistry,
    TaskResult, TaskStatus,
};
use smgglrs_protocol::label::{Confidentiality, DataLabel};
use smgglrs_security::ifc::TaintTracker;

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
    let def: smgglrs_flow::FlowDefinition = toml::from_str(toml_str).unwrap();
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
    let def: smgglrs_flow::DagDefinition = toml::from_str(toml_str).unwrap();
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
    let def: smgglrs_flow::DagDefinition = toml::from_str(toml_str).unwrap();
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
    assert_eq!(msg.body, "sensitive data");
    assert_eq!(msg.label, DataLabel::UNTRUSTED_SENSITIVE);
}

// ── Blackboard taint lattice walk ──

#[test]
fn blackboard_taint_rises_monotonically_through_multiple_reads() {
    let bb = Blackboard::new(10);

    bb.publish("sys", "config", serde_json::json!("safe"), DataLabel::TRUSTED_PUBLIC)
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
    assert_eq!(msgs[0].body, "msg 1");
    assert_eq!(msgs[1].sender, "bob");
    assert_eq!(msgs[1].body, "msg 2");
    assert_eq!(msgs[2].sender, "carol");
    assert_eq!(msgs[2].body, "msg 3");
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
