//! Token operation benchmarks for PAPER.md Section 8.
//!
//! Not a formal benchmark harness — just timed iterations that
//! print results for the paper's evaluation section.

use navra_core::auth::capability::{
    build_payload, encode_token, validate_delegation, CapabilitySet,
};
use navra_core::identity::{CapSigner, Ed25519Signer};
use std::time::Instant;

const ITERATIONS: usize = 10_000;

fn test_signer() -> Ed25519Signer {
    Ed25519Signer::from_seed(&[42u8; 32])
}

fn test_cap_set() -> CapabilitySet {
    CapabilitySet {
        paths: vec![
            "/home/user/projects/**".to_string(),
            "/home/user/documents/**".to_string(),
        ],
        operations: vec![
            "read".to_string(),
            "write".to_string(),
            "search".to_string(),
            "git.status".to_string(),
            "git.commit".to_string(),
        ],
        tools: vec![
            "docs_*".to_string(),
            "git_*".to_string(),
            "rag_*".to_string(),
        ],
        credentials: vec!["github.pat".to_string(), "jira.token".to_string()],
    }
}

#[test]
fn bench_delegation_validation() {
    let signer = test_signer();
    let parent = build_payload(signer.did(), "did:key:z6MkLeader", test_cap_set(), 1, 3600);

    let mut child = build_payload(
        "did:key:z6MkLeader",
        "did:key:z6MkSpecialist",
        CapabilitySet {
            paths: vec!["/home/user/projects/**".to_string()],
            operations: vec!["read".to_string(), "write".to_string()],
            tools: vec!["docs_*".to_string()],
            credentials: vec!["github.pat".to_string()],
        },
        2,
        1800,
    );
    child.parent = Some(parent.nonce);

    // Warmup
    for _ in 0..100 {
        validate_delegation(&parent, &child, 3).unwrap();
    }

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        validate_delegation(&parent, &child, 3).unwrap();
    }
    let elapsed = start.elapsed();

    let per_op = elapsed / ITERATIONS as u32;
    eprintln!(
        "Delegation validation: {:?} total, {:?}/op ({} ops/sec)",
        elapsed,
        per_op,
        ITERATIONS as f64 / elapsed.as_secs_f64()
    );

    // Delegation validation should be sub-microsecond (no crypto)
    assert!(per_op.as_micros() < 50, "delegation too slow: {:?}", per_op);
}

#[test]
fn bench_blake3_auth_comparison() {
    use navra_core::auth::TokenAuthenticator;

    // Measure BLAKE3 token hashing for comparison
    let token = "mcd_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4";

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        TokenAuthenticator::hash_token(token);
    }
    let elapsed = start.elapsed();

    let per_op = elapsed / ITERATIONS as u32;
    eprintln!(
        "BLAKE3 hash: {:?} total, {:?}/op ({} ops/sec)",
        elapsed,
        per_op,
        ITERATIONS as f64 / elapsed.as_secs_f64()
    );
}

#[test]
fn bench_token_size() {
    let signer = test_signer();

    // Minimal token
    let minimal = build_payload(
        signer.did(),
        "did:key:z6MkMin",
        CapabilitySet {
            paths: vec![],
            operations: vec!["read".to_string()],
            tools: vec!["*".to_string()],
            credentials: vec![],
        },
        3,
        60,
    );
    let minimal_token = encode_token(&minimal, &signer).unwrap();

    // Typical token
    let typical = build_payload(signer.did(), "did:key:z6MkTypical", test_cap_set(), 1, 3600);
    let typical_token = encode_token(&typical, &signer).unwrap();

    // Large token (many capabilities)
    let large = build_payload(
        signer.did(),
        "did:key:z6MkLarge",
        CapabilitySet {
            paths: (0..10).map(|i| format!("/path/{i}/**")).collect(),
            operations: (0..15).map(|i| format!("op.{i}")).collect(),
            tools: (0..10).map(|i| format!("mod_{i}_*")).collect(),
            credentials: (0..5).map(|i| format!("cred.{i}")).collect(),
        },
        0,
        7200,
    );
    let large_token = encode_token(&large, &signer).unwrap();

    eprintln!("Token sizes:");
    eprintln!("  Minimal: {} bytes", minimal_token.len());
    eprintln!("  Typical: {} bytes", typical_token.len());
    eprintln!("  Large:   {} bytes", large_token.len());

    // All should fit in a reasonable HTTP header
    assert!(minimal_token.len() < 400, "minimal too large");
    assert!(typical_token.len() < 600, "typical too large");
    assert!(large_token.len() < 1500, "large too large");
}
