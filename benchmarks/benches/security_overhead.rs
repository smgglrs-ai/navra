//! Benchmarks measuring the latency overhead of smgglrs security features.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::path::Path;

// --- IFC ---

fn bench_ifc_taint_propagation(c: &mut Criterion) {
    use smgglrs_security::ifc::{Confidentiality, DataLabel, Integrity, TaintTracker};

    let mut group = c.benchmark_group("ifc");

    group.bench_function("taint_absorb_trusted", |b| {
        b.iter(|| {
            let mut tracker = TaintTracker::new();
            tracker.absorb(black_box(DataLabel {
                confidentiality: Confidentiality::Public,
                integrity: Integrity::Trusted,
            }));
            tracker.level()
        });
    });

    group.bench_function("taint_absorb_untrusted", |b| {
        b.iter(|| {
            let mut tracker = TaintTracker::new();
            tracker.absorb(black_box(DataLabel {
                confidentiality: Confidentiality::Public,
                integrity: Integrity::Untrusted,
            }));
            tracker.level()
        });
    });

    group.bench_function("taint_absorb_confidential", |b| {
        b.iter(|| {
            let mut tracker = TaintTracker::new();
            tracker.absorb(black_box(DataLabel {
                confidentiality: Confidentiality::Secret,
                integrity: Integrity::Trusted,
            }));
            tracker.level()
        });
    });

    group.bench_function("taint_absorb_10_labels", |b| {
        let labels: Vec<DataLabel> = (0..10)
            .map(|i| DataLabel {
                confidentiality: if i % 3 == 0 {
                    Confidentiality::Secret
                } else {
                    Confidentiality::Public
                },
                integrity: if i % 2 == 0 {
                    Integrity::Trusted
                } else {
                    Integrity::Untrusted
                },
            })
            .collect();
        b.iter(|| {
            let mut tracker = TaintTracker::new();
            for label in &labels {
                tracker.absorb(black_box(label.clone()));
            }
            tracker.level()
        });
    });

    group.bench_function("is_trusted_path_match", |b| {
        let patterns = vec!["~/Code/**".to_string(), "~/Documents/**".to_string()];
        b.iter(|| {
            smgglrs_security::ifc::is_trusted_path(
                black_box("/home/user/Code/project/src/main.rs"),
                &patterns,
            )
        });
    });

    group.bench_function("is_trusted_path_no_match", |b| {
        let patterns = vec!["~/Code/**".to_string()];
        b.iter(|| {
            smgglrs_security::ifc::is_trusted_path(black_box("/tmp/random/file.txt"), &patterns)
        });
    });

    group.finish();
}

// --- Capability tokens ---

fn bench_capability_tokens(c: &mut Criterion) {
    use smgglrs_security::auth::capability::{
        build_payload, decode_token, encode_token, CapabilitySet,
    };
    use smgglrs_security::identity::{load_or_create_file_identity, CapSigner};

    let tmp = tempfile::tempdir().unwrap();
    let signer = load_or_create_file_identity(&tmp.path().join("bench.key")).unwrap();

    let cap_set = CapabilitySet {
        paths: vec!["~/Code/**".to_string()],
        operations: vec![
            "read".to_string(),
            "write".to_string(),
            "search".to_string(),
        ],
        tools: vec!["docs_*".to_string(), "git_*".to_string()],
        credentials: vec![],
    };

    let payload = build_payload(signer.did(), "did:key:test-agent", cap_set, 2, 3600);
    let token = encode_token(&payload, &signer).unwrap();

    let mut group = c.benchmark_group("capability_tokens");

    group.bench_function("encode", |b| {
        b.iter(|| encode_token(black_box(&payload), &signer).unwrap());
    });

    group.bench_function("decode_and_verify", |b| {
        b.iter(|| decode_token(black_box(&token), &signer).unwrap());
    });

    group.finish();
}

// --- BLAKE3 token auth ---

fn bench_blake3_auth(c: &mut Criterion) {
    use smgglrs_security::auth::TokenAuthenticator;

    let mut group = c.benchmark_group("blake3_auth");

    group.bench_function("hash_token", |b| {
        b.iter(|| {
            TokenAuthenticator::hash_token(black_box("mcd_a1b2c3d4e5f6789012345678901234567890"))
        });
    });

    group.finish();
}

// --- Safety pipeline ---

fn bench_safety_pipeline(c: &mut Criterion) {
    use smgglrs_security::safety::{build_pipeline, FilterContext};

    let mut group = c.benchmark_group("safety_pipeline");

    let standard = build_pipeline("standard");
    let guardian = build_pipeline("guardian");

    let clean_text = "This is a normal response about code quality and testing.";
    let text_with_secret = "The API key is sk_live_4eC39HqLyjWDarjtT1zdp7dc and should be rotated.";
    let long_text = "Lorem ipsum dolor sit amet. ".repeat(100);

    let ctx = FilterContext {
        agent_name: "bench-agent",
        operation: "read",
        path: None,
    };

    group.bench_function("standard_clean_text", |b| {
        b.iter(|| standard.process(black_box(clean_text), &ctx));
    });

    group.bench_function("standard_text_with_secret", |b| {
        b.iter(|| standard.process(black_box(text_with_secret), &ctx));
    });

    group.bench_function("standard_long_text_1000_words", |b| {
        b.iter(|| standard.process(black_box(&long_text), &ctx));
    });

    group.bench_function("guardian_clean_text", |b| {
        b.iter(|| guardian.process(black_box(clean_text), &ctx));
    });

    group.bench_function("guardian_text_with_secret", |b| {
        b.iter(|| guardian.process(black_box(text_with_secret), &ctx));
    });

    group.finish();
}

// --- Permission checks ---

fn bench_permissions(c: &mut Criterion) {
    use smgglrs_security::permissions::{PathAcl, PermissionEngine};

    let mut engine = PermissionEngine::new();
    engine.add_permission_set(
        "developer".to_string(),
        PathAcl {
            ring: Some(3),
            allow: vec!["~/Code/**".to_string(), "~/Documents/**".to_string()],
            deny: vec![
                "**/.env".to_string(),
                "**/secrets*".to_string(),
                "**/.git/objects/**".to_string(),
            ],
            operations: ["read", "write", "search", "list"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            requires_approval: ["write", "git.commit"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        },
    );

    let allowed = Path::new("/home/user/Code/project/src/main.rs");
    let denied = Path::new("/home/user/Code/project/.env");
    let deep = Path::new("/home/user/Code/project/src/modules/auth/handlers/login.rs");

    let mut group = c.benchmark_group("permissions");

    group.bench_function("check_allowed_path", |b| {
        b.iter(|| engine.check("developer", "read", black_box(allowed)));
    });

    group.bench_function("check_denied_path", |b| {
        b.iter(|| engine.check("developer", "read", black_box(denied)));
    });

    group.bench_function("check_deep_path", |b| {
        b.iter(|| engine.check("developer", "read", black_box(deep)));
    });

    group.bench_function("check_approval_required", |b| {
        b.iter(|| engine.check("developer", "write", black_box(allowed)));
    });

    group.finish();
}

// --- Tool permission rules ---

fn bench_tool_rules(c: &mut Criterion) {
    use smgglrs_security::permissions::{ToolPermissions, ToolPolicy, ToolRule};

    let rules = vec![
        ToolRule {
            tool: "file_read".to_string(),
            policy: ToolPolicy::Allow,
        },
        ToolRule {
            tool: "file_write".to_string(),
            policy: ToolPolicy::Approve,
        },
        ToolRule {
            tool: "file_delete".to_string(),
            policy: ToolPolicy::Deny,
        },
        ToolRule {
            tool: "git_*".to_string(),
            policy: ToolPolicy::Allow,
        },
        ToolRule {
            tool: "sys_*".to_string(),
            policy: ToolPolicy::Deny,
        },
    ];
    let perms = ToolPermissions::new(rules, ToolPolicy::Allow);

    let mut group = c.benchmark_group("tool_rules");

    group.bench_function("check_exact_match", |b| {
        b.iter(|| perms.check(black_box("file_read")));
    });

    group.bench_function("check_glob_match", |b| {
        b.iter(|| perms.check(black_box("git_status")));
    });

    group.bench_function("check_default_policy", |b| {
        b.iter(|| perms.check(black_box("unknown_tool")));
    });

    group.finish();
}

// --- Weaver prompt assembly ---

fn bench_weaver(c: &mut Criterion) {
    let mut group = c.benchmark_group("weaver");

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let demo_path = workspace_root.join("examples/payments-app");
    if !demo_path.exists() {
        eprintln!("Skipping weaver bench: {} not found", demo_path.display());
        group.finish();
        return;
    }

    let forge = match smgglrs_cognitive::ForgeService::load(&demo_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Skipping weaver bench: {e}");
            group.finish();
            return;
        }
    };

    let short_prompt = "Audit handler.rs for SQL injection";
    let long_prompt = "Analyze the following source code files for security \
        vulnerabilities. For each finding, report the file, function, CWE ID, \
        severity, and description. Focus on SQL injection, hardcoded secrets, \
        missing authentication, IDOR, and webhook verification.";

    group.bench_function("assemble_short_prompt", |b| {
        b.iter(|| {
            smgglrs_cognitive::assemble(
                &forge,
                black_box("security_auditor"),
                black_box(short_prompt),
                None,
                None,
            )
            .unwrap()
        });
    });

    group.bench_function("assemble_long_prompt", |b| {
        b.iter(|| {
            smgglrs_cognitive::assemble(
                &forge,
                black_box("security_auditor"),
                black_box(long_prompt),
                None,
                None,
            )
            .unwrap()
        });
    });

    group.bench_function("assemble_with_context", |b| {
        let context = "Previous audit (March 2026): Found SQL injection in process_payment().";
        b.iter(|| {
            smgglrs_cognitive::assemble(
                &forge,
                black_box("analyst"),
                black_box(short_prompt),
                None,
                Some(black_box(context)),
            )
            .unwrap()
        });
    });

    // Report token overhead
    let output =
        smgglrs_cognitive::assemble(&forge, "security_auditor", short_prompt, None, None).unwrap();
    let system_len = output.system_prompt().len();
    let prompt_len = short_prompt.len();
    eprintln!(
        "\n  Weaver token overhead: {} chars system prompt + {} chars user = {} total ({:.1}x)",
        system_len,
        prompt_len,
        system_len + prompt_len,
        (system_len + prompt_len) as f64 / prompt_len as f64
    );

    group.finish();
}

criterion_group!(
    benches,
    bench_ifc_taint_propagation,
    bench_capability_tokens,
    bench_blake3_auth,
    bench_safety_pipeline,
    bench_permissions,
    bench_tool_rules,
    bench_weaver,
);
criterion_main!(benches);
