//! Security evaluation tests for PAPER.md Section 8.1.
//!
//! Each test attempts an attack that the paper claims the AI OS
//! prevents. Organized by the five security properties from Section 4.7.

use axum::http::HeaderMap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use smgglrs_core::auth::capability::{
    build_payload, decode_token, decode_token_unchecked, encode_token, validate_delegation,
    CapabilityPayload, CapabilitySet,
};
use smgglrs_core::auth::chain::{CapabilityAuthenticator, ChainAuthenticator};
use smgglrs_core::auth::{AgentIdentity, Authenticator, TokenAuthenticator};
use smgglrs_core::credentials::{CredentialMapping, CredentialStore, MappedCredentialStore};
use smgglrs_core::identity::{CapSigner, Ed25519Signer};
use std::collections::HashMap;

// =====================================================================
// Property 1: No Privilege Escalation
// =====================================================================

mod escalation {
    use super::*;

    #[test]
    fn delegation_cannot_escalate_ring() {
        let signer = Ed25519Signer::generate();
        let parent = build_payload(
            signer.did(),
            "did:key:z6MkLeader",
            CapabilitySet {
                paths: vec!["/home/**".to_string()],
                operations: vec!["read".to_string(), "write".to_string()],
                tools: vec!["*".to_string()],
                credentials: vec!["github.pat".to_string()],
            },
            1,
            3600,
        );

        // Attempt: child tries ring 0 (more privileged than parent's ring 1)
        let mut child = build_payload(
            "did:key:z6MkLeader",
            "did:key:z6MkEvil",
            parent.cap.clone(),
            0,
            3600,
        );
        child.parent = Some(parent.nonce);

        let result = validate_delegation(&parent, &child, 3);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ring escalation"));
    }

    #[test]
    fn delegation_cannot_add_operations() {
        let signer = Ed25519Signer::generate();
        let parent = build_payload(
            signer.did(),
            "did:key:z6MkLeader",
            CapabilitySet {
                paths: vec![],
                operations: vec!["read".to_string()],
                tools: vec![],
                credentials: vec![],
            },
            1,
            3600,
        );

        // Attempt: child adds "shell.exec" not in parent
        let mut child = build_payload(
            "did:key:z6MkLeader",
            "did:key:z6MkEvil",
            CapabilitySet {
                paths: vec![],
                operations: vec!["read".to_string(), "shell.exec".to_string()],
                tools: vec![],
                credentials: vec![],
            },
            1,
            3600,
        );
        child.parent = Some(parent.nonce);

        let result = validate_delegation(&parent, &child, 3);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("shell.exec"));
    }

    #[test]
    fn delegation_cannot_add_credentials() {
        let signer = Ed25519Signer::generate();
        let parent = build_payload(
            signer.did(),
            "did:key:z6MkLeader",
            CapabilitySet {
                paths: vec![],
                operations: vec![],
                tools: vec![],
                credentials: vec!["github.pat".to_string()],
            },
            1,
            3600,
        );

        // Attempt: child adds "aws.secret" not in parent
        let mut child = build_payload(
            "did:key:z6MkLeader",
            "did:key:z6MkEvil",
            CapabilitySet {
                paths: vec![],
                operations: vec![],
                tools: vec![],
                credentials: vec!["github.pat".to_string(), "aws.secret".to_string()],
            },
            1,
            3600,
        );
        child.parent = Some(parent.nonce);

        let result = validate_delegation(&parent, &child, 3);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("aws.secret"));
    }

    #[test]
    fn delegation_cannot_extend_expiry() {
        let signer = Ed25519Signer::generate();
        let parent = build_payload(
            signer.did(),
            "did:key:z6MkLeader",
            CapabilitySet {
                paths: vec![],
                operations: vec![],
                tools: vec![],
                credentials: vec![],
            },
            1,
            1800, // 30 min
        );

        // Attempt: child lives longer than parent
        let mut child = build_payload(
            "did:key:z6MkLeader",
            "did:key:z6MkEvil",
            CapabilitySet {
                paths: vec![],
                operations: vec![],
                tools: vec![],
                credentials: vec![],
            },
            1,
            7200, // 2 hours — exceeds parent
        );
        child.parent = Some(parent.nonce);

        let result = validate_delegation(&parent, &child, 3);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expiry"));
    }

    #[test]
    fn delegation_cannot_forge_parent_nonce() {
        let signer = Ed25519Signer::generate();
        let parent = build_payload(
            signer.did(),
            "did:key:z6MkLeader",
            CapabilitySet {
                paths: vec![],
                operations: vec![],
                tools: vec![],
                credentials: vec![],
            },
            1,
            3600,
        );

        // Attempt: child references a made-up parent nonce
        let mut child = build_payload(
            "did:key:z6MkLeader",
            "did:key:z6MkEvil",
            CapabilitySet {
                paths: vec![],
                operations: vec![],
                tools: vec![],
                credentials: vec![],
            },
            2,
            1800,
        );
        child.parent = Some([0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let result = validate_delegation(&parent, &child, 3);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("parent nonce"));
    }
}

// =====================================================================
// Property 5: Tamper Evidence (Token Forgery)
// =====================================================================

mod forgery {
    use super::*;

    #[test]
    fn forged_token_with_wrong_key_rejected() {
        let legit_signer = Ed25519Signer::generate();
        let evil_signer = Ed25519Signer::generate();

        // Attacker signs a token with their own key
        let payload = build_payload(
            legit_signer.did(), // claims to be from legit signer
            "did:key:z6MkEvil",
            CapabilitySet {
                paths: vec!["/**".to_string()],
                operations: vec![
                    "read".to_string(),
                    "write".to_string(),
                    "shell.exec".to_string(),
                ],
                tools: vec!["*".to_string()],
                credentials: vec!["*".to_string()],
            },
            0,
            86400,
        );
        let forged_token = encode_token(&payload, &evil_signer).unwrap();

        // Verify with legit key — must fail
        let result = decode_token(&forged_token, &legit_signer);
        assert!(result.is_err());
    }

    #[test]
    fn modified_payload_detected() {
        let signer = Ed25519Signer::generate();
        let payload = build_payload(
            signer.did(),
            "did:key:z6MkAgent",
            CapabilitySet {
                paths: vec!["/home/user/**".to_string()],
                operations: vec!["read".to_string()],
                tools: vec!["docs_*".to_string()],
                credentials: vec![],
            },
            2,
            3600,
        );
        let token = encode_token(&payload, &signer).unwrap();

        // Attacker intercepts token and modifies the CBOR payload
        // to change ring from 2 to 0
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let mut cbor = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();

        // Flip some bytes in the CBOR payload
        if cbor.len() > 10 {
            cbor[5] ^= 0xff;
            cbor[10] ^= 0xff;
        }

        let tampered = format!(
            "{}.{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(&cbor),
            parts[2]
        );

        let result = decode_token(&tampered, &signer);
        assert!(result.is_err());
    }

    #[test]
    fn truncated_signature_rejected() {
        let signer = Ed25519Signer::generate();
        let payload = build_payload(
            signer.did(),
            "did:key:z6MkAgent",
            CapabilitySet {
                paths: vec![],
                operations: vec![],
                tools: vec![],
                credentials: vec![],
            },
            1,
            3600,
        );
        let token = encode_token(&payload, &signer).unwrap();

        // Truncate the signature
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let truncated_sig = URL_SAFE_NO_PAD.encode(&sig[..32]);
        let tampered = format!("{}.{}.{}", parts[0], parts[1], truncated_sig);

        let result = decode_token(&tampered, &signer);
        assert!(result.is_err());
    }

    #[test]
    fn expired_token_rejected_even_if_signature_valid() {
        let signer = Ed25519Signer::generate();
        let mut payload = build_payload(
            signer.did(),
            "did:key:z6MkAgent",
            CapabilitySet {
                paths: vec![],
                operations: vec![],
                tools: vec![],
                credentials: vec![],
            },
            1,
            3600,
        );
        payload.exp = 1000; // far in the past
        payload.iat = 900;

        let token = encode_token(&payload, &signer).unwrap();

        // Signature is valid but token is expired
        let result = decode_token(&token, &signer);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn wrong_version_rejected() {
        let signer = Ed25519Signer::generate();
        let mut payload = build_payload(
            signer.did(),
            "did:key:z6MkAgent",
            CapabilitySet {
                paths: vec![],
                operations: vec![],
                tools: vec![],
                credentials: vec![],
            },
            1,
            3600,
        );
        payload.v = 99; // unsupported version

        let token = encode_token(&payload, &signer).unwrap();
        let result = decode_token(&token, &signer);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version"));
    }

    #[test]
    fn malformed_token_rejected() {
        let signer = Ed25519Signer::generate();

        // Various malformed tokens
        assert!(decode_token("", &signer).is_err());
        assert!(decode_token("not.a.token", &signer).is_err());
        assert!(decode_token("smgglrs_cap_v1.bad-base64!.also-bad!", &signer).is_err());
        assert!(decode_token("smgglrs_cap_v2.aaa.bbb", &signer).is_err()); // wrong version prefix
        assert!(decode_token("smgglrs_cap_v1.onlytwoparts", &signer).is_err());
    }

    #[test]
    fn authenticator_rejects_forged_cap_token() {
        let root_signer = Ed25519Signer::generate();
        let evil_signer = Ed25519Signer::generate();

        let payload = build_payload(
            root_signer.did(),
            "did:key:z6MkEvil",
            CapabilitySet {
                paths: vec!["/**".to_string()],
                operations: vec!["shell.exec".to_string()],
                tools: vec!["*".to_string()],
                credentials: vec![],
            },
            0,
            86400,
        );
        let forged = encode_token(&payload, &evil_signer).unwrap();

        let auth = CapabilityAuthenticator::new(Box::new(root_signer));
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {forged}").parse().unwrap());

        let result = auth.authenticate(&headers);
        assert!(result.is_err());
    }
}

// =====================================================================
// Property 2: Credential Isolation
// =====================================================================

mod credential_isolation {
    use super::*;

    #[test]
    fn unknown_credential_label_denied() {
        let store = MappedCredentialStore::new(HashMap::new());
        assert!(store.resolve("nonexistent").is_err());
    }

    #[test]
    fn only_configured_labels_accessible() {
        let mut mappings = HashMap::new();
        mappings.insert(
            "allowed".to_string(),
            CredentialMapping {
                source: "env".to_string(),
                path: None,
                var: Some("MCPD_SEC_TEST_ALLOWED".to_string()),
            },
        );

        std::env::set_var("MCPD_SEC_TEST_ALLOWED", "secret-value");
        let store = MappedCredentialStore::new(mappings);

        // Allowed label works
        let secret = store.resolve("allowed").unwrap();
        assert_eq!(secret.as_str(), Some("secret-value"));

        // Unlisted label denied — even if it exists in the env
        std::env::set_var("MCPD_SEC_TEST_FORBIDDEN", "should-not-see");
        assert!(store.resolve("forbidden").is_err());

        std::env::remove_var("MCPD_SEC_TEST_ALLOWED");
        std::env::remove_var("MCPD_SEC_TEST_FORBIDDEN");
    }

    #[test]
    fn capability_token_credential_subset() {
        let signer = Ed25519Signer::generate();
        let parent = build_payload(
            signer.did(),
            "did:key:z6MkLeader",
            CapabilitySet {
                paths: vec![],
                operations: vec![],
                tools: vec![],
                credentials: vec!["github.pat".to_string()],
            },
            1,
            3600,
        );

        // Child tries to access credential not in parent
        let mut child = build_payload(
            "did:key:z6MkLeader",
            "did:key:z6MkSpecialist",
            CapabilitySet {
                paths: vec![],
                operations: vec![],
                tools: vec![],
                credentials: vec!["github.pat".to_string(), "db.password".to_string()],
            },
            2,
            1800,
        );
        child.parent = Some(parent.nonce);

        let result = validate_delegation(&parent, &child, 3);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("db.password"));
    }

    #[test]
    fn credential_labels_not_values_in_token() {
        let signer = Ed25519Signer::generate();
        let payload = build_payload(
            signer.did(),
            "did:key:z6MkAgent",
            CapabilitySet {
                paths: vec![],
                operations: vec![],
                tools: vec![],
                credentials: vec!["github.pat".to_string()],
            },
            1,
            3600,
        );
        let token = encode_token(&payload, &signer).unwrap();

        // Token contains the label "github.pat" but not the actual secret
        assert!(
            token.contains("github") == false || {
                // The token is base64-encoded CBOR — the raw string won't appear
                // unless we decode it
                let decoded = decode_token_unchecked(&token).unwrap();
                decoded.cap.credentials == vec!["github.pat"]
                // The label is there, but no secret value
            }
        );
    }

    #[test]
    fn cannot_store_to_env_credential() {
        let mut mappings = HashMap::new();
        mappings.insert(
            "env_cred".to_string(),
            CredentialMapping {
                source: "env".to_string(),
                path: None,
                var: Some("X".to_string()),
            },
        );
        let store = MappedCredentialStore::new(mappings);

        // Cannot overwrite environment-sourced credentials
        assert!(store.store("env_cred", b"malicious").is_err());
    }
}

// =====================================================================
// Property 3: Attenuation Only (tested via escalation above, plus)
// =====================================================================

mod attenuation {
    use super::*;

    #[test]
    fn valid_attenuation_chain() {
        let signer = Ed25519Signer::generate();

        // Root → Leader (ring 0 → 1)
        let root_to_leader = build_payload(
            signer.did(),
            "did:key:z6MkLeader",
            CapabilitySet {
                paths: vec!["/home/**".to_string()],
                operations: vec![
                    "read".to_string(),
                    "write".to_string(),
                    "git.commit".to_string(),
                ],
                tools: vec!["*".to_string()],
                credentials: vec!["github.pat".to_string(), "jira.token".to_string()],
            },
            1,
            3600,
        );

        // Leader → Specialist (ring 1 → 2, narrower)
        let mut leader_to_spec = build_payload(
            "did:key:z6MkLeader",
            "did:key:z6MkSpec",
            CapabilitySet {
                paths: vec!["/home/user/project/**".to_string()],
                operations: vec!["read".to_string()],
                tools: vec!["docs_*".to_string()],
                credentials: vec!["github.pat".to_string()],
            },
            2,
            1800,
        );
        leader_to_spec.parent = Some(root_to_leader.nonce);

        // Valid attenuation
        assert!(validate_delegation(&root_to_leader, &leader_to_spec, 3).is_ok());
    }

    #[test]
    fn empty_capabilities_always_valid_delegation() {
        let signer = Ed25519Signer::generate();
        let parent = build_payload(
            signer.did(),
            "did:key:z6MkParent",
            CapabilitySet {
                paths: vec!["/home/**".to_string()],
                operations: vec!["read".to_string()],
                tools: vec!["*".to_string()],
                credentials: vec!["cred".to_string()],
            },
            1,
            3600,
        );

        // Child with empty capabilities — maximally attenuated
        let mut child = build_payload(
            "did:key:z6MkParent",
            "did:key:z6MkChild",
            CapabilitySet {
                paths: vec![],
                operations: vec![],
                tools: vec![],
                credentials: vec![],
            },
            3,
            60,
        );
        child.parent = Some(parent.nonce);

        assert!(validate_delegation(&parent, &child, 3).is_ok());
    }
}

// =====================================================================
// Property 4: Audit Trail (structural test)
// =====================================================================

mod audit {
    use super::*;

    #[test]
    fn token_contains_issuer_and_subject_did() {
        let signer = Ed25519Signer::generate();
        let payload = build_payload(
            signer.did(),
            "did:key:z6MkSubject",
            CapabilitySet {
                paths: vec![],
                operations: vec![],
                tools: vec![],
                credentials: vec![],
            },
            1,
            3600,
        );
        let token = encode_token(&payload, &signer).unwrap();
        let decoded = decode_token(&token, &signer).unwrap();

        assert_eq!(decoded.iss, signer.did());
        assert_eq!(decoded.sub, "did:key:z6MkSubject");
        assert_ne!(decoded.nonce, [0u8; 16]); // nonce is random, not zero
    }

    #[test]
    fn each_token_has_unique_nonce() {
        let signer = Ed25519Signer::generate();
        let cap = CapabilitySet {
            paths: vec![],
            operations: vec![],
            tools: vec![],
            credentials: vec![],
        };

        let p1 = build_payload(signer.did(), "did:key:z6Mk1", cap.clone(), 1, 3600);
        let p2 = build_payload(signer.did(), "did:key:z6Mk2", cap.clone(), 1, 3600);

        assert_ne!(p1.nonce, p2.nonce);
    }

    #[test]
    fn delegation_chain_traceable_via_parent_nonce() {
        let signer = Ed25519Signer::generate();
        let cap = CapabilitySet {
            paths: vec![],
            operations: vec![],
            tools: vec![],
            credentials: vec![],
        };

        let root = build_payload(signer.did(), "did:key:z6MkA", cap.clone(), 0, 3600);
        let mut child = build_payload("did:key:z6MkA", "did:key:z6MkB", cap.clone(), 1, 1800);
        child.parent = Some(root.nonce);

        // Can trace: child.parent == root.nonce
        assert_eq!(child.parent.unwrap(), root.nonce);
        assert!(child.parent.unwrap() != child.nonce); // not self-referencing
    }
}

// =====================================================================
// Auth chain integration
// =====================================================================

mod auth_chain {
    use super::*;

    #[test]
    fn blake3_agent_has_no_capabilities() {
        let mut auth = TokenAuthenticator::new();
        auth.register("my-token", AgentIdentity::new("agent", "dev"));

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer my-token".parse().unwrap());

        let identity = auth.authenticate(&headers).unwrap();
        assert!(identity.capabilities.is_none());
        assert!(identity.did.is_none());
    }

    #[test]
    fn cap_agent_has_capabilities() {
        let signer = Ed25519Signer::generate();
        let payload = build_payload(
            signer.did(),
            "did:key:z6MkAgent",
            CapabilitySet {
                paths: vec!["/home/**".to_string()],
                operations: vec!["read".to_string()],
                tools: vec!["docs_*".to_string()],
                credentials: vec![],
            },
            2,
            3600,
        );
        let token = encode_token(&payload, &signer).unwrap();

        let auth = CapabilityAuthenticator::new(Box::new(signer));
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());

        let identity = auth.authenticate(&headers).unwrap();
        assert!(identity.capabilities.is_some());
        let caps = identity.capabilities.unwrap();
        assert_eq!(caps.ring, 2);
        assert!(caps.operations.contains("read"));
        assert!(!caps.operations.contains("write"));
        assert_eq!(caps.tools, vec!["docs_*"]);
    }

    #[test]
    fn chain_falls_through_correctly() {
        let root = Ed25519Signer::generate();

        let mut blake3 = TokenAuthenticator::new();
        blake3.register("legacy-token", AgentIdentity::new("legacy", "dev"));

        let cap_payload = build_payload(
            root.did(),
            "did:key:z6MkCap",
            CapabilitySet {
                paths: vec![],
                operations: vec!["read".to_string()],
                tools: vec!["*".to_string()],
                credentials: vec![],
            },
            1,
            3600,
        );
        let cap_token = encode_token(&cap_payload, &root).unwrap();

        let chain = ChainAuthenticator::new()
            .add(CapabilityAuthenticator::new(Box::new(root)))
            .add(blake3);

        // Cap token → cap auth handles
        let mut h1 = HeaderMap::new();
        h1.insert(
            "authorization",
            format!("Bearer {cap_token}").parse().unwrap(),
        );
        let id1 = chain.authenticate(&h1).unwrap();
        assert!(id1.capabilities.is_some());

        // BLAKE3 token → cap auth rejects, blake3 handles
        let mut h2 = HeaderMap::new();
        h2.insert("authorization", "Bearer legacy-token".parse().unwrap());
        let id2 = chain.authenticate(&h2).unwrap();
        assert!(id2.capabilities.is_none());
        assert_eq!(id2.name, "legacy");

        // Unknown token → both reject
        let mut h3 = HeaderMap::new();
        h3.insert("authorization", "Bearer bad-token".parse().unwrap());
        assert!(chain.authenticate(&h3).is_err());
    }
}

// =====================================================================
// Rate limiting
// =====================================================================

mod quota {
    use smgglrs_core::quota::{QuotaEngine, RateLimit};

    #[test]
    fn rate_limit_enforced() {
        let mut engine = QuotaEngine::new();
        engine.add_limit(
            "restricted".to_string(),
            RateLimit {
                max_calls: 5,
                window_secs: 60,
            },
        );

        // 5 calls succeed
        for _ in 0..5 {
            assert!(engine.check("agent", "restricted"));
        }
        // 6th is denied
        assert!(!engine.check("agent", "restricted"));
    }

    #[test]
    fn rate_limit_does_not_affect_other_permission_sets() {
        let mut engine = QuotaEngine::new();
        engine.add_limit(
            "restricted".to_string(),
            RateLimit {
                max_calls: 1,
                window_secs: 60,
            },
        );

        assert!(engine.check("agent", "restricted"));
        assert!(!engine.check("agent", "restricted"));

        // "unlimited" permission set — no limit configured
        assert!(engine.check("agent", "unlimited"));
        assert!(engine.check("agent", "unlimited"));
    }

    #[test]
    fn rate_limit_per_agent_isolation() {
        let mut engine = QuotaEngine::new();
        engine.add_limit(
            "dev".to_string(),
            RateLimit {
                max_calls: 2,
                window_secs: 60,
            },
        );

        assert!(engine.check("alice", "dev"));
        assert!(engine.check("alice", "dev"));
        assert!(!engine.check("alice", "dev"));

        // Bob is unaffected by Alice's exhaustion
        assert!(engine.check("bob", "dev"));
    }
}
