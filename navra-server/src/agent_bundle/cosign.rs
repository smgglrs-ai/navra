use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignaturePolicy {
    Enforce,
    Warn,
    Skip,
}

impl FromStr for SignaturePolicy {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "enforce" => Ok(Self::Enforce),
            "warn" => Ok(Self::Warn),
            "skip" => Ok(Self::Skip),
            other => anyhow::bail!(
                "invalid agent_signature_policy: {other:?} (expected enforce, warn, or skip)"
            ),
        }
    }
}

/// Options for signature verification.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// What to do when verification fails (or cosign is absent).
    pub policy: SignaturePolicy,
    /// Expected signer identity (certificate SAN), passed to cosign
    /// as `--certificate-identity-regexp`. Keyless signatures carry
    /// the OIDC subject of the workflow that signed — e.g.
    /// `^https://github.com/smgglrs-ai/navra/` pins verification to
    /// artifacts signed by this repository's CI. `None` accepts any
    /// signer (not recommended for `enforce`).
    pub identity: Option<String>,
    /// Expected OIDC issuer, passed as `--certificate-oidc-issuer`
    /// (e.g. `https://token.actions.githubusercontent.com`). Should
    /// be set together with `identity` to fully pin a keyless signer.
    pub issuer: Option<String>,
}

/// Build the cosign verify argument list.
fn verify_args(oci_ref: &str, opts: &VerifyOptions) -> Vec<String> {
    let mut args = vec!["verify".to_string(), oci_ref.to_string()];
    if let Some(identity) = &opts.identity {
        args.push("--certificate-identity-regexp".to_string());
        args.push(identity.clone());
    }
    if let Some(issuer) = &opts.issuer {
        args.push("--certificate-oidc-issuer".to_string());
        args.push(issuer.clone());
    }
    args.push("--output".to_string());
    args.push("text".to_string());
    args
}

pub async fn verify_signature(oci_ref: &str, opts: &VerifyOptions) -> anyhow::Result<bool> {
    let policy = opts.policy;
    if policy == SignaturePolicy::Skip {
        return Ok(true);
    }

    let cosign_path = which_cosign().await;
    if cosign_path.is_none() {
        match policy {
            SignaturePolicy::Enforce => {
                anyhow::bail!(
                    "cosign not found in PATH — required when agent_signature_policy = \"enforce\".\n\
                     Install: https://docs.sigstore.dev/cosign/system_config/installation/"
                );
            }
            SignaturePolicy::Warn => {
                eprintln!(
                    "warning: cosign not found in PATH — cannot verify signature for {oci_ref}"
                );
                return Ok(false);
            }
            SignaturePolicy::Skip => unreachable!(),
        }
    }

    let output = tokio::process::Command::new("cosign")
        .args(verify_args(oci_ref, opts))
        .output()
        .await?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        tracing::info!(oci_ref, "cosign signature verified: {}", stdout.trim());
        Ok(true)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        match policy {
            SignaturePolicy::Enforce => {
                anyhow::bail!(
                    "Signature verification failed for {oci_ref}:\n{stderr}\n\n\
                     Use --allow-unsigned to skip, or set agent_signature_policy = \"warn\" in config."
                );
            }
            SignaturePolicy::Warn => {
                eprintln!(
                    "warning: signature verification failed for {oci_ref}: {}",
                    stderr.trim()
                );
                Ok(false)
            }
            SignaturePolicy::Skip => unreachable!(),
        }
    }
}

async fn which_cosign() -> Option<String> {
    let output = tokio::process::Command::new("which")
        .arg("cosign")
        .output()
        .await
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_policy() {
        assert_eq!(
            SignaturePolicy::from_str("enforce").unwrap(),
            SignaturePolicy::Enforce
        );
        assert_eq!(
            SignaturePolicy::from_str("warn").unwrap(),
            SignaturePolicy::Warn
        );
        assert_eq!(
            SignaturePolicy::from_str("skip").unwrap(),
            SignaturePolicy::Skip
        );
        assert!(SignaturePolicy::from_str("invalid").is_err());
    }

    #[test]
    fn verify_args_without_pinning() {
        let opts = VerifyOptions {
            policy: SignaturePolicy::Enforce,
            identity: None,
            issuer: None,
        };
        assert_eq!(
            verify_args("ghcr.io/owner/agent:latest", &opts),
            vec!["verify", "ghcr.io/owner/agent:latest", "--output", "text"]
        );
    }

    #[test]
    fn verify_args_with_identity_pinning() {
        let opts = VerifyOptions {
            policy: SignaturePolicy::Enforce,
            identity: Some("^https://github.com/smgglrs-ai/navra/".into()),
            issuer: Some("https://token.actions.githubusercontent.com".into()),
        };
        let args = verify_args("ghcr.io/owner/agent:latest", &opts);
        let joined = args.join(" ");
        assert!(
            joined.contains("--certificate-identity-regexp ^https://github.com/smgglrs-ai/navra/")
        );
        assert!(
            joined
                .contains("--certificate-oidc-issuer https://token.actions.githubusercontent.com")
        );
        // Order: verify, ref, pinning flags, output
        assert_eq!(args[0], "verify");
        assert_eq!(args[1], "ghcr.io/owner/agent:latest");
        assert_eq!(args.last().unwrap(), "text");
    }
}
