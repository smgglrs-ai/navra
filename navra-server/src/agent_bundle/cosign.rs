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

pub async fn verify_signature(oci_ref: &str, policy: SignaturePolicy) -> anyhow::Result<bool> {
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
        .args(["verify", oci_ref, "--output", "text"])
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
}
