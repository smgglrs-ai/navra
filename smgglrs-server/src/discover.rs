//! AID upstream discovery via HTTP fallback.
//!
//! Queries `GET https://<domain>/.well-known/agent` for each configured
//! domain, parses the AID record, and returns discovered MCP endpoints.
//!
//! See: https://aid.agentcommunity.org/docs/specification

/// A discovered MCP endpoint from AID lookup.
#[derive(Debug, Clone)]
pub struct DiscoveredEndpoint {
    /// Domain that was queried.
    pub domain: String,
    /// MCP endpoint URL (from the AID `u` field).
    pub url: String,
    /// Human-readable description (from the AID `s` field).
    pub description: Option<String>,
    /// Auth hint (from the AID `a` field).
    pub auth: Option<String>,
}

/// Query a domain's `.well-known/agent` endpoint for AID discovery.
///
/// Returns `None` if the domain doesn't serve AID, the record isn't
/// MCP, or the request fails. Uses a default 10-second timeout.
#[allow(dead_code)]
pub async fn lookup_domain(domain: &str) -> Option<DiscoveredEndpoint> {
    lookup_domain_with_timeout(domain, std::time::Duration::from_secs(10)).await
}

/// Query a domain's `.well-known/agent` endpoint with a custom timeout.
pub async fn lookup_domain_with_timeout(
    domain: &str,
    timeout: std::time::Duration,
) -> Option<DiscoveredEndpoint> {
    let url = format!("https://{}/.well-known/agent", domain);

    let client = reqwest::Client::builder().timeout(timeout).build().ok()?;

    let resp = match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::debug!(
                domain,
                status = %r.status(),
                "AID lookup: non-success response"
            );
            return None;
        }
        Err(e) => {
            tracing::debug!(domain, error = %e, "AID lookup: request failed");
            return None;
        }
    };

    let json: serde_json::Value = match resp.json().await {
        Ok(j) => j,
        Err(e) => {
            tracing::debug!(domain, error = %e, "AID lookup: invalid JSON");
            return None;
        }
    };

    // Validate AID version
    let version = json.get("v").and_then(|v| v.as_str()).unwrap_or("");
    if version != "aid1" {
        tracing::debug!(domain, version, "AID lookup: unsupported version");
        return None;
    }

    // Only interested in MCP protocol
    let protocol = json.get("p").and_then(|v| v.as_str()).unwrap_or("");
    if protocol != "mcp" {
        tracing::debug!(domain, protocol, "AID lookup: not MCP, skipping");
        return None;
    }

    let endpoint_url = json.get("u").and_then(|v| v.as_str())?;
    let description = json.get("s").and_then(|v| v.as_str()).map(String::from);
    let auth = json.get("a").and_then(|v| v.as_str()).map(String::from);

    Some(DiscoveredEndpoint {
        domain: domain.to_string(),
        url: endpoint_url.to_string(),
        description,
        auth,
    })
}

/// Discover MCP endpoints from a list of domains.
///
/// Queries all domains concurrently and returns discovered endpoints.
/// Uses a default 10-second timeout.
#[allow(dead_code)]
pub async fn discover_all(domains: &[String]) -> Vec<DiscoveredEndpoint> {
    discover_all_with_timeout(domains, std::time::Duration::from_secs(10)).await
}

/// Discover MCP endpoints from a list of domains with a custom timeout.
pub async fn discover_all_with_timeout(
    domains: &[String],
    timeout: std::time::Duration,
) -> Vec<DiscoveredEndpoint> {
    if domains.is_empty() {
        return Vec::new();
    }

    let mut handles = Vec::with_capacity(domains.len());
    for domain in domains {
        let domain = domain.clone();
        handles.push(tokio::spawn(async move {
            lookup_domain_with_timeout(&domain, timeout).await
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(Some(endpoint)) = handle.await {
            results.push(endpoint);
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn discover_empty_domains() {
        let results = discover_all(&[]).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn lookup_nonexistent_domain() {
        // This domain should not resolve or serve AID
        let result = lookup_domain("this-domain-does-not-exist-smgglrs-test.invalid").await;
        assert!(result.is_none());
    }
}
