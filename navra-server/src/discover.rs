//! Agent discovery via DNS-AID and HTTP fallback.
//!
//! Supports two discovery mechanisms:
//! 1. DNS-AID SVCB records (draft-mozleywilliams-dnsop-dnsaid-02) —
//!    uses SVCB records with `cap`, `well-known`, `bap`, `policy`, `realm`
//!    SvcParamKeys and MCP/A2A ALPN IDs
//! 2. HTTP fallback — queries `GET https://<domain>/.well-known/agent`
//!
//! See: https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/

use serde::{Deserialize, Serialize};

/// Known ALPN protocol IDs for agent protocols (DNS-AID).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentProtocol {
    Mcp,
    A2a,
    Other(String),
}

impl AgentProtocol {
    pub fn from_alpn(alpn: &str) -> Self {
        match alpn {
            "mcp" => Self::Mcp,
            "a2a" => Self::A2a,
            other => Self::Other(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Mcp => "mcp",
            Self::A2a => "a2a",
            Self::Other(s) => s,
        }
    }
}

/// A parsed DNS-AID SVCB record.
///
/// Represents the SvcParamKeys defined by DNS-AID:
/// - `alpn`: ALPN protocol IDs (mcp, a2a)
/// - `cap`: Capability URIs the agent supports
/// - `cap-sha256`: SHA-256 hashes of capability documents
/// - `well-known`: Path to the well-known endpoint
/// - `bap`: Bound Agent Profile URI
/// - `policy`: Policy URI for the agent
/// - `realm`: Trust realm identifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAidRecord {
    /// Target hostname from the SVCB record.
    pub target: String,
    /// Port (from SVCB SvcParamKey 3).
    pub port: Option<u16>,
    /// ALPN protocol IDs.
    pub protocols: Vec<AgentProtocol>,
    /// Capability URIs (`cap` SvcParamKey).
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// SHA-256 hashes of capability documents (`cap-sha256`).
    #[serde(default)]
    pub cap_hashes: Vec<String>,
    /// Well-known endpoint path (`well-known` SvcParamKey).
    pub well_known: Option<String>,
    /// Bound Agent Profile URI (`bap`).
    pub bap: Option<String>,
    /// Policy URI (`policy`).
    pub policy: Option<String>,
    /// Trust realm identifier (`realm`).
    pub realm: Option<String>,
}

#[allow(dead_code)]
impl DnsAidRecord {
    pub fn supports_mcp(&self) -> bool {
        self.protocols.iter().any(|p| *p == AgentProtocol::Mcp)
    }

    pub fn supports_a2a(&self) -> bool {
        self.protocols.iter().any(|p| *p == AgentProtocol::A2a)
    }

    pub fn endpoint_url(&self) -> String {
        let port_suffix = match self.port {
            Some(443) | None => String::new(),
            Some(p) => format!(":{p}"),
        };
        let path = self.well_known.as_deref().unwrap_or("/.well-known/agent");
        format!("https://{}{}{}", self.target, port_suffix, path)
    }
}

/// Parse a DNS-AID SVCB record from a textual representation.
///
/// Expected format (from `dig` or DNS resolver):
/// ```text
/// _agent._tcp.example.org. 300 IN SVCB 1 tools.example.org. alpn=mcp port=443 cap=urn:cap:tools
/// ```
pub fn parse_svcb_text(text: &str) -> Option<DnsAidRecord> {
    let parts: Vec<&str> = text.split_whitespace().collect();

    // Find the SVCB keyword
    let svcb_idx = parts.iter().position(|&p| p == "SVCB" || p == "HTTPS")?;
    if svcb_idx + 2 >= parts.len() {
        return None;
    }

    // Priority is at svcb_idx+1, target at svcb_idx+2
    let target = parts[svcb_idx + 2].trim_end_matches('.').to_string();

    let mut record = DnsAidRecord {
        target,
        port: None,
        protocols: Vec::new(),
        capabilities: Vec::new(),
        cap_hashes: Vec::new(),
        well_known: None,
        bap: None,
        policy: None,
        realm: None,
    };

    // Parse SvcParams (key=value pairs after the target)
    for part in &parts[(svcb_idx + 3)..] {
        if let Some((key, value)) = part.split_once('=') {
            match key {
                "alpn" => {
                    for proto in value.split(',') {
                        record.protocols.push(AgentProtocol::from_alpn(proto));
                    }
                }
                "port" => {
                    record.port = value.parse().ok();
                }
                "cap" => {
                    record.capabilities.push(value.to_string());
                }
                "cap-sha256" => {
                    record.cap_hashes.push(value.to_string());
                }
                "well-known" => {
                    record.well_known = Some(value.to_string());
                }
                "bap" => {
                    record.bap = Some(value.to_string());
                }
                "policy" => {
                    record.policy = Some(value.to_string());
                }
                "realm" => {
                    record.realm = Some(value.to_string());
                }
                _ => {}
            }
        }
    }

    Some(record)
}

/// A discovered MCP endpoint from AID lookup.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredEndpoint {
    /// Domain that was queried.
    pub domain: String,
    /// MCP endpoint URL.
    pub url: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// Auth hint.
    pub auth: Option<String>,
    /// Agent protocols supported (from DNS-AID ALPN).
    #[serde(default)]
    pub protocols: Vec<AgentProtocol>,
    /// Discovery method used.
    pub source: DiscoverySource,
}

impl DiscoveredEndpoint {
    /// Whether this endpoint advertises MCP protocol support.
    pub fn supports_mcp(&self) -> bool {
        self.protocols.iter().any(|p| *p == AgentProtocol::Mcp)
    }

    /// Whether this endpoint advertises A2A protocol support.
    #[allow(dead_code)]
    pub fn supports_a2a(&self) -> bool {
        self.protocols.iter().any(|p| *p == AgentProtocol::A2a)
    }
}

/// How an endpoint was discovered.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    DnsAidSvcb,
    HttpWellKnown,
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

    // Recognize both MCP and A2A protocols
    let protocol = json.get("p").and_then(|v| v.as_str()).unwrap_or("");
    let agent_proto = AgentProtocol::from_alpn(protocol);
    if agent_proto == AgentProtocol::Other(protocol.to_string()) {
        tracing::debug!(domain, protocol, "AID lookup: unrecognized protocol");
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
        protocols: vec![agent_proto],
        source: DiscoverySource::HttpWellKnown,
    })
}

/// Query DNS-AID SVCB records for a domain via `dig`.
///
/// Looks up `_agent._tcp.<domain>` SVCB records. Returns endpoints
/// for each record that advertises MCP or A2A protocols.
pub async fn lookup_dns_aid(domain: &str) -> Vec<DiscoveredEndpoint> {
    let query_name = format!("_agent._tcp.{domain}");
    let output = match tokio::process::Command::new("dig")
        .args(["+short", &query_name, "SVCB"])
        .output()
        .await
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        Ok(_) | Err(_) => {
            tracing::debug!(domain, "DNS-AID: dig command failed or not available");
            return Vec::new();
        }
    };

    let mut endpoints = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let full_line = format!("{query_name}. 300 IN SVCB {line}");
        if let Some(record) = parse_svcb_text(&full_line) {
            let url = record.endpoint_url();
            let protocols = record.protocols.clone();
            endpoints.push(DiscoveredEndpoint {
                domain: domain.to_string(),
                url,
                description: None,
                auth: None,
                protocols,
                source: DiscoverySource::DnsAidSvcb,
            });
        }
    }

    if !endpoints.is_empty() {
        tracing::info!(
            domain,
            count = endpoints.len(),
            "DNS-AID: found SVCB records"
        );
    }
    endpoints
}

/// Discover endpoints from an ARD catalog at `/.well-known/ai-catalog.json`.
pub async fn lookup_ard_catalog(
    domain: &str,
    timeout: std::time::Duration,
) -> Vec<DiscoveredEndpoint> {
    let base_url = format!("https://{domain}");
    match fetch_ard_catalog(&base_url, timeout).await {
        Ok(catalog) => {
            let endpoints = ard_to_endpoints(&catalog, domain);
            if !endpoints.is_empty() {
                tracing::info!(
                    domain,
                    count = endpoints.len(),
                    "ARD: found catalog entries"
                );
            }
            endpoints
        }
        Err(e) => {
            tracing::debug!(domain, error = %e, "ARD catalog lookup failed");
            Vec::new()
        }
    }
}

/// Discover MCP/A2A endpoints for a domain using all available methods.
///
/// Tries in order: DNS-AID SVCB → ARD catalog → HTTP well-known.
/// Returns all endpoints found across all methods (deduped by URL).
async fn discover_domain(domain: &str, timeout: std::time::Duration) -> Vec<DiscoveredEndpoint> {
    let mut all = Vec::new();
    let mut seen_urls = std::collections::HashSet::new();

    // 1. DNS-AID SVCB records
    let svcb = lookup_dns_aid(domain).await;
    for ep in svcb {
        if seen_urls.insert(ep.url.clone()) {
            all.push(ep);
        }
    }

    // 2. ARD catalog
    let ard = lookup_ard_catalog(domain, timeout).await;
    for ep in ard {
        if seen_urls.insert(ep.url.clone()) {
            all.push(ep);
        }
    }

    // 3. HTTP well-known fallback
    if let Some(ep) = lookup_domain_with_timeout(domain, timeout).await {
        if seen_urls.insert(ep.url.clone()) {
            all.push(ep);
        }
    }

    all
}

/// Discover MCP endpoints from a list of domains with a custom timeout.
///
/// For each domain, tries DNS-AID SVCB, ARD catalog, and HTTP
/// well-known in order. Results are deduped by URL per domain.
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
        handles.push(tokio::spawn(
            async move { discover_domain(&domain, timeout).await },
        ));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(endpoints) = handle.await {
            results.extend(endpoints);
        }
    }

    results
}

/// An entry from an ARD (Agentic Resource Discovery) catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArdCatalogEntry {
    /// Server name.
    pub name: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Media type: `application/mcp-server-card+json` or
    /// `application/a2a-agent-card+json`.
    #[serde(default, rename = "mediaType")]
    pub media_type: Option<String>,
    /// Transport configuration.
    #[serde(default)]
    pub transport: Option<ArdTransport>,
}

/// Transport details from an ARD catalog entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArdTransport {
    /// Transport type (e.g., "streamable-http", "sse", "stdio").
    #[serde(default, rename = "type")]
    pub transport_type: Option<String>,
    /// Endpoint URL.
    #[serde(default)]
    pub url: Option<String>,
}

/// Response from an ARD catalog endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArdCatalog {
    /// ARD spec version.
    #[serde(default)]
    pub version: Option<String>,
    /// Catalog entries.
    #[serde(default)]
    pub catalog: Vec<ArdCatalogEntry>,
}

/// Fetch an ARD catalog from a `/.well-known/ai-catalog.json` endpoint.
pub async fn fetch_ard_catalog(
    base_url: &str,
    timeout: std::time::Duration,
) -> Result<ArdCatalog, String> {
    let url = format!(
        "{}/.well-known/ai-catalog.json",
        base_url.trim_end_matches('/')
    );

    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("ARD fetch failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("ARD returned status {}", resp.status()));
    }

    resp.json::<ArdCatalog>()
        .await
        .map_err(|e| format!("ARD parse error: {e}"))
}

/// Convert ARD catalog entries into DiscoveredEndpoints.
pub fn ard_to_endpoints(catalog: &ArdCatalog, source_domain: &str) -> Vec<DiscoveredEndpoint> {
    catalog
        .catalog
        .iter()
        .filter_map(|entry| {
            let transport = entry.transport.as_ref()?;
            let url = transport.url.as_ref()?;

            let protocol = match entry.media_type.as_deref() {
                Some("application/mcp-server-card+json") => AgentProtocol::Mcp,
                Some("application/a2a-agent-card+json") => AgentProtocol::A2a,
                _ => AgentProtocol::Mcp,
            };

            Some(DiscoveredEndpoint {
                domain: source_domain.to_string(),
                url: url.clone(),
                description: entry.description.clone(),
                auth: None,
                protocols: vec![protocol],
                source: DiscoverySource::HttpWellKnown,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn discover_empty_domains() {
        let results = discover_all_with_timeout(&[], std::time::Duration::from_secs(5)).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn lookup_nonexistent_domain() {
        let result = lookup_domain_with_timeout(
            "this-domain-does-not-exist-navra-test.invalid",
            std::time::Duration::from_secs(5),
        )
        .await;
        assert!(result.is_none());
    }

    #[test]
    fn parse_svcb_basic() {
        let text = "_agent._tcp.example.org. 300 IN SVCB 1 tools.example.org. alpn=mcp port=443";
        let record = parse_svcb_text(text).unwrap();

        assert_eq!(record.target, "tools.example.org");
        assert_eq!(record.port, Some(443));
        assert!(record.supports_mcp());
        assert!(!record.supports_a2a());
    }

    #[test]
    fn parse_svcb_multi_alpn() {
        let text =
            "_agent._tcp.example.org. 300 IN SVCB 1 tools.example.org. alpn=mcp,a2a port=8443";
        let record = parse_svcb_text(text).unwrap();

        assert!(record.supports_mcp());
        assert!(record.supports_a2a());
        assert_eq!(record.port, Some(8443));
    }

    #[test]
    fn parse_svcb_with_params() {
        let text = "_agent._tcp.example.org. 300 IN SVCB 1 tools.example.org. \
                    alpn=mcp cap=urn:cap:tools policy=https://example.org/policy \
                    realm=corp.example.org bap=https://bap.example.org/profile";
        let record = parse_svcb_text(text).unwrap();

        assert_eq!(record.capabilities, vec!["urn:cap:tools"]);
        assert_eq!(
            record.policy.as_deref(),
            Some("https://example.org/policy")
        );
        assert_eq!(record.realm.as_deref(), Some("corp.example.org"));
        assert_eq!(
            record.bap.as_deref(),
            Some("https://bap.example.org/profile")
        );
    }

    #[test]
    fn parse_svcb_with_well_known() {
        let text =
            "_agent._tcp.example.org. 300 IN SVCB 1 tools.example.org. alpn=mcp well-known=/mcp";
        let record = parse_svcb_text(text).unwrap();

        assert_eq!(record.well_known.as_deref(), Some("/mcp"));
        assert_eq!(record.endpoint_url(), "https://tools.example.org/mcp");
    }

    #[test]
    fn endpoint_url_default_path() {
        let record = DnsAidRecord {
            target: "tools.example.org".to_string(),
            port: None,
            protocols: vec![AgentProtocol::Mcp],
            capabilities: Vec::new(),
            cap_hashes: Vec::new(),
            well_known: None,
            bap: None,
            policy: None,
            realm: None,
        };

        assert_eq!(
            record.endpoint_url(),
            "https://tools.example.org/.well-known/agent"
        );
    }

    #[test]
    fn endpoint_url_custom_port() {
        let record = DnsAidRecord {
            target: "tools.example.org".to_string(),
            port: Some(9315),
            protocols: vec![AgentProtocol::Mcp],
            capabilities: Vec::new(),
            cap_hashes: Vec::new(),
            well_known: None,
            bap: None,
            policy: None,
            realm: None,
        };

        assert_eq!(
            record.endpoint_url(),
            "https://tools.example.org:9315/.well-known/agent"
        );
    }

    #[test]
    fn parse_svcb_invalid_returns_none() {
        assert!(parse_svcb_text("").is_none());
        assert!(parse_svcb_text("not a DNS record").is_none());
        assert!(parse_svcb_text("example.org. IN A 1.2.3.4").is_none());
    }

    #[test]
    fn parse_svcb_https_record() {
        let text = "_agent._tcp.example.org. 300 IN HTTPS 1 tools.example.org. alpn=a2a";
        let record = parse_svcb_text(text).unwrap();

        assert_eq!(record.target, "tools.example.org");
        assert!(record.supports_a2a());
    }

    #[test]
    fn agent_protocol_round_trip() {
        assert_eq!(AgentProtocol::from_alpn("mcp"), AgentProtocol::Mcp);
        assert_eq!(AgentProtocol::from_alpn("a2a"), AgentProtocol::A2a);
        assert_eq!(
            AgentProtocol::from_alpn("grpc"),
            AgentProtocol::Other("grpc".to_string())
        );
        assert_eq!(AgentProtocol::Mcp.as_str(), "mcp");
        assert_eq!(AgentProtocol::A2a.as_str(), "a2a");
    }

    #[test]
    fn parse_svcb_cap_sha256() {
        let text = "_agent._tcp.example.org. 300 IN SVCB 1 tools.example.org. \
                    alpn=mcp cap-sha256=abc123def456";
        let record = parse_svcb_text(text).unwrap();
        assert_eq!(record.cap_hashes, vec!["abc123def456"]);
    }

    // --- ARD catalog tests ---

    #[test]
    fn ard_catalog_parse() {
        let json = r#"{
            "version": "0.9",
            "catalog": [
                {
                    "name": "code-tools",
                    "description": "Code analysis tools",
                    "mediaType": "application/mcp-server-card+json",
                    "transport": {
                        "type": "streamable-http",
                        "url": "https://tools.example.org/mcp"
                    }
                },
                {
                    "name": "data-agent",
                    "description": "Data processing agent",
                    "mediaType": "application/a2a-agent-card+json",
                    "transport": {
                        "type": "streamable-http",
                        "url": "https://agents.example.org/a2a"
                    }
                }
            ]
        }"#;

        let catalog: ArdCatalog = serde_json::from_str(json).unwrap();
        assert_eq!(catalog.version.as_deref(), Some("0.9"));
        assert_eq!(catalog.catalog.len(), 2);
        assert_eq!(catalog.catalog[0].name, "code-tools");
        assert_eq!(
            catalog.catalog[0].media_type.as_deref(),
            Some("application/mcp-server-card+json")
        );
    }

    #[test]
    fn ard_to_endpoints_converts() {
        let catalog = ArdCatalog {
            version: Some("0.9".to_string()),
            catalog: vec![
                ArdCatalogEntry {
                    name: "tools-server".to_string(),
                    description: Some("MCP tools".to_string()),
                    media_type: Some("application/mcp-server-card+json".to_string()),
                    transport: Some(ArdTransport {
                        transport_type: Some("streamable-http".to_string()),
                        url: Some("https://tools.example.org/mcp".to_string()),
                    }),
                },
                ArdCatalogEntry {
                    name: "no-transport".to_string(),
                    description: None,
                    media_type: None,
                    transport: None,
                },
            ],
        };

        let endpoints = ard_to_endpoints(&catalog, "example.org");
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].url, "https://tools.example.org/mcp");
        assert_eq!(endpoints[0].protocols, vec![AgentProtocol::Mcp]);
        assert_eq!(endpoints[0].source, DiscoverySource::HttpWellKnown);
    }

    #[test]
    fn ard_a2a_media_type_recognized() {
        let catalog = ArdCatalog {
            version: Some("0.9".to_string()),
            catalog: vec![ArdCatalogEntry {
                name: "agent".to_string(),
                description: None,
                media_type: Some("application/a2a-agent-card+json".to_string()),
                transport: Some(ArdTransport {
                    transport_type: Some("streamable-http".to_string()),
                    url: Some("https://agents.example.org/a2a".to_string()),
                }),
            }],
        };

        let endpoints = ard_to_endpoints(&catalog, "example.org");
        assert_eq!(endpoints[0].protocols, vec![AgentProtocol::A2a]);
    }

    #[test]
    fn ard_empty_catalog() {
        let catalog = ArdCatalog {
            version: Some("0.9".to_string()),
            catalog: vec![],
        };
        assert!(ard_to_endpoints(&catalog, "example.org").is_empty());
    }

    #[tokio::test]
    async fn ard_fetch_nonexistent() {
        let result = fetch_ard_catalog(
            "https://this-domain-does-not-exist-navra-test.invalid",
            std::time::Duration::from_secs(2),
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn dns_aid_nonexistent_domain() {
        let results = lookup_dns_aid("this-domain-does-not-exist-navra-test.invalid").await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn ard_catalog_nonexistent_domain() {
        let results = lookup_ard_catalog(
            "this-domain-does-not-exist-navra-test.invalid",
            std::time::Duration::from_secs(2),
        )
        .await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn discover_domain_deduplicates() {
        let results =
            discover_domain("this-domain-does-not-exist-navra-test.invalid", std::time::Duration::from_secs(2))
                .await;
        let urls: std::collections::HashSet<&str> =
            results.iter().map(|e| e.url.as_str()).collect();
        assert_eq!(urls.len(), results.len());
    }
}
