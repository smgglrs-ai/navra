use super::{ContentFilter, FilterContext, Finding};

const DANGEROUS_SCHEMES: &[&str] = &[
    "file://", "gopher://", "ftp://", "data://", "dict://", "ldap://",
];

const METADATA_DOMAINS: &[&str] = &[
    "metadata.google.internal",
    "metadata.goog",
];

pub struct SsrfFilter {
    url_re: regex_lite::Regex,
    bare_ip_re: regex_lite::Regex,
    ipv6_url_re: regex_lite::Regex,
}

impl Default for SsrfFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl SsrfFilter {
    pub fn new() -> Self {
        Self {
            url_re: regex_lite::Regex::new(
                r#"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s\)>\]"']+"#
            ).unwrap(),
            bare_ip_re: regex_lite::Regex::new(
                r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"
            ).unwrap(),
            ipv6_url_re: regex_lite::Regex::new(
                r"[a-zA-Z][a-zA-Z0-9+.\-]*://\[[^\]]+\]"
            ).unwrap(),
        }
    }

    fn check_url(&self, url: &str, start: usize) -> Vec<Finding> {
        let mut findings = Vec::new();

        let url_lower = url.to_ascii_lowercase();

        for &scheme in DANGEROUS_SCHEMES {
            if url_lower.starts_with(scheme) {
                findings.push(Finding {
                    start,
                    end: start + url.len(),
                    category: "ssrf-dangerous-scheme".to_string(),
                    confidence: 1.0,
                });
                return findings;
            }
        }

        let host = extract_host(url);
        if host.is_empty() {
            return findings;
        }

        let host_lower = host.to_ascii_lowercase();

        for &domain in METADATA_DOMAINS {
            if host_lower == domain {
                findings.push(Finding {
                    start,
                    end: start + url.len(),
                    category: "ssrf-metadata".to_string(),
                    confidence: 1.0,
                });
                return findings;
            }
        }

        if let Some(finding) = self.check_host_ip(&host, start, url.len()) {
            findings.push(finding);
        }

        findings
    }

    fn check_host_ip(&self, host: &str, start: usize, url_len: usize) -> Option<Finding> {
        // Check IPv6 in brackets
        if host.starts_with('[') && host.ends_with(']') {
            let inner = &host[1..host.len() - 1];
            return self.check_ipv6(inner, start, url_len);
        }

        // Check for IPv6-mapped IPv4 without brackets (in text)
        let host_lower = host.to_ascii_lowercase();
        if host_lower.starts_with("::ffff:") {
            let mapped = &host[7..];
            if let Some(octets) = normalize_ip(mapped) {
                if is_private_ipv4(octets) {
                    return Some(Finding {
                        start,
                        end: start + url_len,
                        category: "ssrf-encoded-ip".to_string(),
                        confidence: 1.0,
                    });
                }
            }
            // ::ffff:7f00:1 style
            if is_ipv6_mapped_hex_private(&host_lower) {
                return Some(Finding {
                    start,
                    end: start + url_len,
                    category: "ssrf-encoded-ip".to_string(),
                    confidence: 1.0,
                });
            }
        }

        // Check for hex integer IP (0x7f000001)
        if host_lower.starts_with("0x") && !host.contains('.') {
            if let Some(octets) = decode_hex_integer(&host_lower) {
                if is_private_ipv4(octets) {
                    return Some(Finding {
                        start,
                        end: start + url_len,
                        category: "ssrf-encoded-ip".to_string(),
                        confidence: 1.0,
                    });
                }
            }
        }

        // Check for decimal integer IP (2130706433)
        if host.chars().all(|c| c.is_ascii_digit()) && host.len() >= 7 {
            if let Ok(val) = host.parse::<u64>() {
                if val <= 0xFFFFFFFF {
                    let octets = u32_to_octets(val as u32);
                    if is_private_ipv4(octets) {
                        return Some(Finding {
                            start,
                            end: start + url_len,
                            category: "ssrf-encoded-ip".to_string(),
                            confidence: 1.0,
                        });
                    }
                }
            }
        }

        // Dotted notation (standard, hex octets, octal octets, mixed)
        if let Some(octets) = normalize_ip(host) {
            if is_private_ipv4(octets) {
                let category = if is_cloud_metadata_ip(octets) {
                    "ssrf-metadata"
                } else if has_encoded_octets(host) {
                    "ssrf-encoded-ip"
                } else {
                    "ssrf-private-ip"
                };
                return Some(Finding {
                    start,
                    end: start + url_len,
                    category: category.to_string(),
                    confidence: 1.0,
                });
            }
        }

        None
    }

    fn check_ipv6(&self, addr: &str, start: usize, url_len: usize) -> Option<Finding> {
        let addr_lower = addr.to_ascii_lowercase();

        if addr_lower == "::1" {
            return Some(Finding {
                start,
                end: start + url_len,
                category: "ssrf-encoded-ip".to_string(),
                confidence: 1.0,
            });
        }

        // IPv6-mapped IPv4: ::ffff:127.0.0.1 or ::ffff:7f00:1
        if addr_lower.starts_with("::ffff:") {
            let mapped = &addr[7..];
            if let Some(octets) = normalize_ip(mapped) {
                if is_private_ipv4(octets) {
                    return Some(Finding {
                        start,
                        end: start + url_len,
                        category: "ssrf-encoded-ip".to_string(),
                        confidence: 1.0,
                    });
                }
            }
            if is_ipv6_mapped_hex_private(&addr_lower) {
                return Some(Finding {
                    start,
                    end: start + url_len,
                    category: "ssrf-encoded-ip".to_string(),
                    confidence: 1.0,
                });
            }
        }

        // fc00::/7 (ULA)
        if addr_lower.starts_with("fc") || addr_lower.starts_with("fd") {
            return Some(Finding {
                start,
                end: start + url_len,
                category: "ssrf-encoded-ip".to_string(),
                confidence: 1.0,
            });
        }

        // fe80::/10 (link-local)
        if addr_lower.starts_with("fe8") || addr_lower.starts_with("fe9")
            || addr_lower.starts_with("fea") || addr_lower.starts_with("feb")
        {
            return Some(Finding {
                start,
                end: start + url_len,
                category: "ssrf-encoded-ip".to_string(),
                confidence: 1.0,
            });
        }

        None
    }
}

impl ContentFilter for SsrfFilter {
    fn name(&self) -> &str {
        "ssrf"
    }

    fn scan(&self, content: &str, _ctx: &FilterContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for m in self.url_re.find_iter(content) {
            findings.extend(self.check_url(m.as_str(), m.start()));
        }

        // IPv6 URLs with brackets (separate regex since the main one may not capture them well)
        for m in self.ipv6_url_re.find_iter(content) {
            // Skip if already covered by url_re match
            let dominated = findings.iter().any(|f| f.start <= m.start() && f.end >= m.end());
            if dominated {
                continue;
            }
            findings.extend(self.check_url(m.as_str(), m.start()));
        }

        // Bare IPs without scheme (e.g., in curl commands or text)
        for m in self.bare_ip_re.find_iter(content) {
            let dominated = findings.iter().any(|f| f.start <= m.start() && f.end >= m.end());
            if dominated {
                continue;
            }
            let host = m.as_str().split(':').next().unwrap_or(m.as_str());
            if let Some(octets) = normalize_ip(host) {
                if is_cloud_metadata_ip(octets) {
                    findings.push(Finding {
                        start: m.start(),
                        end: m.end(),
                        category: "ssrf-metadata".to_string(),
                        confidence: 1.0,
                    });
                }
            }
        }

        findings
    }
}

fn extract_host(url: &str) -> &str {
    let after_scheme = match url.find("://") {
        Some(idx) => &url[idx + 3..],
        None => return "",
    };

    // Strip userinfo
    let after_userinfo = match after_scheme.find('@') {
        Some(idx) => {
            let candidate = &after_scheme[..idx];
            // Only strip if there's no slash before the @
            if !candidate.contains('/') {
                &after_scheme[idx + 1..]
            } else {
                after_scheme
            }
        }
        None => after_scheme,
    };

    // Handle bracketed IPv6
    if after_userinfo.starts_with('[') {
        if let Some(end) = after_userinfo.find(']') {
            return &after_userinfo[..end + 1];
        }
    }

    // Take host up to port, path, or end
    let end = after_userinfo
        .find(|c: char| c == '/' || c == '?' || c == '#')
        .unwrap_or(after_userinfo.len());
    let host_port = &after_userinfo[..end];

    // Strip port
    if let Some(colon) = host_port.rfind(':') {
        let after_colon = &host_port[colon + 1..];
        if after_colon.chars().all(|c| c.is_ascii_digit()) {
            return &host_port[..colon];
        }
    }

    host_port
}

fn normalize_ip(host: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return None;
    }

    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        octets[i] = parse_octet(part)?;
    }
    Some(octets)
}

fn parse_octet(s: &str) -> Option<u8> {
    if s.is_empty() {
        return None;
    }

    let s_lower = s.to_ascii_lowercase();

    // Hex: 0x...
    if s_lower.starts_with("0x") {
        let hex = &s_lower[2..];
        if hex.is_empty() {
            return None;
        }
        let val = u16::from_str_radix(hex, 16).ok()?;
        if val > 255 {
            return None;
        }
        return Some(val as u8);
    }

    // Octal: leading 0 followed by more digits (but not just "0")
    if s.starts_with('0') && s.len() > 1 && s[1..].chars().all(|c| c.is_ascii_digit()) {
        let val = u16::from_str_radix(s, 8).ok()?;
        if val > 255 {
            return None;
        }
        return Some(val as u8);
    }

    // Decimal
    let val: u16 = s.parse().ok()?;
    if val > 255 {
        return None;
    }
    Some(val as u8)
}

fn decode_hex_integer(s: &str) -> Option<[u8; 4]> {
    let hex = s.strip_prefix("0x")?;
    if hex.is_empty() || hex.len() > 8 {
        return None;
    }
    let val = u32::from_str_radix(hex, 16).ok()?;
    Some(u32_to_octets(val))
}

fn u32_to_octets(val: u32) -> [u8; 4] {
    [
        ((val >> 24) & 0xFF) as u8,
        ((val >> 16) & 0xFF) as u8,
        ((val >> 8) & 0xFF) as u8,
        (val & 0xFF) as u8,
    ]
}

fn is_private_ipv4(octets: [u8; 4]) -> bool {
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // 127.0.0.0/8
    if octets[0] == 127 {
        return true;
    }
    // 0.0.0.0
    if octets == [0, 0, 0, 0] {
        return true;
    }
    // 169.254.0.0/16 (link-local)
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    // Alibaba metadata: 100.100.100.200
    if octets == [100, 100, 100, 200] {
        return true;
    }
    // Oracle metadata: 192.0.0.192
    if octets == [192, 0, 0, 192] {
        return true;
    }
    false
}

fn is_cloud_metadata_ip(octets: [u8; 4]) -> bool {
    // AWS/GCP/Azure/DigitalOcean: 169.254.169.254
    if octets == [169, 254, 169, 254] {
        return true;
    }
    // Alibaba: 100.100.100.200
    if octets == [100, 100, 100, 200] {
        return true;
    }
    // Oracle: 192.0.0.192
    if octets == [192, 0, 0, 192] {
        return true;
    }
    false
}

fn has_encoded_octets(host: &str) -> bool {
    host.split('.').any(|part| {
        let lower = part.to_ascii_lowercase();
        lower.starts_with("0x")
            || (part.starts_with('0') && part.len() > 1 && part[1..].chars().all(|c| c.is_ascii_digit()))
    })
}

/// Check if an IPv6-mapped hex address like ::ffff:7f00:1 maps to a private IPv4
fn is_ipv6_mapped_hex_private(addr: &str) -> bool {
    let suffix = match addr.strip_prefix("::ffff:") {
        Some(s) => s,
        None => return false,
    };

    let hex_parts: Vec<&str> = suffix.split(':').collect();
    if hex_parts.len() != 2 {
        return false;
    }

    let high = u16::from_str_radix(hex_parts[0], 16).ok();
    let low = u16::from_str_radix(hex_parts[1], 16).ok();

    if let (Some(h), Some(l)) = (high, low) {
        let octets = [
            ((h >> 8) & 0xFF) as u8,
            (h & 0xFF) as u8,
            ((l >> 8) & 0xFF) as u8,
            (l & 0xFF) as u8,
        ];
        is_private_ipv4(octets)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> FilterContext<'static> {
        FilterContext {
            agent_name: "test",
            operation: "read",
            path: Some("/test"),
        }
    }

    // --- Private IP detection ---

    #[test]
    fn detect_private_ip_10() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://10.0.0.1/admin", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-private-ip");
    }

    #[test]
    fn detect_private_ip_172() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://172.16.0.1/secret", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-private-ip");
    }

    #[test]
    fn detect_private_ip_192_168() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://192.168.1.1/", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-private-ip");
    }

    #[test]
    fn detect_private_ip_127() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://127.0.0.1:8080/api", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-private-ip");
    }

    // --- Cloud metadata endpoints ---

    #[test]
    fn detect_aws_metadata() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://169.254.169.254/latest/meta-data/", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-metadata");
    }

    #[test]
    fn detect_gcp_metadata_domain() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://metadata.google.internal/computeMetadata/v1/", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-metadata");
    }

    #[test]
    fn detect_gcp_metadata_goog() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://metadata.goog/computeMetadata/v1/", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-metadata");
    }

    #[test]
    fn detect_alibaba_metadata() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://100.100.100.200/latest/meta-data/", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-metadata");
    }

    #[test]
    fn detect_oracle_metadata() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://192.0.0.192/opc/v2/instance/", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-metadata");
    }

    // --- Hex IP evasion ---

    #[test]
    fn detect_hex_integer_ip() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://0x7f000001/secret", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-encoded-ip");
    }

    #[test]
    fn detect_hex_octets() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://0x7f.0x0.0x0.0x1/secret", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-encoded-ip");
    }

    // --- Octal IP evasion ---

    #[test]
    fn detect_octal_ip() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://0177.0.0.01/secret", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-encoded-ip");
    }

    // --- Decimal integer IP evasion ---

    #[test]
    fn detect_decimal_integer_ip() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://2130706433/secret", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-encoded-ip");
    }

    // --- IPv6 ---

    #[test]
    fn detect_ipv6_loopback() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://[::1]/admin", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-encoded-ip");
    }

    #[test]
    fn detect_ipv6_private_fc00() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://[fc00::1]/internal", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-encoded-ip");
    }

    #[test]
    fn detect_ipv6_link_local() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://[fe80::1]/internal", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-encoded-ip");
    }

    #[test]
    fn detect_ipv6_mapped_ipv4() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://[::ffff:127.0.0.1]/admin", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-encoded-ip");
    }

    #[test]
    fn detect_ipv6_mapped_hex() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://[::ffff:7f00:1]/admin", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-encoded-ip");
    }

    // --- Dangerous schemes ---

    #[test]
    fn detect_file_scheme() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("file:///etc/passwd", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-dangerous-scheme");
    }

    #[test]
    fn detect_gopher_scheme() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("gopher://evil.com:70/_", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-dangerous-scheme");
    }

    #[test]
    fn detect_dict_scheme() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("dict://evil.com/d:test", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-dangerous-scheme");
    }

    // --- No false positives ---

    #[test]
    fn no_false_positive_public_ip() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://8.8.8.8/dns-query", &ctx());
        assert!(findings.is_empty());
    }

    #[test]
    fn no_false_positive_public_domain() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("https://github.com/example/repo", &ctx());
        assert!(findings.is_empty());
    }

    #[test]
    fn no_false_positive_normal_text() {
        let filter = SsrfFilter::new();
        let findings = filter.scan(
            "This is a normal document about programming. No URLs here.",
            &ctx(),
        );
        assert!(findings.is_empty());
    }

    // --- URLs in context ---

    #[test]
    fn detect_url_in_curl_command() {
        let filter = SsrfFilter::new();
        let findings = filter.scan(
            "curl http://169.254.169.254/latest/meta-data/",
            &ctx(),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-metadata");
    }

    #[test]
    fn detect_url_in_markdown_link() {
        let filter = SsrfFilter::new();
        let findings = filter.scan(
            "Click [here](http://10.0.0.1/admin) for access",
            &ctx(),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-private-ip");
    }

    // --- normalize_ip unit tests ---

    #[test]
    fn normalize_standard_ip() {
        assert_eq!(normalize_ip("127.0.0.1"), Some([127, 0, 0, 1]));
    }

    #[test]
    fn normalize_hex_octets() {
        assert_eq!(normalize_ip("0x7f.0x0.0x0.0x1"), Some([127, 0, 0, 1]));
    }

    #[test]
    fn normalize_octal_octets() {
        assert_eq!(normalize_ip("0177.0.0.01"), Some([127, 0, 0, 1]));
    }

    #[test]
    fn normalize_mixed_octets() {
        assert_eq!(normalize_ip("0x7f.0.0.1"), Some([127, 0, 0, 1]));
    }

    #[test]
    fn normalize_invalid_ip() {
        assert_eq!(normalize_ip("not.an.ip.address"), None);
    }

    #[test]
    fn normalize_too_few_parts() {
        assert_eq!(normalize_ip("127.0.0"), None);
    }

    // --- extract_host ---

    #[test]
    fn extract_host_simple() {
        assert_eq!(extract_host("http://example.com/path"), "example.com");
    }

    #[test]
    fn extract_host_with_port() {
        assert_eq!(extract_host("http://example.com:8080/path"), "example.com");
    }

    #[test]
    fn extract_host_with_userinfo() {
        assert_eq!(extract_host("http://user:pass@example.com/path"), "example.com");
    }

    #[test]
    fn extract_host_ipv6_brackets() {
        assert_eq!(extract_host("http://[::1]/path"), "[::1]");
    }

    // --- Multiple findings ---

    #[test]
    fn detect_multiple_ssrf_urls() {
        let filter = SsrfFilter::new();
        let content = "Try http://10.0.0.1/a and file:///etc/shadow";
        let findings = filter.scan(content, &ctx());
        assert_eq!(findings.len(), 2);
        let cats: Vec<&str> = findings.iter().map(|f| f.category.as_str()).collect();
        assert!(cats.contains(&"ssrf-private-ip"));
        assert!(cats.contains(&"ssrf-dangerous-scheme"));
    }

    #[test]
    fn detect_0000_ip() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://0.0.0.0:8080/", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-private-ip");
    }

    #[test]
    fn detect_link_local() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://169.254.1.1/test", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssrf-private-ip");
    }

    #[test]
    fn no_false_positive_172_15() {
        let filter = SsrfFilter::new();
        // 172.15.x.x is NOT private (only 172.16-31.x)
        let findings = filter.scan("http://172.15.0.1/api", &ctx());
        assert!(findings.is_empty());
    }

    #[test]
    fn no_false_positive_172_32() {
        let filter = SsrfFilter::new();
        let findings = filter.scan("http://172.32.0.1/api", &ctx());
        assert!(findings.is_empty());
    }
}
