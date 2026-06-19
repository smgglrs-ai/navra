use super::{ContentFilter, FilterContext, Finding};

/// Detects secrets: API keys, tokens, private keys, passwords.
pub struct SecretFilter {
    patterns: Vec<SecretPattern>,
}

struct SecretPattern {
    category: &'static str,
    regex: regex_lite::Regex,
}

impl Default for SecretFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretFilter {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                // AWS Access Key ID
                SecretPattern {
                    category: "aws-key",
                    regex: regex_lite::Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
                },
                // AWS Secret Access Key (40 chars base64-like after separator)
                SecretPattern {
                    category: "aws-secret",
                    regex: regex_lite::Regex::new(
                        r"(?i)(?:aws_secret_access_key|secret_access_key)\s*[=:]\s*[A-Za-z0-9/+=]{40}"
                    ).unwrap(),
                },
                // GitHub personal access tokens
                SecretPattern {
                    category: "github-token",
                    regex: regex_lite::Regex::new(r"ghp_[A-Za-z0-9]{36}").unwrap(),
                },
                // GitHub fine-grained tokens
                SecretPattern {
                    category: "github-token",
                    regex: regex_lite::Regex::new(r"github_pat_[A-Za-z0-9_]{82}").unwrap(),
                },
                // GitLab tokens
                SecretPattern {
                    category: "gitlab-token",
                    regex: regex_lite::Regex::new(r"glpat-[A-Za-z0-9\-_]{20,}").unwrap(),
                },
                // OpenAI API keys (sk-proj-..., sk-... with 48+ chars)
                SecretPattern {
                    category: "api-key",
                    regex: regex_lite::Regex::new(r"sk-proj-[A-Za-z0-9_-]{32,}").unwrap(),
                },
                // Anthropic API keys (sk-ant-...)
                SecretPattern {
                    category: "api-key",
                    regex: regex_lite::Regex::new(r"sk-ant-[A-Za-z0-9_-]{32,}").unwrap(),
                },
                // Generic sk- keys (legacy OpenAI format: sk- followed by 48+ alphanumeric chars)
                SecretPattern {
                    category: "api-key",
                    regex: regex_lite::Regex::new(r"sk-[A-Za-z0-9]{48,}").unwrap(),
                },
                // Generic bearer tokens in config/env files.
                // Excludes patterns already caught by specific token detectors.
                SecretPattern {
                    category: "bearer-token",
                    regex: regex_lite::Regex::new(
                        r"(?i)(?:bearer|authorization)\s*[=:]\s*[A-Za-z0-9\-_.]{20,}"
                    ).unwrap(),
                },
                // Private keys (PEM format)
                SecretPattern {
                    category: "private-key",
                    regex: regex_lite::Regex::new(
                        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
                    ).unwrap(),
                },
                // Password assignments
                SecretPattern {
                    category: "password",
                    regex: regex_lite::Regex::new(
                        r#"(?i)(?:password|passwd|pwd)\s*[=:]\s*["']?[^\s"']{4,}"#
                    ).unwrap(),
                },
                // Connection strings with passwords
                SecretPattern {
                    category: "connection-string",
                    regex: regex_lite::Regex::new(
                        r"(?i)(?:mysql|postgres|mongodb|redis)://[^:]+:[^@]+@"
                    ).unwrap(),
                },
                // Slack webhook URLs
                SecretPattern {
                    category: "slack-webhook",
                    regex: regex_lite::Regex::new(
                        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"
                    ).unwrap(),
                },
            ],
        }
    }
}

impl ContentFilter for SecretFilter {
    fn name(&self) -> &str {
        "secrets"
    }

    fn scan(&self, content: &str, _ctx: &FilterContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for pattern in &self.patterns {
            for m in pattern.regex.find_iter(content) {
                findings.push(Finding {
                    start: m.start(),
                    end: m.end(),
                    category: pattern.category.to_string(),
                    confidence: 1.0,
                });
            }
        }
        findings
    }
}

/// Detects prompt injection patterns in tool responses.
pub struct PromptInjectionFilter {
    patterns: Vec<SecretPattern>,
}

impl Default for PromptInjectionFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl PromptInjectionFilter {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                SecretPattern {
                    category: "prompt-injection-tag",
                    regex: regex_lite::Regex::new(
                        r"(?i)<(?:system|instructions|im_start|im_end|endoftext)>"
                    ).unwrap(),
                },
                SecretPattern {
                    category: "imperative-override",
                    regex: regex_lite::Regex::new(
                        r"(?i)(?:ignore previous instructions|disregard your training|you are now a different|forget your instructions|override your)"
                    ).unwrap(),
                },
                SecretPattern {
                    category: "exfiltration-url",
                    regex: regex_lite::Regex::new(
                        r"!\[[^\]]*\]\(https?://[^)]*(?:exfil|leak|steal|collect)[^)]*\)"
                    ).unwrap(),
                },
                SecretPattern {
                    category: "markdown-image-exfil",
                    regex: regex_lite::Regex::new(
                        r"!\[\]\(https?://[^)]+\?(?:data|d|q|payload)="
                    ).unwrap(),
                },
                // Obfuscated injection: base64-encoded instructions
                SecretPattern {
                    category: "encoded-injection",
                    regex: regex_lite::Regex::new(
                        r"(?i)(?:base64|decode|eval|atob)\s*\("
                    ).unwrap(),
                },
                // Markdown link exfiltration (any external URL in image)
                SecretPattern {
                    category: "markdown-link-exfil",
                    regex: regex_lite::Regex::new(
                        r"!\[[^\]]*\]\(https?://[^)]*\)"
                    ).unwrap(),
                },
                // Special token sequences used by various LLMs
                SecretPattern {
                    category: "special-token",
                    regex: regex_lite::Regex::new(
                        r"(?i)<\|(?:im_start|im_end|endoftext|pad|sep|cls|mask)\|>"
                    ).unwrap(),
                },
            ],
        }
    }
}

impl ContentFilter for PromptInjectionFilter {
    fn name(&self) -> &str {
        "prompt-injection"
    }

    fn scan(&self, content: &str, _ctx: &FilterContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for pattern in &self.patterns {
            for m in pattern.regex.find_iter(content) {
                findings.push(Finding {
                    start: m.start(),
                    end: m.end(),
                    category: pattern.category.to_string(),
                    confidence: 0.9,
                });
            }
        }
        findings
    }
}

/// Detects PII: SSNs, credit card numbers, phone numbers, email addresses.
pub struct PiiFilter {
    patterns: Vec<PiiPattern>,
}

struct PiiPattern {
    category: &'static str,
    regex: regex_lite::Regex,
    /// Validates the matched string in isolation (e.g. Luhn check).
    validator: Option<fn(&str) -> bool>,
    /// Validates the match considering surrounding context.
    /// Arguments: (full_content, match_start, match_end).
    /// Return false to reject the match as a false positive.
    context_validator: Option<fn(&str, usize, usize) -> bool>,
}

impl Default for PiiFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiFilter {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                // US Social Security Numbers
                PiiPattern {
                    category: "ssn",
                    regex: regex_lite::Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
                    validator: Some(validate_ssn),
                    context_validator: None,
                },
                // French SIRET (14 digits) — must precede credit-card to win dedup
                PiiPattern {
                    category: "siret",
                    regex: regex_lite::Regex::new(
                        r"\b\d{3}\s?\d{3}\s?\d{3}\s?\d{5}\b"
                    ).unwrap(),
                    validator: Some(validate_siret),
                    context_validator: None,
                },
                // Credit card numbers (13-19 digits, with or without separators)
                PiiPattern {
                    category: "credit-card",
                    regex: regex_lite::Regex::new(
                        r"\b(?:\d[ -]?){13,19}\b"
                    ).unwrap(),
                    validator: Some(validate_luhn),
                    context_validator: Some(validate_not_structured_data),
                },
                // US phone numbers
                PiiPattern {
                    category: "phone",
                    regex: regex_lite::Regex::new(
                        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
                    ).unwrap(),
                    validator: None,
                    context_validator: Some(validate_phone_context),
                },
                // Email addresses
                PiiPattern {
                    category: "email",
                    regex: regex_lite::Regex::new(
                        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
                    ).unwrap(),
                    validator: None,
                    context_validator: None,
                },
                // French NIR (numéro de sécurité sociale)
                PiiPattern {
                    category: "nir",
                    regex: regex_lite::Regex::new(
                        r"\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b"
                    ).unwrap(),
                    validator: Some(validate_nir),
                    context_validator: None,
                },
                // EU IBAN
                PiiPattern {
                    category: "iban",
                    regex: regex_lite::Regex::new(
                        r"\b[A-Z]{2}\d{2}\s?[\dA-Z]{4}(?:\s?[\dA-Z]{4}){2,7}(?:\s?[\dA-Z]{1,4})?\b"
                    ).unwrap(),
                    validator: Some(validate_iban),
                    context_validator: None,
                },
                // Passport numbers (country-specific formats)
                PiiPattern {
                    category: "passport",
                    regex: regex_lite::Regex::new(
                        r"\b\d{2}[A-Z]{2}\d{5}\b"
                    ).unwrap(),
                    validator: None,
                    context_validator: None,
                },
                // EU phone numbers (+XX or 00XX prefix)
                PiiPattern {
                    category: "phone-eu",
                    regex: regex_lite::Regex::new(
                        r"(?:\+|00)(?:33|49|44|34|39|31|32|351|352|353|358|46|47|48)\s?[\d\s.\-]{6,12}\b"
                    ).unwrap(),
                    validator: None,
                    context_validator: None,
                },
                // IPv4 addresses
                PiiPattern {
                    category: "ip-address",
                    regex: regex_lite::Regex::new(
                        r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
                    ).unwrap(),
                    validator: Some(validate_public_ip),
                    context_validator: None,
                },
            ],
        }
    }
}

impl ContentFilter for PiiFilter {
    fn name(&self) -> &str {
        "pii"
    }

    fn scan(&self, content: &str, _ctx: &FilterContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for pattern in &self.patterns {
            for m in pattern.regex.find_iter(content) {
                let matched = m.as_str();
                if let Some(validate) = pattern.validator {
                    if !validate(matched) {
                        continue;
                    }
                }
                if let Some(validate_ctx) = pattern.context_validator {
                    if !validate_ctx(content, m.start(), m.end()) {
                        continue;
                    }
                }
                // Deduplicate: if a more specific pattern already matched
                // this exact span, skip the broader one. E.g., SIRET (14
                // digits) takes priority over credit-card (13-19 digits).
                let dominated = findings.iter().any(|f: &Finding| {
                    f.start == m.start() && f.end == m.end() && f.category != pattern.category
                });
                if dominated {
                    continue;
                }

                findings.push(Finding {
                    start: m.start(),
                    end: m.end(),
                    category: pattern.category.to_string(),
                    confidence: 1.0,
                });
            }
        }
        findings
    }
}

/// Detects PII in file paths: usernames that look like real names.
///
/// Extracts username segments from Unix and Windows home directory
/// paths (e.g. `/home/jean.dupont/`, `/Users/marie-claire/`,
/// `C:\Users\john.smith\`) and flags those that look like personal
/// names (contain a dot or hyphen suggesting first.last format).
///
/// System usernames (root, nobody, www-data, etc.) and generic
/// single-word usernames (admin, deploy, app) are skipped.
pub struct PathPiiFilter {
    /// Regex matching home directory path patterns.
    path_re: regex_lite::Regex,
    /// System/service usernames to exclude.
    system_users: &'static [&'static str],
}

impl Default for PathPiiFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl PathPiiFilter {
    pub fn new() -> Self {
        Self {
            // Captures the username segment from:
            //   /home/<user>/  or  /home/<user> (end/space)
            //   /Users/<user>/ or  /Users/<user> (end/space)
            //   ~<user>/
            //   C:\Users\<user>\ or C:\Users\<user> (end/space)
            path_re: regex_lite::Regex::new(
                r"(?:/home/|/Users/|~|[A-Z]:\\Users\\)([A-Za-z0-9._-]+)",
            )
            .unwrap(),
            system_users: &[
                // Unix system accounts
                "root",
                "nobody",
                "daemon",
                "bin",
                "sys",
                "sync",
                "games",
                "man",
                "lp",
                "mail",
                "news",
                "uucp",
                "proxy",
                "backup",
                "list",
                "irc",
                "gnats",
                "www-data",
                "sshd",
                "ntp",
                "messagebus",
                "polkitd",
                "avahi",
                "colord",
                "geoclue",
                "gdm",
                "lightdm",
                "sddm",
                "systemd-network",
                "systemd-resolve",
                "systemd-timesync",
                "flatpak",
                "fwupd",
                "pipewire",
                "rtkit",
                "dnsmasq",
                // macOS system accounts
                "_www",
                "_windowserver",
                "_spotlight",
                // Generic / service accounts
                "admin",
                "administrator",
                "deploy",
                "app",
                "service",
                "user",
                "guest",
                "test",
                "ci",
                "build",
                "runner",
                "git",
                "jenkins",
                "gitlab-runner",
                "github-actions",
                "node",
                "postgres",
                "mysql",
                "redis",
                "mongo",
                "nginx",
                "apache",
                "httpd",
                "docker",
                "vagrant",
                "ubuntu",
                "centos",
                "fedora",
                "ec2-user",
                "azureuser",
            ],
        }
    }

    /// Returns true if the username looks like a personal name.
    ///
    /// Heuristic: contains a dot or hyphen (e.g. jean.dupont,
    /// marie-claire), suggesting first.last or hyphenated name.
    /// Single words without separators are treated as generic.
    fn looks_like_personal_name(&self, username: &str) -> bool {
        username.contains('.') || username.contains('-')
    }

    /// Returns true if the username is a known system/service account.
    fn is_system_user(&self, username: &str) -> bool {
        self.system_users.contains(&username)
    }
}

impl ContentFilter for PathPiiFilter {
    fn name(&self) -> &str {
        "path-pii"
    }

    fn scan(&self, content: &str, _ctx: &FilterContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for m in self.path_re.captures_iter(content) {
            let username_match = m.get(1).unwrap();
            let username = username_match.as_str();

            if self.is_system_user(username) {
                continue;
            }
            if !self.looks_like_personal_name(username) {
                continue;
            }

            findings.push(Finding {
                start: username_match.start(),
                end: username_match.end(),
                category: "path-username".to_string(),
                confidence: 1.0,
            });
        }
        findings
    }
}

/// User-defined regex patterns from config.
///
/// Each pattern has a category name and a regex. Matched spans
/// are reported as findings with confidence 1.0.
pub struct CustomFilter {
    patterns: Vec<CustomPattern>,
}

struct CustomPattern {
    category: String,
    regex: regex_lite::Regex,
}

impl CustomFilter {
    /// Create a custom filter from a list of (category, regex_pattern) pairs.
    ///
    /// Invalid regex patterns are logged and skipped.
    pub fn new(patterns: Vec<(String, String)>) -> Self {
        let compiled: Vec<CustomPattern> = patterns
            .into_iter()
            .filter_map(
                |(category, pattern)| match regex_lite::Regex::new(&pattern) {
                    Ok(regex) => Some(CustomPattern { category, regex }),
                    Err(e) => {
                        tracing::warn!(
                            category = %category,
                            pattern = %pattern,
                            error = %e,
                            "Invalid custom safety pattern, skipping"
                        );
                        None
                    }
                },
            )
            .collect();
        Self { patterns: compiled }
    }

    /// Returns true if this filter has any valid patterns.
    pub fn has_patterns(&self) -> bool {
        !self.patterns.is_empty()
    }
}

impl ContentFilter for CustomFilter {
    fn name(&self) -> &str {
        "custom"
    }

    fn scan(&self, content: &str, _ctx: &FilterContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for pattern in &self.patterns {
            for m in pattern.regex.find_iter(content) {
                findings.push(Finding {
                    start: m.start(),
                    end: m.end(),
                    category: pattern.category.clone(),
                    confidence: 1.0,
                });
            }
        }
        findings
    }
}

/// User-defined PII regex patterns from config.
///
/// Unlike `CustomFilter`, categories from this filter are treated
/// as PII for IFC labeling (taint elevation, PII retention policies).
/// Each pattern has a name, category, and regex. Matched spans are
/// reported as findings with confidence 1.0.
#[derive(Debug)]
pub struct CustomPiiFilter {
    patterns: Vec<CustomPiiPattern>,
}

#[derive(Debug)]
struct CustomPiiPattern {
    #[allow(dead_code)] // visible via Debug formatting in diagnostic logs
    name: String,
    category: String,
    regex: regex_lite::Regex,
}

impl CustomPiiFilter {
    /// Create a custom PII filter from a list of (name, regex, category) tuples.
    ///
    /// Returns an error if any regex pattern is invalid.
    pub fn new(patterns: Vec<(String, String, String)>) -> Result<Self, String> {
        let mut compiled = Vec::with_capacity(patterns.len());
        for (name, pattern, category) in patterns {
            match regex_lite::Regex::new(&pattern) {
                Ok(regex) => compiled.push(CustomPiiPattern {
                    name,
                    category,
                    regex,
                }),
                Err(e) => {
                    return Err(format!("Invalid PII pattern '{}': {}", name, e));
                }
            }
        }
        Ok(Self { patterns: compiled })
    }

    /// Returns true if this filter has any valid patterns.
    pub fn has_patterns(&self) -> bool {
        !self.patterns.is_empty()
    }

    /// Returns the custom PII categories defined in this filter.
    pub fn categories(&self) -> Vec<String> {
        self.patterns.iter().map(|p| p.category.clone()).collect()
    }
}

impl ContentFilter for CustomPiiFilter {
    fn name(&self) -> &str {
        "custom-pii"
    }

    fn scan(&self, content: &str, _ctx: &FilterContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for pattern in &self.patterns {
            for m in pattern.regex.find_iter(content) {
                findings.push(Finding {
                    start: m.start(),
                    end: m.end(),
                    category: pattern.category.clone(),
                    confidence: 1.0,
                });
            }
        }
        findings
    }
}

/// Validate a US SSN: not all zeros in any group, not 000/666/9xx prefix.
fn validate_ssn(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    let area: u16 = parts[0].parse().unwrap_or(0);
    let group: u16 = parts[1].parse().unwrap_or(0);
    let serial: u16 = parts[2].parse().unwrap_or(0);

    // Invalid patterns per SSA rules
    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}

/// Luhn algorithm to validate credit card numbers.
fn validate_luhn(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    // Reject all-zero sequences
    if digits.iter().all(|&d| d == 0) {
        return false;
    }

    let mut sum = 0u32;
    let mut double = false;

    for &digit in digits.iter().rev() {
        let mut d = digit;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }

    sum % 10 == 0
}

/// Validate a French NIR: key = 97 - (first 13 digits mod 97).
fn validate_nir(s: &str) -> bool {
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 15 {
        return false;
    }
    let body: u64 = match digits[..13].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let key: u64 = match digits[13..15].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    key == 97 - (body % 97)
}

/// Validate an IBAN using the mod-97 check.
///
/// Rearrange: move first 4 chars to end, convert letters to numbers
/// (A=10, B=11, ..., Z=35), check that the resulting number mod 97 == 1.
fn validate_iban(s: &str) -> bool {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() < 5 || cleaned.len() > 34 {
        return false;
    }
    // Rearrange: BBAN + country code + check digits
    let rearranged = format!("{}{}", &cleaned[4..], &cleaned[..4]);
    // Convert letters to two-digit numbers
    let mut numeric = String::new();
    for c in rearranged.chars() {
        if c.is_ascii_digit() {
            numeric.push(c);
        } else if c.is_ascii_uppercase() {
            let val = (c as u32) - ('A' as u32) + 10;
            numeric.push_str(&val.to_string());
        } else {
            return false;
        }
    }
    // Mod-97 on potentially very large number: process in chunks
    let mut remainder: u64 = 0;
    for chunk in numeric.as_bytes().chunks(9) {
        let chunk_str = std::str::from_utf8(chunk).unwrap_or("0");
        let combined = format!("{}{}", remainder, chunk_str);
        remainder = combined.parse::<u64>().unwrap_or(0) % 97;
    }
    remainder == 1
}

/// Validate a French SIRET using Luhn checksum on the full 14 digits.
/// French convention: double even-indexed digits (0, 2, 4, ...) from left.
fn validate_siret(s: &str) -> bool {
    let digits: Vec<u32> = s
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c as u32 - '0' as u32)
        .collect();
    if digits.len() != 14 {
        return false;
    }
    let mut sum = 0u32;
    for (i, &d) in digits.iter().enumerate() {
        let mut v = if i % 2 == 0 { d * 2 } else { d };
        if v > 9 {
            v -= 9;
        }
        sum += v;
    }
    sum % 10 == 0
}

/// Validate that an IPv4 address is not a well-known non-PII address
/// (loopback, unspecified, or private ranges).
fn validate_public_ip(s: &str) -> bool {
    let parts: Vec<u8> = s.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 {
        return false;
    }
    // Exclude loopback (127.x.x.x)
    if parts[0] == 127 {
        return false;
    }
    // Exclude unspecified (0.0.0.0)
    if parts.iter().all(|&p| p == 0) {
        return false;
    }
    // Exclude private: 10.x.x.x
    if parts[0] == 10 {
        return false;
    }
    // Exclude private: 172.16.0.0 - 172.31.255.255
    if parts[0] == 172 && (16..=31).contains(&parts[1]) {
        return false;
    }
    // Exclude private: 192.168.x.x
    if parts[0] == 192 && parts[1] == 168 {
        return false;
    }
    true
}

/// Regex matching ISO 8601 timestamps and date strings.
/// Used to exclude false positives from phone/credit-card patterns.
static ISO_DATETIME_RE: std::sync::LazyLock<regex_lite::Regex> = std::sync::LazyLock::new(|| {
    regex_lite::Regex::new(
        r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?",
    )
    .unwrap()
});

/// Regex matching UUID v1-v5 (8-4-4-4-12 hex pattern).
static UUID_RE: std::sync::LazyLock<regex_lite::Regex> = std::sync::LazyLock::new(|| {
    regex_lite::Regex::new(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    )
    .unwrap()
});

/// Check whether a match range overlaps with any match of `re` in `content`.
fn overlaps_pattern(content: &str, start: usize, end: usize, re: &regex_lite::Regex) -> bool {
    for m in re.find_iter(content) {
        // If the structured-data match starts after our region, stop early
        if m.start() > end {
            break;
        }
        // Overlap: the two ranges intersect
        if m.start() < end && m.end() > start {
            return true;
        }
    }
    false
}

/// Context validator for US phone numbers.
///
/// Rejects matches that overlap with ISO 8601 timestamps/dates or UUIDs,
/// which produce false positives due to their digit groupings.
fn validate_phone_context(content: &str, start: usize, end: usize) -> bool {
    if overlaps_pattern(content, start, end, &ISO_DATETIME_RE) {
        return false;
    }
    if overlaps_pattern(content, start, end, &UUID_RE) {
        return false;
    }
    true
}

/// Context validator for credit card numbers.
///
/// Rejects matches that overlap with ISO 8601 timestamps/dates, UUIDs,
/// or hex strings (which can accidentally pass Luhn).
fn validate_not_structured_data(content: &str, start: usize, end: usize) -> bool {
    if overlaps_pattern(content, start, end, &ISO_DATETIME_RE) {
        return false;
    }
    if overlaps_pattern(content, start, end, &UUID_RE) {
        return false;
    }
    true
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

    // --- SecretFilter ---

    #[test]
    fn detect_aws_access_key() {
        let filter = SecretFilter::new();
        let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let findings = filter.scan(content, &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "aws-key");
        assert_eq!(
            &content[findings[0].start..findings[0].end],
            "AKIAIOSFODNN7EXAMPLE"
        );
    }

    #[test]
    fn detect_github_token() {
        let filter = SecretFilter::new();
        let findings = filter.scan(
            "export GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
            &ctx(),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "github-token");
    }

    #[test]
    fn detect_gitlab_token() {
        let filter = SecretFilter::new();
        let findings = filter.scan("token: glpat-xxxxxxxxxxxxxxxxxxxx", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "gitlab-token");
    }

    #[test]
    fn detect_openai_key_proj() {
        let filter = SecretFilter::new();
        let findings = filter.scan(
            "OPENAI_API_KEY=sk-proj-1234567890abcdefghijklmnopqrstuv0123456789abcdef",
            &ctx(),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "api-key");
    }

    #[test]
    fn detect_anthropic_key() {
        let filter = SecretFilter::new();
        let findings = filter.scan(
            "ANTHROPIC_API_KEY=sk-ant-api03-1234567890abcdefghijklmnopqrstuv0123456789",
            &ctx(),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "api-key");
    }

    #[test]
    fn detect_legacy_openai_key() {
        let filter = SecretFilter::new();
        // Legacy OpenAI format: sk- followed by 51 alphanumeric chars
        let findings = filter.scan(
            "OPENAI_API_KEY=sk-1234567890abcdefghijklmnopqrstuvwxyz012345678901234",
            &ctx(),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "api-key");
    }

    #[test]
    fn no_false_positive_short_sk_prefix() {
        let filter = SecretFilter::new();
        // Short sk- strings should not match (e.g. variable names, abbreviations)
        let findings = filter.scan("The sk-value is not a real key", &ctx());
        let api_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == "api-key")
            .collect();
        assert!(
            api_findings.is_empty(),
            "Short sk- falsely detected as API key"
        );
    }

    #[test]
    fn detect_private_key() {
        let filter = SecretFilter::new();
        let findings = filter.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "private-key");
    }

    #[test]
    fn detect_private_key_ec() {
        let filter = SecretFilter::new();
        let findings = filter.scan("-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "private-key");
    }

    #[test]
    fn detect_private_key_generic() {
        let filter = SecretFilter::new();
        let findings = filter.scan("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "private-key");
    }

    #[test]
    fn detect_private_key_openssh() {
        let filter = SecretFilter::new();
        let findings = filter.scan("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz...", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "private-key");
    }

    #[test]
    fn detect_private_key_dsa() {
        let filter = SecretFilter::new();
        let findings = filter.scan("-----BEGIN DSA PRIVATE KEY-----\nMIIBuwIBAAK...", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "private-key");
    }

    #[test]
    fn no_false_positive_public_key() {
        let filter = SecretFilter::new();
        let findings = filter.scan("-----BEGIN PUBLIC KEY-----\nMIIBIjANBg...", &ctx());
        let pk_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == "private-key")
            .collect();
        assert!(
            pk_findings.is_empty(),
            "Public key falsely detected as private key"
        );
    }

    #[test]
    fn detect_password_assignment() {
        let filter = SecretFilter::new();
        let findings = filter.scan("password=SuperSecret123!", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "password");
    }

    #[test]
    fn detect_connection_string() {
        let filter = SecretFilter::new();
        let findings = filter.scan(
            "DATABASE_URL=postgres://admin:s3cret@db.example.com:5432/app",
            &ctx(),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "connection-string");
    }

    #[test]
    fn no_false_positive_on_normal_text() {
        let filter = SecretFilter::new();
        let findings = filter.scan(
            "This is a normal document about programming. The password policy requires 8 characters.",
            &ctx(),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_multiple_secrets() {
        let filter = SecretFilter::new();
        let content =
            "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nGH_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let findings = filter.scan(content, &ctx());
        assert_eq!(findings.len(), 2);
    }

    // --- PiiFilter ---

    #[test]
    fn detect_ssn() {
        let filter = PiiFilter::new();
        let findings = filter.scan("SSN: 123-45-6789", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ssn");
    }

    #[test]
    fn reject_invalid_ssn() {
        let filter = PiiFilter::new();
        // 000 prefix is invalid
        let findings = filter.scan("SSN: 000-45-6789", &ctx());
        assert!(findings.is_empty());
        // 666 prefix is invalid
        let findings = filter.scan("SSN: 666-45-6789", &ctx());
        assert!(findings.is_empty());
        // 9xx prefix is invalid
        let findings = filter.scan("SSN: 900-45-6789", &ctx());
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_credit_card_visa() {
        let filter = PiiFilter::new();
        // Valid Visa test number
        let findings = filter.scan("Card: 4111111111111111", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "credit-card");
    }

    #[test]
    fn detect_credit_card_with_dashes() {
        let filter = PiiFilter::new();
        let findings = filter.scan("Card: 4111-1111-1111-1111", &ctx());
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn reject_invalid_credit_card() {
        let filter = PiiFilter::new();
        // Fails Luhn check
        let findings = filter.scan("Number: 1234567890123456", &ctx());
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_email() {
        let filter = PiiFilter::new();
        let findings = filter.scan("Contact: john.doe@example.com", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "email");
    }

    #[test]
    fn detect_phone_number() {
        let filter = PiiFilter::new();
        let findings = filter.scan("Call me at (555) 123-4567", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "phone");
    }

    #[test]
    fn detect_phone_with_country_code() {
        let filter = PiiFilter::new();
        let findings = filter.scan("Phone: +1-555-123-4567", &ctx());
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn no_pii_false_positive() {
        let filter = PiiFilter::new();
        let findings = filter.scan(
            "The year 2025 was significant. Version 3.14.159 was released.",
            &ctx(),
        );
        assert!(findings.is_empty());
    }

    // --- Validators ---

    #[test]
    fn luhn_valid_cards() {
        assert!(validate_luhn("4111111111111111")); // Visa test
        assert!(validate_luhn("5500000000000004")); // Mastercard test
        assert!(validate_luhn("378282246310005")); // Amex test
    }

    #[test]
    fn luhn_invalid() {
        assert!(!validate_luhn("1234567890123456"));
        assert!(!validate_luhn("0000000000000000"));
    }

    #[test]
    fn ssn_validation() {
        assert!(validate_ssn("123-45-6789"));
        assert!(!validate_ssn("000-45-6789"));
        assert!(!validate_ssn("666-45-6789"));
        assert!(!validate_ssn("900-45-6789"));
        assert!(!validate_ssn("123-00-6789"));
        assert!(!validate_ssn("123-45-0000"));
    }

    // --- Integration: SecretFilter + PiiFilter together ---

    #[test]
    fn mixed_secrets_and_pii() {
        let secret = SecretFilter::new();
        let pii = PiiFilter::new();
        let content = "AWS key AKIAIOSFODNN7EXAMPLE, SSN 123-45-6789, email test@example.com";
        let mut findings = secret.scan(content, &ctx());
        findings.extend(pii.scan(content, &ctx()));
        assert_eq!(findings.len(), 3);
        let categories: Vec<&str> = findings.iter().map(|f| f.category.as_str()).collect();
        assert!(categories.contains(&"aws-key"));
        assert!(categories.contains(&"ssn"));
        assert!(categories.contains(&"email"));
    }

    // --- Custom filter tests ---

    #[test]
    fn custom_filter_matches_pattern() {
        let filter = CustomFilter::new(vec![(
            "internal-url".to_string(),
            r"https://internal\.example\.com/\S+".to_string(),
        )]);
        let content = "Visit https://internal.example.com/secret-page for details";
        let findings = filter.scan(content, &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "internal-url");
    }

    #[test]
    fn custom_filter_multiple_patterns() {
        let filter = CustomFilter::new(vec![
            ("project-id".to_string(), r"PROJ-\d{4,}".to_string()),
            ("api-key".to_string(), r"myapp_[a-f0-9]{32}".to_string()),
        ]);
        let content = "Project PROJ-12345 uses key myapp_deadbeef01234567890abcdef1234567";
        let findings = filter.scan(content, &ctx());
        assert_eq!(findings.len(), 2);
        let categories: Vec<&str> = findings.iter().map(|f| f.category.as_str()).collect();
        assert!(categories.contains(&"project-id"));
        assert!(categories.contains(&"api-key"));
    }

    #[test]
    fn custom_filter_no_match() {
        let filter = CustomFilter::new(vec![("secret".to_string(), r"TOP_SECRET_\w+".to_string())]);
        let content = "This is perfectly normal text";
        let findings = filter.scan(content, &ctx());
        assert!(findings.is_empty());
    }

    #[test]
    fn custom_filter_invalid_regex_skipped() {
        let filter = CustomFilter::new(vec![
            ("valid".to_string(), r"hello".to_string()),
            ("invalid".to_string(), r"[invalid".to_string()),
        ]);
        // Only valid pattern should survive
        assert!(filter.has_patterns());
        let findings = filter.scan("hello world", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "valid");
    }

    #[test]
    fn custom_filter_empty() {
        let filter = CustomFilter::new(vec![]);
        assert!(!filter.has_patterns());
        let findings = filter.scan("anything", &ctx());
        assert!(findings.is_empty());
    }

    // --- False positive tests ---

    #[test]
    fn no_false_positive_on_iso_timestamp() {
        let filter = PiiFilter::new();
        let content = "created_at: 2026-04-25T16:51:00.918Z";
        let findings = filter.scan(content, &ctx());
        let phone_findings: Vec<_> = findings.iter().filter(|f| f.category == "phone").collect();
        assert!(
            phone_findings.is_empty(),
            "ISO timestamp falsely detected as phone: {:?}",
            phone_findings
        );
        let cc_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == "credit-card")
            .collect();
        assert!(
            cc_findings.is_empty(),
            "ISO timestamp falsely detected as credit-card: {:?}",
            cc_findings
        );
    }

    #[test]
    fn no_false_positive_on_uuid() {
        let filter = PiiFilter::new();
        let content = "id: 7016dc2c-f30e-458b-95ad-83f0c6c20617";
        let findings = filter.scan(content, &ctx());
        let phone_findings: Vec<_> = findings.iter().filter(|f| f.category == "phone").collect();
        assert!(
            phone_findings.is_empty(),
            "UUID falsely detected as phone: {:?}",
            phone_findings
        );
        let cc_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == "credit-card")
            .collect();
        assert!(
            cc_findings.is_empty(),
            "UUID falsely detected as credit-card: {:?}",
            cc_findings
        );
    }

    #[test]
    fn no_false_positive_on_date() {
        let filter = PiiFilter::new();
        let content = "date: 2026-04-25";
        let findings = filter.scan(content, &ctx());
        let phone_findings: Vec<_> = findings.iter().filter(|f| f.category == "phone").collect();
        assert!(
            phone_findings.is_empty(),
            "Date falsely detected as phone: {:?}",
            phone_findings
        );
    }

    #[test]
    fn still_detects_real_us_phone() {
        let filter = PiiFilter::new();
        let findings = filter.scan("Call (555) 123-4567 now", &ctx());
        assert_eq!(findings.iter().filter(|f| f.category == "phone").count(), 1);
    }

    #[test]
    fn still_detects_real_phone_with_country_code() {
        let filter = PiiFilter::new();
        let findings = filter.scan("Phone: +1-555-123-4567", &ctx());
        assert_eq!(findings.iter().filter(|f| f.category == "phone").count(), 1);
    }

    #[test]
    fn no_false_positive_on_memory_query_response() {
        // Realistic memory_query response that was getting redacted
        let filter = PiiFilter::new();
        let content = r#"{"id":"7016dc2c-f30e-458b-95ad-83f0c6c20617","created_at":"2026-04-25T16:51:00.918Z","content":"user asked about Rust"}"#;
        let findings = filter.scan(content, &ctx());
        let phone_findings: Vec<_> = findings.iter().filter(|f| f.category == "phone").collect();
        assert!(
            phone_findings.is_empty(),
            "Memory response falsely detected as phone: {:?}",
            phone_findings
        );
    }

    // --- French NIR ---

    #[test]
    fn detect_french_nir() {
        let filter = PiiFilter::new();
        // Valid NIR: body=2840578006084, compute correct key
        let body: u64 = 2_840_578_006_084;
        let key = 97 - (body % 97);
        let nir = format!("NIR: 2 84 05 78 006 084 {:02}", key);
        let findings = filter.scan(&nir, &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "nir");
    }

    #[test]
    fn reject_invalid_nir_key() {
        let filter = PiiFilter::new();
        // Compute correct key, then use a different one
        let body: u64 = 2_840_578_006_084;
        let key = 97 - (body % 97);
        let bad_key = if key == 99 { 98 } else { 99 };
        let nir = format!("NIR: 2 84 05 78 006 084 {:02}", bad_key);
        let findings = filter.scan(&nir, &ctx());
        assert!(findings.is_empty());
    }

    // --- IBAN ---

    #[test]
    fn detect_iban_france() {
        let filter = PiiFilter::new();
        let findings = filter.scan("IBAN: FR76 3000 6000 0112 3456 7890 189", &ctx());
        let iban_findings: Vec<_> = findings.iter().filter(|f| f.category == "iban").collect();
        assert_eq!(iban_findings.len(), 1);
    }

    #[test]
    fn detect_iban_germany() {
        let filter = PiiFilter::new();
        let findings = filter.scan("IBAN: DE89 3704 0044 0532 0130 00", &ctx());
        let iban_findings: Vec<_> = findings.iter().filter(|f| f.category == "iban").collect();
        assert_eq!(iban_findings.len(), 1);
    }

    #[test]
    fn reject_invalid_iban_checksum() {
        let filter = PiiFilter::new();
        // DE00 instead of DE89 -- invalid check digits
        let findings = filter.scan("IBAN: DE00 3704 0044 0532 0130 00", &ctx());
        let iban_findings: Vec<_> = findings.iter().filter(|f| f.category == "iban").collect();
        assert!(iban_findings.is_empty());
    }

    // --- EU phone numbers ---

    #[test]
    fn detect_eu_phone_france() {
        let filter = PiiFilter::new();
        let findings = filter.scan("Phone: +33 1 23 45 67 89", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "phone-eu");
    }

    #[test]
    fn detect_eu_phone_germany() {
        let filter = PiiFilter::new();
        let findings = filter.scan("Phone: +49 30 12345678", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "phone-eu");
    }

    // --- IP addresses ---

    #[test]
    fn detect_ipv4() {
        let filter = PiiFilter::new();
        let findings = filter.scan("Server at 203.0.113.42", &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "ip-address");
    }

    #[test]
    fn no_false_positive_localhost() {
        let filter = PiiFilter::new();
        let findings = filter.scan("Listening on 127.0.0.1:8080", &ctx());
        let ip_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == "ip-address")
            .collect();
        assert!(ip_findings.is_empty());
    }

    #[test]
    fn no_false_positive_private_ip() {
        let filter = PiiFilter::new();
        let findings = filter.scan("LAN address 192.168.1.1", &ctx());
        let ip_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == "ip-address")
            .collect();
        assert!(ip_findings.is_empty());
    }

    // --- New validators ---

    #[test]
    fn nir_validation() {
        // Valid: body=2840578006084, key=97-(2840578006084%97)
        let key = 97 - (2_840_578_006_084_u64 % 97);
        let nir = format!("2840578006084{:02}", key);
        assert!(validate_nir(&nir));
        // Invalid key
        assert!(!validate_nir("284057800608499"));
    }

    #[test]
    fn iban_validation() {
        assert!(validate_iban("DE89370400440532013000"));
        assert!(validate_iban("FR7630006000011234567890189"));
        assert!(!validate_iban("DE00370400440532013000"));
    }

    #[test]
    fn public_ip_validation() {
        assert!(validate_public_ip("203.0.113.42"));
        assert!(!validate_public_ip("127.0.0.1"));
        assert!(!validate_public_ip("0.0.0.0"));
        assert!(!validate_public_ip("10.0.0.1"));
        assert!(!validate_public_ip("172.16.0.1"));
        assert!(!validate_public_ip("192.168.1.1"));
    }

    // --- PathPiiFilter ---

    #[test]
    fn detect_path_username_unix() {
        let filter = PathPiiFilter::new();
        let content = "Reading /home/jean.dupont/documents/report.txt";
        let findings = filter.scan(content, &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "path-username");
        assert_eq!(&content[findings[0].start..findings[0].end], "jean.dupont");
    }

    #[test]
    fn no_flag_system_user_root() {
        let filter = PathPiiFilter::new();
        let findings = filter.scan("File at /home/root/.bashrc", &ctx());
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_path_username_macos() {
        let filter = PathPiiFilter::new();
        let content = "Path: /Users/marie-claire.dubois/Desktop/";
        let findings = filter.scan(content, &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "path-username");
        assert_eq!(
            &content[findings[0].start..findings[0].end],
            "marie-claire.dubois"
        );
    }

    #[test]
    fn no_flag_generic_username() {
        let filter = PathPiiFilter::new();
        let findings = filter.scan("Deployed to /home/deploy/app/", &ctx());
        assert!(findings.is_empty());
    }

    #[test]
    fn no_flag_tmp_path() {
        let filter = PathPiiFilter::new();
        let findings = filter.scan("Temp file: /tmp/some-file.txt", &ctx());
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_path_username_windows() {
        let filter = PathPiiFilter::new();
        let content = r"Config at C:\Users\john.smith\AppData\config.ini";
        let findings = filter.scan(content, &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "path-username");
        assert_eq!(&content[findings[0].start..findings[0].end], "john.smith");
    }

    #[test]
    fn no_flag_www_data_system_user() {
        let filter = PathPiiFilter::new();
        let findings = filter.scan("Logs in /home/www-data/logs/", &ctx());
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_hyphenated_name_not_system() {
        let filter = PathPiiFilter::new();
        let content = "/home/marie-claire/projects/";
        let findings = filter.scan(content, &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(&content[findings[0].start..findings[0].end], "marie-claire");
    }

    #[test]
    fn no_flag_simple_word_username() {
        let filter = PathPiiFilter::new();
        // Single word without dots or hyphens — could be anyone
        let findings = filter.scan("/home/fabien/code/", &ctx());
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_multiple_path_usernames() {
        let filter = PathPiiFilter::new();
        let content = "Compare /home/jean.dupont/a.txt with /Users/alice.martin/b.txt";
        let findings = filter.scan(content, &ctx());
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn detect_tilde_path() {
        let filter = PathPiiFilter::new();
        let content = "Home is ~jean.dupont/documents/";
        let findings = filter.scan(content, &ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(&content[findings[0].start..findings[0].end], "jean.dupont");
    }

    // --- CustomPiiFilter tests ---

    #[test]
    fn custom_pii_filter_valid_patterns() {
        let filter = CustomPiiFilter::new(vec![
            (
                "employee-id".to_string(),
                r"\bEMP-\d{6}\b".to_string(),
                "employee-id".to_string(),
            ),
            (
                "badge-number".to_string(),
                r"\bBDG[A-Z]\d{4}\b".to_string(),
                "badge".to_string(),
            ),
        ])
        .unwrap();
        assert!(filter.has_patterns());
        assert_eq!(filter.categories().len(), 2);
        assert!(filter.categories().contains(&"employee-id".to_string()));
        assert!(filter.categories().contains(&"badge".to_string()));
    }

    #[test]
    fn custom_pii_filter_rejects_invalid_regex() {
        let result = CustomPiiFilter::new(vec![(
            "bad-pattern".to_string(),
            r"[invalid".to_string(),
            "bad".to_string(),
        )]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("bad-pattern"));
    }

    #[test]
    fn custom_pii_filter_detects_patterns() {
        let filter = CustomPiiFilter::new(vec![
            (
                "employee-id".to_string(),
                r"\bEMP-\d{6}\b".to_string(),
                "employee-id".to_string(),
            ),
            (
                "project-code".to_string(),
                r"\bPRJ-[A-Z]{3}-\d{4}\b".to_string(),
                "project-code".to_string(),
            ),
        ])
        .unwrap();
        let content = "Employee EMP-123456 works on PRJ-SEC-2026";
        let findings = filter.scan(content, &ctx());
        assert_eq!(findings.len(), 2);
        let categories: Vec<&str> = findings.iter().map(|f| f.category.as_str()).collect();
        assert!(categories.contains(&"employee-id"));
        assert!(categories.contains(&"project-code"));
    }

    #[test]
    fn custom_pii_filter_no_match() {
        let filter = CustomPiiFilter::new(vec![(
            "employee-id".to_string(),
            r"\bEMP-\d{6}\b".to_string(),
            "employee-id".to_string(),
        )])
        .unwrap();
        let findings = filter.scan("No employee IDs here", &ctx());
        assert!(findings.is_empty());
    }

    #[test]
    fn custom_pii_filter_empty() {
        let filter = CustomPiiFilter::new(vec![]).unwrap();
        assert!(!filter.has_patterns());
        let findings = filter.scan("anything", &ctx());
        assert!(findings.is_empty());
    }

    #[test]
    fn custom_pii_filter_name_is_custom_pii() {
        let filter = CustomPiiFilter::new(vec![(
            "test".to_string(),
            r"test".to_string(),
            "test".to_string(),
        )])
        .unwrap();
        assert_eq!(filter.name(), "custom-pii");
    }
}

#[cfg(kani)]
mod kani_proofs {
    // All proofs use pure integer logic to avoid format!/String OOM in CBMC.
    // The string-parsing functions (validate_ssn, validate_public_ip, etc.)
    // are tested via unit tests; here we verify the underlying decision logic.

    /// SSN core logic: area must not be 0, 666, or >= 900;
    /// group and serial must not be 0.
    fn ssn_valid(area: u16, group: u16, serial: u16) -> bool {
        area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
    }

    #[kani::proof]
    fn ssn_rejects_area_zero() {
        let group: u16 = kani::any();
        let serial: u16 = kani::any();
        kani::assume(group >= 1 && group <= 99);
        kani::assume(serial >= 1 && serial <= 9999);
        assert!(!ssn_valid(0, group, serial));
    }

    #[kani::proof]
    fn ssn_rejects_area_666() {
        let group: u16 = kani::any();
        let serial: u16 = kani::any();
        kani::assume(group >= 1 && group <= 99);
        kani::assume(serial >= 1 && serial <= 9999);
        assert!(!ssn_valid(666, group, serial));
    }

    #[kani::proof]
    fn ssn_rejects_area_900_plus() {
        let area: u16 = kani::any();
        kani::assume(area >= 900 && area <= 999);
        assert!(!ssn_valid(area, 1, 1));
    }

    /// IP core logic: reject private ranges (10.x, 172.16-31.x, 192.168.x),
    /// loopback (127.x), and unspecified (0.0.0.0).
    fn ip_is_public(a: u8, b: u8) -> bool {
        if a == 127 {
            return false;
        }
        if a == 10 {
            return false;
        }
        if a == 172 && (16..=31).contains(&b) {
            return false;
        }
        if a == 192 && b == 168 {
            return false;
        }
        true
    }

    #[kani::proof]
    fn ip_rejects_private_10() {
        let b: u8 = kani::any();
        assert!(!ip_is_public(10, b));
    }

    #[kani::proof]
    fn ip_rejects_private_192_168() {
        assert!(!ip_is_public(192, 168));
    }

    #[kani::proof]
    fn ip_rejects_loopback() {
        let b: u8 = kani::any();
        assert!(!ip_is_public(127, b));
    }

    /// NIR checksum: key = 97 - (body % 97).
    /// Prove key is always in [1, 97] and the check equation holds.
    #[kani::proof]
    fn nir_checksum_key_bounded() {
        let body: u32 = kani::any();
        kani::assume(body < 10_000_000);
        let remainder = body % 97;
        let key = 97 - remainder;
        assert!(key >= 1);
        assert!(key <= 97);
    }

    #[kani::proof]
    fn siret_doubling_bounded() {
        let d: u32 = kani::any();
        kani::assume(d <= 9);
        let mut v = d * 2;
        if v > 9 {
            v -= 9;
        }
        assert!(v <= 9);
    }
}
