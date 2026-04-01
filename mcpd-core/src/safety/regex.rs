use super::{ContentFilter, FilterContext, Finding};

/// Detects secrets: API keys, tokens, private keys, passwords.
pub struct SecretFilter {
    patterns: Vec<SecretPattern>,
}

struct SecretPattern {
    category: &'static str,
    regex: regex_lite::Regex,
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
                // OpenAI / Anthropic API keys
                SecretPattern {
                    category: "api-key",
                    regex: regex_lite::Regex::new(r"sk-[A-Za-z0-9]{32,}").unwrap(),
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

/// Detects PII: SSNs, credit card numbers, phone numbers, email addresses.
pub struct PiiFilter {
    patterns: Vec<PiiPattern>,
}

struct PiiPattern {
    category: &'static str,
    regex: regex_lite::Regex,
    validator: Option<fn(&str) -> bool>,
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
                },
                // Credit card numbers (13-19 digits, with or without separators)
                PiiPattern {
                    category: "credit-card",
                    regex: regex_lite::Regex::new(
                        r"\b(?:\d[ -]?){13,19}\b"
                    ).unwrap(),
                    validator: Some(validate_luhn),
                },
                // US phone numbers
                PiiPattern {
                    category: "phone",
                    regex: regex_lite::Regex::new(
                        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
                    ).unwrap(),
                    validator: None,
                },
                // Email addresses
                PiiPattern {
                    category: "email",
                    regex: regex_lite::Regex::new(
                        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
                    ).unwrap(),
                    validator: None,
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
                // If a validator exists, check it
                if let Some(validate) = pattern.validator {
                    if !validate(matched) {
                        continue;
                    }
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
            .filter_map(|(category, pattern)| {
                match regex_lite::Regex::new(&pattern) {
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
                }
            })
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
        assert_eq!(&content[findings[0].start..findings[0].end], "AKIAIOSFODNN7EXAMPLE");
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
    fn detect_openai_key() {
        let filter = SecretFilter::new();
        let findings = filter.scan(
            "OPENAI_API_KEY=sk-1234567890abcdefghijklmnopqrstuv",
            &ctx(),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "api-key");
    }

    #[test]
    fn detect_private_key() {
        let filter = SecretFilter::new();
        let findings = filter.scan(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...",
            &ctx(),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "private-key");
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
        let content = "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nGH_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
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
        assert!(validate_luhn("378282246310005"));  // Amex test
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
        let filter = CustomFilter::new(vec![
            ("internal-url".to_string(), r"https://internal\.example\.com/\S+".to_string()),
        ]);
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
        let filter = CustomFilter::new(vec![
            ("secret".to_string(), r"TOP_SECRET_\w+".to_string()),
        ]);
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
}
