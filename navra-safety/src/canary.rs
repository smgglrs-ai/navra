use super::{ContentFilter, FilterContext, Finding};

pub enum CanaryMatch {
    Exact(String),
    Pattern(regex_lite::Regex),
}

pub struct CanaryToken {
    pub name: String,
    pub value: CanaryMatch,
}

pub struct CanaryFilter {
    tokens: Vec<CanaryToken>,
}

impl CanaryFilter {
    pub fn new(tokens: Vec<CanaryToken>) -> Self {
        Self { tokens }
    }

    /// Returns true if this filter has any canary tokens configured.
    pub fn has_tokens(&self) -> bool {
        !self.tokens.is_empty()
    }

    pub fn from_config(configs: Vec<(String, String, bool)>) -> Self {
        let tokens = configs
            .into_iter()
            .filter_map(|(name, value, is_regex)| {
                let canary_match = if is_regex {
                    match regex_lite::Regex::new(&value) {
                        Ok(re) => CanaryMatch::Pattern(re),
                        Err(e) => {
                            tracing::warn!(
                                name = %name,
                                pattern = %value,
                                error = %e,
                                "skipping canary token with invalid regex"
                            );
                            return None;
                        }
                    }
                } else {
                    CanaryMatch::Exact(value)
                };
                Some(CanaryToken {
                    name,
                    value: canary_match,
                })
            })
            .collect();
        Self { tokens }
    }
}

impl ContentFilter for CanaryFilter {
    fn name(&self) -> &str {
        "canary"
    }

    fn scan(&self, content: &str, _ctx: &FilterContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        for token in &self.tokens {
            match &token.value {
                CanaryMatch::Exact(needle) => {
                    let mut start = 0;
                    while let Some(pos) = content[start..].find(needle) {
                        let abs_start = start + pos;
                        let abs_end = abs_start + needle.len();
                        findings.push(Finding {
                            start: abs_start,
                            end: abs_end,
                            category: format!("canary:{}", token.name),
                            confidence: 1.0,
                        });
                        start = abs_end;
                    }
                }
                CanaryMatch::Pattern(re) => {
                    for m in re.find_iter(content) {
                        findings.push(Finding {
                            start: m.start(),
                            end: m.end(),
                            category: format!("canary:{}", token.name),
                            confidence: 0.95,
                        });
                    }
                }
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx() -> FilterContext<'static> {
        FilterContext {
            agent_name: "test",
            operation: "read",
            path: None,
        }
    }

    #[test]
    fn exact_match_detection() {
        let filter = CanaryFilter::new(vec![CanaryToken {
            name: "db-password-canary".into(),
            value: CanaryMatch::Exact("CANARY_xK9mP2qR".into()),
        }]);
        let findings = filter.scan("password is CANARY_xK9mP2qR here", &test_ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "canary:db-password-canary");
        assert_eq!(findings[0].confidence, 1.0);
        assert_eq!(findings[0].start, 12);
        assert_eq!(findings[0].end, 27);
    }

    #[test]
    fn regex_pattern_detection() {
        let filter = CanaryFilter::new(vec![CanaryToken {
            name: "secret-format".into(),
            value: CanaryMatch::Pattern(
                regex_lite::Regex::new(r"TRAP-[A-Z0-9]{8}").unwrap(),
            ),
        }]);
        let findings = filter.scan("found TRAP-AB12CD34 in output", &test_ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "canary:secret-format");
        assert_eq!(findings[0].confidence, 0.95);
    }

    #[test]
    fn multiple_canary_tokens_in_same_content() {
        let filter = CanaryFilter::new(vec![
            CanaryToken {
                name: "token-a".into(),
                value: CanaryMatch::Exact("ALPHA_CANARY".into()),
            },
            CanaryToken {
                name: "token-b".into(),
                value: CanaryMatch::Exact("BETA_CANARY".into()),
            },
        ]);
        let findings = filter.scan("ALPHA_CANARY and BETA_CANARY", &test_ctx());
        assert_eq!(findings.len(), 2);
        let categories: Vec<&str> = findings.iter().map(|f| f.category.as_str()).collect();
        assert!(categories.contains(&"canary:token-a"));
        assert!(categories.contains(&"canary:token-b"));
    }

    #[test]
    fn no_false_positive_when_canary_not_present() {
        let filter = CanaryFilter::new(vec![CanaryToken {
            name: "missing".into(),
            value: CanaryMatch::Exact("CANARY_UNIQUE_VALUE".into()),
        }]);
        let findings = filter.scan("this text contains nothing sensitive", &test_ctx());
        assert!(findings.is_empty());
    }

    #[test]
    fn case_sensitive_exact_match() {
        let filter = CanaryFilter::new(vec![CanaryToken {
            name: "case-test".into(),
            value: CanaryMatch::Exact("SecretCanary".into()),
        }]);
        let findings = filter.scan("secretcanary SECRETCANARY secretCanary", &test_ctx());
        assert!(findings.is_empty());
    }

    #[test]
    fn invalid_regex_in_from_config_is_skipped() {
        let filter = CanaryFilter::from_config(vec![
            ("good".into(), "valid-pattern".into(), false),
            ("bad-regex".into(), "[invalid(".into(), true),
            ("good-regex".into(), r"ok-\d+".into(), true),
        ]);
        assert_eq!(filter.tokens.len(), 2);
    }

    #[test]
    fn empty_filter_produces_no_findings() {
        let filter = CanaryFilter::new(vec![]);
        let findings = filter.scan("any content here", &test_ctx());
        assert!(findings.is_empty());
    }

    #[test]
    fn finding_category_includes_token_name() {
        let filter = CanaryFilter::new(vec![CanaryToken {
            name: "my-custom-name".into(),
            value: CanaryMatch::Exact("tripwire".into()),
        }]);
        let findings = filter.scan("tripwire detected", &test_ctx());
        assert_eq!(findings[0].category, "canary:my-custom-name");
    }

    #[test]
    fn canary_at_start_of_content() {
        let filter = CanaryFilter::new(vec![CanaryToken {
            name: "start".into(),
            value: CanaryMatch::Exact("START_TOKEN".into()),
        }]);
        let findings = filter.scan("START_TOKEN followed by text", &test_ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].start, 0);
    }

    #[test]
    fn canary_at_end_of_content() {
        let filter = CanaryFilter::new(vec![CanaryToken {
            name: "end".into(),
            value: CanaryMatch::Exact("END_TOKEN".into()),
        }]);
        let findings = filter.scan("text followed by END_TOKEN", &test_ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].end, 26);
    }

    #[test]
    fn canary_in_middle_of_content() {
        let filter = CanaryFilter::new(vec![CanaryToken {
            name: "mid".into(),
            value: CanaryMatch::Exact("MID_CANARY".into()),
        }]);
        let findings = filter.scan("before MID_CANARY after", &test_ctx());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].start, 7);
        assert_eq!(findings[0].end, 17);
    }
}
