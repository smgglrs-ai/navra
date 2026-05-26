use regex::Regex;

/// Extract repository references from a GraphQL query string.
/// Returns a list of "owner/repo" strings found in the query.
///
/// Parses `repository(owner: "...", name: "...")` patterns from
/// GitHub GraphQL queries. Handles arguments in either order.
pub fn extract_repo_refs(query: &str) -> Vec<String> {
    let mut refs = Vec::new();

    // Pattern: repository(owner: "...", name: "...")
    let owner_first =
        Regex::new(r#"repository\s*\(\s*owner\s*:\s*"([^"]+)"\s*,\s*name\s*:\s*"([^"]+)""#)
            .expect("valid regex");

    // Pattern: repository(name: "...", owner: "...")
    let name_first =
        Regex::new(r#"repository\s*\(\s*name\s*:\s*"([^"]+)"\s*,\s*owner\s*:\s*"([^"]+)""#)
            .expect("valid regex");

    for cap in owner_first.captures_iter(query) {
        let owner = &cap[1];
        let name = &cap[2];
        let repo_ref = format!("{owner}/{name}");
        if !refs.contains(&repo_ref) {
            refs.push(repo_ref);
        }
    }

    for cap in name_first.captures_iter(query) {
        let name = &cap[1];
        let owner = &cap[2];
        let repo_ref = format!("{owner}/{name}");
        if !refs.contains(&repo_ref) {
            refs.push(repo_ref);
        }
    }

    refs
}

/// Validate that all repository references in a GraphQL query
/// are within the allowed set. Allowed repos support glob patterns
/// (e.g., `org/*` matches any repo in that org).
///
/// Returns `Ok(())` if the query only references allowed repos,
/// or if the query contains no repository references at all.
/// Returns `Err` with the unauthorized repo name on violation.
pub fn validate_repo_scope(query: &str, allowed_repos: &[String]) -> Result<(), String> {
    let refs = extract_repo_refs(query);
    for repo_ref in &refs {
        let allowed = allowed_repos.iter().any(|pattern| {
            glob::Pattern::new(pattern)
                .map(|p| p.matches(repo_ref))
                .unwrap_or(false)
        });
        if !allowed {
            return Err(format!(
                "GraphQL query references unauthorized repository: {}",
                repo_ref
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_simple_repository() {
        let query = r#"
            query {
                repository(owner: "octocat", name: "hello-world") {
                    issues(first: 10) {
                        nodes { title }
                    }
                }
            }
        "#;
        let refs = extract_repo_refs(query);
        assert_eq!(refs, vec!["octocat/hello-world"]);
    }

    #[test]
    fn extract_reversed_argument_order() {
        let query = r#"
            query {
                repository(name: "my-repo", owner: "my-org") {
                    pullRequests(first: 5) {
                        nodes { title }
                    }
                }
            }
        "#;
        let refs = extract_repo_refs(query);
        assert_eq!(refs, vec!["my-org/my-repo"]);
    }

    #[test]
    fn extract_multiple_repositories() {
        let query = r#"
            query {
                a: repository(owner: "org1", name: "repo1") {
                    issues(first: 5) { nodes { title } }
                }
                b: repository(owner: "org2", name: "repo2") {
                    issues(first: 5) { nodes { title } }
                }
            }
        "#;
        let refs = extract_repo_refs(query);
        assert_eq!(refs.len(), 2);
        assert!(refs.contains(&"org1/repo1".to_string()));
        assert!(refs.contains(&"org2/repo2".to_string()));
    }

    #[test]
    fn extract_no_repository_references() {
        let query = r#"
            query {
                viewer {
                    login
                    name
                }
            }
        "#;
        let refs = extract_repo_refs(query);
        assert!(refs.is_empty());
    }

    #[test]
    fn extract_nested_query() {
        let query = r#"
            query {
                repository(owner: "outer-org", name: "outer-repo") {
                    object(expression: "main") {
                        ... on Commit {
                            history(first: 10) {
                                nodes { message }
                            }
                        }
                    }
                }
            }
        "#;
        let refs = extract_repo_refs(query);
        assert_eq!(refs, vec!["outer-org/outer-repo"]);
    }

    #[test]
    fn extract_deduplicates_same_repo() {
        let query = r#"
            query {
                a: repository(owner: "org", name: "repo") {
                    issues(first: 5) { nodes { title } }
                }
                b: repository(owner: "org", name: "repo") {
                    pullRequests(first: 5) { nodes { title } }
                }
            }
        "#;
        let refs = extract_repo_refs(query);
        assert_eq!(refs, vec!["org/repo"]);
    }

    #[test]
    fn extract_mixed_argument_orders() {
        let query = r#"
            query {
                a: repository(owner: "org1", name: "repo1") {
                    issues(first: 5) { nodes { title } }
                }
                b: repository(name: "repo2", owner: "org2") {
                    issues(first: 5) { nodes { title } }
                }
            }
        "#;
        let refs = extract_repo_refs(query);
        assert_eq!(refs.len(), 2);
        assert!(refs.contains(&"org1/repo1".to_string()));
        assert!(refs.contains(&"org2/repo2".to_string()));
    }

    #[test]
    fn extract_with_extra_whitespace() {
        let query = r#"
            query {
                repository(
                    owner:   "spaced-org"  ,
                    name:    "spaced-repo"
                ) {
                    issues(first: 10) { nodes { title } }
                }
            }
        "#;
        let refs = extract_repo_refs(query);
        assert_eq!(refs, vec!["spaced-org/spaced-repo"]);
    }

    // --- validate_repo_scope tests ---

    #[test]
    fn validate_passes_for_allowed_repo() {
        let query = r#"
            query {
                repository(owner: "my-org", name: "my-repo") {
                    issues(first: 10) { nodes { title } }
                }
            }
        "#;
        let allowed = vec!["my-org/my-repo".to_string()];
        assert!(validate_repo_scope(query, &allowed).is_ok());
    }

    #[test]
    fn validate_fails_for_unauthorized_repo() {
        let query = r#"
            query {
                repository(owner: "evil-org", name: "secret-repo") {
                    issues(first: 10) { nodes { title } }
                }
            }
        "#;
        let allowed = vec!["my-org/my-repo".to_string()];
        let result = validate_repo_scope(query, &allowed);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("evil-org/secret-repo"));
        assert!(err.contains("unauthorized"));
    }

    #[test]
    fn validate_glob_pattern_matches_all_repos_in_org() {
        let query = r#"
            query {
                repository(owner: "my-org", name: "any-repo") {
                    issues(first: 10) { nodes { title } }
                }
            }
        "#;
        let allowed = vec!["my-org/*".to_string()];
        assert!(validate_repo_scope(query, &allowed).is_ok());
    }

    #[test]
    fn validate_glob_rejects_different_org() {
        let query = r#"
            query {
                repository(owner: "other-org", name: "repo") {
                    issues(first: 10) { nodes { title } }
                }
            }
        "#;
        let allowed = vec!["my-org/*".to_string()];
        let result = validate_repo_scope(query, &allowed);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("other-org/repo"));
    }

    #[test]
    fn validate_passes_with_no_repo_references() {
        let query = r#"
            query {
                viewer { login }
            }
        "#;
        let allowed = vec!["my-org/my-repo".to_string()];
        assert!(validate_repo_scope(query, &allowed).is_ok());
    }

    #[test]
    fn validate_multi_repo_partial_deny() {
        let query = r#"
            query {
                a: repository(owner: "allowed-org", name: "repo1") {
                    issues(first: 5) { nodes { title } }
                }
                b: repository(owner: "denied-org", name: "repo2") {
                    issues(first: 5) { nodes { title } }
                }
            }
        "#;
        let allowed = vec!["allowed-org/*".to_string()];
        let result = validate_repo_scope(query, &allowed);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("denied-org/repo2"));
    }

    #[test]
    fn validate_empty_allowed_list_denies_all() {
        let query = r#"
            query {
                repository(owner: "any-org", name: "any-repo") {
                    issues(first: 10) { nodes { title } }
                }
            }
        "#;
        let allowed: Vec<String> = vec![];
        assert!(validate_repo_scope(query, &allowed).is_err());
    }

    #[test]
    fn validate_multiple_allowed_patterns() {
        let query = r#"
            query {
                a: repository(owner: "org-a", name: "repo1") {
                    issues(first: 5) { nodes { title } }
                }
                b: repository(owner: "org-b", name: "special") {
                    issues(first: 5) { nodes { title } }
                }
            }
        "#;
        let allowed = vec!["org-a/*".to_string(), "org-b/special".to_string()];
        assert!(validate_repo_scope(query, &allowed).is_ok());
    }
}
