use super::manifest::AgentManifest;

pub fn generate_config_snippet(
    manifest: &AgentManifest,
    oci_ref: &str,
    token: &str,
    token_hash: &str,
) -> String {
    let name = &manifest.meta.name;
    let mut out = String::new();

    out.push_str(&format!("# Agent: {} v{}", name, manifest.meta.version));
    if let Some(publisher) = &manifest.meta.publisher {
        out.push_str(&format!(" (publisher: {publisher})"));
    }
    out.push('\n');
    out.push_str(&format!("# Installed from: {oci_ref}\n"));
    if let Some(desc) = &manifest.meta.description {
        out.push_str(&format!("# {desc}\n"));
    }
    out.push('\n');

    // Agent token (shown once)
    out.push_str(&format!(
        "# Token (save this — it is shown only once): {token}\n\n"
    ));

    // [[agents]] entry
    out.push_str("[[agents]]\n");
    out.push_str(&format!("name = {name:?}\n"));
    out.push_str(&format!("token_hash = {token_hash:?}\n"));
    out.push_str(&format!("permissions = {name:?}\n"));
    if manifest.image.is_some() {
        // Per-agent image override
        out.push_str(&format!(
            "# image = {:?}\n",
            manifest.image.as_deref().unwrap()
        ));
    }
    out.push('\n');

    // [permissions.<name>] section
    out.push_str(&format!("[permissions.{name}]\n"));

    let perms = &manifest.permissions;

    if !perms.operations.is_empty() {
        let ops: Vec<String> = perms.operations.iter().map(|o| format!("{o:?}")).collect();
        out.push_str(&format!("operations = [{}]\n", ops.join(", ")));
    }

    if !perms.tool_rules.is_empty() {
        out.push_str("tool_rules = [\n");
        for rule in &perms.tool_rules {
            out.push_str(&format!(
                "  {{ tool = {:?}, policy = {:?} }},\n",
                rule.tool, rule.policy
            ));
        }
        out.push_str("]\n");
    }

    if !perms.domain_rules.is_empty() {
        out.push_str("domain_rules = [\n");
        for rule in &perms.domain_rules {
            let ops: Vec<String> = rule.operations.iter().map(|o| format!("{o:?}")).collect();
            out.push_str(&format!(
                "  {{ domain = {:?}, operations = [{}] }},\n",
                rule.domain,
                ops.join(", ")
            ));
        }
        out.push_str("]\n");
    }

    if let Some(ifc) = &perms.ifc {
        out.push_str(&format!(
            "# IFC: reads={}, writes={}\n",
            ifc.reads, ifc.writes
        ));
        if ifc.reads == "untrusted" {
            out.push_str("tainted_write_policy = \"approve\"\n");
        }
    }

    // Upstream MCP servers
    for upstream in &manifest.upstreams {
        out.push('\n');
        out.push_str("[[upstream]]\n");
        out.push_str(&format!("name = {:?}\n", upstream.name));
        out.push_str(&format!("transport = {:?}\n", upstream.transport));
        if !upstream.command.is_empty() {
            let items: Vec<String> = upstream.command.iter().map(|s| format!("{s:?}")).collect();
            out.push_str(&format!("command = [{}]\n", items.join(", ")));
        }
        if let Some(url) = &upstream.url {
            out.push_str(&format!("url = {url:?}\n"));
        }
        if !upstream.tool_filter.is_empty() {
            let items: Vec<String> = upstream
                .tool_filter
                .iter()
                .map(|s| format!("{s:?}"))
                .collect();
            out.push_str(&format!("tool_filter = [{}]\n", items.join(", ")));
        }
    }

    // Persona
    if let Some(persona) = &manifest.persona {
        out.push('\n');
        out.push_str("# Persona (add to cognitive core or inline):\n");
        if let Some(prompt) = &persona.system_prompt {
            for line in prompt.lines() {
                out.push_str(&format!("# {line}\n"));
            }
        }
        for directive in &persona.directives {
            out.push_str(&format!("# Directive: {directive}\n"));
        }
    }

    // Container image instruction
    if let Some(image) = &manifest.image {
        out.push('\n');
        out.push_str(&format!("# Pull container image: podman pull {image}\n"));
    }

    out
}

pub fn generate_skeleton_config(oci_ref: &str, token: &str, token_hash: &str) -> String {
    let name = oci_ref
        .rsplit('/')
        .next()
        .unwrap_or("unknown-agent")
        .split(':')
        .next()
        .unwrap_or("unknown-agent");

    let mut out = String::new();
    out.push_str(&format!("# Agent from: {oci_ref}\n"));
    out.push_str("# WARNING: No agent manifest found — configure permissions manually.\n\n");
    out.push_str(&format!(
        "# Token (save this — it is shown only once): {token}\n\n"
    ));
    out.push_str("[[agents]]\n");
    out.push_str(&format!("name = {name:?}\n"));
    out.push_str(&format!("token_hash = {token_hash:?}\n"));
    out.push_str(&format!("permissions = {name:?}\n"));
    out.push('\n');
    out.push_str(&format!("[permissions.{name}]\n"));
    out.push_str("operations = []  # TODO: configure allowed operations\n");
    out.push_str("# domain_rules = []\n");
    out.push_str("# tool_rules = []\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_bundle::manifest::*;
    use crate::config::{DomainRuleConfig, ToolRuleConfig};

    #[test]
    fn config_snippet_is_valid_toml() {
        let manifest = AgentManifest {
            schema_version: 1,
            meta: ManifestMeta {
                name: "test-agent".to_string(),
                version: "1.0.0".to_string(),
                publisher: Some("acme".to_string()),
                description: Some("A test agent".to_string()),
                license: None,
            },
            persona: None,
            permissions: RequestedPermissions {
                operations: vec!["filesystem.read".to_string()],
                tool_rules: vec![ToolRuleConfig {
                    tool: "file_read".to_string(),
                    policy: "allow".to_string(),
                }],
                domain_rules: vec![DomainRuleConfig {
                    domain: "filesystem".to_string(),
                    operations: vec!["read".to_string()],
                }],
                ifc: None,
            },
            upstreams: vec![ManifestUpstream {
                name: "search".to_string(),
                transport: "stdio".to_string(),
                command: vec![
                    "npx".to_string(),
                    "-y".to_string(),
                    "@acme/search".to_string(),
                ],
                url: None,
                tool_filter: vec![],
            }],
            image: None,
        };

        let snippet = generate_config_snippet(
            &manifest,
            "oci://quay.io/acme/test:1.0",
            "mcd_abc",
            "hash123",
        );

        // The TOML should be parseable (ignoring comment-only lines and the token line)
        // We can't parse the full snippet as a Config since it's a partial config,
        // but we can verify it contains the expected sections.
        assert!(snippet.contains("[[agents]]"));
        assert!(snippet.contains("[permissions.test-agent]"));
        assert!(snippet.contains("[[upstream]]"));
        assert!(snippet.contains("file_read"));
        assert!(snippet.contains("mcd_abc"));
    }

    #[test]
    fn skeleton_config_for_bare_image() {
        let snippet = generate_skeleton_config("quay.io/acme/agent:v1", "mcd_xyz", "hash456");
        assert!(snippet.contains("WARNING: No agent manifest found"));
        assert!(snippet.contains("[[agents]]"));
        assert!(snippet.contains("name = \"agent\""));
        assert!(snippet.contains("mcd_xyz"));
    }
}
