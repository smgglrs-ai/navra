// --- Agent bundle CLI commands ---

pub(crate) async fn agent_install(
    oci_ref: &str,
    allow_unsigned: bool,
    max_permissions: Option<&str>,
    cfg: &crate::config::Config,
) -> anyhow::Result<()> {
    use crate::agent_bundle::{compare, cosign, fetch, install, registry};

    // Local directory install (v2 bundle format)
    let path = std::path::Path::new(oci_ref);
    if path.is_dir() {
        return agent_install_local(path);
    }

    let policy = if allow_unsigned {
        cosign::SignaturePolicy::Skip
    } else {
        cfg.server
            .agent_signature_policy
            .parse::<cosign::SignaturePolicy>()?
    };

    // Gate 1: signature verification
    let signed = cosign::verify_signature(oci_ref, policy).await?;

    // Fetch manifest
    let client = reqwest::Client::new();
    let manifest = fetch::fetch_agent_manifest(&client, oci_ref).await?;

    let token = crate::config::generate_token();
    let hash = navra_core::auth::TokenAuthenticator::hash_token(&token);

    match manifest {
        Some(manifest) => {
            println!("Agent: {} v{}", manifest.meta.name, manifest.meta.version);
            if let Some(publisher) = &manifest.meta.publisher {
                println!("Publisher: {publisher}");
            }
            if let Some(desc) = &manifest.meta.description {
                println!("Description: {desc}");
            }
            println!("Signed: {signed}");
            println!();

            // Gate 2: permission check
            let max_policy = match max_permissions {
                Some(name) => cfg.permissions.get(name).ok_or_else(|| {
                    anyhow::anyhow!("permission set {name:?} not found in config")
                })?,
                None => &crate::config::PermissionSet::default(),
            };

            let diff = compare::compare_permissions(&manifest.permissions, max_policy);
            if !diff.allowed {
                println!("{diff}");
                anyhow::bail!(
                    "Installation aborted — bundle permissions exceed operator policy.\n\
                     Use --max-permissions to specify a more permissive policy, or adjust your config."
                );
            }

            let snippet = install::generate_config_snippet(&manifest, oci_ref, &token, &hash);
            println!("Add to config.toml:\n");
            println!("{snippet}");

            registry::save(&registry::InstalledAgent {
                name: manifest.meta.name.clone(),
                version: manifest.meta.version.clone(),
                publisher: manifest.meta.publisher.clone(),
                oci_ref: oci_ref.to_string(),
                installed_at: {
                    use std::time::SystemTime;
                    let d = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default();
                    format!("{}", d.as_secs())
                },
                signed,
            })?;

            if let Some(image) = &manifest.image {
                println!("\nPull container image:");
                println!("  podman pull {image}");
            }
        }
        None => {
            eprintln!("warning: no agent manifest found for {oci_ref}");
            eprintln!("Generating skeleton config — configure permissions manually.\n");
            let snippet = install::generate_skeleton_config(oci_ref, &token, &hash);
            println!("Add to config.toml:\n");
            println!("{snippet}");
        }
    }

    Ok(())
}

fn agent_install_local(dir: &std::path::Path) -> anyhow::Result<()> {
    use crate::agent_bundle::bundle_dir;

    // Check for existing bundle to show permission diff
    let new_bundle = bundle_dir::load_bundle(dir)?;
    let existing_dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("navra/agent-bundles")
        .join(&new_bundle.meta.name);
    if existing_dir.exists()
        && let Ok(old_bundle) = bundle_dir::load_bundle(&existing_dir)
    {
        let diff = bundle_dir::diff_permissions(&old_bundle.permissions, &new_bundle.permissions);
        if !diff.is_empty() {
            println!(
                "Upgrading {} v{} → v{}",
                old_bundle.meta.name, old_bundle.meta.version, new_bundle.meta.version
            );
            print!("{diff}");
            println!();
        }
    }

    let installed = bundle_dir::install_from_dir(dir)?;
    println!("Installed: {} v{}", installed.name, installed.version);
    println!("Location: {}", installed.path.display());

    if !installed.workflows.is_empty() {
        println!("\nWorkflows:");
        for wf in &installed.workflows {
            println!("  navra run {}/{}", installed.name, wf);
        }
    }

    if let Ok(Some(template)) = bundle_dir::load_config_template(dir)
        && !template.credentials.is_empty()
    {
        println!("\nThis agent needs credentials. Run:");
        println!("  navra agent init {}", installed.name);
    }

    Ok(())
}

pub(crate) fn agent_init(bundle_name: &str, instance_name: Option<&str>) -> anyhow::Result<()> {
    use crate::agent_bundle::bundle_dir;

    let bundles_dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("navra/agent-bundles")
        .join(bundle_name);

    if !bundles_dir.exists() {
        anyhow::bail!(
            "bundle '{}' not installed. Run: navra agent install <path-or-oci-ref>",
            bundle_name
        );
    }

    let bundle = bundle_dir::load_bundle(&bundles_dir)?;
    let template = bundle_dir::load_config_template(&bundles_dir)?;
    let instance = instance_name.unwrap_or(bundle_name);
    let instance_dir = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("navra/agents")
        .join(instance);

    std::fs::create_dir_all(&instance_dir)?;

    // Generate instance config
    let mut config = String::new();
    config.push_str(&format!("# Agent instance: {instance}\n"));
    config.push_str(&format!(
        "# Bundle: {} v{}\n\n",
        bundle.meta.name, bundle.meta.version
    ));
    config.push_str(&format!("bundle = \"{}\"\n", bundle.meta.name));

    // Model preferences
    if let Some(ref preferred) = bundle.model.preferred {
        config.push_str(&format!("model = \"{preferred}\"\n"));
    }

    // Credential references
    if let Some(ref tmpl) = template
        && !tmpl.credentials.is_empty()
    {
        config.push_str("\n[credentials]\n");
        for cred in &tmpl.credentials {
            let required = if cred.required { "" } else { "  # optional" };
            config.push_str(&format!("# {} ({}){}", cred.name, cred.cred_type, required));
            if let Some(ref desc) = cred.description {
                config.push_str(&format!(" — {desc}"));
            }
            config.push('\n');
            if !cred.scopes.is_empty() {
                config.push_str(&format!("# scopes: {}\n", cred.scopes.join(", ")));
            }
            config.push_str(&format!(
                "{} = \"navra/{instance}/{}\"\n\n",
                cred.name, cred.name
            ));
        }
    }

    // Permission envelope
    if !bundle.permissions.operations.is_empty() || !bundle.permissions.default.is_empty() {
        config.push_str("[permissions]\n");
        if !bundle.permissions.operations.is_empty() {
            config.push_str(&format!(
                "operations = [{}]\n",
                bundle
                    .permissions
                    .operations
                    .iter()
                    .map(|o| format!("\"{o}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        for (upstream, ops) in &bundle.permissions.default {
            config.push_str(&format!(
                "{upstream} = [{}]\n",
                ops.iter()
                    .map(|o| format!("\"{o}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }

    // Workflow triggers
    if !bundle.workflows.is_empty() {
        config.push_str("\n# Triggers (uncomment and configure as needed)\n");
        config.push_str("# [[triggers]]\n");
        config.push_str("# type = \"schedule\"\n");
        config.push_str("# cron = \"0 9 * * 1-5\"\n");
        if let Some(wf_name) = bundle.workflows.keys().next() {
            config.push_str(&format!("# workflow = \"{wf_name}\"\n"));
        }
    }

    let config_path = instance_dir.join("config.toml");
    std::fs::write(&config_path, &config)?;

    println!(
        "Instance '{instance}' initialized from bundle '{}'",
        bundle.meta.name
    );
    println!("Config: {}", config_path.display());

    if let Some(ref tmpl) = template
        && !tmpl.credentials.is_empty()
    {
        println!("\nCredentials needed:");
        for cred in &tmpl.credentials {
            let req = if cred.required {
                "(required)"
            } else {
                "(optional)"
            };
            println!("  {} — {} {}", cred.name, cred.cred_type, req);
        }
        println!("\nStore credentials in your OS keyring under 'navra/{instance}/<name>'");
    }

    if !bundle.workflows.is_empty() {
        println!("\nAvailable workflows:");
        for (wf_name, wf) in &bundle.workflows {
            let desc = wf.description.as_deref().unwrap_or("");
            println!("  navra run {instance}/{wf_name}  {desc}");
        }
    }

    Ok(())
}

pub(crate) fn agent_upgrade(bundle_name: &str) -> anyhow::Result<()> {
    use crate::agent_bundle::bundle_dir;

    let bundles_dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("navra/agent-bundles")
        .join(bundle_name);

    if !bundles_dir.exists() {
        anyhow::bail!("bundle '{}' not installed. Cannot upgrade.", bundle_name);
    }

    let old_bundle = bundle_dir::load_bundle(&bundles_dir)?;

    // For local upgrades, the user re-installs from the new directory.
    // For OCI upgrades, we'd pull the new version first (TODO).
    // For now, show the current state and diff mechanism.
    println!(
        "Bundle: {} v{}",
        old_bundle.meta.name, old_bundle.meta.version
    );
    println!("Location: {}", bundles_dir.display());
    println!();
    println!(
        "To upgrade, re-install from the new source:\n  \
         navra agent install ./path-to-new-version/\n\n\
         The permission diff will be shown automatically."
    );

    Ok(())
}

pub(crate) async fn agent_inspect(oci_ref: &str) -> anyhow::Result<()> {
    use crate::agent_bundle::fetch;

    let client = reqwest::Client::new();
    let manifest = fetch::fetch_agent_manifest(&client, oci_ref).await?;

    match manifest {
        Some(manifest) => {
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
        None => {
            println!("No agent manifest found for {oci_ref}");
        }
    }

    Ok(())
}

pub(crate) fn agent_list() -> anyhow::Result<()> {
    use crate::agent_bundle::registry;

    let agents = registry::list()?;
    if agents.is_empty() {
        println!("No agent bundles installed.");
        return Ok(());
    }

    println!(
        "{:<20} {:<10} {:<15} {:<6} OCI REF",
        "NAME", "VERSION", "PUBLISHER", "SIGNED"
    );
    println!(
        "{:<20} {:<10} {:<15} {:<6} -------",
        "----", "-------", "---------", "------"
    );
    for agent in &agents {
        println!(
            "{:<20} {:<10} {:<15} {:<6} {}",
            agent.name,
            agent.version,
            agent.publisher.as_deref().unwrap_or("-"),
            if agent.signed { "yes" } else { "no" },
            agent.oci_ref,
        );
    }

    Ok(())
}

pub(crate) fn agent_remove(name: &str) -> anyhow::Result<()> {
    use crate::agent_bundle::registry;

    if registry::remove(name)? {
        println!("Removed agent bundle: {name}");
        println!("Note: config.toml entries for this agent must be removed manually.");
    } else {
        println!("No installed agent bundle named {name:?}.");
    }

    Ok(())
}
