//! Utility functions shared across navra-server CLI commands.

use crate::config;

/// Expand `~/` to the user's home directory and `$VAR`/`${VAR}` patterns
/// to their environment variable values.
pub(crate) fn expand_tilde(path: &str) -> String {
    let mut result = path.to_string();
    if result.starts_with("~/")
        && let Some(home) = dirs::home_dir()
    {
        result = format!("{}{}", home.display(), &result[1..]);
    }
    // Expand $VAR and ${VAR} patterns
    let mut out = String::with_capacity(result.len());
    let mut chars = result.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            let braced = chars.peek() == Some(&'{');
            if braced {
                chars.next();
            }
            let var_name: String = chars
                .by_ref()
                .take_while(|&ch| {
                    if braced {
                        ch != '}'
                    } else {
                        ch.is_alphanumeric() || ch == '_'
                    }
                })
                .collect();
            if let Ok(val) = std::env::var(&var_name) {
                out.push_str(&val);
            } else {
                out.push('$');
                if braced {
                    out.push('{');
                }
                out.push_str(&var_name);
                if braced {
                    out.push('}');
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Resolve a single `${VAR}` pattern to its environment variable value.
pub(crate) fn resolve_env_vars(s: &str) -> String {
    if let Some(var) = s.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
        std::env::var(var).unwrap_or_else(|_| s.to_string())
    } else {
        s.to_string()
    }
}

/// Resolve OpenAPI authentication configuration, expanding environment
/// variable references in secrets.
pub(crate) fn resolve_openapi_auth(
    auth_cfg: &Option<config::OpenApiAuthConfig>,
) -> navra_openapi::auth::AuthConfig {
    let Some(auth) = auth_cfg else {
        return navra_openapi::auth::AuthConfig::default();
    };

    let bearer = auth.bearer.as_deref().map(resolve_env_vars);

    let api_key = match (&auth.api_key_name, &auth.api_key_value) {
        (Some(name), Some(value)) => {
            let location = match auth.api_key_location.as_deref() {
                Some("query") => navra_openapi::auth::ApiKeyLocation::Query,
                _ => navra_openapi::auth::ApiKeyLocation::Header,
            };
            Some(navra_openapi::auth::ApiKeyAuth {
                name: name.clone(),
                value: resolve_env_vars(value),
                location,
            })
        }
        _ => None,
    };

    let basic = match (&auth.basic_username, &auth.basic_password) {
        (Some(user), Some(pass)) => Some(navra_openapi::auth::BasicAuth {
            username: user.clone(),
            password: resolve_env_vars(pass),
        }),
        _ => None,
    };

    navra_openapi::auth::AuthConfig {
        bearer,
        api_key,
        basic,
        oauth: None,
    }
}

/// Convert navra config model entries to model-server config entries.
pub(crate) fn convert_model_configs(
    models: &std::collections::HashMap<String, config::ModelConfig>,
) -> std::collections::HashMap<String, navra_model_server::config::ModelEntry> {
    models
        .iter()
        .map(|(name, mc)| {
            (
                name.clone(),
                navra_model_server::config::ModelEntry {
                    model_path: mc.model_path.clone(),
                    source: mc.source.clone(),
                    tokenizer_path: mc.tokenizer_path.clone(),
                    task: mc.task.clone(),
                    device: mc.device.clone(),
                    dimensions: mc.dimensions,
                    labels: mc.labels.clone(),
                    threshold: mc.threshold,
                    format: mc.format.clone(),
                    execution_mode: mc.execution_mode,
                    runtime: mc.runtime.clone(),
                    port: mc.port,
                    context_size: mc.context_size,
                    parallel: mc.parallel,
                    model_name: mc.model_name.clone(),
                    cache_type: mc.cache_type,
                    kv_cache: mc.kv_cache,
                    speculative: mc.speculative.as_ref().map(|s| {
                        navra_model_server::config::SpeculativeEntry {
                            draft_model: s.draft_model.clone(),
                            draft_tokens: s.draft_tokens,
                            draft_min_p: s.draft_min_p,
                        }
                    }),
                    base_url: mc.base_url.clone(),
                    api_key: mc.api_key.clone(),
                    locality: mc.locality.clone(),
                },
            )
        })
        .collect()
}

/// Parse a human-readable size string (e.g. `24GB`, `512MB`) into bytes.
pub(crate) fn parse_size_bytes(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    if let Some(gb) = s.strip_suffix("GB").or_else(|| s.strip_suffix("gb")) {
        let n: u64 = gb.trim().parse()?;
        Ok(n * 1024 * 1024 * 1024)
    } else if let Some(mb) = s.strip_suffix("MB").or_else(|| s.strip_suffix("mb")) {
        let n: u64 = mb.trim().parse()?;
        Ok(n * 1024 * 1024)
    } else {
        s.parse::<u64>()
            .map_err(|_| anyhow::anyhow!("invalid size: {s} (use e.g. 24GB, 16GB, 512MB)"))
    }
}
