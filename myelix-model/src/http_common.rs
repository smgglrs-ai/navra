//! Shared HTTP helpers for model backends.
//!
//! Extracts common patterns (retry logic) used by both the OpenAI and
//! Anthropic backends to avoid code duplication.

use crate::ModelError;

/// Maximum number of retry attempts on HTTP 429 (rate limit).
const MAX_RETRIES: u32 = 3;

/// Execute an HTTP request with retry-on-429 logic.
///
/// Calls `build_request` on each attempt to construct a fresh
/// `reqwest::RequestBuilder`, then sends it. If the response is
/// 429 Too Many Requests and we haven't exhausted retries, it
/// sleeps for the duration indicated by the `Retry-After` header
/// (falling back to exponential backoff: 1s, 2s, 4s) and retries.
///
/// Returns the successful (or final non-429) `reqwest::Response`.
pub(crate) async fn send_with_retry(
    build_request: impl Fn() -> reqwest::RequestBuilder,
) -> Result<reqwest::Response, ModelError> {
    let mut attempt = 0u32;
    loop {
        let req = build_request();
        let resp = req
            .send()
            .await
            .map_err(|e| ModelError::Api(format!("request failed: {e}")))?;

        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS && attempt < MAX_RETRIES {
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok());
            let delay = retry_after.unwrap_or(1u64 << attempt);
            tracing::warn!(
                attempt = attempt + 1,
                delay_secs = delay,
                "Rate limited (429), retrying"
            );
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            attempt += 1;
            continue;
        }
        return Ok(resp);
    }
}
