//! Resilient transport wrapper with retry, reconnection, and timeout support.
//!
//! `ResilientTransport` wraps any `Transport` implementation and adds:
//! - Exponential backoff on transient errors
//! - Automatic reconnection via a `TransportFactory`
//! - Request timeouts
//! - Sleep detection (resets retry budget after long inactivity)

use super::transport::Transport;
use super::UpstreamError;
use async_trait::async_trait;
use std::time::{Duration, Instant};

/// Configuration for retry and reconnection behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Base delay for exponential backoff (default: 1s).
    pub base_delay: Duration,
    /// Maximum delay between retries (default: 30s).
    pub max_delay: Duration,
    /// Total time budget for reconnection attempts (default: 10min).
    pub total_budget: Duration,
    /// How long to wait for a single request before timing out (default: 45s).
    pub request_timeout: Duration,
    /// Gap threshold for sleep detection (default: 60s).
    /// If the gap since last successful request exceeds this, the retry
    /// budget is reset (assumes the system was asleep).
    pub sleep_gap_threshold: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            total_budget: Duration::from_secs(600),
            request_timeout: Duration::from_secs(45),
            sleep_gap_threshold: Duration::from_secs(60),
        }
    }
}

/// Factory for creating fresh transport instances.
///
/// Used by `ResilientTransport` to reconnect after a transport dies.
/// Each implementation holds the configuration needed to construct
/// a new transport (command + cwd for stdio, URL for HTTP/SSE).
#[async_trait]
pub trait TransportFactory: Send + Sync + 'static {
    /// Create a new transport instance.
    async fn create(&self) -> Result<Box<dyn Transport>, UpstreamError>;
}

/// Stdio transport factory: respawns the subprocess.
pub struct StdioTransportFactory {
    name: String,
    command: Vec<String>,
    cwd: Option<String>,
}

impl StdioTransportFactory {
    pub fn new(name: &str, command: &[String], cwd: Option<&str>) -> Self {
        Self {
            name: name.to_string(),
            command: command.to_vec(),
            cwd: cwd.map(String::from),
        }
    }
}

#[async_trait]
impl TransportFactory for StdioTransportFactory {
    async fn create(&self) -> Result<Box<dyn Transport>, UpstreamError> {
        let transport =
            super::stdio::StdioTransport::spawn(&self.name, &self.command, self.cwd.as_deref())?;
        Ok(Box::new(transport))
    }
}

/// HTTP transport factory: creates a new HTTP client.
pub struct HttpTransportFactory {
    name: String,
    url: String,
}

impl HttpTransportFactory {
    pub fn new(name: &str, url: &str) -> Self {
        Self {
            name: name.to_string(),
            url: url.to_string(),
        }
    }
}

#[async_trait]
impl TransportFactory for HttpTransportFactory {
    async fn create(&self) -> Result<Box<dyn Transport>, UpstreamError> {
        let transport = super::http::HttpTransport::new(&self.name, &self.url);
        Ok(Box::new(transport))
    }
}

/// SSE transport factory: creates a new SSE client.
pub struct SseTransportFactory {
    name: String,
    url: String,
}

impl SseTransportFactory {
    pub fn new(name: &str, url: &str) -> Self {
        Self {
            name: name.to_string(),
            url: url.to_string(),
        }
    }
}

#[async_trait]
impl TransportFactory for SseTransportFactory {
    async fn create(&self) -> Result<Box<dyn Transport>, UpstreamError> {
        let transport = super::sse::SseTransport::new(&self.name, &self.url);
        Ok(Box::new(transport))
    }
}

/// A transport wrapper that adds retry, reconnection, and timeout behavior.
///
/// On transient errors, retries with exponential backoff up to a total
/// time budget. On transport death (EOF, broken pipe), uses the factory
/// to create a fresh transport. Permanent errors (401, 403, 404, command
/// not found) are returned immediately without retry.
pub struct ResilientTransport {
    name: String,
    inner: Option<Box<dyn Transport>>,
    factory: Box<dyn TransportFactory>,
    config: RetryConfig,
    last_success: Instant,
}

impl ResilientTransport {
    /// Create a new resilient transport wrapping an existing transport.
    pub fn new(
        name: &str,
        transport: Box<dyn Transport>,
        factory: Box<dyn TransportFactory>,
        config: RetryConfig,
    ) -> Self {
        Self {
            name: name.to_string(),
            inner: Some(transport),
            factory,
            config,
            last_success: Instant::now(),
        }
    }

    /// Create a resilient transport by using the factory for the initial connection too.
    pub async fn from_factory(
        name: &str,
        factory: Box<dyn TransportFactory>,
        config: RetryConfig,
    ) -> Result<Self, UpstreamError> {
        let transport = factory.create().await?;
        Ok(Self::new(name, transport, factory, config))
    }

    /// Calculate the backoff delay for a given attempt number.
    /// Uses exponential backoff with ±25% jitter to avoid thundering herd.
    fn backoff_delay(&self, attempt: u32) -> Duration {
        let base = self.config.base_delay * 2u32.saturating_pow(attempt);
        let base = base.min(self.config.max_delay);
        // Add ±25% jitter using system time nanos as cheap randomness
        let base_ms = base.as_millis() as u64;
        let jitter_range = base_ms / 4;
        if jitter_range > 0 {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos() as u64;
            let jitter = nanos % (jitter_range * 2);
            Duration::from_millis(base_ms.saturating_sub(jitter_range) + jitter)
        } else {
            base
        }
    }

    /// Attempt to reconnect by creating a new transport via the factory.
    async fn reconnect(&mut self) -> Result<(), UpstreamError> {
        tracing::info!(upstream = %self.name, "Attempting to reconnect");

        // Shut down old transport if it exists
        if let Some(ref mut t) = self.inner {
            t.shutdown();
        }
        self.inner = None;

        let transport = self.factory.create().await?;
        self.inner = Some(transport);

        tracing::info!(upstream = %self.name, "Reconnected successfully");
        Ok(())
    }
}

#[async_trait]
impl Transport for ResilientTransport {
    async fn request(
        &mut self,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, UpstreamError> {
        let now = Instant::now();

        // Sleep detection: if we haven't had activity in a long time,
        // assume the system was asleep and reset the budget.
        let time_since_last = now.duration_since(self.last_success);
        let budget_start = if time_since_last > self.config.sleep_gap_threshold {
            tracing::debug!(
                upstream = %self.name,
                gap_secs = time_since_last.as_secs(),
                "Sleep detected, resetting retry budget"
            );
            Instant::now()
        } else {
            now
        };

        let mut attempt: u32 = 0;

        loop {
            // Check if we've exhausted the retry budget
            if attempt > 0 {
                let elapsed = Instant::now().duration_since(budget_start);
                if elapsed >= self.config.total_budget {
                    return Err(UpstreamError::Protocol {
                        name: self.name.clone(),
                        message: format!(
                            "retry budget exhausted after {} attempts ({:.0}s)",
                            attempt,
                            elapsed.as_secs_f64()
                        ),
                    });
                }
            }

            // Ensure we have a transport
            if self.inner.is_none() {
                match self.reconnect().await {
                    Ok(()) => {}
                    Err(e) => {
                        if e.is_permanent() {
                            return Err(e);
                        }
                        tracing::warn!(
                            upstream = %self.name,
                            attempt,
                            error = %e,
                            "Reconnection failed, will retry"
                        );
                        let delay = self.backoff_delay(attempt);
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                        continue;
                    }
                }
            }

            // Attempt the request with a timeout
            let transport = self.inner.as_mut().unwrap();
            let result = tokio::time::timeout(
                self.config.request_timeout,
                transport.request(body.clone()),
            )
            .await;

            match result {
                Ok(Ok(response)) => {
                    self.last_success = Instant::now();
                    return Ok(response);
                }
                Ok(Err(e)) => {
                    if e.is_permanent() {
                        return Err(e);
                    }

                    tracing::warn!(
                        upstream = %self.name,
                        attempt,
                        error = %e,
                        "Request failed, will retry"
                    );

                    // Transport is likely dead, force reconnection
                    self.inner = None;
                }
                Err(_elapsed) => {
                    tracing::warn!(
                        upstream = %self.name,
                        attempt,
                        timeout_secs = self.config.request_timeout.as_secs(),
                        "Request timed out, will retry"
                    );

                    // Transport might be stuck, force reconnection
                    self.inner = None;
                }
            }

            let delay = self.backoff_delay(attempt);
            tracing::debug!(
                upstream = %self.name,
                attempt,
                delay_ms = delay.as_millis(),
                "Backing off before retry"
            );
            tokio::time::sleep(delay).await;
            attempt += 1;
        }
    }

    fn shutdown(&mut self) {
        if let Some(ref mut t) = self.inner {
            t.shutdown();
        }
        self.inner = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// A mock transport that fails a configured number of times, then succeeds.
    struct MockTransport {
        fail_count: Arc<AtomicU32>,
        calls: Arc<AtomicU32>,
        permanent: bool,
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn request(
            &mut self,
            _body: serde_json::Value,
        ) -> Result<serde_json::Value, UpstreamError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let remaining = self.fail_count.load(Ordering::SeqCst);
            if remaining > 0 {
                self.fail_count.fetch_sub(1, Ordering::SeqCst);
                if self.permanent {
                    Err(UpstreamError::Protocol {
                        name: "mock".to_string(),
                        message: "HTTP 403: forbidden".to_string(),
                    })
                } else {
                    Err(UpstreamError::Io {
                        name: "mock".to_string(),
                        source: std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken"),
                    })
                }
            } else {
                Ok(serde_json::json!({"result": "ok", "call": call}))
            }
        }

        fn shutdown(&mut self) {}
    }

    struct MockFactory {
        fail_count: Arc<AtomicU32>,
        calls: Arc<AtomicU32>,
    }

    #[async_trait]
    impl TransportFactory for MockFactory {
        async fn create(&self) -> Result<Box<dyn Transport>, UpstreamError> {
            Ok(Box::new(MockTransport {
                fail_count: self.fail_count.clone(),
                calls: self.calls.clone(),
                permanent: false,
            }))
        }
    }

    fn fast_config() -> RetryConfig {
        RetryConfig {
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            total_budget: Duration::from_secs(5),
            request_timeout: Duration::from_secs(5),
            sleep_gap_threshold: Duration::from_secs(60),
        }
    }

    #[tokio::test]
    async fn success_on_first_try() {
        let fail_count = Arc::new(AtomicU32::new(0));
        let calls = Arc::new(AtomicU32::new(0));

        let transport = Box::new(MockTransport {
            fail_count: fail_count.clone(),
            calls: calls.clone(),
            permanent: false,
        });

        let factory = Box::new(MockFactory {
            fail_count: fail_count.clone(),
            calls: calls.clone(),
        });

        let mut resilient = ResilientTransport::new("test", transport, factory, fast_config());
        let result = resilient.request(serde_json::json!({})).await;

        assert!(result.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retries_on_transient_error() {
        let fail_count = Arc::new(AtomicU32::new(2));
        let calls = Arc::new(AtomicU32::new(0));

        let transport = Box::new(MockTransport {
            fail_count: fail_count.clone(),
            calls: calls.clone(),
            permanent: false,
        });

        let factory = Box::new(MockFactory {
            fail_count: fail_count.clone(),
            calls: calls.clone(),
        });

        let mut resilient = ResilientTransport::new("test", transport, factory, fast_config());
        let result = resilient.request(serde_json::json!({})).await;

        assert!(result.is_ok());
        // First call fails, reconnect + second call fails, reconnect + third succeeds
        assert!(calls.load(Ordering::SeqCst) >= 3);
    }

    #[tokio::test]
    async fn permanent_error_no_retry() {
        let fail_count = Arc::new(AtomicU32::new(10));
        let calls = Arc::new(AtomicU32::new(0));

        let transport = Box::new(MockTransport {
            fail_count: fail_count.clone(),
            calls: calls.clone(),
            permanent: true,
        });

        let factory = Box::new(MockFactory {
            fail_count: fail_count.clone(),
            calls: calls.clone(),
        });

        let mut resilient = ResilientTransport::new("test", transport, factory, fast_config());
        let result = resilient.request(serde_json::json!({})).await;

        assert!(result.is_err());
        // Only one call: permanent error returns immediately
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn backoff_delay_calculation() {
        let config = RetryConfig {
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            ..RetryConfig::default()
        };
        let rt = ResilientTransport {
            name: "test".to_string(),
            inner: None,
            factory: Box::new(MockFactory {
                fail_count: Arc::new(AtomicU32::new(0)),
                calls: Arc::new(AtomicU32::new(0)),
            }),
            config,
            last_success: Instant::now(),
        };

        // Delays include ±25% jitter, so check within range
        let check = |attempt, expected_ms: u64| {
            let delay = rt.backoff_delay(attempt);
            let ms = delay.as_millis() as u64;
            let lo = expected_ms * 3 / 4;
            let hi = expected_ms * 5 / 4;
            assert!(ms >= lo && ms <= hi, "attempt {attempt}: {ms}ms not in [{lo}, {hi}]");
        };
        check(0, 1000);
        check(1, 2000);
        check(2, 4000);
        check(3, 8000);
        check(4, 16000);
        check(5, 30000); // capped
        check(10, 30000); // still capped
    }

    #[tokio::test]
    async fn budget_exhaustion() {
        let fail_count = Arc::new(AtomicU32::new(1000));
        let calls = Arc::new(AtomicU32::new(0));

        let transport = Box::new(MockTransport {
            fail_count: fail_count.clone(),
            calls: calls.clone(),
            permanent: false,
        });

        let factory = Box::new(MockFactory {
            fail_count: fail_count.clone(),
            calls: calls.clone(),
        });

        let config = RetryConfig {
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(1),
            total_budget: Duration::from_millis(50),
            request_timeout: Duration::from_secs(1),
            sleep_gap_threshold: Duration::from_secs(60),
        };

        let mut resilient = ResilientTransport::new("test", transport, factory, config);
        let result = resilient.request(serde_json::json!({})).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("retry budget exhausted"));
    }
}
