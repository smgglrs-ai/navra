//! mDNS/DNS-SD local network discovery for MCP servers.
//!
//! Uses the `_mcp._tcp.local.` service type to:
//! - **Advertise** navra on the LAN so other agents can find it
//! - **Browse** for other MCP servers on the LAN
//!
//! Works on any Linux with multicast networking (PipeWire/Avahi not
//! required — mdns-sd handles mDNS directly).

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::time::Duration;

/// mDNS service type for MCP servers.
const SERVICE_TYPE: &str = "_mcp._tcp.local.";

/// A discovered MCP server on the local network.
#[derive(Debug, Clone)]
pub struct LanServer {
    /// Service instance name.
    pub name: String,
    /// Host address.
    pub host: String,
    /// Port number.
    pub port: u16,
    /// MCP endpoint path (from TXT record, default "/mcp").
    pub path: String,
}

impl LanServer {
    /// Full URL for connecting to this server.
    pub fn url(&self) -> String {
        format!("http://{}:{}{}", self.host, self.port, self.path)
    }
}

/// Advertise navra on the local network via mDNS.
///
/// Returns the ServiceDaemon handle — drop it to stop advertising.
pub fn advertise(instance_name: &str, port: u16, path: &str) -> Result<ServiceDaemon, String> {
    let mdns = ServiceDaemon::new().map_err(|e| format!("mDNS daemon failed: {e}"))?;

    let properties = [("path", path), ("version", env!("CARGO_PKG_VERSION"))];
    let service = ServiceInfo::new(
        SERVICE_TYPE,
        instance_name,
        &format!("{}.local.", hostname()),
        "",
        port,
        &properties[..],
    )
    .map_err(|e| format!("mDNS service info error: {e}"))?
    .enable_addr_auto();

    mdns.register(service)
        .map_err(|e| format!("mDNS registration failed: {e}"))?;

    Ok(mdns)
}

/// Browse the local network for MCP servers.
///
/// Listens for `browse_duration` and returns all discovered servers.
pub async fn browse(browse_duration: Duration) -> Vec<LanServer> {
    let handle = tokio::task::spawn_blocking(move || {
        let mdns = match ServiceDaemon::new() {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("mDNS browse failed: {e}");
                return Vec::new();
            }
        };

        let receiver = match mdns.browse(SERVICE_TYPE) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("mDNS browse failed: {e}");
                return Vec::new();
            }
        };

        let deadline = std::time::Instant::now() + browse_duration;
        let mut servers = Vec::new();

        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            match receiver.recv_timeout(remaining) {
                Ok(ServiceEvent::ServiceResolved(info)) => {
                    let path = info
                        .get_properties()
                        .get("path")
                        .map(|v| v.val_str().to_string())
                        .unwrap_or_else(|| "/mcp".to_string());

                    // Use the first address
                    if let Some(addr) = info.get_addresses().iter().next() {
                        let server = LanServer {
                            name: info.get_fullname().to_string(),
                            host: addr.to_string(),
                            port: info.get_port(),
                            path,
                        };
                        tracing::info!(
                            name = %server.name,
                            url = %server.url(),
                            "Discovered MCP server on LAN"
                        );
                        servers.push(server);
                    }
                }
                Ok(_) => {} // Ignore other events
                Err(flume::RecvTimeoutError::Timeout) => break,
                Err(_) => break,
            }
        }

        let _ = mdns.shutdown();
        servers
    });

    match handle.await {
        Ok(servers) => servers,
        Err(e) => {
            tracing::warn!("mDNS browse task failed: {e}");
            Vec::new()
        }
    }
}

/// Get the system hostname (fallback to "navra").
fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::fs::read_to_string("/etc/hostname").map(|s| s.trim().to_string()))
        .unwrap_or_else(|_| "navra".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_server_url() {
        let server = LanServer {
            name: "test._mcp._tcp.local.".to_string(),
            host: "192.168.1.100".to_string(),
            port: 9315,
            path: "/mcp".to_string(),
        };
        assert_eq!(server.url(), "http://192.168.1.100:9315/mcp");
    }

    #[test]
    fn hostname_returns_something() {
        let h = hostname();
        assert!(!h.is_empty());
    }
}
