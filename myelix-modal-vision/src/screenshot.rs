//! Screen capture via XDG Desktop Portal.
//!
//! Uses `org.freedesktop.portal.Screenshot` to capture the screen.
//! Works on both Wayland and X11 (GNOME, KDE, Sway, etc.).
//! The portal shows a system dialog asking for user consent.

use std::collections::HashMap;
use zbus::zvariant::Value;

/// Capture a screenshot via the XDG Desktop Portal.
///
/// Returns the path to the screenshot file (typically in /tmp).
/// The portal may show a consent dialog to the user.
pub async fn capture_screen() -> Result<String, String> {
    let connection = zbus::Connection::session()
        .await
        .map_err(|e| format!("D-Bus session connection failed: {e}"))?;

    let proxy = zbus::Proxy::new(
        &connection,
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.Screenshot",
    )
    .await
    .map_err(|e| format!("Failed to create portal proxy: {e}"))?;

    let options: HashMap<&str, Value<'_>> = HashMap::from([
        ("interactive", Value::Bool(false)),
        ("modal", Value::Bool(true)),
    ]);

    let reply: zbus::zvariant::OwnedObjectPath = proxy
        .call("Screenshot", &("", options))
        .await
        .map_err(|e| format!("Screenshot portal call failed: {e}"))?;

    // The portal returns a request object path. We need to listen for
    // the Response signal on that path to get the actual URI.
    let request_proxy = zbus::Proxy::new(
        &connection,
        "org.freedesktop.portal.Desktop",
        reply.as_ref(),
        "org.freedesktop.portal.Request",
    )
    .await
    .map_err(|e| format!("Failed to create request proxy: {e}"))?;

    // Wait for the Response signal (with timeout)
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        wait_for_response(&request_proxy),
    )
    .await
    .map_err(|_| "Screenshot timed out (30s)".to_string())?;

    response
}

/// Wait for the portal Response signal and extract the URI.
async fn wait_for_response(proxy: &zbus::Proxy<'_>) -> Result<String, String> {
    use futures_util::StreamExt;

    let mut stream = proxy
        .receive_signal("Response")
        .await
        .map_err(|e| format!("Failed to listen for response: {e}"))?;

    if let Some(signal) = stream.next().await {
        let body = signal
            .body();
        let (response_code, results): (u32, HashMap<String, Value<'_>>) = body
            .deserialize()
            .map_err(|e| format!("Failed to parse response: {e}"))?;

        if response_code != 0 {
            return Err(format!(
                "Screenshot cancelled or failed (code: {response_code})"
            ));
        }

        if let Some(Value::Str(uri)) = results.get("uri") {
            let path = uri
                .strip_prefix("file://")
                .unwrap_or(uri.as_str());
            Ok(path.to_string())
        } else {
            Err("No URI in screenshot response".to_string())
        }
    } else {
        Err("Response signal stream ended unexpectedly".to_string())
    }
}
