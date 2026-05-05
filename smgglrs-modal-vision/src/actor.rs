use std::future::Future;
use std::pin::Pin;

/// A single computer-use action.
#[derive(Debug, Clone)]
pub enum Action {
    Wait { ms: u64 },
    MouseMove { x: i32, y: i32 },
    MouseDown { button: MouseButton },
    MouseUp { button: MouseButton },
    Click { x: i32, y: i32, button: MouseButton },
    TypeText { text: String },
    KeyDown { key: String },
    KeyUp { key: String },
    Screenshot { max_width: Option<u32>, max_height: Option<u32> },
}

/// Mouse button for click/press actions.
#[derive(Debug, Clone, Copy)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

/// Result of performing actions.
#[derive(Debug)]
pub struct ActionResult {
    pub success: bool,
    pub screenshot: Option<Vec<u8>>,
    pub error: Option<String>,
}

/// Platform-independent computer-use interface.
pub trait Actor: Send + Sync {
    fn perform_actions<'a>(
        &'a mut self,
        actions: &'a [Action],
    ) -> Pin<Box<dyn Future<Output = ActionResult> + Send + 'a>>;

    fn platform(&self) -> &str;
}

/// Screenshot sizing parameters for LLM-friendly images.
#[derive(Debug, Clone)]
pub struct ScreenshotParams {
    pub max_long_edge_px: u32,
    pub max_total_px: u64,
}

impl Default for ScreenshotParams {
    fn default() -> Self {
        Self {
            max_long_edge_px: 1280,
            max_total_px: 1_280_000,
        }
    }
}

/// Detect the display server platform.
pub fn detect_platform() -> &'static str {
    if std::env::var("WAYLAND_DISPLAY").is_ok() {
        "wayland"
    } else if std::env::var("DISPLAY").is_ok() {
        "x11"
    } else {
        "headless"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_platform_returns_known_value() {
        let platform = detect_platform();
        assert!(
            ["wayland", "x11", "headless"].contains(&platform),
            "unexpected platform: {platform}",
        );
    }

    #[test]
    fn screenshot_params_default() {
        let params = ScreenshotParams::default();
        assert_eq!(params.max_long_edge_px, 1280);
        assert_eq!(params.max_total_px, 1_280_000);
    }

    #[test]
    fn action_debug_formatting() {
        let action = Action::Click {
            x: 100,
            y: 200,
            button: MouseButton::Left,
        };
        let debug = format!("{action:?}");
        assert!(debug.contains("Click"));
        assert!(debug.contains("100"));
        assert!(debug.contains("200"));
        assert!(debug.contains("Left"));
    }

    #[test]
    fn action_result_success() {
        let result = ActionResult {
            success: true,
            screenshot: Some(vec![0x89, 0x50, 0x4E, 0x47]),
            error: None,
        };
        assert!(result.success);
        assert!(result.screenshot.is_some());
        assert!(result.error.is_none());
    }

    #[test]
    fn action_result_failure() {
        let result = ActionResult {
            success: false,
            screenshot: None,
            error: Some("display not available".into()),
        };
        assert!(!result.success);
        assert_eq!(result.error.as_deref(), Some("display not available"));
    }

    #[test]
    fn mouse_button_clone_copy() {
        let btn = MouseButton::Right;
        let btn2 = btn;
        assert!(matches!(btn, MouseButton::Right));
        assert!(matches!(btn2, MouseButton::Right));
    }
}
