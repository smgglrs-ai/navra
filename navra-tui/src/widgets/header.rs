use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Widget;

use crate::state::AppState;
use crate::theme;

#[cfg(test)]
use crate::test_helpers::buf_to_string;

pub struct Header<'a> {
    state: &'a AppState,
}

impl<'a> Header<'a> {
    pub fn new(state: &'a AppState) -> Self {
        Self { state }
    }
}

impl Widget for Header<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let name = self
            .state
            .server_status
            .as_ref()
            .map(|s| s.name.as_str())
            .unwrap_or("navra");
        let version = self
            .state
            .server_status
            .as_ref()
            .map(|s| s.version.as_str())
            .unwrap_or("?");

        let conn_span = if self.state.connected {
            Span::styled(" connected ", theme::status_ok())
        } else {
            Span::styled(" disconnected ", theme::status_error())
        };

        let line = Line::from(vec![
            Span::styled(format!(" {name} "), theme::header()),
            Span::styled(format!("v{version} "), theme::muted()),
            Span::raw("| "),
            conn_span,
            Span::raw(
                self.state
                    .last_error
                    .as_deref()
                    .map(|e| format!("  {e}"))
                    .unwrap_or_default(),
            ),
        ]);

        buf.set_style(area, theme::header());
        line.render(area, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ServerStatus;

    fn render_header(state: &AppState, width: u16) -> String {
        let area = Rect::new(0, 0, width, 1);
        let mut buf = Buffer::empty(area);
        Header::new(state).render(area, &mut buf);
        buf_to_string(&buf)
    }

    #[test]
    fn header_disconnected_default() {
        let state = AppState::default();
        let out = render_header(&state, 60);
        assert!(out.contains("navra"));
        assert!(out.contains("disconnected"));
    }

    #[test]
    fn header_connected_with_status() {
        let mut state = AppState::default();
        state.connected = true;
        state.server_status = Some(ServerStatus {
            name: "my-gw".into(),
            version: "0.3.0".into(),
            status: "running".into(),
            ..Default::default()
        });
        let out = render_header(&state, 60);
        assert!(out.contains("my-gw"));
        assert!(out.contains("v0.3.0"));
        assert!(out.contains("connected"));
    }

    #[test]
    fn header_shows_error() {
        let mut state = AppState::default();
        state.last_error = Some("connection refused".into());
        let out = render_header(&state, 60);
        assert!(out.contains("connection refused"));
    }

    #[test]
    fn snapshot_header_disconnected() {
        let state = AppState::default();
        let out = render_header(&state, 60);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn snapshot_header_connected() {
        let mut state = AppState::default();
        state.connected = true;
        state.server_status = Some(ServerStatus {
            name: "navra".into(),
            version: "0.3.0".into(),
            status: "running".into(),
            ..Default::default()
        });
        let out = render_header(&state, 60);
        insta::assert_snapshot!(out);
    }
}
