use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Widget;

use crate::state::{AppState, InputMode};
use crate::theme;

#[cfg(test)]
use crate::test_helpers::buf_to_string;

pub struct Footer<'a> {
    state: &'a AppState,
}

impl<'a> Footer<'a> {
    pub fn new(state: &'a AppState) -> Self {
        Self { state }
    }
}

impl Widget for Footer<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let line = match self.state.input_mode {
            InputMode::Filter => Line::from(vec![
                Span::styled(" Filter: ", theme::accent()),
                Span::raw(&self.state.filter_text),
                Span::styled("_ ", theme::accent()),
                Span::styled("  Esc/Enter: apply  ", theme::muted()),
            ]),
            InputMode::Normal => Line::from(vec![
                Span::styled(" 1-6", theme::accent()),
                Span::styled(":tab  ", theme::muted()),
                Span::styled("j/k", theme::accent()),
                Span::styled(":scroll  ", theme::muted()),
                Span::styled("/", theme::accent()),
                Span::styled(":filter  ", theme::muted()),
                Span::styled("r", theme::accent()),
                Span::styled(":refresh  ", theme::muted()),
                Span::styled("q", theme::accent()),
                Span::styled(":quit", theme::muted()),
            ]),
        };
        buf.set_style(area, theme::header());
        line.render(area, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render_footer(state: &AppState, width: u16) -> String {
        let area = Rect::new(0, 0, width, 1);
        let mut buf = Buffer::empty(area);
        Footer::new(state).render(area, &mut buf);
        buf_to_string(&buf)
    }

    #[test]
    fn footer_normal_mode_shows_keybindings() {
        let state = AppState::default();
        let out = render_footer(&state, 60);
        assert!(out.contains("1-6"));
        assert!(out.contains("j/k"));
        assert!(out.contains("quit"));
    }

    #[test]
    fn footer_filter_mode_shows_input() {
        let mut state = AppState::default();
        state.input_mode = InputMode::Filter;
        state.filter_text = "test".into();
        let out = render_footer(&state, 60);
        assert!(out.contains("Filter:"));
        assert!(out.contains("test"));
    }

    #[test]
    fn snapshot_footer_normal() {
        let state = AppState::default();
        let out = render_footer(&state, 60);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn snapshot_footer_filter() {
        let mut state = AppState::default();
        state.input_mode = InputMode::Filter;
        state.filter_text = "agent-x".into();
        let out = render_footer(&state, 60);
        insta::assert_snapshot!(out);
    }
}
