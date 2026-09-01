use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table, Widget};

use crate::state::AppState;
use crate::theme;

#[cfg(test)]
use crate::test_helpers::buf_to_string;

pub struct SafetyTab<'a> {
    state: &'a AppState,
}

impl<'a> SafetyTab<'a> {
    pub fn new(state: &'a AppState) -> Self {
        Self { state }
    }
}

impl Widget for SafetyTab<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let chunks = Layout::vertical([Constraint::Length(7), Constraint::Min(5)]).split(area);

        self.render_summary(chunks[0], buf);
        self.render_categories(chunks[1], buf);
    }
}

impl SafetyTab<'_> {
    fn render_summary(&self, area: Rect, buf: &mut Buffer) {
        let block = Block::default()
            .title(" PII Safety Metrics ")
            .borders(Borders::ALL)
            .border_style(theme::muted());
        let inner = block.inner(area);
        block.render(area, buf);

        let m = self.state.safety.as_ref();
        let lines = vec![
            Line::from(vec![
                Span::styled("Total scans:  ", theme::muted()),
                Span::raw(
                    m.map(|s| s.total_scans.to_string())
                        .unwrap_or_else(|| "--".into()),
                ),
            ]),
            Line::from(vec![
                Span::styled("PII detected: ", theme::muted()),
                Span::styled(
                    m.map(|s| s.pii_detected.to_string())
                        .unwrap_or_else(|| "--".into()),
                    theme::accent(),
                ),
            ]),
            Line::from(vec![
                Span::styled("PII redacted: ", theme::muted()),
                Span::styled(
                    m.map(|s| s.pii_redacted.to_string())
                        .unwrap_or_else(|| "--".into()),
                    theme::status_ok(),
                ),
            ]),
            Line::from(vec![
                Span::styled("PII blocked:  ", theme::muted()),
                Span::styled(
                    m.map(|s| s.pii_blocked.to_string())
                        .unwrap_or_else(|| "--".into()),
                    if m.map(|s| s.pii_blocked).unwrap_or(0) > 0 {
                        theme::status_error()
                    } else {
                        theme::status_ok()
                    },
                ),
            ]),
        ];
        Paragraph::new(lines).render(inner, buf);
    }

    fn render_categories(&self, area: Rect, buf: &mut Buffer) {
        let header = Row::new(vec!["Category", "Count"]).style(theme::table_header());

        let rows: Vec<Row> = self
            .state
            .safety
            .as_ref()
            .map(|m| {
                let mut cats: Vec<_> = m.by_category.iter().collect();
                cats.sort_by(|a, b| b.1.cmp(a.1));
                cats.into_iter()
                    .map(|(cat, count)| Row::new(vec![cat.clone(), count.to_string()]))
                    .collect()
            })
            .unwrap_or_default();

        let widths = [Constraint::Length(24), Constraint::Min(10)];

        Table::new(rows, widths)
            .header(header)
            .block(
                Block::default()
                    .title(" By Category ")
                    .borders(Borders::ALL)
                    .border_style(theme::muted()),
            )
            .render(area, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SafetyMetrics;

    fn render_safety(state: &AppState, width: u16, height: u16) -> String {
        let area = Rect::new(0, 0, width, height);
        let mut buf = Buffer::empty(area);
        SafetyTab::new(state).render(area, &mut buf);
        buf_to_string(&buf)
    }

    #[test]
    fn safety_empty() {
        let state = AppState::default();
        let out = render_safety(&state, 60, 15);
        assert!(out.contains("PII Safety Metrics"));
        assert!(out.contains("--"));
    }

    #[test]
    fn safety_with_data() {
        let mut state = AppState::default();
        let mut by_category = std::collections::HashMap::new();
        by_category.insert("email".into(), 5);
        by_category.insert("phone".into(), 2);
        state.safety = Some(SafetyMetrics {
            total_scans: 100,
            pii_detected: 7,
            pii_redacted: 5,
            pii_blocked: 2,
            by_category,
        });
        let out = render_safety(&state, 60, 15);
        assert!(out.contains("100"));
        assert!(out.contains("email"));
    }

    #[test]
    fn snapshot_safety_with_metrics() {
        let mut state = AppState::default();
        let mut by_category = std::collections::HashMap::new();
        by_category.insert("ssn".into(), 3);
        state.safety = Some(SafetyMetrics {
            total_scans: 50,
            pii_detected: 3,
            pii_redacted: 3,
            pii_blocked: 0,
            by_category,
        });
        let out = render_safety(&state, 60, 15);
        insta::assert_snapshot!(out);
    }
}
