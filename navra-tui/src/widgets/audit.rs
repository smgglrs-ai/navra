use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Row, Table, Widget};

use crate::state::AppState;
use crate::theme;

#[cfg(test)]
use crate::test_helpers::buf_to_string;

pub struct AuditTab<'a> {
    state: &'a AppState,
}

impl<'a> AuditTab<'a> {
    pub fn new(state: &'a AppState) -> Self {
        Self { state }
    }
}

impl Widget for AuditTab<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let entries = &self.state.audit.entries;

        let header = Row::new(vec!["Seq", "Agent", "Tool", "Outcome", "Duration", "IFC"])
            .style(theme::table_header());

        let filtered: Vec<_> = entries
            .iter()
            .filter(|e| {
                self.state.filter_text.is_empty()
                    || e.agent_name
                        .to_lowercase()
                        .contains(&self.state.filter_text.to_lowercase())
                    || e.tool_name
                        .to_lowercase()
                        .contains(&self.state.filter_text.to_lowercase())
            })
            .collect();

        let rows: Vec<Row> = filtered
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let style = if i == self.state.selected_row {
                    theme::selected_row()
                } else {
                    theme::base()
                };
                Row::new(vec![
                    Span::raw(e.seq.to_string()),
                    Span::styled(e.agent_name.clone(), theme::accent()),
                    Span::raw(e.tool_name.clone()),
                    Span::styled(e.outcome.clone(), theme::outcome_style(&e.outcome)),
                    Span::raw(format_us(e.duration_us)),
                    Span::styled(e.ifc_label.clone(), theme::muted()),
                ])
                .style(style)
            })
            .collect();

        let widths = [
            ratatui::layout::Constraint::Length(6),
            ratatui::layout::Constraint::Length(14),
            ratatui::layout::Constraint::Length(24),
            ratatui::layout::Constraint::Length(10),
            ratatui::layout::Constraint::Length(10),
            ratatui::layout::Constraint::Min(10),
        ];

        let title = format!(
            " Audit Log ({}/{}) ",
            filtered.len(),
            self.state.audit.total
        );
        let table = Table::new(rows, widths).header(header).block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(theme::muted()),
        );

        table.render(area, buf);
    }
}

fn format_us(us: u64) -> String {
    if us < 1_000 {
        format!("{us}us")
    } else if us < 1_000_000 {
        format!("{:.1}ms", us as f64 / 1_000.0)
    } else {
        format!("{:.2}s", us as f64 / 1_000_000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::BlackboxEntry;

    fn render_audit(state: &AppState, width: u16, height: u16) -> String {
        let area = Rect::new(0, 0, width, height);
        let mut buf = Buffer::empty(area);
        AuditTab::new(state).render(area, &mut buf);
        buf_to_string(&buf)
    }

    #[test]
    fn format_us_microseconds() {
        assert_eq!(format_us(500), "500us");
    }

    #[test]
    fn format_us_milliseconds() {
        assert_eq!(format_us(1500), "1.5ms");
    }

    #[test]
    fn format_us_seconds() {
        assert_eq!(format_us(2_500_000), "2.50s");
    }

    #[test]
    fn audit_empty() {
        let state = AppState::default();
        let out = render_audit(&state, 80, 10);
        assert!(out.contains("Audit Log (0/0)"));
    }

    #[test]
    fn audit_with_entries() {
        let mut state = AppState::default();
        state.audit.total = 100;
        state.audit.entries = vec![
            BlackboxEntry {
                seq: 1,
                agent_name: "bot-a".into(),
                tool_name: "file_write".into(),
                outcome: "denied".into(),
                duration_us: 250,
                ifc_label: "secret".into(),
                ..Default::default()
            },
            BlackboxEntry {
                seq: 2,
                agent_name: "bot-b".into(),
                tool_name: "file_read".into(),
                outcome: "allowed".into(),
                duration_us: 12000,
                ..Default::default()
            },
        ];
        let out = render_audit(&state, 80, 10);
        assert!(out.contains("Audit Log (2/100)"));
        assert!(out.contains("bot-a"));
        assert!(out.contains("denied"));
        assert!(out.contains("bot-b"));
    }

    #[test]
    fn audit_filter_narrows_results() {
        let mut state = AppState::default();
        state.filter_text = "bot-a".into();
        state.audit.total = 2;
        state.audit.entries = vec![
            BlackboxEntry {
                seq: 1,
                agent_name: "bot-a".into(),
                tool_name: "file_read".into(),
                outcome: "allowed".into(),
                ..Default::default()
            },
            BlackboxEntry {
                seq: 2,
                agent_name: "bot-b".into(),
                tool_name: "exec".into(),
                outcome: "denied".into(),
                ..Default::default()
            },
        ];
        let out = render_audit(&state, 80, 10);
        assert!(out.contains("1/2"));
        assert!(out.contains("bot-a"));
        assert!(!out.contains("bot-b"));
    }

    #[test]
    fn snapshot_audit_with_entries() {
        let mut state = AppState::default();
        state.audit.total = 1;
        state.audit.entries = vec![BlackboxEntry {
            seq: 42,
            agent_name: "test-agent".into(),
            tool_name: "git_commit".into(),
            outcome: "allowed".into(),
            duration_us: 5000,
            ifc_label: "public".into(),
            ..Default::default()
        }];
        let out = render_audit(&state, 80, 8);
        insta::assert_snapshot!(out);
    }
}
