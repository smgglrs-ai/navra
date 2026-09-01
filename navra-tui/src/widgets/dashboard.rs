use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Widget};

use crate::state::AppState;
use crate::theme;

#[cfg(test)]
use crate::test_helpers::buf_to_string;

pub struct Dashboard<'a> {
    state: &'a AppState,
}

impl<'a> Dashboard<'a> {
    pub fn new(state: &'a AppState) -> Self {
        Self { state }
    }
}

impl Widget for Dashboard<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let chunks = Layout::vertical([
            Constraint::Length(5),
            Constraint::Length(5),
            Constraint::Min(3),
        ])
        .split(area);

        self.render_server_info(chunks[0], buf);
        self.render_counts(chunks[1], buf);
        self.render_recent_activity(chunks[2], buf);
    }
}

impl Dashboard<'_> {
    fn render_server_info(&self, area: Rect, buf: &mut Buffer) {
        let block = Block::default()
            .title(" Server ")
            .borders(Borders::ALL)
            .border_style(theme::muted());

        let inner = block.inner(area);
        block.render(area, buf);

        let status = self.state.server_status.as_ref();
        let lines = vec![
            Line::from(vec![
                Span::styled("Name:    ", theme::muted()),
                Span::raw(status.map(|s| s.name.as_str()).unwrap_or("--")),
            ]),
            Line::from(vec![
                Span::styled("Version: ", theme::muted()),
                Span::raw(status.map(|s| s.version.as_str()).unwrap_or("--")),
            ]),
            Line::from(vec![
                Span::styled("Status:  ", theme::muted()),
                Span::styled(
                    status.map(|s| s.status.as_str()).unwrap_or("unknown"),
                    if self.state.connected {
                        theme::status_ok()
                    } else {
                        theme::status_error()
                    },
                ),
            ]),
        ];
        Paragraph::new(lines).render(inner, buf);
    }

    fn render_counts(&self, area: Rect, buf: &mut Buffer) {
        let cols = Layout::horizontal([
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
        ])
        .split(area);

        let agent_count = self
            .state
            .sys_status
            .as_ref()
            .map(|s| s.agents.len())
            .unwrap_or(0);
        let session_count = self
            .state
            .sys_status
            .as_ref()
            .map(|s| s.session_count)
            .unwrap_or(0);
        let model_count = self.state.models.len();
        let flow_count = self.state.flows.len();

        render_stat_card(
            "Agents",
            &agent_count.to_string(),
            theme::ACCENT,
            cols[0],
            buf,
        );
        render_stat_card(
            "Sessions",
            &session_count.to_string(),
            theme::ACCENT,
            cols[1],
            buf,
        );
        render_stat_card(
            "Models",
            &model_count.to_string(),
            theme::SUCCESS,
            cols[2],
            buf,
        );
        render_stat_card("Flows", &flow_count.to_string(), theme::WARN, cols[3], buf);
    }

    fn render_recent_activity(&self, area: Rect, buf: &mut Buffer) {
        let block = Block::default()
            .title(" Recent Audit ")
            .borders(Borders::ALL)
            .border_style(theme::muted());
        let inner = block.inner(area);
        block.render(area, buf);

        let lines: Vec<Line> = self
            .state
            .audit
            .entries
            .iter()
            .take(inner.height as usize)
            .map(|e| {
                Line::from(vec![
                    Span::styled(format!("{:<12}", e.agent_name), theme::accent()),
                    Span::raw(format!("{:<24}", e.tool_name)),
                    Span::styled(
                        format!("{:<10}", e.outcome),
                        theme::outcome_style(&e.outcome),
                    ),
                    Span::styled(format!("{}us", e.duration_us), theme::muted()),
                ])
            })
            .collect();

        if lines.is_empty() {
            Paragraph::new("  No audit entries yet")
                .style(theme::muted())
                .render(inner, buf);
        } else {
            Paragraph::new(lines).render(inner, buf);
        }
    }
}

fn render_stat_card(
    title: &str,
    value: &str,
    color: ratatui::style::Color,
    area: Rect,
    buf: &mut Buffer,
) {
    let block = Block::default()
        .title(format!(" {title} "))
        .borders(Borders::ALL)
        .border_style(theme::muted());
    let inner = block.inner(area);
    block.render(area, buf);

    let lines = vec![
        Line::raw(""),
        Line::from(Span::styled(
            format!("  {value}"),
            ratatui::style::Style::default()
                .fg(color)
                .add_modifier(ratatui::style::Modifier::BOLD),
        )),
    ];
    Paragraph::new(lines).render(inner, buf);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{BlackboxEntry, ModelInfo, ServerStatus, SysStatus};

    fn render_dashboard(state: &AppState, width: u16, height: u16) -> String {
        let area = Rect::new(0, 0, width, height);
        let mut buf = Buffer::empty(area);
        Dashboard::new(state).render(area, &mut buf);
        buf_to_string(&buf)
    }

    #[test]
    fn dashboard_empty_state() {
        let state = AppState::default();
        let out = render_dashboard(&state, 80, 20);
        assert!(out.contains("Server"));
        assert!(out.contains("--"));
        assert!(out.contains("No audit entries yet"));
    }

    #[test]
    fn dashboard_with_data() {
        let mut state = AppState::default();
        state.connected = true;
        state.server_status = Some(ServerStatus {
            name: "test-gw".into(),
            version: "1.0.0".into(),
            status: "running".into(),
            ..Default::default()
        });
        state.models = vec![
            ModelInfo {
                name: "m1".into(),
                ..Default::default()
            },
            ModelInfo {
                name: "m2".into(),
                ..Default::default()
            },
        ];
        state.sys_status = Some(SysStatus {
            agents: vec![],
            session_count: 5,
        });
        let out = render_dashboard(&state, 80, 20);
        assert!(out.contains("test-gw"));
        assert!(out.contains("1.0.0"));
        assert!(out.contains("Agents"));
        assert!(out.contains("Models"));
    }

    #[test]
    fn dashboard_shows_audit_entries() {
        let mut state = AppState::default();
        state.audit.entries.push(BlackboxEntry {
            agent_name: "bot".into(),
            tool_name: "file_read".into(),
            outcome: "allowed".into(),
            duration_us: 1500,
            ..Default::default()
        });
        let out = render_dashboard(&state, 80, 20);
        assert!(out.contains("bot"));
        assert!(out.contains("file_read"));
        assert!(out.contains("allowed"));
    }

    #[test]
    fn snapshot_dashboard_empty() {
        let state = AppState::default();
        let out = render_dashboard(&state, 80, 20);
        insta::assert_snapshot!(out);
    }
}
