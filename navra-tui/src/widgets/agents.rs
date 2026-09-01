use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Row, Table, Widget};

use crate::state::AppState;
use crate::theme;

#[cfg(test)]
use crate::test_helpers::buf_to_string;

pub struct AgentsTab<'a> {
    state: &'a AppState,
}

impl<'a> AgentsTab<'a> {
    pub fn new(state: &'a AppState) -> Self {
        Self { state }
    }
}

impl Widget for AgentsTab<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let agents = self
            .state
            .sys_status
            .as_ref()
            .map(|s| &s.agents[..])
            .unwrap_or(&[]);

        let header = Row::new(vec![
            "Name",
            "Permissions",
            "Ring",
            "Calls",
            "Denied",
            "Uptime",
            "Idle",
            "Active",
        ])
        .style(theme::table_header());

        let rows: Vec<Row> = agents
            .iter()
            .enumerate()
            .filter(|(_, a)| {
                self.state.filter_text.is_empty()
                    || a.name
                        .to_lowercase()
                        .contains(&self.state.filter_text.to_lowercase())
            })
            .map(|(i, a)| {
                let style = if i == self.state.selected_row {
                    theme::selected_row()
                } else {
                    theme::base()
                };
                Row::new(vec![
                    a.name.clone(),
                    a.permissions.clone(),
                    a.ring.map(|r| r.to_string()).unwrap_or_else(|| "--".into()),
                    a.call_count.to_string(),
                    a.denied_count.to_string(),
                    format_duration(a.uptime_secs),
                    format_duration(a.idle_secs),
                    a.active_calls.join(", "),
                ])
                .style(style)
            })
            .collect();

        let widths = [
            ratatui::layout::Constraint::Length(16),
            ratatui::layout::Constraint::Length(14),
            ratatui::layout::Constraint::Length(5),
            ratatui::layout::Constraint::Length(7),
            ratatui::layout::Constraint::Length(7),
            ratatui::layout::Constraint::Length(10),
            ratatui::layout::Constraint::Length(10),
            ratatui::layout::Constraint::Min(20),
        ];

        let table = Table::new(rows, widths).header(header).block(
            Block::default()
                .title(" Active Agents ")
                .borders(Borders::ALL)
                .border_style(theme::muted()),
        );

        table.render(area, buf);
    }
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ProcessSnapshot, SysStatus};

    fn render_agents(state: &AppState, width: u16, height: u16) -> String {
        let area = Rect::new(0, 0, width, height);
        let mut buf = Buffer::empty(area);
        AgentsTab::new(state).render(area, &mut buf);
        buf_to_string(&buf)
    }

    #[test]
    fn format_duration_seconds() {
        assert_eq!(format_duration(42), "42s");
    }

    #[test]
    fn format_duration_minutes() {
        assert_eq!(format_duration(125), "2m5s");
    }

    #[test]
    fn format_duration_hours() {
        assert_eq!(format_duration(7260), "2h1m");
    }

    #[test]
    fn agents_empty() {
        let state = AppState::default();
        let out = render_agents(&state, 100, 10);
        assert!(out.contains("Active Agents"));
        assert!(out.contains("Name"));
    }

    #[test]
    fn agents_with_data() {
        let mut state = AppState::default();
        state.sys_status = Some(SysStatus {
            agents: vec![ProcessSnapshot {
                name: "claude-code".into(),
                permissions: "default".into(),
                ring: Some(2),
                call_count: 15,
                denied_count: 1,
                uptime_secs: 3700,
                idle_secs: 10,
                active_calls: vec!["file_read".into()],
                ..Default::default()
            }],
            session_count: 1,
        });
        let out = render_agents(&state, 100, 10);
        assert!(out.contains("claude-code"));
        assert!(out.contains("default"));
        assert!(out.contains("file_read"));
    }

    #[test]
    fn agents_filter() {
        let mut state = AppState::default();
        state.filter_text = "missing".into();
        state.sys_status = Some(SysStatus {
            agents: vec![ProcessSnapshot {
                name: "bot".into(),
                permissions: "admin".into(),
                ..Default::default()
            }],
            session_count: 1,
        });
        let out = render_agents(&state, 100, 10);
        assert!(!out.contains("bot"));
    }

    #[test]
    fn snapshot_agents_with_data() {
        let mut state = AppState::default();
        state.sys_status = Some(SysStatus {
            agents: vec![ProcessSnapshot {
                name: "agent-a".into(),
                permissions: "ops".into(),
                ring: Some(1),
                call_count: 42,
                denied_count: 0,
                uptime_secs: 120,
                idle_secs: 5,
                active_calls: vec![],
                ..Default::default()
            }],
            session_count: 1,
        });
        let out = render_agents(&state, 100, 8);
        insta::assert_snapshot!(out);
    }
}
