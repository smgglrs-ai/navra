use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::widgets::{Block, Borders, Row, Table, Widget};

use crate::state::AppState;
use crate::theme;

pub struct FlowsTab<'a> {
    state: &'a AppState,
}

impl<'a> FlowsTab<'a> {
    pub fn new(state: &'a AppState) -> Self {
        Self { state }
    }
}

impl Widget for FlowsTab<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let chunks =
            Layout::vertical([Constraint::Percentage(40), Constraint::Percentage(60)]).split(area);

        self.render_flows(chunks[0], buf);
        self.render_runs(chunks[1], buf);
    }
}

impl FlowsTab<'_> {
    fn render_flows(&self, area: Rect, buf: &mut Buffer) {
        let header = Row::new(vec!["Name", "Path", "Tasks"]).style(theme::table_header());

        let rows: Vec<Row> = self
            .state
            .flows
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let style = if i == self.state.selected_row {
                    theme::selected_row()
                } else {
                    theme::base()
                };
                Row::new(vec![f.name.clone(), f.path.clone(), f.tasks.to_string()]).style(style)
            })
            .collect();

        let widths = [
            Constraint::Length(20),
            Constraint::Min(30),
            Constraint::Length(6),
        ];

        Table::new(rows, widths)
            .header(header)
            .block(
                Block::default()
                    .title(format!(" Flows ({}) ", self.state.flows.len()))
                    .borders(Borders::ALL)
                    .border_style(theme::muted()),
            )
            .render(area, buf);
    }

    fn render_runs(&self, area: Rect, buf: &mut Buffer) {
        let header = Row::new(vec!["Flow ID", "Name", "Status", "Elapsed", "Nodes"])
            .style(theme::table_header());

        let rows: Vec<Row> = self
            .state
            .flow_runs
            .iter()
            .map(|r| {
                Row::new(vec![
                    r.flow_id.clone(),
                    r.name.clone(),
                    r.status.clone(),
                    format!("{:.1}s", r.elapsed_secs),
                    r.node_count.to_string(),
                ])
            })
            .collect();

        let widths = [
            Constraint::Length(14),
            Constraint::Length(16),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(6),
        ];

        Table::new(rows, widths)
            .header(header)
            .block(
                Block::default()
                    .title(" Recent Runs ")
                    .borders(Borders::ALL)
                    .border_style(theme::muted()),
            )
            .render(area, buf);
    }
}
