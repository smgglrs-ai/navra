use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Row, Table, Widget};

use crate::state::AppState;
use crate::theme;

#[cfg(test)]
use crate::test_helpers::buf_to_string;

pub struct ModelsTab<'a> {
    state: &'a AppState,
}

impl<'a> ModelsTab<'a> {
    pub fn new(state: &'a AppState) -> Self {
        Self { state }
    }
}

impl Widget for ModelsTab<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let header = Row::new(vec!["Name", "Task", "Backend", "Source", "Context"])
            .style(theme::table_header());

        let rows: Vec<Row> = self
            .state
            .models
            .iter()
            .enumerate()
            .filter(|(_, m)| {
                self.state.filter_text.is_empty()
                    || m.name
                        .to_lowercase()
                        .contains(&self.state.filter_text.to_lowercase())
            })
            .map(|(i, m)| {
                let style = if i == self.state.selected_row {
                    theme::selected_row()
                } else {
                    theme::base()
                };
                Row::new(vec![
                    m.name.clone(),
                    m.task.clone(),
                    m.backend.clone(),
                    m.source.clone().unwrap_or_else(|| "--".into()),
                    m.context_size
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "--".into()),
                ])
                .style(style)
            })
            .collect();

        let widths = [
            ratatui::layout::Constraint::Length(24),
            ratatui::layout::Constraint::Length(16),
            ratatui::layout::Constraint::Length(10),
            ratatui::layout::Constraint::Length(20),
            ratatui::layout::Constraint::Min(10),
        ];

        let table = Table::new(rows, widths).header(header).block(
            Block::default()
                .title(format!(" Models ({}) ", self.state.models.len()))
                .borders(Borders::ALL)
                .border_style(theme::muted()),
        );

        table.render(area, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ModelInfo;

    fn render_models(state: &AppState, width: u16, height: u16) -> String {
        let area = Rect::new(0, 0, width, height);
        let mut buf = Buffer::empty(area);
        ModelsTab::new(state).render(area, &mut buf);
        buf_to_string(&buf)
    }

    #[test]
    fn models_empty() {
        let state = AppState::default();
        let out = render_models(&state, 90, 8);
        assert!(out.contains("Models (0)"));
    }

    #[test]
    fn models_with_data() {
        let mut state = AppState::default();
        state.models = vec![
            ModelInfo {
                name: "guardian-hap".into(),
                task: "classification".into(),
                backend: "onnx".into(),
                source: Some("hf:ibm/guardian-hap".into()),
                context_size: Some(512),
                ..Default::default()
            },
            ModelInfo {
                name: "granite-embed".into(),
                task: "embedding".into(),
                backend: "onnx".into(),
                source: None,
                context_size: None,
                ..Default::default()
            },
        ];
        let out = render_models(&state, 90, 8);
        assert!(out.contains("Models (2)"));
        assert!(out.contains("guardian-hap"));
        assert!(out.contains("classification"));
        assert!(out.contains("granite-embed"));
    }

    #[test]
    fn snapshot_models() {
        let mut state = AppState::default();
        state.models = vec![ModelInfo {
            name: "test-model".into(),
            task: "chat".into(),
            backend: "external".into(),
            source: None,
            context_size: Some(4096),
            ..Default::default()
        }];
        let out = render_models(&state, 90, 8);
        insta::assert_snapshot!(out);
    }
}
