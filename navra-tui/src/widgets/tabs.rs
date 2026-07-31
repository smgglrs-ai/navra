use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Widget;

use crate::state::Tab;
use crate::theme;

#[cfg(test)]
use crate::test_helpers::buf_to_string;

pub struct TabBar {
    active: Tab,
}

impl TabBar {
    pub fn new(active: Tab) -> Self {
        Self { active }
    }
}

impl Widget for TabBar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let spans: Vec<Span> = Tab::ALL
            .iter()
            .enumerate()
            .flat_map(|(i, &tab)| {
                let num = format!(" {} ", i + 1);
                let label = format!("{} ", tab.label());
                let style = if tab == self.active {
                    theme::tab_active()
                } else {
                    theme::tab_inactive()
                };
                vec![
                    Span::styled(num, if tab == self.active { theme::accent() } else { theme::muted() }),
                    Span::styled(label, style),
                ]
            })
            .collect();

        Line::from(spans).render(area, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render_tabs(active: Tab, width: u16) -> String {
        let area = Rect::new(0, 0, width, 1);
        let mut buf = Buffer::empty(area);
        TabBar::new(active).render(area, &mut buf);
        buf_to_string(&buf)
    }

    #[test]
    fn tabs_shows_all_labels() {
        let out = render_tabs(Tab::Dashboard, 80);
        for tab in Tab::ALL {
            assert!(out.contains(tab.label()), "missing tab label: {}", tab.label());
        }
    }

    #[test]
    fn tabs_shows_numbers() {
        let out = render_tabs(Tab::Dashboard, 80);
        for i in 1..=6 {
            assert!(out.contains(&i.to_string()));
        }
    }

    #[test]
    fn snapshot_tabs_dashboard() {
        let out = render_tabs(Tab::Dashboard, 80);
        insta::assert_snapshot!(out);
    }

    #[test]
    fn snapshot_tabs_audit() {
        let out = render_tabs(Tab::Audit, 80);
        insta::assert_snapshot!(out);
    }
}
