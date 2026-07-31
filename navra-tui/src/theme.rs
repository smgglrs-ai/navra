use ratatui::style::{Color, Modifier, Style};

pub const BG: Color = Color::Reset;
pub const FG: Color = Color::White;
pub const ACCENT: Color = Color::Cyan;
pub const SUCCESS: Color = Color::Green;
pub const WARN: Color = Color::Yellow;
pub const ERROR: Color = Color::Red;
pub const MUTED: Color = Color::DarkGray;
pub const HEADER_BG: Color = Color::Rgb(30, 30, 40);
pub const TAB_ACTIVE_BG: Color = Color::Rgb(40, 40, 60);
pub const TABLE_HEADER_BG: Color = Color::Rgb(35, 35, 50);

pub fn base() -> Style {
    Style::default().fg(FG).bg(BG)
}

pub fn header() -> Style {
    Style::default().fg(ACCENT).bg(HEADER_BG).add_modifier(Modifier::BOLD)
}

pub fn tab_active() -> Style {
    Style::default().fg(ACCENT).bg(TAB_ACTIVE_BG).add_modifier(Modifier::BOLD)
}

pub fn tab_inactive() -> Style {
    Style::default().fg(MUTED)
}

pub fn table_header() -> Style {
    Style::default()
        .fg(ACCENT)
        .bg(TABLE_HEADER_BG)
        .add_modifier(Modifier::BOLD)
}

pub fn selected_row() -> Style {
    Style::default().fg(Color::White).bg(Color::Rgb(50, 50, 70))
}

pub fn status_ok() -> Style {
    Style::default().fg(SUCCESS)
}

pub fn status_error() -> Style {
    Style::default().fg(ERROR)
}

pub fn muted() -> Style {
    Style::default().fg(MUTED)
}

pub fn accent() -> Style {
    Style::default().fg(ACCENT)
}

pub fn outcome_style(outcome: &str) -> Style {
    match outcome {
        "allowed" | "ok" => Style::default().fg(SUCCESS),
        "denied" | "blocked" => Style::default().fg(ERROR),
        "approved" => Style::default().fg(WARN),
        _ => Style::default().fg(FG),
    }
}
