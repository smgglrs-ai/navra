use crossterm::event::{self, Event as CtEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use std::time::Duration;

#[derive(Debug)]
pub enum AppEvent {
    Key(KeyEvent),
    Resize(#[allow(dead_code)] u16, #[allow(dead_code)] u16),
    Tick,
}

pub fn poll(timeout: Duration) -> std::io::Result<Option<AppEvent>> {
    if event::poll(timeout)? {
        match event::read()? {
            CtEvent::Key(key) if key.kind == KeyEventKind::Press => Ok(Some(AppEvent::Key(key))),
            CtEvent::Resize(w, h) => Ok(Some(AppEvent::Resize(w, h))),
            _ => Ok(None),
        }
    } else {
        Ok(Some(AppEvent::Tick))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Quit,
    NextTab,
    PrevTab,
    SelectTab(usize),
    ScrollUp,
    ScrollDown,
    PageUp,
    PageDown,
    Home,
    End,
    Enter,
    StartFilter,
    StopFilter,
    FilterChar(char),
    FilterBackspace,
    Refresh,
    None,
}

pub fn map_key_normal(key: KeyEvent) -> Action {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Action::Quit;
    }
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
        KeyCode::Tab => Action::NextTab,
        KeyCode::BackTab => Action::PrevTab,
        KeyCode::Char('1') => Action::SelectTab(0),
        KeyCode::Char('2') => Action::SelectTab(1),
        KeyCode::Char('3') => Action::SelectTab(2),
        KeyCode::Char('4') => Action::SelectTab(3),
        KeyCode::Char('5') => Action::SelectTab(4),
        KeyCode::Char('6') => Action::SelectTab(5),
        KeyCode::Char('j') | KeyCode::Down => Action::ScrollDown,
        KeyCode::Char('k') | KeyCode::Up => Action::ScrollUp,
        KeyCode::PageDown => Action::PageDown,
        KeyCode::PageUp => Action::PageUp,
        KeyCode::Home => Action::Home,
        KeyCode::End => Action::End,
        KeyCode::Enter => Action::Enter,
        KeyCode::Char('/') => Action::StartFilter,
        KeyCode::Char('r') => Action::Refresh,
        _ => Action::None,
    }
}

pub fn map_key_filter(key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Esc | KeyCode::Enter => Action::StopFilter,
        KeyCode::Char(c) => Action::FilterChar(c),
        KeyCode::Backspace => Action::FilterBackspace,
        _ => Action::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEventState;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn normal_quit_keys() {
        assert_eq!(map_key_normal(press(KeyCode::Char('q'))), Action::Quit);
        assert_eq!(map_key_normal(press(KeyCode::Esc)), Action::Quit);
        assert_eq!(map_key_normal(ctrl(KeyCode::Char('c'))), Action::Quit);
    }

    #[test]
    fn normal_tab_switching() {
        assert_eq!(map_key_normal(press(KeyCode::Tab)), Action::NextTab);
        assert_eq!(map_key_normal(press(KeyCode::BackTab)), Action::PrevTab);
        assert_eq!(map_key_normal(press(KeyCode::Char('1'))), Action::SelectTab(0));
        assert_eq!(map_key_normal(press(KeyCode::Char('6'))), Action::SelectTab(5));
    }

    #[test]
    fn normal_scrolling() {
        assert_eq!(map_key_normal(press(KeyCode::Char('j'))), Action::ScrollDown);
        assert_eq!(map_key_normal(press(KeyCode::Char('k'))), Action::ScrollUp);
        assert_eq!(map_key_normal(press(KeyCode::Down)), Action::ScrollDown);
        assert_eq!(map_key_normal(press(KeyCode::Up)), Action::ScrollUp);
        assert_eq!(map_key_normal(press(KeyCode::PageDown)), Action::PageDown);
        assert_eq!(map_key_normal(press(KeyCode::PageUp)), Action::PageUp);
        assert_eq!(map_key_normal(press(KeyCode::Home)), Action::Home);
        assert_eq!(map_key_normal(press(KeyCode::End)), Action::End);
    }

    #[test]
    fn normal_filter_and_refresh() {
        assert_eq!(map_key_normal(press(KeyCode::Char('/'))), Action::StartFilter);
        assert_eq!(map_key_normal(press(KeyCode::Char('r'))), Action::Refresh);
    }

    #[test]
    fn filter_mode_typing() {
        assert_eq!(map_key_filter(press(KeyCode::Char('a'))), Action::FilterChar('a'));
        assert_eq!(map_key_filter(press(KeyCode::Backspace)), Action::FilterBackspace);
    }

    #[test]
    fn filter_mode_exit() {
        assert_eq!(map_key_filter(press(KeyCode::Esc)), Action::StopFilter);
        assert_eq!(map_key_filter(press(KeyCode::Enter)), Action::StopFilter);
    }

    #[test]
    fn unknown_key_returns_none() {
        assert_eq!(map_key_normal(press(KeyCode::F(1))), Action::None);
        assert_eq!(map_key_filter(press(KeyCode::F(1))), Action::None);
    }
}
