#![allow(dead_code, clippy::field_reassign_with_default)]
mod client;
mod event;
mod state;
mod theme;
mod widgets;

#[cfg(test)]
mod test_helpers;

use anyhow::Result;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::widgets::Widget;
use std::time::Duration;
use tokio::sync::mpsc;

use client::NavraClient;
use event::{map_key_filter, map_key_normal, Action, AppEvent};
use state::{AppState, InputMode, Tab};

pub async fn run(endpoint: String, token: Option<String>) -> Result<()> {
    let client = NavraClient::new(&endpoint, token.clone())?;
    let mut state = AppState::default();
    let (tx, mut rx) = mpsc::channel::<DataUpdate>(16);

    let poll_client = NavraClient::new(&endpoint, token)?;
    let shutdown = tokio::sync::watch::channel(false);
    let mut shutdown_rx = shutdown.1.clone();

    tokio::spawn(async move {
        poll_loop(poll_client, tx, &mut shutdown_rx).await;
    });

    let mut terminal = ratatui::init();

    loop {
        while let Ok(update) = rx.try_recv() {
            apply_update(&mut state, update);
        }

        terminal.draw(|frame| {
            let app = AppView { state: &state };
            frame.render_widget(app, frame.area());
        })?;

        match event::poll(Duration::from_millis(100))? {
            Some(AppEvent::Key(key)) => {
                let action = match state.input_mode {
                    InputMode::Normal => map_key_normal(key),
                    InputMode::Filter => map_key_filter(key),
                };
                if handle_action(&mut state, action, &client).await {
                    break;
                }
            }
            Some(AppEvent::Resize(_, _)) => {}
            _ => {}
        }
    }

    let _ = shutdown.0.send(true);
    ratatui::restore();
    Ok(())
}

async fn handle_action(state: &mut AppState, action: Action, _client: &NavraClient) -> bool {
    match action {
        Action::Quit => return true,
        Action::NextTab => {
            state.tab = state.tab.next();
            state.reset_selection();
        }
        Action::PrevTab => {
            state.tab = state.tab.prev();
            state.reset_selection();
        }
        Action::SelectTab(i) => {
            if let Some(&tab) = Tab::ALL.get(i) {
                state.tab = tab;
                state.reset_selection();
            }
        }
        Action::ScrollDown => {
            state.selected_row = state.selected_row.saturating_add(1);
        }
        Action::ScrollUp => {
            state.selected_row = state.selected_row.saturating_sub(1);
        }
        Action::PageDown => {
            state.selected_row = state.selected_row.saturating_add(20);
        }
        Action::PageUp => {
            state.selected_row = state.selected_row.saturating_sub(20);
        }
        Action::Home => {
            state.selected_row = 0;
        }
        Action::End => {
            state.selected_row = usize::MAX;
        }
        Action::StartFilter => {
            state.input_mode = InputMode::Filter;
            state.filter_text.clear();
        }
        Action::StopFilter => {
            state.input_mode = InputMode::Normal;
        }
        Action::FilterChar(c) => {
            state.filter_text.push(c);
        }
        Action::FilterBackspace => {
            state.filter_text.pop();
        }
        Action::Refresh | Action::Enter | Action::None => {}
    }
    false
}

enum DataUpdate {
    Status(state::ServerStatus),
    SysStatus(state::SysStatus),
    Models(Vec<state::ModelInfo>),
    Audit(state::AuditResponse),
    Flows(Vec<state::FlowInfo>),
    FlowRuns(Vec<state::FlowRunSummary>),
    Safety(state::SafetyMetrics),
    Error(String),
}

fn apply_update(state: &mut AppState, update: DataUpdate) {
    state.connected = true;
    state.last_error = None;
    match update {
        DataUpdate::Status(s) => state.server_status = Some(s),
        DataUpdate::SysStatus(s) => state.sys_status = Some(s),
        DataUpdate::Models(m) => state.models = m,
        DataUpdate::Audit(a) => state.audit = a,
        DataUpdate::Flows(f) => state.flows = f,
        DataUpdate::FlowRuns(r) => state.flow_runs = r,
        DataUpdate::Safety(s) => state.safety = Some(s),
        DataUpdate::Error(e) => {
            state.connected = false;
            state.last_error = Some(e);
        }
    }
}

async fn poll_loop(
    client: NavraClient,
    tx: mpsc::Sender<DataUpdate>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = shutdown.changed() => return,
        }

        match client.status().await {
            Ok(s) => {
                let _ = tx.send(DataUpdate::Status(s)).await;
            }
            Err(e) => {
                let _ = tx.send(DataUpdate::Error(e.to_string())).await;
                continue;
            }
        }

        if let Ok(s) = client.sys_status().await {
            let _ = tx.send(DataUpdate::SysStatus(s)).await;
        }
        if let Ok(m) = client.models().await {
            let _ = tx.send(DataUpdate::Models(m)).await;
        }
        if let Ok(a) = client.audit(50).await {
            let _ = tx.send(DataUpdate::Audit(a)).await;
        }
        if let Ok(f) = client.flows().await {
            let _ = tx.send(DataUpdate::Flows(f)).await;
        }
        if let Ok(r) = client.flow_runs().await {
            let _ = tx.send(DataUpdate::FlowRuns(r)).await;
        }
        if let Ok(s) = client.safety_metrics().await {
            let _ = tx.send(DataUpdate::Safety(s)).await;
        }
    }
}

struct AppView<'a> {
    state: &'a AppState,
}

impl Widget for AppView<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let chunks = Layout::vertical([
            Constraint::Length(1), // header
            Constraint::Length(1), // tabs
            Constraint::Min(5),   // content
            Constraint::Length(1), // footer
        ])
        .split(area);

        widgets::header::Header::new(self.state).render(chunks[0], buf);
        widgets::tabs::TabBar::new(self.state.tab).render(chunks[1], buf);

        match self.state.tab {
            Tab::Dashboard => widgets::dashboard::Dashboard::new(self.state).render(chunks[2], buf),
            Tab::Agents => widgets::agents::AgentsTab::new(self.state).render(chunks[2], buf),
            Tab::Audit => widgets::audit::AuditTab::new(self.state).render(chunks[2], buf),
            Tab::Models => widgets::models::ModelsTab::new(self.state).render(chunks[2], buf),
            Tab::Flows => widgets::flows::FlowsTab::new(self.state).render(chunks[2], buf),
            Tab::Safety => widgets::safety::SafetyTab::new(self.state).render(chunks[2], buf),
        }

        widgets::footer::Footer::new(self.state).render(chunks[3], buf);
    }
}
