use ksni::menu::{StandardItem, SubMenu};
use ksni::{MenuItem, Status, ToolTip, Tray, TrayMethods};
use navra_core::permissions::ApprovalStore;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Commands from tray menu actions to the server.
#[derive(Debug)]
pub enum TrayCommand {
    Approve(String),
    Deny(String),
    Pause,
    Resume,
    Quit,
}

/// State for the system tray icon.
pub struct McpdTray {
    pending: Vec<PendingItem>,
    agents: Vec<AgentInfo>,
    paused: bool,
    cmd_tx: mpsc::UnboundedSender<TrayCommand>,
    /// Whether the navra icon is installed in the hicolor theme.
    has_custom_icon: bool,
}

#[derive(Clone)]
struct PendingItem {
    id: String,
    agent: String,
    operation: String,
    path: String,
}

#[derive(Clone)]
pub struct AgentInfo {
    pub name: String,
    pub permissions: String,
}

impl Tray for McpdTray {
    const MENU_ON_ACTIVATE: bool = true;

    fn id(&self) -> String {
        "navra".to_string()
    }

    fn title(&self) -> String {
        "navra".to_string()
    }

    fn category(&self) -> ksni::Category {
        ksni::Category::SystemServices
    }

    fn status(&self) -> Status {
        if !self.pending.is_empty() {
            Status::NeedsAttention
        } else if self.paused {
            Status::Passive
        } else {
            Status::Active
        }
    }

    fn icon_name(&self) -> String {
        if self.paused {
            "media-playback-pause".to_string()
        } else if self.has_custom_icon {
            "navra".to_string()
        } else {
            "security-medium".to_string()
        }
    }

    fn attention_icon_name(&self) -> String {
        "dialog-warning".to_string()
    }

    fn icon_theme_path(&self) -> String {
        if self.has_custom_icon {
            icon_theme_dir().to_string_lossy().into_owned()
        } else {
            String::new()
        }
    }

    fn tool_tip(&self) -> ToolTip {
        let text = if self.paused {
            "navra — paused".to_string()
        } else if self.pending.is_empty() {
            format!("navra — {} agent(s)", self.agents.len())
        } else {
            format!("navra — {} pending approval(s)", self.pending.len())
        };
        ToolTip {
            title: "navra".to_string(),
            description: text,
            icon_name: String::new(),
            icon_pixmap: Vec::new(),
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let mut items: Vec<MenuItem<Self>> = Vec::new();

        // Pending approvals section
        if !self.pending.is_empty() {
            items.push(MenuItem::Standard(StandardItem {
                label: format!("Pending Approvals ({})", self.pending.len()),
                enabled: false,
                ..Default::default()
            }));

            for pending in &self.pending {
                let id_approve = pending.id.clone();
                let id_deny = pending.id.clone();
                items.push(MenuItem::SubMenu(SubMenu {
                    label: format!(
                        "{} wants to {} {}",
                        pending.agent,
                        pending.operation,
                        short_path(&pending.path),
                    ),
                    icon_name: "dialog-password".to_string(),
                    submenu: vec![
                        MenuItem::Standard(StandardItem {
                            label: "Approve".to_string(),
                            icon_name: "emblem-ok-symbolic".to_string(),
                            activate: Box::new(move |tray: &mut Self| {
                                let _ = tray.cmd_tx.send(TrayCommand::Approve(id_approve.clone()));
                            }),
                            ..Default::default()
                        }),
                        MenuItem::Standard(StandardItem {
                            label: "Deny".to_string(),
                            icon_name: "process-stop-symbolic".to_string(),
                            activate: Box::new(move |tray: &mut Self| {
                                let _ = tray.cmd_tx.send(TrayCommand::Deny(id_deny.clone()));
                            }),
                            ..Default::default()
                        }),
                    ],
                    ..Default::default()
                }));
            }

            items.push(MenuItem::Separator);
        }

        // Connected agents
        if !self.agents.is_empty() {
            items.push(MenuItem::Standard(StandardItem {
                label: "Connected Agents".to_string(),
                enabled: false,
                ..Default::default()
            }));

            for agent in &self.agents {
                items.push(MenuItem::Standard(StandardItem {
                    label: format!("  {} ({})", agent.name, agent.permissions),
                    enabled: false,
                    icon_name: "avatar-default-symbolic".to_string(),
                    ..Default::default()
                }));
            }

            items.push(MenuItem::Separator);
        }

        // Pause/Resume
        if self.paused {
            items.push(MenuItem::Standard(StandardItem {
                label: "Resume".to_string(),
                icon_name: "media-playback-start".to_string(),
                activate: Box::new(|tray: &mut Self| {
                    let _ = tray.cmd_tx.send(TrayCommand::Resume);
                }),
                ..Default::default()
            }));
        } else {
            items.push(MenuItem::Standard(StandardItem {
                label: "Pause".to_string(),
                icon_name: "media-playback-pause".to_string(),
                activate: Box::new(|tray: &mut Self| {
                    let _ = tray.cmd_tx.send(TrayCommand::Pause);
                }),
                ..Default::default()
            }));
        }

        // Quit
        items.push(MenuItem::Standard(StandardItem {
            label: "Quit".to_string(),
            icon_name: "application-exit".to_string(),
            activate: Box::new(|tray: &mut Self| {
                let _ = tray.cmd_tx.send(TrayCommand::Quit);
            }),
            ..Default::default()
        }));

        items
    }
}

/// Shorten a path for display in the menu.
fn short_path(path: &str) -> String {
    if let Some(home) = dirs::home_dir() {
        let home_str = home.to_string_lossy();
        if let Some(rest) = path.strip_prefix(home_str.as_ref()) {
            return format!("~{rest}");
        }
    }
    // Show only last 2 components if path is long
    let parts: Vec<&str> = path.rsplitn(3, '/').collect();
    if parts.len() >= 3 {
        format!(".../{}/{}", parts[1], parts[0])
    } else {
        path.to_string()
    }
}

/// Return the base directory for the navra icon theme overlay.
fn icon_theme_dir() -> std::path::PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("navra/icons")
}

/// Install the navra icon into a hicolor theme directory so the tray
/// can reference it by name. Returns `true` if the icon was installed
/// (or already exists).
fn install_tray_icon() -> bool {
    let sizes = [(
        "64x64",
        include_bytes!("../../assets/logo/navra-icon-64.png").as_slice(),
    )];
    let base = icon_theme_dir();

    for (size, data) in &sizes {
        let dir = base.join(format!("hicolor/{size}/apps"));
        if let Err(e) = std::fs::create_dir_all(&dir) {
            tracing::debug!(error = %e, "Failed to create icon directory");
            return false;
        }
        let dest = dir.join("navra.png");
        if dest.exists() {
            continue;
        }
        if let Err(e) = std::fs::write(&dest, data) {
            tracing::debug!(error = %e, "Failed to write tray icon");
            return false;
        }
    }

    // Write a minimal index.theme so the icon resolver picks up the directory
    let index = base.join("hicolor/index.theme");
    if !index.exists() {
        let _ = std::fs::write(
            &index,
            "[Icon Theme]\nName=hicolor\nDirectories=64x64/apps\n\n[64x64/apps]\nSize=64\nType=Fixed\n",
        );
    }

    true
}

/// Spawn the tray icon and return a command receiver + handle for updates.
///
/// The tray runs on its own tokio task. The caller receives:
/// - `TrayCommand` receiver for menu actions (approve, deny, pause, quit)
/// - `ksni::Handle` to push state updates (pending approvals, agents)
pub async fn spawn_tray(
) -> anyhow::Result<(mpsc::UnboundedReceiver<TrayCommand>, ksni::Handle<McpdTray>)> {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

    let has_custom_icon = install_tray_icon();

    let tray = McpdTray {
        pending: Vec::new(),
        agents: Vec::new(),
        paused: false,
        cmd_tx,
        has_custom_icon,
    };

    let handle = tray
        .spawn()
        .await
        .map_err(|e| anyhow::anyhow!("Tray spawn failed: {e}"))?;

    Ok((cmd_rx, handle))
}

/// Background task: polls the approval store and updates the tray icon.
pub async fn run_tray_updater(
    handle: ksni::Handle<McpdTray>,
    approvals: Arc<ApprovalStore>,
    pause_flag: Arc<std::sync::atomic::AtomicBool>,
    mut cmd_rx: mpsc::UnboundedReceiver<TrayCommand>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Update pending approvals in the tray
                let pending_list: Vec<PendingItem> = approvals
                    .pending_requests()
                    .into_iter()
                    .map(|r| PendingItem {
                        id: r.id,
                        agent: r.agent_name,
                        operation: r.operation,
                        path: r.path,
                    })
                    .collect();

                let closed = handle.update(|tray| {
                    tray.pending = pending_list;
                }).await.is_none();

                if closed {
                    tracing::info!("Tray closed");
                    return;
                }
            }
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    TrayCommand::Approve(id) => {
                        tracing::info!(request_id = %id, "Tray: user approved");
                        approvals.approve(&id);
                    }
                    TrayCommand::Deny(id) => {
                        tracing::info!(request_id = %id, "Tray: user denied");
                        approvals.deny(&id);
                    }
                    TrayCommand::Pause => {
                        tracing::info!("Tray: server paused");
                        pause_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                        handle.update(|tray| tray.paused = true).await;
                    }
                    TrayCommand::Resume => {
                        tracing::info!("Tray: server resumed");
                        pause_flag.store(false, std::sync::atomic::Ordering::Relaxed);
                        handle.update(|tray| tray.paused = false).await;
                    }
                    TrayCommand::Quit => {
                        tracing::info!("Tray: quit requested");
                        handle.shutdown();
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_path_with_home() {
        // Can't test ~ expansion reliably, but test the fallback
        let short = short_path("/very/long/path/to/some/file.md");
        assert!(short.starts_with("..."));
        assert!(short.contains("file.md"));
    }

    #[test]
    fn short_path_already_short() {
        // Two components: just the filename
        assert_eq!(short_path("file.md"), "file.md");
    }

    #[test]
    fn tray_status_active_when_no_pending() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let tray = McpdTray {
            pending: Vec::new(),
            agents: Vec::new(),
            paused: false,
            cmd_tx: tx,
            has_custom_icon: false,
        };
        assert_eq!(tray.status(), Status::Active);
    }

    #[test]
    fn tray_status_attention_when_pending() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let tray = McpdTray {
            pending: vec![PendingItem {
                id: "1".to_string(),
                agent: "a".to_string(),
                operation: "write".to_string(),
                path: "/p".to_string(),
            }],
            agents: Vec::new(),
            paused: false,
            cmd_tx: tx,
            has_custom_icon: false,
        };
        assert_eq!(tray.status(), Status::NeedsAttention);
    }

    #[test]
    fn tray_status_passive_when_paused() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let tray = McpdTray {
            pending: Vec::new(),
            agents: Vec::new(),
            paused: true,
            cmd_tx: tx,
            has_custom_icon: false,
        };
        assert_eq!(tray.status(), Status::Passive);
    }

    #[test]
    fn tray_menu_has_quit() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let tray = McpdTray {
            pending: Vec::new(),
            agents: Vec::new(),
            paused: false,
            cmd_tx: tx,
            has_custom_icon: false,
        };
        let menu = tray.menu();
        let has_quit = menu
            .iter()
            .any(|item| matches!(item, MenuItem::Standard(s) if s.label == "Quit"));
        assert!(has_quit);
    }

    #[test]
    fn tray_menu_shows_pending_approvals() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let tray = McpdTray {
            pending: vec![PendingItem {
                id: "abc".to_string(),
                agent: "claude".to_string(),
                operation: "write".to_string(),
                path: "/home/user/doc.md".to_string(),
            }],
            agents: Vec::new(),
            paused: false,
            cmd_tx: tx,
            has_custom_icon: false,
        };
        let menu = tray.menu();
        let has_pending_header = menu.iter().any(
            |item| matches!(item, MenuItem::Standard(s) if s.label.contains("Pending Approvals")),
        );
        assert!(has_pending_header);
    }

    #[test]
    fn tray_menu_shows_agents() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let tray = McpdTray {
            pending: Vec::new(),
            agents: vec![AgentInfo {
                name: "claude-code".to_string(),
                permissions: "developer".to_string(),
            }],
            paused: false,
            cmd_tx: tx,
            has_custom_icon: false,
        };
        let menu = tray.menu();
        let has_agent = menu
            .iter()
            .any(|item| matches!(item, MenuItem::Standard(s) if s.label.contains("claude-code")));
        assert!(has_agent);
    }
}
