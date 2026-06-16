use std::sync::Arc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let perm = Arc::new(navra_mcp::permissions::PermissionEngine::new());
    let approvals = Arc::new(navra_mcp::permissions::ApprovalStore::new(3600));
    let notifier: Arc<dyn navra_core::notify::Notifier> =
        Arc::new(navra_core::notify::NoopNotifier);
    let module = navra_tools_git::GitModule::new(perm, approvals, notifier);
    navra_core::serve_module(module).await.unwrap();
}
