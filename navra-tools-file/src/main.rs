use std::sync::Arc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();

    let db_path = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("navra/file-index.db");
    let index = Arc::new(
        navra_tools_file::IndexStore::open(&db_path.to_string_lossy())
            .expect("failed to open index database"),
    );
    let perm = Arc::new(navra_core::permissions::PermissionEngine::new());
    let approvals = Arc::new(navra_core::permissions::ApprovalStore::new(3600));
    let notifier: Arc<dyn navra_core::notify::Notifier> = Arc::new(navra_core::notify::NoopNotifier);
    let module = navra_tools_file::FileModule::new(perm, index, approvals, notifier);
    navra_core::serve_module(module).await.unwrap();
}
