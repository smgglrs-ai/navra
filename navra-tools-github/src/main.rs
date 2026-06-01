#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    navra_core::serve_module(navra_tools_github::GithubModule)
        .await
        .unwrap();
}
