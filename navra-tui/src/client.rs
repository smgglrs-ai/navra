use anyhow::{Context, Result};
use reqwest::Client;

use crate::state::{
    AuditResponse, FlowInfo, FlowRunSummary, ModelInfo, SafetyMetrics, ServerStatus, SysStatus,
};

pub struct NavraClient {
    http: Client,
    base_url: String,
    token: Option<String>,
}

impl NavraClient {
    pub fn new(endpoint: &str, token: Option<String>) -> Result<Self> {
        let base_url = endpoint.trim_end_matches('/').to_string();
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self {
            http,
            base_url,
            token,
        })
    }

    fn request(&self, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.get(&url);
        if let Some(ref tok) = self.token {
            req = req.bearer_auth(tok);
        }
        req
    }

    pub async fn status(&self) -> Result<ServerStatus> {
        self.request("/api/status")
            .send()
            .await?
            .json()
            .await
            .context("failed to parse status")
    }

    pub async fn sys_status(&self) -> Result<SysStatus> {
        self.request("/sys/status")
            .send()
            .await?
            .json()
            .await
            .context("failed to parse sys status")
    }

    pub async fn models(&self) -> Result<Vec<ModelInfo>> {
        self.request("/api/models")
            .send()
            .await?
            .json()
            .await
            .context("failed to parse models")
    }

    pub async fn audit(&self, limit: usize) -> Result<AuditResponse> {
        self.request(&format!("/api/audit?limit={limit}"))
            .send()
            .await?
            .json()
            .await
            .context("failed to parse audit")
    }

    pub async fn flows(&self) -> Result<Vec<FlowInfo>> {
        self.request("/api/flows")
            .send()
            .await?
            .json()
            .await
            .context("failed to parse flows")
    }

    pub async fn flow_runs(&self) -> Result<Vec<FlowRunSummary>> {
        self.request("/api/flows/runs")
            .send()
            .await?
            .json()
            .await
            .context("failed to parse flow runs")
    }

    pub async fn safety_metrics(&self) -> Result<SafetyMetrics> {
        self.request("/api/safety/metrics")
            .send()
            .await?
            .json()
            .await
            .context("failed to parse safety metrics")
    }
}
