use crate::oauth::OAuthTokenManager;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION};

#[derive(Clone, Default)]
pub struct AuthConfig {
    pub bearer: Option<String>,
    pub api_key: Option<ApiKeyAuth>,
    pub basic: Option<BasicAuth>,
    pub oauth: Option<OAuthTokenManager>,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("bearer", &self.bearer.as_ref().map(|_| "[redacted]"))
            .field("api_key", &self.api_key)
            .field("basic", &self.basic.as_ref().map(|_| "[redacted]"))
            .field("oauth", &self.oauth.is_some())
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct ApiKeyAuth {
    pub name: String,
    pub value: String,
    pub location: ApiKeyLocation,
}

#[derive(Debug, Clone)]
pub enum ApiKeyLocation {
    Header,
    Query,
}

#[derive(Debug, Clone)]
pub struct BasicAuth {
    pub username: String,
    pub password: String,
}

impl AuthConfig {
    pub fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(ref token) = self.bearer
            && let Ok(val) = HeaderValue::from_str(&format!("Bearer {token}")) {
                headers.insert(AUTHORIZATION, val);
            }
        if let Some(ref api_key) = self.api_key
            && matches!(api_key.location, ApiKeyLocation::Header)
                && let (Ok(name), Ok(val)) = (
                    HeaderName::from_bytes(api_key.name.as_bytes()),
                    HeaderValue::from_str(&api_key.value),
                ) {
                    headers.insert(name, val);
                }
        if let Some(ref basic) = self.basic {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", basic.username, basic.password));
            if let Ok(val) = HeaderValue::from_str(&format!("Basic {encoded}")) {
                headers.insert(AUTHORIZATION, val);
            }
        }
        headers
    }

    pub async fn oauth_bearer(&self) -> Option<String> {
        if let Some(ref mgr) = self.oauth {
            match mgr.access_token().await {
                Ok(token) => Some(token),
                Err(e) => {
                    tracing::error!("OAuth token acquisition failed: {e}");
                    None
                }
            }
        } else {
            None
        }
    }

    pub async fn headers_with_oauth(&self) -> HeaderMap {
        let mut headers = self.headers();
        if let Some(token) = self.oauth_bearer().await
            && let Ok(val) = HeaderValue::from_str(&format!("Bearer {token}")) {
                headers.insert(AUTHORIZATION, val);
            }
        headers
    }

    pub fn query_params(&self) -> Vec<(String, String)> {
        let mut params = Vec::new();
        if let Some(ref api_key) = self.api_key
            && matches!(api_key.location, ApiKeyLocation::Query) {
                params.push((api_key.name.clone(), api_key.value.clone()));
            }
        params
    }
}
