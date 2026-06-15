use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION};

#[derive(Debug, Clone, Default)]
pub struct AuthConfig {
    pub bearer: Option<String>,
    pub api_key: Option<ApiKeyAuth>,
    pub basic: Option<BasicAuth>,
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
        if let Some(ref token) = self.bearer {
            if let Ok(val) = HeaderValue::from_str(&format!("Bearer {token}")) {
                headers.insert(AUTHORIZATION, val);
            }
        }
        if let Some(ref api_key) = self.api_key {
            if matches!(api_key.location, ApiKeyLocation::Header) {
                if let (Ok(name), Ok(val)) = (
                    HeaderName::from_bytes(api_key.name.as_bytes()),
                    HeaderValue::from_str(&api_key.value),
                ) {
                    headers.insert(name, val);
                }
            }
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

    pub fn query_params(&self) -> Vec<(String, String)> {
        let mut params = Vec::new();
        if let Some(ref api_key) = self.api_key {
            if matches!(api_key.location, ApiKeyLocation::Query) {
                params.push((api_key.name.clone(), api_key.value.clone()));
            }
        }
        params
    }
}
