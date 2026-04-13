//! Error types from the Open Responses spec.

use serde::{Deserialize, Serialize};

/// Error returned in a response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResponseError {
    /// Error category.
    pub code: String,
    /// Human-readable description.
    pub message: String,
}

/// Error type categories.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorType {
    ServerError,
    InvalidRequest,
    NotFound,
    ModelError,
    TooManyRequests,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_roundtrip() {
        let err = ResponseError {
            code: "model_error".to_string(),
            message: "Context length exceeded".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let parsed: ResponseError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, parsed);
    }
}
