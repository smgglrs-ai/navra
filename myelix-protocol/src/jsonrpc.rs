use serde::{Deserialize, Serialize};

/// JSON-RPC 2.0 request identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    Number(i64),
    String(String),
}

/// JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    pub id: RequestId,
}

/// JSON-RPC 2.0 notification (no id).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: RequestId,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<ErrorData>,
}

/// Opaque error data attached to a JSON-RPC error.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ErrorData {
    Value(serde_json::Value),
}

/// Standard JSON-RPC 2.0 error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    InternalError,
    Custom(i32),
}

impl ErrorCode {
    pub fn code(self) -> i32 {
        match self {
            Self::ParseError => -32700,
            Self::InvalidRequest => -32600,
            Self::MethodNotFound => -32601,
            Self::InvalidParams => -32602,
            Self::InternalError => -32603,
            Self::Custom(c) => c,
        }
    }

    pub fn from_code(code: i32) -> Self {
        match code {
            -32700 => Self::ParseError,
            -32600 => Self::InvalidRequest,
            -32601 => Self::MethodNotFound,
            -32602 => Self::InvalidParams,
            -32603 => Self::InternalError,
            c => Self::Custom(c),
        }
    }
}

impl JsonRpcError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code.code(),
            message: message.into(),
            data: None,
        }
    }

    pub fn parse_error() -> Self {
        Self::new(ErrorCode::ParseError, "Parse error")
    }

    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequest, msg)
    }

    pub fn method_not_found(method: &str) -> Self {
        Self::new(
            ErrorCode::MethodNotFound,
            format!("Method not found: {method}"),
        )
    }

    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidParams, msg)
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(ErrorCode::InternalError, msg)
    }
}

impl JsonRpcRequest {
    pub fn new(method: impl Into<String>, params: Option<serde_json::Value>, id: RequestId) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.into(),
            params,
            id,
        }
    }
}

impl JsonRpcResponse {
    pub fn success(id: RequestId, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn error(id: RequestId, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(error),
            id,
        }
    }
}

/// A batch request is an array of individual requests and/or notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BatchRequest {
    Single(JsonRpcRequest),
    Batch(Vec<serde_json::Value>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_request() {
        let req = JsonRpcRequest::new(
            "initialize",
            Some(serde_json::json!({"protocolVersion": "2025-03-26"})),
            RequestId::Number(1),
        );
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["method"], "initialize");
        assert_eq!(json["id"], 1);
    }

    #[test]
    fn deserialize_request_string_id() {
        let json = r#"{"jsonrpc":"2.0","method":"tools/list","id":"abc-123"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, RequestId::String("abc-123".to_string()));
        assert!(req.params.is_none());
    }

    #[test]
    fn serialize_success_response() {
        let resp = JsonRpcResponse::success(
            RequestId::Number(1),
            serde_json::json!({"tools": []}),
        );
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["result"]["tools"], serde_json::json!([]));
        assert!(json.get("error").is_none());
    }

    #[test]
    fn serialize_error_response() {
        let resp = JsonRpcResponse::error(
            RequestId::Number(1),
            JsonRpcError::method_not_found("foo/bar"),
        );
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["error"]["code"], -32601);
        assert!(json["error"]["message"].as_str().unwrap().contains("foo/bar"));
        assert!(json.get("result").is_none());
    }

    #[test]
    fn error_code_roundtrip() {
        for code in [
            ErrorCode::ParseError,
            ErrorCode::InvalidRequest,
            ErrorCode::MethodNotFound,
            ErrorCode::InvalidParams,
            ErrorCode::InternalError,
            ErrorCode::Custom(-32000),
        ] {
            assert_eq!(ErrorCode::from_code(code.code()), code);
        }
    }

    #[test]
    fn deserialize_notification() {
        let json = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let notif: JsonRpcNotification = serde_json::from_str(json).unwrap();
        assert_eq!(notif.method, "notifications/initialized");
    }
}
