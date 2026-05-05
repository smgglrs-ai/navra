use smgglrs_macros::smgglrs_tool;
use smgglrs_protocol::{CallToolResult, Content, TextContent};
use smgglrs_security::auth::CallContext;

// --- Basic tool: single required arg ---

#[smgglrs_tool(
    name = "test_echo",
    description = "Echo a message back",
)]
async fn test_echo(
    #[arg(description = "Message to echo")] message: String,
    ctx: CallContext,
) -> CallToolResult {
    let _ = ctx;
    CallToolResult {
        content: vec![Content::Text(TextContent {
            text: message,
        })],
        is_error: false,
        label: Default::default(),
    }
}

#[test]
fn tool_def_has_correct_name() {
    let def = test_echo_tool_def();
    assert_eq!(def.name, "test_echo");
}

#[test]
fn tool_def_has_description() {
    let def = test_echo_tool_def();
    assert_eq!(def.description.as_deref(), Some("Echo a message back"));
}

#[test]
fn tool_def_has_required_field() {
    let def = test_echo_tool_def();
    let required = def.input_schema.required.as_ref().unwrap();
    assert_eq!(required, &["message"]);
}

#[test]
fn tool_def_has_message_property() {
    let def = test_echo_tool_def();
    let props = def.input_schema.properties.as_ref().unwrap();
    let msg_schema = props.get("message").unwrap();
    assert_eq!(msg_schema["type"], "string");
    assert_eq!(msg_schema["description"], "Message to echo");
}

// --- Tool with optional args and defaults ---

#[smgglrs_tool(
    name = "test_search",
    description = "Search with limit",
)]
async fn test_search(
    #[arg(description = "Search query")] query: String,
    #[arg(description = "Max results", default = "10")] limit: Option<u32>,
    ctx: CallContext,
) -> CallToolResult {
    let _ = (query, limit, ctx);
    CallToolResult {
        content: vec![],
        is_error: false,
        label: Default::default(),
    }
}

#[test]
fn optional_arg_not_required() {
    let def = test_search_tool_def();
    let required = def.input_schema.required.as_ref().unwrap();
    assert!(required.contains(&"query".to_string()));
    assert!(!required.contains(&"limit".to_string()));
}

#[test]
fn optional_arg_has_default_in_schema() {
    let def = test_search_tool_def();
    let props = def.input_schema.properties.as_ref().unwrap();
    let limit_schema = props.get("limit").unwrap();
    assert_eq!(limit_schema["type"], "integer");
    assert_eq!(limit_schema["default"], 10);
}

// --- Tool with multiple types ---

#[smgglrs_tool(
    name = "test_types",
    description = "Test type mapping",
)]
async fn test_types(
    #[arg(description = "A string")] name: String,
    #[arg(description = "An integer")] count: u64,
    #[arg(description = "A float")] ratio: f64,
    #[arg(description = "A bool")] verbose: bool,
    #[arg(description = "A list")] tags: Vec<String>,
    ctx: CallContext,
) -> CallToolResult {
    let _ = (name, count, ratio, verbose, tags, ctx);
    CallToolResult {
        content: vec![],
        is_error: false,
        label: Default::default(),
    }
}

#[test]
fn type_mapping_string() {
    let def = test_types_tool_def();
    let props = def.input_schema.properties.as_ref().unwrap();
    assert_eq!(props["name"]["type"], "string");
}

#[test]
fn type_mapping_integer() {
    let def = test_types_tool_def();
    let props = def.input_schema.properties.as_ref().unwrap();
    assert_eq!(props["count"]["type"], "integer");
}

#[test]
fn type_mapping_number() {
    let def = test_types_tool_def();
    let props = def.input_schema.properties.as_ref().unwrap();
    assert_eq!(props["ratio"]["type"], "number");
}

#[test]
fn type_mapping_boolean() {
    let def = test_types_tool_def();
    let props = def.input_schema.properties.as_ref().unwrap();
    assert_eq!(props["verbose"]["type"], "boolean");
}

#[test]
fn type_mapping_array() {
    let def = test_types_tool_def();
    let props = def.input_schema.properties.as_ref().unwrap();
    assert_eq!(props["tags"]["type"], "array");
    assert_eq!(props["tags"]["items"]["type"], "string");
}

#[test]
fn all_non_option_args_required() {
    let def = test_types_tool_def();
    let required = def.input_schema.required.as_ref().unwrap();
    assert!(required.contains(&"name".to_string()));
    assert!(required.contains(&"count".to_string()));
    assert!(required.contains(&"ratio".to_string()));
    assert!(required.contains(&"verbose".to_string()));
    assert!(required.contains(&"tags".to_string()));
}

// --- Handler returns valid pair ---

#[test]
fn handler_returns_def_and_handler() {
    let (def, _handler) = test_echo_handler();
    assert_eq!(def.name, "test_echo");
}

#[tokio::test]
async fn handler_can_be_called() {
    let (_, handler) = test_echo_handler();
    let args = serde_json::json!({"message": "hello"});
    let ctx = CallContext::new(
        smgglrs_security::auth::AgentIdentity {
            name: "test".to_string(),
            permissions: "admin".to_string(),
            signing_key: None,
            did: None,
            capabilities: None,
        },
        "test-session",
    );
    let result = handler(args, ctx).await;
    assert!(!result.is_error);
    match &result.content[0] {
        Content::Text(t) => assert_eq!(t.text, "hello"),
        _ => panic!("expected text content"),
    }
}

// --- Tool with no args (besides context) ---

#[smgglrs_tool(
    name = "test_noop",
    description = "A tool with no arguments",
)]
async fn test_noop(ctx: CallContext) -> CallToolResult {
    let _ = ctx;
    CallToolResult {
        content: vec![],
        is_error: false,
        label: Default::default(),
    }
}

#[test]
fn no_args_tool_has_no_properties() {
    let def = test_noop_tool_def();
    assert!(def.input_schema.properties.is_none());
    assert!(def.input_schema.required.is_none());
}
