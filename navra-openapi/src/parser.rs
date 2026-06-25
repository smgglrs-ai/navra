use anyhow::{Context, Result};
use navra_mcp::protocol::{ToolAnnotations, ToolDefinition};
use openapiv3::{
    OpenAPI, Operation, Parameter, ParameterSchemaOrContent, ReferenceOr, Schema, SchemaKind, Type,
};
use std::collections::HashMap;

/// HTTP method type (avoids external http crate dependency).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

impl Method {
    pub fn as_str(&self) -> &str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
            Method::Head => "HEAD",
            Method::Options => "OPTIONS",
        }
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct OperationMeta {
    pub method: Method,
    pub path: String,
    pub path_params: Vec<String>,
    pub query_params: Vec<String>,
    pub has_body: bool,
}

#[derive(Debug, Clone)]
pub struct ParsedOperation {
    pub definition: ToolDefinition,
    pub meta: OperationMeta,
}

pub fn parse_spec(json: &str) -> Result<OpenAPI> {
    serde_json::from_str(json).context("Failed to parse OpenAPI spec")
}

pub fn parse_spec_yaml(yaml: &str) -> Result<OpenAPI> {
    serde_yaml::from_str(yaml).context("Failed to parse OpenAPI YAML spec")
}

pub fn extract_base_url(spec: &OpenAPI) -> String {
    spec.servers
        .first()
        .map(|s| s.url.trim_end_matches('/').to_string())
        .unwrap_or_default()
}

pub fn generate_tools(
    spec: &OpenAPI,
    upstream_name: &str,
    filter: &[String],
) -> Vec<ParsedOperation> {
    let mut ops = Vec::new();

    for (path_str, path_item) in &spec.paths.paths {
        let item = match path_item {
            ReferenceOr::Item(item) => item,
            ReferenceOr::Reference { .. } => continue,
        };

        let path_params_from_path = collect_params(&item.parameters, "path", spec);
        let query_params_from_path = collect_params(&item.parameters, "query", spec);

        let methods: &[(Method, Option<&Operation>)] = &[
            (Method::Get, item.get.as_ref()),
            (Method::Post, item.post.as_ref()),
            (Method::Put, item.put.as_ref()),
            (Method::Patch, item.patch.as_ref()),
            (Method::Delete, item.delete.as_ref()),
        ];

        for (method, maybe_op) in methods {
            let op = match maybe_op {
                Some(op) => op,
                None => continue,
            };

            let operation_id = match &op.operation_id {
                Some(id) => id,
                None => {
                    tracing::warn!(
                        path = %path_str,
                        method = %method,
                        "Skipping operation without operationId"
                    );
                    continue;
                }
            };

            let tool_name = format!("{}_{}", upstream_name, sanitize_name(operation_id));

            if !filter.is_empty() && !matches_filter(&tool_name, operation_id, filter) {
                continue;
            }

            let mut path_params: Vec<String> = path_params_from_path.clone();
            let mut query_params: Vec<String> = query_params_from_path.clone();

            let op_path_params = collect_params(&op.parameters, "path", spec);
            let op_query_params = collect_params(&op.parameters, "query", spec);
            for p in &op_path_params {
                if !path_params.contains(p) {
                    path_params.push(p.clone());
                }
            }
            for q in &op_query_params {
                if !query_params.contains(q) {
                    query_params.push(q.clone());
                }
            }

            let has_body = op.request_body.is_some();

            let (properties, required) =
                build_input_schema(&path_params, &query_params, &op.parameters, op, spec);

            let description = op
                .summary
                .as_deref()
                .or(op.description.as_deref())
                .map(|s| s.to_string());

            let annotations = annotations_from_method(method);

            let definition = {
                let props = if properties.is_empty() {
                    None
                } else {
                    Some(properties)
                };
                let req = if required.is_empty() {
                    None
                } else {
                    Some(required)
                };
                let mut tool = ToolDefinition::new_with_raw(
                    tool_name,
                    description.map(std::borrow::Cow::Owned),
                    navra_protocol::compat::tool_input_schema(props, req),
                );
                tool.annotations = Some(annotations);
                tool
            };

            let meta = OperationMeta {
                method: method.clone(),
                path: path_str.clone(),
                path_params,
                query_params,
                has_body,
            };

            ops.push(ParsedOperation { definition, meta });
        }
    }

    ops
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .to_lowercase()
}

fn matches_filter(tool_name: &str, operation_id: &str, filter: &[String]) -> bool {
    filter.iter().any(|f| {
        if f.contains('*') {
            glob_match(f, tool_name) || glob_match(f, operation_id)
        } else {
            tool_name == f || operation_id == f
        }
    })
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match text[pos..].find(part) {
            Some(found) => {
                if i == 0 && found != 0 {
                    return false;
                }
                pos += found + part.len();
            }
            None => return false,
        }
    }
    if let Some(last) = parts.last() {
        if !last.is_empty() {
            return text.ends_with(last);
        }
    }
    true
}

fn annotations_from_method(method: &Method) -> ToolAnnotations {
    match method {
        Method::Get | Method::Head | Method::Options => {
            ToolAnnotations::from_raw(None, Some(true), Some(false), Some(true), Some(true))
        }
        Method::Put => {
            ToolAnnotations::from_raw(None, Some(false), Some(false), Some(true), Some(true))
        }
        Method::Post | Method::Patch => {
            ToolAnnotations::from_raw(None, Some(false), Some(false), Some(false), Some(true))
        }
        Method::Delete => {
            ToolAnnotations::from_raw(None, Some(false), Some(true), Some(true), Some(true))
        }
    }
}

fn collect_params(
    params: &[ReferenceOr<Parameter>],
    location: &str,
    spec: &OpenAPI,
) -> Vec<String> {
    params
        .iter()
        .filter_map(|p| resolve_param(p, spec))
        .filter(|p| param_location(p) == location)
        .map(|p| param_name(p).to_string())
        .collect()
}

fn resolve_param<'a>(p: &'a ReferenceOr<Parameter>, spec: &'a OpenAPI) -> Option<&'a Parameter> {
    match p {
        ReferenceOr::Item(param) => Some(param),
        ReferenceOr::Reference { reference } => {
            let name = reference.strip_prefix("#/components/parameters/")?;
            let components = spec.components.as_ref()?;
            match components.parameters.get(name)? {
                ReferenceOr::Item(param) => Some(param),
                _ => None,
            }
        }
    }
}

fn param_location(p: &Parameter) -> &str {
    match p {
        Parameter::Query { .. } => "query",
        Parameter::Header { .. } => "header",
        Parameter::Path { .. } => "path",
        Parameter::Cookie { .. } => "cookie",
    }
}

fn param_name(p: &Parameter) -> &str {
    match p {
        Parameter::Query { parameter_data, .. }
        | Parameter::Header { parameter_data, .. }
        | Parameter::Path { parameter_data, .. }
        | Parameter::Cookie { parameter_data, .. } => &parameter_data.name,
    }
}

fn param_required(p: &Parameter) -> bool {
    match p {
        Parameter::Path { .. } => true,
        Parameter::Query { parameter_data, .. }
        | Parameter::Header { parameter_data, .. }
        | Parameter::Cookie { parameter_data, .. } => parameter_data.required,
    }
}

fn param_description(p: &Parameter) -> Option<&str> {
    match p {
        Parameter::Query { parameter_data, .. }
        | Parameter::Header { parameter_data, .. }
        | Parameter::Path { parameter_data, .. }
        | Parameter::Cookie { parameter_data, .. } => parameter_data.description.as_deref(),
    }
}

fn param_schema(p: &Parameter) -> Option<&Schema> {
    let data = match p {
        Parameter::Query { parameter_data, .. }
        | Parameter::Header { parameter_data, .. }
        | Parameter::Path { parameter_data, .. }
        | Parameter::Cookie { parameter_data, .. } => parameter_data,
    };
    match &data.format {
        ParameterSchemaOrContent::Schema(ReferenceOr::Item(schema)) => Some(schema),
        _ => None,
    }
}

fn schema_to_json_type(schema: &Schema) -> serde_json::Value {
    match &schema.schema_kind {
        SchemaKind::Type(Type::String(_)) => serde_json::json!({"type": "string"}),
        SchemaKind::Type(Type::Integer(_)) => serde_json::json!({"type": "integer"}),
        SchemaKind::Type(Type::Number(_)) => serde_json::json!({"type": "number"}),
        SchemaKind::Type(Type::Boolean(_)) => serde_json::json!({"type": "boolean"}),
        SchemaKind::Type(Type::Array(_)) => serde_json::json!({"type": "array"}),
        SchemaKind::Type(Type::Object(_)) => serde_json::json!({"type": "object"}),
        _ => serde_json::json!({"type": "string"}),
    }
}

fn build_input_schema(
    path_params: &[String],
    query_params: &[String],
    op_params: &[ReferenceOr<Parameter>],
    op: &Operation,
    spec: &OpenAPI,
) -> (HashMap<String, serde_json::Value>, Vec<String>) {
    let mut properties = HashMap::new();
    let mut required = Vec::new();

    let all_params: Vec<&Parameter> = op_params
        .iter()
        .filter_map(|p| resolve_param(p, spec))
        .collect();

    for param in &all_params {
        let name = param_name(param);
        let loc = param_location(param);
        if loc != "path" && loc != "query" {
            continue;
        }

        let mut prop = if let Some(schema) = param_schema(param) {
            schema_to_json_type(schema)
        } else {
            serde_json::json!({"type": "string"})
        };

        if let Some(desc) = param_description(param) {
            prop.as_object_mut().unwrap().insert(
                "description".to_string(),
                serde_json::Value::String(desc.to_string()),
            );
        }

        properties.insert(name.to_string(), prop);

        if param_required(param) {
            required.push(name.to_string());
        }
    }

    // Also include path params not in op_params (from path-level params)
    for pp in path_params {
        if !properties.contains_key(pp) {
            properties.insert(
                pp.clone(),
                serde_json::json!({"type": "string", "description": format!("Path parameter: {pp}")}),
            );
            if !required.contains(pp) {
                required.push(pp.clone());
            }
        }
    }

    // Query params not in op_params
    for qp in query_params {
        if !properties.contains_key(qp) {
            properties.insert(
                qp.clone(),
                serde_json::json!({"type": "string", "description": format!("Query parameter: {qp}")}),
            );
        }
    }

    // Request body → "body" property
    if op.request_body.is_some() {
        properties.insert(
            "body".to_string(),
            serde_json::json!({
                "type": "object",
                "description": "Request body (JSON)"
            }),
        );
    }

    (properties, required)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn petstore_spec() -> &'static str {
        r#"{
            "openapi": "3.0.0",
            "info": { "title": "Petstore", "version": "1.0.0" },
            "servers": [{ "url": "https://petstore.example.com/v1" }],
            "paths": {
                "/pets": {
                    "get": {
                        "operationId": "listPets",
                        "summary": "List all pets",
                        "parameters": [
                            {
                                "name": "limit",
                                "in": "query",
                                "required": false,
                                "schema": { "type": "integer" }
                            }
                        ],
                        "responses": { "200": { "description": "OK" } }
                    },
                    "post": {
                        "operationId": "createPet",
                        "summary": "Create a pet",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": { "type": "object" }
                                }
                            }
                        },
                        "responses": { "201": { "description": "Created" } }
                    }
                },
                "/pets/{petId}": {
                    "get": {
                        "operationId": "getPetById",
                        "summary": "Get a pet by ID",
                        "parameters": [
                            {
                                "name": "petId",
                                "in": "path",
                                "required": true,
                                "schema": { "type": "string" }
                            }
                        ],
                        "responses": { "200": { "description": "OK" } }
                    },
                    "delete": {
                        "operationId": "deletePet",
                        "summary": "Delete a pet",
                        "parameters": [
                            {
                                "name": "petId",
                                "in": "path",
                                "required": true,
                                "schema": { "type": "string" }
                            }
                        ],
                        "responses": { "204": { "description": "Deleted" } }
                    }
                }
            }
        }"#
    }

    #[test]
    fn parse_petstore_spec() {
        let spec = parse_spec(petstore_spec()).unwrap();
        assert_eq!(spec.info.title, "Petstore");
        assert_eq!(spec.paths.paths.len(), 2);
    }

    #[test]
    fn extract_base_url_from_spec() {
        let spec = parse_spec(petstore_spec()).unwrap();
        assert_eq!(extract_base_url(&spec), "https://petstore.example.com/v1");
    }

    #[test]
    fn generate_all_tools() {
        let spec = parse_spec(petstore_spec()).unwrap();
        let tools = generate_tools(&spec, "petstore", &[]);
        assert_eq!(tools.len(), 4);
        let names: Vec<&str> = tools.iter().map(|t| &*t.definition.name).collect();
        assert!(names.contains(&"petstore_listpets"));
        assert!(names.contains(&"petstore_createpet"));
        assert!(names.contains(&"petstore_getpetbyid"));
        assert!(names.contains(&"petstore_deletepet"));
    }

    #[test]
    fn tool_name_prefixed_and_sanitized() {
        let spec = parse_spec(petstore_spec()).unwrap();
        let tools = generate_tools(&spec, "my_api", &[]);
        assert!(tools
            .iter()
            .all(|t| t.definition.name.starts_with("my_api_")));
    }

    #[test]
    fn get_method_annotated_read_only() {
        let spec = parse_spec(petstore_spec()).unwrap();
        let tools = generate_tools(&spec, "ps", &[]);
        let list_pets = tools
            .iter()
            .find(|t| t.definition.name == "ps_listpets")
            .unwrap();
        let ann = list_pets.definition.annotations.as_ref().unwrap();
        assert_eq!(ann.read_only_hint, Some(true));
        assert_eq!(ann.destructive_hint, Some(false));
        assert_eq!(ann.idempotent_hint, Some(true));
    }

    #[test]
    fn delete_method_annotated_destructive() {
        let spec = parse_spec(petstore_spec()).unwrap();
        let tools = generate_tools(&spec, "ps", &[]);
        let delete = tools
            .iter()
            .find(|t| t.definition.name == "ps_deletepet")
            .unwrap();
        let ann = delete.definition.annotations.as_ref().unwrap();
        assert_eq!(ann.read_only_hint, Some(false));
        assert_eq!(ann.destructive_hint, Some(true));
    }

    #[test]
    fn post_method_annotated_not_idempotent() {
        let spec = parse_spec(petstore_spec()).unwrap();
        let tools = generate_tools(&spec, "ps", &[]);
        let create = tools
            .iter()
            .find(|t| t.definition.name == "ps_createpet")
            .unwrap();
        let ann = create.definition.annotations.as_ref().unwrap();
        assert_eq!(ann.idempotent_hint, Some(false));
    }

    #[test]
    fn path_params_are_required() {
        let spec = parse_spec(petstore_spec()).unwrap();
        let tools = generate_tools(&spec, "ps", &[]);
        let get_by_id = tools
            .iter()
            .find(|t| t.definition.name == "ps_getpetbyid")
            .unwrap();
        let required: Vec<String> = serde_json::from_value(
            get_by_id
                .definition
                .input_schema
                .get("required")
                .cloned()
                .unwrap(),
        )
        .unwrap();
        assert!(required.contains(&"petId".to_string()));
    }

    #[test]
    fn query_params_are_optional() {
        let spec = parse_spec(petstore_spec()).unwrap();
        let tools = generate_tools(&spec, "ps", &[]);
        let list = tools
            .iter()
            .find(|t| t.definition.name == "ps_listpets")
            .unwrap();
        let props = list
            .definition
            .input_schema
            .get("properties")
            .and_then(|v| v.as_object())
            .unwrap();
        assert!(props.contains_key("limit"));
        let required: Vec<String> = list
            .definition
            .input_schema
            .get("required")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        assert!(!required.contains(&"limit".to_string()));
    }

    #[test]
    fn post_has_body_property() {
        let spec = parse_spec(petstore_spec()).unwrap();
        let tools = generate_tools(&spec, "ps", &[]);
        let create = tools
            .iter()
            .find(|t| t.definition.name == "ps_createpet")
            .unwrap();
        let props = create
            .definition
            .input_schema
            .get("properties")
            .and_then(|v| v.as_object())
            .unwrap();
        assert!(props.contains_key("body"));
        assert!(create.meta.has_body);
    }

    #[test]
    fn filter_by_operation_id() {
        let spec = parse_spec(petstore_spec()).unwrap();
        let tools = generate_tools(&spec, "ps", &["listPets".to_string()]);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].definition.name, "ps_listpets");
    }

    #[test]
    fn filter_by_tool_name() {
        let spec = parse_spec(petstore_spec()).unwrap();
        let tools = generate_tools(&spec, "ps", &["ps_deletepet".to_string()]);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].definition.name, "ps_deletepet");
    }

    #[test]
    fn filter_with_glob() {
        let spec = parse_spec(petstore_spec()).unwrap();
        let tools = generate_tools(&spec, "ps", &["ps_*pet".to_string()]);
        let names: Vec<&str> = tools.iter().map(|t| &*t.definition.name).collect();
        assert!(names.contains(&"ps_createpet"));
        assert!(names.contains(&"ps_deletepet"));
        assert!(!names.contains(&"ps_listpets"));
    }

    #[test]
    fn empty_filter_includes_all() {
        let spec = parse_spec(petstore_spec()).unwrap();
        let tools = generate_tools(&spec, "ps", &[]);
        assert_eq!(tools.len(), 4);
    }

    #[test]
    fn operation_meta_method() {
        let spec = parse_spec(petstore_spec()).unwrap();
        let tools = generate_tools(&spec, "ps", &[]);
        let list = tools
            .iter()
            .find(|t| t.definition.name == "ps_listpets")
            .unwrap();
        assert_eq!(list.meta.method, Method::Get);
        let create = tools
            .iter()
            .find(|t| t.definition.name == "ps_createpet")
            .unwrap();
        assert_eq!(create.meta.method, Method::Post);
    }

    #[test]
    fn operation_meta_path() {
        let spec = parse_spec(petstore_spec()).unwrap();
        let tools = generate_tools(&spec, "ps", &[]);
        let get_by_id = tools
            .iter()
            .find(|t| t.definition.name == "ps_getpetbyid")
            .unwrap();
        assert_eq!(get_by_id.meta.path, "/pets/{petId}");
        assert!(get_by_id.meta.path_params.contains(&"petId".to_string()));
    }

    #[test]
    fn description_from_summary() {
        let spec = parse_spec(petstore_spec()).unwrap();
        let tools = generate_tools(&spec, "ps", &[]);
        let list = tools
            .iter()
            .find(|t| t.definition.name == "ps_listpets")
            .unwrap();
        assert_eq!(
            list.definition.description.as_deref(),
            Some("List all pets")
        );
    }

    #[test]
    fn skip_operations_without_operation_id() {
        let json = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0.0" },
            "paths": {
                "/ping": {
                    "get": {
                        "summary": "No operation ID",
                        "responses": { "200": { "description": "OK" } }
                    }
                }
            }
        }"#;
        let spec = parse_spec(json).unwrap();
        let tools = generate_tools(&spec, "t", &[]);
        assert!(tools.is_empty());
    }

    #[test]
    fn sanitize_name_special_chars() {
        assert_eq!(sanitize_name("get-pet-by-id"), "get_pet_by_id");
        assert_eq!(sanitize_name("GET.Pet.By.ID"), "get_pet_by_id");
        assert_eq!(sanitize_name("normal_name"), "normal_name");
    }

    #[test]
    fn base_url_trailing_slash_stripped() {
        let json = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0.0" },
            "servers": [{ "url": "https://api.example.com/v1/" }],
            "paths": {}
        }"#;
        let spec = parse_spec(json).unwrap();
        assert_eq!(extract_base_url(&spec), "https://api.example.com/v1");
    }

    #[test]
    fn no_servers_returns_empty_base_url() {
        let json = r#"{
            "openapi": "3.0.0",
            "info": { "title": "Test", "version": "1.0.0" },
            "paths": {}
        }"#;
        let spec = parse_spec(json).unwrap();
        assert_eq!(extract_base_url(&spec), "");
    }
}
