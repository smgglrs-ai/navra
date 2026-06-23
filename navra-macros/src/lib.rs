//! Proc macros for navra tool definitions.
//!
//! Provides `#[tool]` which transforms an async function into a
//! `(ToolDefinition, ToolHandler)` pair with auto-generated JSON Schema.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    FnArg, Ident, ItemFn, LitStr, Pat, Token, Type,
};

/// Attribute macro that transforms an async function into a
/// `(ToolDefinition, ToolHandler)` pair for navra modules.
///
/// # Usage
///
/// ```text
/// #[tool(
///     name = "file_read",
///     description = "Read a file from disk",
/// )]
/// async fn file_read(
///     #[arg(description = "Path to the file")] path: String,
///     #[arg(description = "Max lines", default = "100")] limit: Option<u32>,
///     ctx: CallContext,
/// ) -> CallToolResult {
///     // ...
/// }
/// ```
///
/// This generates:
/// - `fn file_read_tool_def() -> ToolDefinition` returning the schema
/// - `fn file_read_handler() -> (ToolDefinition, ToolHandler)` returning
///   the definition paired with an `Arc`-wrapped handler closure
/// - The original async function is preserved unchanged
#[proc_macro_attribute]
pub fn tool(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attrs = parse_macro_input!(attr as ToolAttrs);
    let func = parse_macro_input!(item as ItemFn);

    match expand_tool(attrs, &func) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

// --- Attribute parsing ---

struct ToolAttrs {
    name: String,
    description: String,
}

impl Parse for ToolAttrs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut name = None;
        let mut description = None;

        let pairs = Punctuated::<MetaKeyValue, Token![,]>::parse_terminated(input)?;
        for pair in pairs {
            match pair.key.to_string().as_str() {
                "name" => name = Some(pair.value),
                "description" => description = Some(pair.value),
                other => {
                    return Err(syn::Error::new_spanned(
                        pair.key,
                        format!("unknown attribute `{other}`, expected `name` or `description`"),
                    ))
                }
            }
        }

        let name = name.ok_or_else(|| input.error("missing `name` attribute"))?;
        let description =
            description.ok_or_else(|| input.error("missing `description` attribute"))?;

        Ok(ToolAttrs { name, description })
    }
}

struct MetaKeyValue {
    key: Ident,
    value: String,
}

impl Parse for MetaKeyValue {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let key: Ident = input.parse()?;
        let _: Token![=] = input.parse()?;
        let value: LitStr = input.parse()?;
        Ok(MetaKeyValue {
            key,
            value: value.value(),
        })
    }
}

// --- Argument metadata extracted from function params ---

struct ArgInfo {
    name: String,
    json_name: Option<String>,
    ty: Type,
    description: Option<String>,
    default: Option<String>,
    is_option: bool,
    is_context: bool,
    is_state: bool,
}

impl ArgInfo {
    fn field_name(&self) -> &str {
        self.json_name.as_deref().unwrap_or(&self.name)
    }
}

fn extract_args(func: &ItemFn) -> syn::Result<Vec<ArgInfo>> {
    let mut args = Vec::new();

    for input in &func.sig.inputs {
        let FnArg::Typed(pat_type) = input else {
            return Err(syn::Error::new_spanned(input, "expected typed argument"));
        };

        let Pat::Ident(pat_ident) = &*pat_type.pat else {
            return Err(syn::Error::new_spanned(
                &pat_type.pat,
                "expected simple identifier pattern",
            ));
        };

        let arg_name = pat_ident.ident.to_string();
        let ty = (*pat_type.ty).clone();

        // Check if this is a CallContext parameter (by type name)
        let is_context = is_call_context_type(&ty);

        // Parse #[arg(...)] and #[state] attributes
        let mut description = None;
        let mut default = None;
        let mut json_name = None;
        let mut is_state = false;

        for attr in &pat_type.attrs {
            if attr.path().is_ident("state") {
                is_state = true;
            } else if attr.path().is_ident("arg") {
                let nested =
                    attr.parse_args_with(Punctuated::<MetaKeyValue, Token![,]>::parse_terminated)?;
                for kv in nested {
                    match kv.key.to_string().as_str() {
                        "description" => description = Some(kv.value),
                        "default" => default = Some(kv.value),
                        "name" => json_name = Some(kv.value),
                        other => {
                            return Err(syn::Error::new_spanned(
                                kv.key,
                                format!("unknown arg attribute `{other}`"),
                            ))
                        }
                    }
                }
            }
        }

        let is_option = is_option_type(&ty);

        args.push(ArgInfo {
            name: arg_name,
            json_name,
            ty,
            description,
            default,
            is_option,
            is_context,
            is_state,
        });
    }

    Ok(args)
}

/// Check whether a type path ends with `CallContext`.
fn is_call_context_type(ty: &Type) -> bool {
    if let Type::Path(tp) = ty {
        if let Some(seg) = tp.path.segments.last() {
            return seg.ident == "CallContext";
        }
    }
    false
}

/// Check whether a type is `Option<T>`.
fn is_option_type(ty: &Type) -> bool {
    if let Type::Path(tp) = ty {
        if let Some(seg) = tp.path.segments.last() {
            return seg.ident == "Option";
        }
    }
    false
}

/// Map a Rust type to a JSON Schema `{"type": ...}` value (as tokens).
fn type_to_json_schema(ty: &Type) -> TokenStream2 {
    // For Option<T>, unwrap the inner type
    if let Type::Path(tp) = ty {
        if let Some(seg) = tp.path.segments.last() {
            let ident_str = seg.ident.to_string();

            match ident_str.as_str() {
                "String" | "str" => {
                    return quote! { "string" };
                }
                "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "i8" | "i16" | "i32" | "i64"
                | "i128" | "isize" => {
                    return quote! { "integer" };
                }
                "f32" | "f64" => {
                    return quote! { "number" };
                }
                "bool" => {
                    return quote! { "boolean" };
                }
                "Option" => {
                    // Unwrap inner type
                    if let syn::PathArguments::AngleBracketed(ab) = &seg.arguments {
                        if let Some(syn::GenericArgument::Type(inner)) = ab.args.first() {
                            return type_to_json_schema(inner);
                        }
                    }
                }
                "Vec" => {
                    return quote! { "array" };
                }
                "HashMap" | "BTreeMap" => {
                    return quote! { "object" };
                }
                _ => {}
            }
        }
    }
    // Fallback to string
    quote! { "string" }
}

/// Build a full JSON schema value for a property, including description.
fn build_property_schema(
    ty: &Type,
    description: &Option<String>,
    default: &Option<String>,
) -> TokenStream2 {
    let is_vec = matches!(ty, Type::Path(tp)
        if tp.path.segments.last().map(|s| s.ident == "Vec").unwrap_or(false));
    let is_option = is_option_type(ty);

    // For Vec<T>, build array schema with items
    if is_vec {
        if let Type::Path(tp) = ty {
            if let Some(seg) = tp.path.segments.last() {
                if let syn::PathArguments::AngleBracketed(ab) = &seg.arguments {
                    if let Some(syn::GenericArgument::Type(inner)) = ab.args.first() {
                        let inner_type = type_to_json_schema(inner);
                        let desc_field = description.as_ref().map(|d| {
                            quote! { schema.insert("description".to_string(), serde_json::json!(#d)); }
                        });
                        return quote! {{
                            let mut schema = serde_json::Map::new();
                            schema.insert("type".to_string(), serde_json::Value::String("array".to_string()));
                            schema.insert("items".to_string(), serde_json::json!({"type": #inner_type}));
                            #desc_field
                            serde_json::Value::Object(schema)
                        }};
                    }
                }
            }
        }
    }

    // For Option<T>, unwrap to inner type schema
    let effective_ty = if is_option {
        if let Type::Path(tp) = ty {
            if let Some(seg) = tp.path.segments.last() {
                if let syn::PathArguments::AngleBracketed(ab) = &seg.arguments {
                    if let Some(syn::GenericArgument::Type(inner)) = ab.args.first() {
                        inner
                    } else {
                        ty
                    }
                } else {
                    ty
                }
            } else {
                ty
            }
        } else {
            ty
        }
    } else {
        ty
    };

    let effective_type_str = type_to_json_schema(effective_ty);

    let desc_field = description.as_ref().map(|d| {
        quote! { schema.insert("description".to_string(), serde_json::json!(#d)); }
    });

    let default_field = default.as_ref().map(|d| {
        // Try to parse as a number or bool, otherwise use as string
        quote! {
            schema.insert("default".to_string(), {
                let s = #d;
                if let Ok(n) = s.parse::<i64>() {
                    serde_json::Value::Number(n.into())
                } else if let Ok(n) = s.parse::<f64>() {
                    serde_json::json!(n)
                } else if let Ok(b) = s.parse::<bool>() {
                    serde_json::Value::Bool(b)
                } else {
                    serde_json::Value::String(s.to_string())
                }
            });
        }
    });

    quote! {{
        let mut schema = serde_json::Map::new();
        schema.insert("type".to_string(), serde_json::Value::String(#effective_type_str.to_string()));
        #desc_field
        #default_field
        serde_json::Value::Object(schema)
    }}
}

// --- Main expansion ---

fn expand_tool(attrs: ToolAttrs, func: &ItemFn) -> syn::Result<TokenStream2> {
    let func_name = &func.sig.ident;
    let tool_def_fn = format_ident!("{}_tool_def", func_name);
    let handler_fn = format_ident!("{}_handler", func_name);
    let vis = &func.vis;

    let tool_name = &attrs.name;
    let tool_desc = &attrs.description;

    let args = extract_args(func)?;

    // Separate tool args from context/state (only tool args go in schema)
    let tool_args: Vec<&ArgInfo> = args
        .iter()
        .filter(|a| !a.is_context && !a.is_state)
        .collect();
    let state_args: Vec<&ArgInfo> = args.iter().filter(|a| a.is_state).collect();

    // Build properties map entries
    let property_inserts: Vec<TokenStream2> = tool_args
        .iter()
        .map(|arg| {
            let name = arg.field_name();
            let schema = build_property_schema(&arg.ty, &arg.description, &arg.default);
            quote! {
                properties.insert(#name.to_string(), #schema);
            }
        })
        .collect();

    // Build required list (non-optional args)
    let required_names: Vec<&str> = tool_args
        .iter()
        .filter(|a| !a.is_option && a.default.is_none())
        .map(|a| a.field_name())
        .collect();

    let required_tokens = if required_names.is_empty() {
        quote! { None }
    } else {
        quote! { Some(vec![#(#required_names.to_string()),*]) }
    };

    // State clones run in the Fn closure body (before the async block)
    // so the captured state can be cloned on each invocation.
    let state_clones: Vec<TokenStream2> = args
        .iter()
        .filter(|a| a.is_state)
        .map(|arg| {
            let ident = format_ident!("{}", &arg.name);
            quote! { let #ident = #ident.clone(); }
        })
        .collect();

    // Arg extractions run inside the async block
    let arg_extractions: Vec<TokenStream2> = args
        .iter()
        .filter(|a| !a.is_state)
        .map(|arg| {
            let ident = format_ident!("{}", &arg.name);

            if arg.is_context {
                return quote! { let #ident = ctx.clone(); };
            }

            let field = arg.field_name();
            let ty = &arg.ty;

            if arg.is_option {
                if let Some(ref default_val) = arg.default {
                    let inner_ty = unwrap_option_inner(ty);
                    let default_expr = parse_default(default_val, &inner_ty);
                    quote! {
                        let #ident: #ty = args.get(#field)
                            .and_then(|v| serde_json::from_value(v.clone()).ok())
                            .or_else(|| Some(#default_expr));
                    }
                } else {
                    quote! {
                        let #ident: #ty = args.get(#field)
                            .and_then(|v| serde_json::from_value(v.clone()).ok());
                    }
                }
            } else {
                quote! {
                    let #ident: #ty = match args.get(#field)
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                    {
                        Some(v) => v,
                        None => return {
                            use navra_protocol::compat::CallToolResultExt;
                            navra_protocol::CallToolResult::error_msg(
                                format!("Missing required parameter: {}", #field)
                            )
                        },
                    };
                }
            }
        })
        .collect();

    // Build call arguments
    let call_args: Vec<TokenStream2> = args
        .iter()
        .map(|arg| {
            let ident = format_ident!("{}", &arg.name);
            quote! { #ident }
        })
        .collect();

    // Build state parameter list for _handler() signature
    let state_params: Vec<TokenStream2> = state_args
        .iter()
        .map(|arg| {
            let ident = format_ident!("{}", &arg.name);
            let ty = &arg.ty;
            quote! { #ident: #ty }
        })
        .collect();

    // Strip #[arg(...)] and #[state] attributes from the original function
    let mut clean_func = func.clone();
    for input in &mut clean_func.sig.inputs {
        if let FnArg::Typed(pat_type) = input {
            pat_type
                .attrs
                .retain(|attr| !attr.path().is_ident("arg") && !attr.path().is_ident("state"));
        }
    }

    Ok(quote! {
        #clean_func

        #vis fn #tool_def_fn() -> navra_protocol::ToolDefinition {
            let mut properties = std::collections::HashMap::new();
            #(#property_inserts)*

            navra_protocol::ToolDefinition::new(
                #tool_name,
                #tool_desc,
                navra_protocol::compat::tool_input_schema(
                    if properties.is_empty() { None } else { Some(properties) },
                    #required_tokens,
                ),
            )
        }

        #vis fn #handler_fn(#(#state_params),*) -> (navra_protocol::ToolDefinition, std::sync::Arc<
            dyn Fn(serde_json::Value, navra_mcp::auth::CallContext)
                -> std::pin::Pin<Box<dyn std::future::Future<Output = navra_protocol::CallToolResult> + Send>>
                + Send + Sync
        >) {
            let handler: std::sync::Arc<
                dyn Fn(serde_json::Value, navra_mcp::auth::CallContext)
                    -> std::pin::Pin<Box<dyn std::future::Future<Output = navra_protocol::CallToolResult> + Send>>
                    + Send + Sync
            > = std::sync::Arc::new(move |args: serde_json::Value, ctx: navra_mcp::auth::CallContext| {
                #(#state_clones)*
                Box::pin(async move {
                    #(#arg_extractions)*
                    #func_name(#(#call_args),*).await
                })
            });
            (#tool_def_fn(), handler)
        }
    })
}

/// Unwrap Option<T> to get T. Returns the original type if not Option.
fn unwrap_option_inner(ty: &Type) -> Type {
    if let Type::Path(tp) = ty {
        if let Some(seg) = tp.path.segments.last() {
            if seg.ident == "Option" {
                if let syn::PathArguments::AngleBracketed(ab) = &seg.arguments {
                    if let Some(syn::GenericArgument::Type(inner)) = ab.args.first() {
                        return inner.clone();
                    }
                }
            }
        }
    }
    ty.clone()
}

/// Parse a default value string into a token expression for a given type.
fn parse_default(val: &str, _ty: &Type) -> TokenStream2 {
    if let Ok(n) = val.parse::<i64>() {
        return quote! { #n as _ };
    }
    if let Ok(b) = val.parse::<bool>() {
        return quote! { #b };
    }
    // Fall back to string
    quote! { #val.to_string() }
}
