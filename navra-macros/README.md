# navra-macros

Proc macro crate for navra. Provides the `#[tool]` attribute macro
that generates `(ToolDefinition, ToolHandler)` pairs from annotated
async functions.

## Usage

```rust
use navra_macros::tool;

#[tool(name = "file_read", description = "Read a file from disk")]
async fn file_read(
    #[arg(description = "Path to the file")] path: String,
    #[arg(description = "Max lines to read", default = "100")] limit: Option<u32>,
    ctx: CallContext,
) -> CallToolResult {
    // implementation
}
```

This generates:

- A `ToolDefinition` with the name, description, and JSON Schema
  for the input parameters
- A `ToolHandler` closure that deserializes arguments, calls the
  function, and returns the result

## Parameter attributes

| Attribute | Description |
|---|---|
| `#[arg(description = "...")]` | Parameter description for the JSON Schema |
| `#[arg(default = "...")]` | Default value (makes the parameter optional) |

The last parameter must be `ctx: CallContext` and is not included
in the generated schema.

`Option<T>` parameters are automatically marked as optional in the
schema. `String`, `bool`, `u32`, `i64`, and `f64` are mapped to
their JSON Schema equivalents.

## Dependency layer

```
navra-macros (proc-macro, no navra deps)
```
