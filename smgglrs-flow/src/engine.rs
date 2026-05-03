//! Flow execution engine with handoff-based multi-agent routing.

use crate::blackboard::Blackboard;
use crate::definition::FlowDefinition;
use crate::error::FlowError;
use crate::handoff::{handoff_tool_def, parse_handoff, routing_instructions, HANDOFF_TOOL_NAME};
use crate::mailbox::MailboxRegistry;
use crate::mesh_tools::{
    self, bb_keys_tool_def, bb_publish_tool_def, bb_read_tool_def, mesh_post_tool_def,
    mesh_recv_tool_def,
};
use smgglrs_agent::{extract_text, Agent};
use smgglrs_model::{
    CreateResponseRequest, FunctionCallItem, FunctionCallOutputItem, FunctionCallOutputContent,
    InputItem, ItemStatus, Locality, ModelResponse, OpenAiBackend,
    OutputItem, ResponseTool, ResponseToolChoice,
};
use smgglrs_protocol::label::DataLabel;
use smgglrs_security::ifc::TaintTracker;
use std::collections::HashMap;

/// A node in the flow graph, wrapping an agent.
pub struct FlowNode {
    pub(crate) agent: Agent,
    /// System prompt augmented with routing instructions.
    pub(crate) effective_prompt: String,
    /// Whether this node has outgoing edges (determines if handoff tool is injected).
    pub(crate) has_edges: bool,
    /// Max tool-use iterations per hop.
    pub(crate) max_iterations: usize,
    /// Temperature for model calls.
    pub(crate) temperature: Option<f32>,
    /// Max tokens per model response.
    pub(crate) max_tokens: Option<u32>,
}

/// Result of a completed flow execution.
#[derive(Debug)]
pub struct FlowResult {
    /// Final response text from the terminal node.
    pub response: String,
    /// Number of handoff hops taken.
    pub hops: usize,
    /// Total prompt tokens consumed across all nodes.
    pub prompt_tokens: u32,
    /// Total completion tokens consumed across all nodes.
    pub completion_tokens: u32,
    /// Accumulated taint from all nodes.
    pub taint: DataLabel,
    /// Sequence of node IDs visited.
    pub path: Vec<String>,
}

/// Outcome of running a single node's agent loop.
enum NodeOutcome {
    /// The agent completed with a final response.
    Stop(String),
    /// The agent requested a handoff to another node.
    Handoff { target: String, task: String },
}

/// Result from a single node's execution.
struct NodeResult {
    outcome: NodeOutcome,
    prompt_tokens: u32,
    completion_tokens: u32,
    taint: DataLabel,
}

/// A multi-agent flow with handoff-based routing.
pub struct Flow {
    pub(crate) name: String,
    pub(crate) entry: String,
    pub(crate) max_hops: usize,
    pub(crate) nodes: HashMap<String, FlowNode>,
    pub(crate) mailbox_registry: Option<MailboxRegistry>,
    pub(crate) blackboard: Option<Blackboard>,
}

impl Flow {
    /// Create a new [`FlowBuilder`](crate::FlowBuilder).
    pub fn builder(name: impl Into<String>) -> crate::FlowBuilder {
        crate::FlowBuilder::new(name)
    }

    /// Construct a flow from a parsed TOML definition.
    ///
    /// Creates an [`Agent`] per node, connecting to the specified
    /// MCP endpoints and model backends.
    pub async fn from_definition(def: FlowDefinition) -> Result<Self, FlowError> {
        let config = def.flow;

        if !config.nodes.iter().any(|n| n.id == config.entry) {
            return Err(FlowError::NoEntry);
        }

        // Index edges by source
        let mut edges_map: HashMap<String, Vec<crate::definition::EdgeDefinition>> =
            HashMap::new();
        for edge in &config.edges {
            edges_map
                .entry(edge.from.clone())
                .or_default()
                .push(edge.clone());
        }

        let mut nodes = HashMap::new();
        for node_def in &config.nodes {
            let model = OpenAiBackend::new(
                &node_def.model_url,
                &node_def.model_name,
                node_def.api_key.clone(),
                Locality::Local,
            );

            let agent = Agent::builder()
                .endpoint(&node_def.endpoint)
                .await
                .map_err(|e| FlowError::Agent {
                    node: node_def.id.clone(),
                    source: e,
                })?
                .model(model)
                .max_iterations(node_def.max_iterations)
                .build()
                .await
                .map_err(|e| FlowError::Agent {
                    node: node_def.id.clone(),
                    source: e,
                })?;

            let outgoing = edges_map
                .get(&node_def.id)
                .map(|e| e.as_slice())
                .unwrap_or(&[]);
            let has_edges = !outgoing.is_empty();
            let effective_prompt = format!(
                "{}{}",
                node_def.system_prompt,
                routing_instructions(outgoing),
            );

            nodes.insert(
                node_def.id.clone(),
                FlowNode {
                    agent,
                    effective_prompt,
                    has_edges,
                    max_iterations: node_def.max_iterations,
                    temperature: node_def.temperature,
                    max_tokens: node_def.max_tokens,
                },
            );
        }

        let node_ids: Vec<String> = nodes.keys().cloned().collect();

        let mailbox_registry = config.mailbox_capacity.map(|cap| {
            MailboxRegistry::new(&node_ids, cap)
        });

        let blackboard = config.blackboard_capacity.map(Blackboard::new);

        Ok(Flow {
            name: config.name,
            entry: config.entry,
            max_hops: config.max_hops,
            nodes,
            mailbox_registry,
            blackboard,
        })
    }

    /// Construct a flow from a TOML string.
    pub async fn from_toml(toml_str: &str) -> Result<Self, FlowError> {
        let def: FlowDefinition = toml::from_str(toml_str)?;
        Self::from_definition(def).await
    }

    /// Execute the flow, starting at the entry node.
    pub async fn run(&mut self, prompt: &str) -> Result<FlowResult, FlowError> {
        let mut current_node_id = self.entry.clone();
        let mut current_prompt = prompt.to_string();
        let mut taint = TaintTracker::new();
        let mut total_prompt = 0u32;
        let mut total_completion = 0u32;
        let mut path = Vec::new();

        for hop in 0..self.max_hops {
            path.push(current_node_id.clone());

            let node = self
                .nodes
                .get_mut(&current_node_id)
                .ok_or_else(|| FlowError::UnknownTarget(current_node_id.clone()))?;

            tracing::info!(
                flow = %self.name,
                node = %current_node_id,
                hop = hop,
                "Running flow node"
            );

            let result = run_node_loop(
                node,
                &current_node_id,
                &current_prompt,
                self.mailbox_registry.as_ref(),
                self.blackboard.as_ref(),
            )
            .await?;

            total_prompt += result.prompt_tokens;
            total_completion += result.completion_tokens;
            taint.absorb(result.taint);

            match result.outcome {
                NodeOutcome::Stop(response) => {
                    return Ok(FlowResult {
                        response,
                        hops: hop + 1,
                        prompt_tokens: total_prompt,
                        completion_tokens: total_completion,
                        taint: taint.level(),
                        path,
                    });
                }
                NodeOutcome::Handoff { target, task } => {
                    if !self.nodes.contains_key(&target) {
                        return Err(FlowError::UnknownTarget(target));
                    }
                    tracing::info!(
                        from = %current_node_id,
                        to = %target,
                        "Handoff"
                    );
                    current_node_id = target;
                    current_prompt = task;
                }
            }
        }

        Err(FlowError::MaxHops(self.max_hops))
    }

    /// Flow name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Run a single node's agent loop with handoff and mesh tool interception.
///
/// This is the per-node ReAct loop. It calls the model, executes real
/// MCP tool calls, and intercepts `handoff` and mesh tool calls to
/// handle them internally.
async fn run_node_loop(
    node: &mut FlowNode,
    node_id: &str,
    user_prompt: &str,
    mailbox: Option<&MailboxRegistry>,
    blackboard: Option<&Blackboard>,
) -> Result<NodeResult, FlowError> {
    // Get MCP tools + inject virtual tools
    let mcp_tools = node
        .agent
        .client()
        .list_tools()
        .await
        .map_err(|e| FlowError::Agent {
            node: node_id.into(),
            source: e,
        })?;
    let mut tools: Vec<ResponseTool> = mcp_tools
        .iter()
        .map(|t| ResponseTool {
            kind: "function".to_string(),
            name: t.name.clone(),
            description: t.description.clone(),
            parameters: Some(serde_json::json!({
                "type": t.input_schema.schema_type,
                "properties": t.input_schema.properties,
                "required": t.input_schema.required,
            })),
            strict: None,
        })
        .collect();
    if node.has_edges {
        tools.push(handoff_tool_def());
    }
    // Inject mesh tools when mailbox/blackboard are enabled
    if mailbox.is_some() {
        tools.push(mesh_post_tool_def());
        tools.push(mesh_recv_tool_def());
    }
    if blackboard.is_some() {
        tools.push(bb_publish_tool_def());
        tools.push(bb_read_tool_def());
        tools.push(bb_keys_tool_def());
    }

    let mut input: Vec<InputItem> = Vec::new();
    input.push(InputItem::system(&node.effective_prompt));
    input.push(InputItem::user(user_prompt));

    let mut total_input = 0u32;
    let mut total_output = 0u32;
    // Local taint tracker for blackboard reads within this node
    let mut local_taint = TaintTracker::new();

    for _iteration in 0..node.max_iterations {
        let request = CreateResponseRequest {
            model: String::new(),
            input: input.clone(),
            tools: tools.clone(),
            tool_choice: Some(ResponseToolChoice::auto()),
            temperature: node.temperature,
            max_output_tokens: node.max_tokens,
            ..CreateResponseRequest::new(String::new(), vec![])
        };

        let response: ModelResponse =
            node.agent
                .model()
                .respond(&request)
                .await
                .map_err(|e| FlowError::Agent {
                    node: node_id.into(),
                    source: e.into(),
                })?;

        if let Some(ref usage) = response.usage {
            total_input += usage.input_tokens;
            total_output += usage.output_tokens;
        }

        // Check for function calls
        let function_calls: Vec<&FunctionCallItem> = response
            .output
            .iter()
            .filter_map(|item| match item {
                OutputItem::FunctionCall(fc) => Some(fc),
                _ => None,
            })
            .collect();

        if function_calls.is_empty() {
            // Text response — done
            let text = response.text().unwrap_or_default();
            return Ok(NodeResult {
                outcome: NodeOutcome::Stop(text),
                prompt_tokens: total_input,
                completion_tokens: total_output,
                taint: node.agent.taint().join(local_taint.level()),
            });
        }

        // Process function calls
        for fc in &function_calls {
            if fc.name == HANDOFF_TOOL_NAME {
                let handoff = parse_handoff(&fc.arguments)?;
                return Ok(NodeResult {
                    outcome: NodeOutcome::Handoff {
                        target: handoff.target,
                        task: handoff.task,
                    },
                    prompt_tokens: total_input,
                    completion_tokens: total_output,
                    taint: node.agent.taint().join(local_taint.level()),
                });
            }

            // Add function call to input
            input.push(InputItem::FunctionCall(FunctionCallItem {
                id: fc.id.clone(),
                call_id: fc.call_id.clone(),
                name: fc.name.clone(),
                arguments: fc.arguments.clone(),
                status: Some(ItemStatus::Completed),
            }));

            // Intercept mesh tools before falling through to MCP
            let tool_output = match fc.name.as_str() {
                mesh_tools::MESH_POST => {
                    let (target, message) = mesh_tools::parse_mesh_post(&fc.arguments)?;
                    if let Some(reg) = mailbox {
                        let label = node.agent.taint().join(local_taint.level());
                        match reg.post(node_id, label, &target, message) {
                            Ok(()) => "Message delivered.".to_string(),
                            Err(e) => format!("Error: {e}"),
                        }
                    } else {
                        "Error: mailbox not enabled for this flow.".to_string()
                    }
                }
                mesh_tools::MESH_RECV => {
                    if let Some(reg) = mailbox {
                        let msgs = reg.recv_all(node_id);
                        let json_msgs: Vec<serde_json::Value> = msgs
                            .iter()
                            .map(|m| {
                                serde_json::json!({
                                    "sender": m.sender,
                                    "body": m.body,
                                })
                            })
                            .collect();
                        serde_json::to_string(&json_msgs).unwrap_or_else(|e| {
                            tracing::warn!(error = %e, "Failed to serialize mailbox messages");
                            "[]".to_string()
                        })
                    } else {
                        "Error: mailbox not enabled for this flow.".to_string()
                    }
                }
                mesh_tools::BB_PUBLISH => {
                    let (key, value) = mesh_tools::parse_bb_publish(&fc.arguments)?;
                    if let Some(bb) = blackboard {
                        let label = node.agent.taint().join(local_taint.level());
                        match bb.publish(node_id, &key, value, label) {
                            Ok(version) => format!("Published key '{}' (version {}).", key, version),
                            Err(e) => format!("Error: {e}"),
                        }
                    } else {
                        "Error: blackboard not enabled for this flow.".to_string()
                    }
                }
                mesh_tools::BB_READ => {
                    let key = mesh_tools::parse_bb_read(&fc.arguments)?;
                    if let Some(bb) = blackboard {
                        match bb.read(&key, &mut local_taint) {
                            Ok(entry) => serde_json::json!({
                                "key": entry.key,
                                "value": entry.value,
                                "author": entry.author,
                                "version": entry.version,
                            })
                            .to_string(),
                            Err(e) => format!("Error: {e}"),
                        }
                    } else {
                        "Error: blackboard not enabled for this flow.".to_string()
                    }
                }
                mesh_tools::BB_KEYS => {
                    if let Some(bb) = blackboard {
                        serde_json::to_string(&bb.keys())
                            .unwrap_or_else(|e| {
                                tracing::warn!(error = %e, "Failed to serialize blackboard keys");
                                "[]".to_string()
                            })
                    } else {
                        "Error: blackboard not enabled for this flow.".to_string()
                    }
                }
                _ => {
                    // Fall through to MCP tool call
                    let args: serde_json::Value = serde_json::from_str(&fc.arguments)
                        .unwrap_or_else(|e| {
                            tracing::warn!(tool = %fc.name, error = %e, "Failed to parse tool arguments as JSON");
                            serde_json::json!({})
                        });

                    tracing::debug!(tool = %fc.name, "Flow node executing tool");

                    let result = node
                        .agent
                        .client()
                        .call_tool(&fc.name, args)
                        .await
                        .map_err(|e| FlowError::Agent {
                            node: node_id.into(),
                            source: e,
                        })?;
                    extract_text(&result)
                }
            };

            input.push(InputItem::FunctionCallOutput(FunctionCallOutputItem {
                id: None,
                call_id: fc.call_id.clone(),
                output: FunctionCallOutputContent::Text(tool_output),
                status: Some(ItemStatus::Completed),
            }));
        }
    }

    Err(FlowError::Agent {
        node: node_id.into(),
        source: smgglrs_agent::AgentError::MaxIterations(node.max_iterations),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use smgglrs_model::{
        CreateResponseRequest, ModelBackend, ModelError, ModelResponse,
        FunctionCallItem, ItemStatus, MessageItem, OutputItem, ResponseStatus,
    };
    use smgglrs_protocol::upstream::{Transport, UpstreamError};
    use smgglrs_protocol::Upstream;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    struct MockModel {
        responses: Mutex<Vec<ModelResponse>>,
    }

    impl MockModel {
        fn new(responses: Vec<ModelResponse>) -> Self {
            Self {
                responses: Mutex::new(responses),
            }
        }
    }

    impl ModelBackend for MockModel {
        fn respond(
            &self,
            _req: &CreateResponseRequest,
        ) -> Pin<Box<dyn Future<Output = Result<ModelResponse, ModelError>> + Send + '_>> {
            let response = {
                let mut responses = self.responses.lock().unwrap();
                if responses.is_empty() {
                    return Box::pin(async {
                        Err(ModelError::Inference("no more responses".into()))
                    });
                }
                responses.remove(0)
            };
            Box::pin(async move { Ok(response) })
        }
    }

    struct MockTransport {
        responses: Mutex<Vec<serde_json::Value>>,
    }

    impl MockTransport {
        fn new(responses: Vec<serde_json::Value>) -> Self {
            Self {
                responses: Mutex::new(responses),
            }
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn request(
            &mut self,
            _body: serde_json::Value,
        ) -> Result<serde_json::Value, UpstreamError> {
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                Ok(serde_json::json!({"jsonrpc": "2.0", "result": {}, "id": 1}))
            } else {
                Ok(responses.remove(0))
            }
        }

        fn shutdown(&mut self) {}
    }

    fn init_responses() -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({
                "jsonrpc": "2.0",
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "serverInfo": {"name": "test", "version": "0.1.0"}
                },
                "id": 1
            }),
            serde_json::json!({"jsonrpc": "2.0", "result": {}, "id": 2}),
        ]
    }

    async fn mock_agent(
        model_responses: Vec<ModelResponse>,
        tool_responses: Vec<serde_json::Value>,
    ) -> Agent {
        let mut transport_responses = init_responses();
        // list_tools response
        transport_responses.push(serde_json::json!({
            "jsonrpc": "2.0",
            "result": {"tools": []},
            "id": 3
        }));
        transport_responses.extend(tool_responses);

        let transport = MockTransport::new(transport_responses);
        let upstream = Upstream::connect("test", transport).await.unwrap();
        let model = MockModel::new(model_responses);

        Agent::builder()
            .upstream(upstream)
            .model(model)
            .build()
            .await
            .unwrap()
    }

    fn make_response(output: Vec<OutputItem>) -> ModelResponse {
        use smgglrs_responses::response::Usage;
        ModelResponse {
            id: "resp_test".into(),
            object: "response".into(),
            created_at: None, completed_at: None,
            status: ResponseStatus::Completed,
            model: Some("test".into()),
            output,
            usage: Some(Usage {
                input_tokens: 10, output_tokens: 5, total_tokens: 15,
                input_tokens_details: None, output_tokens_details: None,
            }),
            error: None, previous_response_id: None, instructions: None,
            tools: vec![], tool_choice: None, text: None, reasoning: None,
            truncation: None, temperature: None, max_output_tokens: None,
            metadata: Default::default(), incomplete_details: None, extra: Default::default(),
        }
    }

    fn stop_response(text: &str) -> ModelResponse {
        make_response(vec![OutputItem::Message(MessageItem::assistant(text))])
    }

    fn handoff_response(target: &str, task: &str) -> ModelResponse {
        make_response(vec![OutputItem::FunctionCall(FunctionCallItem {
            id: Some("call_handoff".into()),
            call_id: "call_handoff".into(),
            name: HANDOFF_TOOL_NAME.to_string(),
            arguments: serde_json::json!({
                "target": target,
                "task": task
            }).to_string(),
            status: Some(ItemStatus::Completed),
        })])
    }

    #[tokio::test]
    async fn single_node_stop() {
        let agent = mock_agent(vec![stop_response("Done!")], vec![]).await;

        let mut flow = Flow::builder("test")
            .entry("main")
            .node("main", agent, "You are helpful.")
            .build()
            .unwrap();

        let result = flow.run("Hello").await.unwrap();
        assert_eq!(result.response, "Done!");
        assert_eq!(result.hops, 1);
        assert_eq!(result.path, vec!["main"]);
        assert_eq!(result.prompt_tokens, 10);
        assert_eq!(result.completion_tokens, 5);
    }

    #[tokio::test]
    async fn two_node_handoff() {
        let router = mock_agent(
            vec![handoff_response("coder", "Write fizzbuzz")],
            vec![],
        )
        .await;
        let coder = mock_agent(vec![stop_response("def fizzbuzz()...")], vec![]).await;

        let mut flow = Flow::builder("test")
            .entry("router")
            .node("router", router, "You are a router.")
            .node("coder", coder, "You are a coder.")
            .edge("router", "coder", "Coding tasks")
            .build()
            .unwrap();

        let result = flow.run("Write fizzbuzz").await.unwrap();
        assert_eq!(result.response, "def fizzbuzz()...");
        assert_eq!(result.hops, 2);
        assert_eq!(result.path, vec!["router", "coder"]);
        assert_eq!(result.prompt_tokens, 20);
        assert_eq!(result.completion_tokens, 10);
    }

    async fn mock_agent_multi(
        model_responses: Vec<ModelResponse>,
        visits: usize,
    ) -> Agent {
        let mut transport_responses = init_responses();
        // Add list_tools responses for each visit
        for _ in 0..visits {
            transport_responses.push(serde_json::json!({
                "jsonrpc": "2.0",
                "result": {"tools": []},
                "id": 3
            }));
        }

        let transport = MockTransport::new(transport_responses);
        let upstream = Upstream::connect("test", transport).await.unwrap();
        let model = MockModel::new(model_responses);

        Agent::builder()
            .upstream(upstream)
            .model(model)
            .build()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn max_hops_exceeded() {
        // Two nodes that keep handing off to each other.
        // With max_hops=3, we need: a(visit1)→b(visit1)→a(visit2)→exceeds.
        // Node a is visited twice, node b once.
        let a = mock_agent_multi(
            vec![
                handoff_response("b", "task"),
                handoff_response("b", "task"),
            ],
            2,
        )
        .await;
        let b = mock_agent_multi(
            vec![handoff_response("a", "task")],
            1,
        )
        .await;

        let mut flow = Flow::builder("loop")
            .entry("a")
            .node("a", a, "")
            .node("b", b, "")
            .edge("a", "b", "go to b")
            .edge("b", "a", "go to a")
            .max_hops(3)
            .build()
            .unwrap();

        let err = flow.run("start").await.unwrap_err();
        assert!(matches!(err, FlowError::MaxHops(3)));
    }

    #[tokio::test]
    async fn unknown_handoff_target() {
        let agent = mock_agent(
            vec![handoff_response("nonexistent", "task")],
            vec![],
        )
        .await;

        let mut flow = Flow::builder("test")
            .entry("main")
            .node("main", agent, "")
            .edge("main", "main", "self") // edge exists but handoff targets "nonexistent"
            .build()
            .unwrap();

        let err = flow.run("go").await.unwrap_err();
        assert!(matches!(err, FlowError::UnknownTarget(_)));
    }

    // ── Integration tests: mesh tools through the flow engine ──

    fn tool_call_response(tool_name: &str, args: serde_json::Value) -> ModelResponse {
        make_response(vec![OutputItem::FunctionCall(FunctionCallItem {
            id: Some(format!("call_{tool_name}")),
            call_id: format!("call_{tool_name}"),
            name: tool_name.to_string(),
            arguments: args.to_string(),
            status: Some(ItemStatus::Completed),
        })])
    }

    #[tokio::test]
    async fn mailbox_post_and_recv_through_flow() {
        // Agent "sender" calls mesh_post to "receiver", then hands off.
        // Agent "receiver" calls mesh_recv, then stops with the messages.
        let sender = mock_agent_multi(
            vec![
                // First: call mesh_post
                tool_call_response(
                    "mesh_post",
                    serde_json::json!({"target": "receiver", "message": "hello from sender"}),
                ),
                // Second: handoff to receiver
                handoff_response("receiver", "Check your mailbox"),
            ],
            1,
        )
        .await;

        let receiver = mock_agent_multi(
            vec![
                // First: call mesh_recv
                tool_call_response("mesh_recv", serde_json::json!({})),
                // Second: stop with confirmation
                stop_response("Got it!"),
            ],
            1,
        )
        .await;

        let mut flow = Flow::builder("mail_test")
            .entry("sender")
            .node("sender", sender, "You send messages.")
            .node("receiver", receiver, "You receive messages.")
            .edge("sender", "receiver", "Forward to receiver")
            .enable_mailbox(16)
            .build()
            .unwrap();

        let result = flow.run("Send a message").await.unwrap();
        assert_eq!(result.response, "Got it!");
        assert_eq!(result.hops, 2);
        assert_eq!(result.path, vec!["sender", "receiver"]);

        // Verify audit log recorded the delivery
        let audit = flow.mailbox_registry.as_ref().unwrap().audit_log();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].sender, "sender");
        assert_eq!(audit[0].body, "hello from sender");
    }

    #[tokio::test]
    async fn blackboard_publish_and_read_through_flow() {
        // Agent "writer" publishes to blackboard, hands off to "reader".
        // Agent "reader" reads from blackboard, then stops.
        let writer = mock_agent_multi(
            vec![
                tool_call_response(
                    "bb_publish",
                    serde_json::json!({"key": "analysis", "value": {"score": 95}}),
                ),
                handoff_response("reader", "Read the analysis"),
            ],
            1,
        )
        .await;

        let reader = mock_agent_multi(
            vec![
                tool_call_response("bb_read", serde_json::json!({"key": "analysis"})),
                stop_response("Read the analysis."),
            ],
            1,
        )
        .await;

        let mut flow = Flow::builder("bb_test")
            .entry("writer")
            .node("writer", writer, "You write data.")
            .node("reader", reader, "You read data.")
            .edge("writer", "reader", "Forward to reader")
            .enable_blackboard(64)
            .build()
            .unwrap();

        let result = flow.run("Analyze").await.unwrap();
        assert_eq!(result.response, "Read the analysis.");
        assert_eq!(result.hops, 2);

        // Verify blackboard has the published entry
        let bb = flow.blackboard.as_ref().unwrap();
        let snap = bb.snapshot();
        assert_eq!(snap.len(), 1);
        assert!(snap.contains_key("analysis"));
        assert_eq!(snap["analysis"].value["score"], 95);
        assert_eq!(snap["analysis"].author, "writer");
    }

    #[tokio::test]
    async fn blackboard_keys_through_flow() {
        // Agent publishes two keys, then calls bb_keys, then stops.
        let agent = mock_agent_multi(
            vec![
                tool_call_response(
                    "bb_publish",
                    serde_json::json!({"key": "alpha", "value": 1}),
                ),
                tool_call_response(
                    "bb_publish",
                    serde_json::json!({"key": "beta", "value": 2}),
                ),
                tool_call_response("bb_keys", serde_json::json!({})),
                stop_response("Done listing."),
            ],
            1,
        )
        .await;

        let mut flow = Flow::builder("keys_test")
            .entry("main")
            .node("main", agent, "")
            .enable_blackboard(64)
            .build()
            .unwrap();

        let result = flow.run("List keys").await.unwrap();
        assert_eq!(result.response, "Done listing.");

        let bb = flow.blackboard.as_ref().unwrap();
        let mut keys = bb.keys();
        keys.sort();
        assert_eq!(keys, vec!["alpha", "beta"]);
    }

}
