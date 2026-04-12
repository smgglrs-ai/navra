//! Flow execution engine with handoff-based multi-agent routing.

use crate::definition::FlowDefinition;
use crate::error::FlowError;
use crate::handoff::{handoff_tool_def, parse_handoff, routing_instructions, HANDOFF_TOOL_NAME};
use myelix_agent::{extract_text, Agent};
use myelix_model::{
    ChatMessage, ChatRequest, ChatResponse, FinishReason, Locality, OpenAiBackend, ToolChoice,
};
use myelix_protocol::label::DataLabel;
use myelix_security::ifc::TaintTracker;
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

        Ok(Flow {
            name: config.name,
            entry: config.entry,
            max_hops: config.max_hops,
            nodes,
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

            let result = run_node_loop(node, &current_prompt).await?;

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

/// Run a single node's agent loop with handoff interception.
///
/// This is the per-node ReAct loop. It calls the model, executes real
/// MCP tool calls, and intercepts `handoff` calls to return control
/// to the outer flow loop.
async fn run_node_loop(node: &mut FlowNode, user_prompt: &str) -> Result<NodeResult, FlowError> {
    let node_id = "node"; // for error context

    // Get MCP tools + inject virtual handoff tool
    let mut tools = node
        .agent
        .client()
        .chat_tools()
        .await
        .map_err(|e| FlowError::Agent {
            node: node_id.into(),
            source: e,
        })?;
    if node.has_edges {
        tools.push(handoff_tool_def());
    }

    let mut messages = Vec::new();
    messages.push(ChatMessage::system(&node.effective_prompt));
    messages.push(ChatMessage::user(user_prompt));

    let mut total_prompt = 0u32;
    let mut total_completion = 0u32;

    for _iteration in 0..node.max_iterations {
        let request = ChatRequest {
            messages: messages.clone(),
            tools: tools.clone(),
            tool_choice: Some(ToolChoice::Auto),
            temperature: node.temperature,
            max_tokens: node.max_tokens,
        };

        let response: ChatResponse =
            node.agent
                .model()
                .chat(&request)
                .await
                .map_err(|e| FlowError::Agent {
                    node: node_id.into(),
                    source: e.into(),
                })?;

        total_prompt += response.prompt_tokens.unwrap_or(0);
        total_completion += response.completion_tokens.unwrap_or(0);

        match response.finish_reason {
            FinishReason::Stop | FinishReason::Length => {
                return Ok(NodeResult {
                    outcome: NodeOutcome::Stop(
                        response.message.content.unwrap_or_default(),
                    ),
                    prompt_tokens: total_prompt,
                    completion_tokens: total_completion,
                    taint: node.agent.taint(),
                });
            }
            FinishReason::ToolCalls => {
                let tool_calls = response.message.tool_calls.clone();
                messages.push(ChatMessage::assistant_tool_calls(tool_calls.clone()));

                for tc in &tool_calls {
                    if tc.function.name == HANDOFF_TOOL_NAME {
                        let handoff = parse_handoff(&tc.function.arguments)?;
                        return Ok(NodeResult {
                            outcome: NodeOutcome::Handoff {
                                target: handoff.target,
                                task: handoff.task,
                            },
                            prompt_tokens: total_prompt,
                            completion_tokens: total_completion,
                            taint: node.agent.taint(),
                        });
                    }

                    // Regular MCP tool call
                    let args: serde_json::Value =
                        serde_json::from_str(&tc.function.arguments)
                            .unwrap_or(serde_json::json!({}));

                    tracing::debug!(
                        tool = %tc.function.name,
                        "Flow node executing tool"
                    );

                    let result = node
                        .agent
                        .client()
                        .call_tool(&tc.function.name, args)
                        .await
                        .map_err(|e| FlowError::Agent {
                            node: node_id.into(),
                            source: e,
                        })?;
                    let text = extract_text(&result);
                    messages.push(ChatMessage::tool_result(&tc.id, text));
                }
            }
        }
    }

    Err(FlowError::Agent {
        node: node_id.into(),
        source: myelix_agent::AgentError::MaxIterations(node.max_iterations),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use myelix_model::{
        ChatRequest, ChatResponse, FunctionCall, ModelBackend, ModelError, ToolCall,
    };
    use myelix_protocol::upstream::{Transport, UpstreamError};
    use myelix_protocol::Upstream;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    /// Mock model returning scripted responses.
    struct MockModel {
        responses: Mutex<Vec<ChatResponse>>,
    }

    impl MockModel {
        fn new(responses: Vec<ChatResponse>) -> Self {
            Self {
                responses: Mutex::new(responses),
            }
        }
    }

    impl ModelBackend for MockModel {
        fn chat(
            &self,
            _req: &ChatRequest,
        ) -> Pin<Box<dyn Future<Output = Result<ChatResponse, ModelError>> + Send + '_>> {
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
        model_responses: Vec<ChatResponse>,
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
            .unwrap()
    }

    fn stop_response(text: &str) -> ChatResponse {
        ChatResponse {
            message: ChatMessage::assistant(text),
            finish_reason: FinishReason::Stop,
            prompt_tokens: Some(10),
            completion_tokens: Some(5),
        }
    }

    fn handoff_response(target: &str, task: &str) -> ChatResponse {
        ChatResponse {
            message: ChatMessage::assistant_tool_calls(vec![ToolCall {
                id: "call_handoff".to_string(),
                call_type: "function".to_string(),
                function: FunctionCall {
                    name: HANDOFF_TOOL_NAME.to_string(),
                    arguments: serde_json::json!({
                        "target": target,
                        "task": task
                    })
                    .to_string(),
                },
            }]),
            finish_reason: FinishReason::ToolCalls,
            prompt_tokens: Some(10),
            completion_tokens: Some(5),
        }
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
        model_responses: Vec<ChatResponse>,
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
}
