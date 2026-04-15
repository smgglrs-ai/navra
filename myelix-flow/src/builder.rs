//! Programmatic flow construction via builder pattern.

use crate::blackboard::Blackboard;
use crate::definition::EdgeDefinition;
use crate::engine::{Flow, FlowNode};
use crate::error::FlowError;
use crate::handoff::routing_instructions;
use crate::mailbox::MailboxRegistry;
use myelix_agent::Agent;
use std::collections::HashMap;

/// Builder for constructing a [`Flow`] programmatically.
pub struct FlowBuilder {
    name: String,
    entry: Option<String>,
    max_hops: usize,
    nodes: Vec<(String, Agent, String)>, // (id, agent, system_prompt)
    edges: Vec<EdgeDefinition>,
    mailbox_capacity: Option<usize>,
    blackboard_capacity: Option<usize>,
}

impl FlowBuilder {
    /// Create a new flow builder with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            entry: None,
            max_hops: 10,
            nodes: Vec::new(),
            edges: Vec::new(),
            mailbox_capacity: None,
            blackboard_capacity: None,
        }
    }

    /// Set the entry node ID (where execution starts).
    pub fn entry(mut self, node_id: impl Into<String>) -> Self {
        self.entry = Some(node_id.into());
        self
    }

    /// Set the maximum number of handoff hops (default: 10).
    pub fn max_hops(mut self, n: usize) -> Self {
        self.max_hops = n;
        self
    }

    /// Add an agent node.
    pub fn node(
        mut self,
        id: impl Into<String>,
        agent: Agent,
        system_prompt: impl Into<String>,
    ) -> Self {
        self.nodes.push((id.into(), agent, system_prompt.into()));
        self
    }

    /// Enable agent mailboxes with the given channel capacity.
    pub fn enable_mailbox(mut self, capacity: usize) -> Self {
        self.mailbox_capacity = Some(capacity);
        self
    }

    /// Enable the shared blackboard with the given entry limit.
    pub fn enable_blackboard(mut self, capacity: usize) -> Self {
        self.blackboard_capacity = Some(capacity);
        self
    }

    /// Add a directed edge (handoff route) between two nodes.
    pub fn edge(
        mut self,
        from: impl Into<String>,
        to: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        self.edges.push(EdgeDefinition {
            from: from.into(),
            to: to.into(),
            description: description.into(),
        });
        self
    }

    /// Build the flow. Validates that the entry node exists and all
    /// edge endpoints reference valid nodes.
    pub fn build(self) -> Result<Flow, FlowError> {
        let entry = self
            .entry
            .ok_or_else(|| FlowError::InvalidFlow("no entry node specified".into()))?;

        let node_ids: std::collections::HashSet<&str> =
            self.nodes.iter().map(|(id, _, _)| id.as_str()).collect();

        if !node_ids.contains(entry.as_str()) {
            return Err(FlowError::InvalidFlow(format!(
                "entry node '{}' not found",
                entry
            )));
        }

        // Validate edges reference valid nodes
        for edge in &self.edges {
            if !node_ids.contains(edge.from.as_str()) {
                return Err(FlowError::InvalidFlow(format!(
                    "edge from unknown node '{}'",
                    edge.from
                )));
            }
            if !node_ids.contains(edge.to.as_str()) {
                return Err(FlowError::InvalidFlow(format!(
                    "edge to unknown node '{}'",
                    edge.to
                )));
            }
        }

        // Check for duplicate node IDs
        if node_ids.len() != self.nodes.len() {
            return Err(FlowError::InvalidFlow("duplicate node IDs".into()));
        }

        // Index edges by source
        let mut edges_map: HashMap<String, Vec<EdgeDefinition>> = HashMap::new();
        for edge in &self.edges {
            edges_map
                .entry(edge.from.clone())
                .or_default()
                .push(edge.clone());
        }

        // Build flow nodes with effective prompts
        let mut nodes = HashMap::new();
        for (id, agent, system_prompt) in self.nodes {
            let outgoing = edges_map.get(&id).map(|e| e.as_slice()).unwrap_or(&[]);
            let has_edges = !outgoing.is_empty();
            let effective_prompt = format!("{}{}", system_prompt, routing_instructions(outgoing));

            nodes.insert(
                id,
                FlowNode {
                    agent,
                    effective_prompt,
                    has_edges,
                    max_iterations: 10,
                    temperature: None,
                    max_tokens: None,
                },
            );
        }

        let node_ids: Vec<String> = nodes.keys().cloned().collect();

        let mailbox_registry = self
            .mailbox_capacity
            .map(|cap| MailboxRegistry::new(&node_ids, cap));

        let blackboard = self.blackboard_capacity.map(Blackboard::new);

        Ok(Flow {
            name: self.name,
            entry,
            max_hops: self.max_hops,
            nodes,
            mailbox_registry,
            blackboard,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Can't easily test build() without async Agent construction,
    // so test validation logic via error cases.

    #[test]
    fn build_fails_without_entry() {
        let result = FlowBuilder::new("test").build();
        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("entry"));
    }
}
