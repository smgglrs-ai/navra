//! BPMN 2.0 XML parser and DAG compiler.
//!
//! Parses BPMN process definitions and compiles them into navra-flow
//! `DagConfig` for execution by `DagExecutor`. Business analysts author
//! workflows in standard BPMN editors; navra executes them with IFC.

use crate::definition::{DagConfig, TaskDefinition};
use roxmltree::Document;
use std::collections::{HashMap, HashSet};

// ── BPMN AST types ──

#[derive(Debug, Clone)]
pub struct BpmnProcess {
    pub id: String,
    pub name: Option<String>,
    pub nodes: HashMap<String, BpmnNode>,
    pub flows: Vec<BpmnFlow>,
}

#[derive(Debug, Clone)]
pub enum BpmnNode {
    StartEvent {
        id: String,
        name: Option<String>,
        incoming: Vec<String>,
        outgoing: Vec<String>,
    },
    EndEvent {
        id: String,
        name: Option<String>,
        incoming: Vec<String>,
        outgoing: Vec<String>,
    },
    ServiceTask {
        id: String,
        name: Option<String>,
        task_type: String,
        incoming: Vec<String>,
        outgoing: Vec<String>,
    },
    UserTask {
        id: String,
        name: Option<String>,
        incoming: Vec<String>,
        outgoing: Vec<String>,
    },
    ExclusiveGateway {
        id: String,
        name: Option<String>,
        incoming: Vec<String>,
        outgoing: Vec<String>,
    },
    ParallelGateway {
        id: String,
        name: Option<String>,
        incoming: Vec<String>,
        outgoing: Vec<String>,
    },
}

impl BpmnNode {
    pub fn id(&self) -> &str {
        match self {
            Self::StartEvent { id, .. }
            | Self::EndEvent { id, .. }
            | Self::ServiceTask { id, .. }
            | Self::UserTask { id, .. }
            | Self::ExclusiveGateway { id, .. }
            | Self::ParallelGateway { id, .. } => id,
        }
    }

    fn add_incoming(&mut self, flow_id: &str) {
        match self {
            Self::StartEvent { incoming, .. }
            | Self::EndEvent { incoming, .. }
            | Self::ServiceTask { incoming, .. }
            | Self::UserTask { incoming, .. }
            | Self::ExclusiveGateway { incoming, .. }
            | Self::ParallelGateway { incoming, .. } => incoming.push(flow_id.to_string()),
        }
    }

    fn add_outgoing(&mut self, flow_id: &str) {
        match self {
            Self::StartEvent { outgoing, .. }
            | Self::EndEvent { outgoing, .. }
            | Self::ServiceTask { outgoing, .. }
            | Self::UserTask { outgoing, .. }
            | Self::ExclusiveGateway { outgoing, .. }
            | Self::ParallelGateway { outgoing, .. } => outgoing.push(flow_id.to_string()),
        }
    }

    pub fn outgoing(&self) -> &[String] {
        match self {
            Self::StartEvent { outgoing, .. }
            | Self::EndEvent { outgoing, .. }
            | Self::ServiceTask { outgoing, .. }
            | Self::UserTask { outgoing, .. }
            | Self::ExclusiveGateway { outgoing, .. }
            | Self::ParallelGateway { outgoing, .. } => outgoing,
        }
    }

    fn incoming(&self) -> &[String] {
        match self {
            Self::StartEvent { incoming, .. }
            | Self::EndEvent { incoming, .. }
            | Self::ServiceTask { incoming, .. }
            | Self::UserTask { incoming, .. }
            | Self::ExclusiveGateway { incoming, .. }
            | Self::ParallelGateway { incoming, .. } => incoming,
        }
    }

    fn is_task(&self) -> bool {
        matches!(self, Self::ServiceTask { .. } | Self::UserTask { .. })
    }

    fn is_gateway(&self) -> bool {
        matches!(
            self,
            Self::ExclusiveGateway { .. } | Self::ParallelGateway { .. }
        )
    }
}

#[derive(Debug, Clone)]
pub struct BpmnFlow {
    pub id: String,
    pub source: String,
    pub target: String,
    pub condition: Option<String>,
    pub is_default: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum BpmnError {
    #[error("XML parse error: {0}")]
    Xml(#[from] roxmltree::Error),
    #[error("no <process> element found")]
    NoProcess,
    #[error("missing required attribute '{0}'")]
    MissingAttribute(String),
    #[error("no start event found")]
    NoStartEvent,
    #[error("compilation error: {0}")]
    Compile(String),
}

// ── Parser ──

pub fn parse(xml: &str) -> Result<BpmnProcess, BpmnError> {
    let doc = Document::parse(xml)?;

    let process = doc
        .descendants()
        .find(|n| n.tag_name().name() == "process")
        .ok_or(BpmnError::NoProcess)?;

    let process_id = attr(&process, "id")?;
    let process_name = attr_opt(&process, "name");

    let mut nodes: HashMap<String, BpmnNode> = HashMap::new();
    let mut flows: Vec<BpmnFlow> = Vec::new();

    for child in process.children().filter(|n| n.is_element()) {
        match child.tag_name().name() {
            "startEvent" => {
                let node = parse_event(&child, true)?;
                nodes.insert(node.id().to_string(), node);
            }
            "endEvent" => {
                let node = parse_event(&child, false)?;
                nodes.insert(node.id().to_string(), node);
            }
            "serviceTask" => {
                let node = parse_service_task(&child)?;
                nodes.insert(node.id().to_string(), node);
            }
            "userTask" => {
                let node = parse_user_task(&child)?;
                nodes.insert(node.id().to_string(), node);
            }
            "exclusiveGateway" => {
                let node = parse_gateway(&child, false)?;
                nodes.insert(node.id().to_string(), node);
            }
            "parallelGateway" => {
                let node = parse_gateway(&child, true)?;
                nodes.insert(node.id().to_string(), node);
            }
            "sequenceFlow" => {
                flows.push(parse_sequence_flow(&child)?);
            }
            _ => {}
        }
    }

    // Mark default flows on exclusive gateways
    for child in process.children().filter(|n| n.is_element()) {
        if child.tag_name().name() == "exclusiveGateway"
            && let Some(default_id) = child.attribute("default")
        {
            for flow in &mut flows {
                if flow.id == default_id {
                    flow.is_default = true;
                }
            }
        }
    }

    // Wire flow IDs to nodes
    for flow in &flows {
        if let Some(node) = nodes.get_mut(&flow.source) {
            node.add_outgoing(&flow.id);
        }
        if let Some(node) = nodes.get_mut(&flow.target) {
            node.add_incoming(&flow.id);
        }
    }

    Ok(BpmnProcess {
        id: process_id,
        name: process_name,
        nodes,
        flows,
    })
}

fn attr(node: &roxmltree::Node, name: &str) -> Result<String, BpmnError> {
    node.attribute(name)
        .map(String::from)
        .ok_or_else(|| BpmnError::MissingAttribute(name.to_string()))
}

fn attr_opt(node: &roxmltree::Node, name: &str) -> Option<String> {
    node.attribute(name).map(String::from)
}

fn parse_event(node: &roxmltree::Node, is_start: bool) -> Result<BpmnNode, BpmnError> {
    let id = attr(node, "id")?;
    let name = attr_opt(node, "name");
    if is_start {
        Ok(BpmnNode::StartEvent {
            id,
            name,
            incoming: vec![],
            outgoing: vec![],
        })
    } else {
        Ok(BpmnNode::EndEvent {
            id,
            name,
            incoming: vec![],
            outgoing: vec![],
        })
    }
}

fn parse_service_task(node: &roxmltree::Node) -> Result<BpmnNode, BpmnError> {
    let id = attr(node, "id")?;
    let name = attr_opt(node, "name");
    let mut task_type = name.clone().unwrap_or_else(|| "default".to_string());

    for ext in node
        .children()
        .filter(|n| n.tag_name().name() == "extensionElements")
    {
        for e in ext.children().filter(|n| n.is_element()) {
            if e.tag_name().name() == "taskDefinition"
                && let Some(ty) = e.attribute("type")
            {
                task_type = ty.to_string();
            }
        }
    }

    Ok(BpmnNode::ServiceTask {
        id,
        name,
        task_type,
        incoming: vec![],
        outgoing: vec![],
    })
}

fn parse_user_task(node: &roxmltree::Node) -> Result<BpmnNode, BpmnError> {
    let id = attr(node, "id")?;
    let name = attr_opt(node, "name");
    Ok(BpmnNode::UserTask {
        id,
        name,
        incoming: vec![],
        outgoing: vec![],
    })
}

fn parse_gateway(node: &roxmltree::Node, is_parallel: bool) -> Result<BpmnNode, BpmnError> {
    let id = attr(node, "id")?;
    let name = attr_opt(node, "name");
    if is_parallel {
        Ok(BpmnNode::ParallelGateway {
            id,
            name,
            incoming: vec![],
            outgoing: vec![],
        })
    } else {
        Ok(BpmnNode::ExclusiveGateway {
            id,
            name,
            incoming: vec![],
            outgoing: vec![],
        })
    }
}

fn parse_sequence_flow(node: &roxmltree::Node) -> Result<BpmnFlow, BpmnError> {
    let id = attr(node, "id")?;
    let source = attr(node, "sourceRef")?;
    let target = attr(node, "targetRef")?;
    let condition = node
        .children()
        .find(|n| n.tag_name().name() == "conditionExpression")
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string());
    Ok(BpmnFlow {
        id,
        source,
        target,
        condition,
        is_default: false,
    })
}

// ── Compiler: BPMN → DagConfig ──

pub fn compile(process: &BpmnProcess) -> Result<DagConfig, BpmnError> {
    let flow_index: HashMap<&str, &BpmnFlow> =
        process.flows.iter().map(|f| (f.id.as_str(), f)).collect();

    let mut tasks: Vec<TaskDefinition> = Vec::new();
    let mut visited_tasks: HashSet<String> = HashSet::new();

    for node in process.nodes.values() {
        if !node.is_task() {
            continue;
        }
        let task = compile_task(node, process, &flow_index)?;
        visited_tasks.insert(node.id().to_string());
        tasks.push(task);
    }

    if tasks.is_empty() {
        return Err(BpmnError::Compile(
            "no service or user tasks found".to_string(),
        ));
    }

    Ok(DagConfig {
        name: process.name.clone().unwrap_or_else(|| process.id.clone()),
        description: None,
        parameters: HashMap::new(),
        tasks,
        blackboard_capacity: None,
    })
}

fn compile_task(
    node: &BpmnNode,
    process: &BpmnProcess,
    flow_index: &HashMap<&str, &BpmnFlow>,
) -> Result<TaskDefinition, BpmnError> {
    let (id, name, is_user_task, specialist) = match node {
        BpmnNode::ServiceTask {
            id,
            name,
            task_type,
            ..
        } => (id, name, false, task_type.clone()),
        BpmnNode::UserTask { id, name, .. } => (id, name, true, "human_reviewer".to_string()),
        _ => unreachable!(),
    };

    let depends_on = resolve_dependencies(node, process, flow_index);

    let mandate = name.clone().unwrap_or_else(|| format!("Execute task {id}"));

    Ok(TaskDefinition {
        id: id.clone(),
        specialist,
        model: None,
        mandate,
        depends_on,
        expected_output: None,
        success_criteria: vec![],
        back_edges: vec![],
        generates_tasks: false,
        verification: None,
        tools: None,
        operations: None,
        temperature: None,
        approval_required: is_user_task,
    })
}

/// Walk backward from a task node through gateways and sequence flows
/// to find the task nodes it depends on.
fn resolve_dependencies(
    node: &BpmnNode,
    process: &BpmnProcess,
    flow_index: &HashMap<&str, &BpmnFlow>,
) -> Vec<String> {
    let mut deps: Vec<String> = Vec::new();
    let mut queue: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Seed: all incoming flow sources
    for flow_id in node.incoming() {
        if let Some(flow) = flow_index.get(flow_id.as_str()) {
            queue.push(flow.source.clone());
        }
    }

    while let Some(source_id) = queue.pop() {
        if !seen.insert(source_id.clone()) {
            continue;
        }
        if let Some(source_node) = process.nodes.get(&source_id) {
            if source_node.is_task() {
                deps.push(source_id);
            } else if source_node.is_gateway() || matches!(source_node, BpmnNode::StartEvent { .. })
            {
                // Traverse through gateways and start events
                for flow_id in source_node.incoming() {
                    if let Some(flow) = flow_index.get(flow_id.as_str()) {
                        queue.push(flow.source.clone());
                    }
                }
            }
        }
    }

    deps.sort();
    deps.dedup();
    deps
}

/// Load a BPMN file and compile to DagConfig.
pub fn load_bpmn_file(path: &str) -> Result<DagConfig, BpmnError> {
    let xml = std::fs::read_to_string(path)
        .map_err(|e| BpmnError::Compile(format!("Failed to read '{path}': {e}")))?;
    let process = parse(&xml)?;
    compile(&process)
}

// ── Generator: DagConfig → BPMN XML ──

/// Generate BPMN 2.0 XML from a DagConfig and optional node status map.
///
/// Produces valid BPMN that can be rendered by bpmn.io or any BPMN viewer.
/// Status values in `statuses` (pending/running/done/failed) are embedded
/// as extension elements so renderers can color nodes.
pub fn generate_bpmn(dag: &DagConfig, statuses: &HashMap<String, String>) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL"
             xmlns:navra="https://navra.dev/bpmn/extensions"
             id="generated"
             name="navra-generated"
             targetNamespace="https://navra.dev/bpmn/generated">
  <process id="process" name=""#,
    );
    xml_escape_into(&mut xml, &dag.name);
    xml.push_str("\">\n");

    // Start event
    xml.push_str("    <startEvent id=\"__start\"/>\n");

    // Tasks
    for task in &dag.tasks {
        if task.approval_required {
            xml.push_str("    <userTask id=\"");
        } else {
            xml.push_str("    <serviceTask id=\"");
        }
        xml_escape_into(&mut xml, &task.id);
        xml.push_str("\" name=\"");
        xml_escape_into(&mut xml, &task.mandate);
        xml.push_str("\">\n");

        // Status extension
        if let Some(status) = statuses.get(&task.id) {
            xml.push_str("      <extensionElements>\n");
            xml.push_str("        <navra:status>");
            xml_escape_into(&mut xml, status);
            xml.push_str("</navra:status>\n");
            xml.push_str("      </extensionElements>\n");
        }

        if task.approval_required {
            xml.push_str("    </userTask>\n");
        } else {
            xml.push_str("    </serviceTask>\n");
        }
    }

    // End event
    xml.push_str("    <endEvent id=\"__end\"/>\n");

    // Sequence flows
    let mut flow_id = 0u32;

    // Roots (no dependencies) get an edge from start event
    for task in &dag.tasks {
        if task.depends_on.is_empty() {
            flow_id += 1;
            xml.push_str(&format!(
                "    <sequenceFlow id=\"f{flow_id}\" sourceRef=\"__start\" targetRef=\"{}\"/>\n",
                task.id
            ));
        }
    }

    // Dependency edges
    for task in &dag.tasks {
        for dep in &task.depends_on {
            flow_id += 1;
            xml.push_str(&format!(
                "    <sequenceFlow id=\"f{flow_id}\" sourceRef=\"{dep}\" targetRef=\"{}\"/>\n",
                task.id
            ));
        }
    }

    // Terminal tasks (not depended on by anyone) get an edge to end event
    let depended_on: HashSet<&str> = dag
        .tasks
        .iter()
        .flat_map(|t| t.depends_on.iter().map(|s| s.as_str()))
        .collect();
    for task in &dag.tasks {
        if !depended_on.contains(task.id.as_str()) {
            flow_id += 1;
            xml.push_str(&format!(
                "    <sequenceFlow id=\"f{flow_id}\" sourceRef=\"{}\" targetRef=\"__end\"/>\n",
                task.id
            ));
        }
    }

    xml.push_str("  </process>\n</definitions>\n");
    xml
}

fn xml_escape_into(buf: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => buf.push_str("&amp;"),
            '<' => buf.push_str("&lt;"),
            '>' => buf.push_str("&gt;"),
            '"' => buf.push_str("&quot;"),
            '\'' => buf.push_str("&apos;"),
            _ => buf.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINEAR_BPMN: &str = r##"<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL"
             id="defs" name="Linear" targetNamespace="https://navra.dev">
  <process id="p1" name="Linear Process">
    <startEvent id="start"/>
    <serviceTask id="draft" name="Draft document"/>
    <endEvent id="end"/>
    <sequenceFlow id="f1" sourceRef="start" targetRef="draft"/>
    <sequenceFlow id="f2" sourceRef="draft" targetRef="end"/>
  </process>
</definitions>"##;

    const PARALLEL_BPMN: &str = r##"<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL"
             id="defs" name="Parallel" targetNamespace="https://navra.dev">
  <process id="p1" name="Parallel Process">
    <startEvent id="start"/>
    <serviceTask id="prepare" name="Prepare data"/>
    <parallelGateway id="fork"/>
    <serviceTask id="analyze_a" name="Analysis A"/>
    <serviceTask id="analyze_b" name="Analysis B"/>
    <parallelGateway id="join"/>
    <serviceTask id="merge" name="Merge results"/>
    <endEvent id="end"/>
    <sequenceFlow id="f1" sourceRef="start" targetRef="prepare"/>
    <sequenceFlow id="f2" sourceRef="prepare" targetRef="fork"/>
    <sequenceFlow id="f3" sourceRef="fork" targetRef="analyze_a"/>
    <sequenceFlow id="f4" sourceRef="fork" targetRef="analyze_b"/>
    <sequenceFlow id="f5" sourceRef="analyze_a" targetRef="join"/>
    <sequenceFlow id="f6" sourceRef="analyze_b" targetRef="join"/>
    <sequenceFlow id="f7" sourceRef="join" targetRef="merge"/>
    <sequenceFlow id="f8" sourceRef="merge" targetRef="end"/>
  </process>
</definitions>"##;

    const USER_TASK_BPMN: &str = r##"<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL"
             id="defs" name="Review" targetNamespace="https://navra.dev">
  <process id="p1" name="Review Process">
    <startEvent id="start"/>
    <serviceTask id="draft" name="Draft report"/>
    <userTask id="review" name="Human review"/>
    <serviceTask id="publish" name="Publish report"/>
    <endEvent id="end"/>
    <sequenceFlow id="f1" sourceRef="start" targetRef="draft"/>
    <sequenceFlow id="f2" sourceRef="draft" targetRef="review"/>
    <sequenceFlow id="f3" sourceRef="review" targetRef="publish"/>
    <sequenceFlow id="f4" sourceRef="publish" targetRef="end"/>
  </process>
</definitions>"##;

    #[test]
    fn parse_linear() {
        let process = parse(LINEAR_BPMN).unwrap();
        assert_eq!(process.id, "p1");
        assert_eq!(process.name.as_deref(), Some("Linear Process"));
        assert_eq!(process.nodes.len(), 3);
        assert_eq!(process.flows.len(), 2);
        assert!(matches!(
            process.nodes.get("start"),
            Some(BpmnNode::StartEvent { .. })
        ));
        assert!(matches!(
            process.nodes.get("draft"),
            Some(BpmnNode::ServiceTask { .. })
        ));
        assert!(matches!(
            process.nodes.get("end"),
            Some(BpmnNode::EndEvent { .. })
        ));
    }

    #[test]
    fn parse_parallel_gateways() {
        let process = parse(PARALLEL_BPMN).unwrap();
        assert_eq!(process.nodes.len(), 8);
        assert!(matches!(
            process.nodes.get("fork"),
            Some(BpmnNode::ParallelGateway { .. })
        ));
        assert!(matches!(
            process.nodes.get("join"),
            Some(BpmnNode::ParallelGateway { .. })
        ));
    }

    #[test]
    fn parse_user_task() {
        let process = parse(USER_TASK_BPMN).unwrap();
        assert!(matches!(
            process.nodes.get("review"),
            Some(BpmnNode::UserTask { .. })
        ));
    }

    #[test]
    fn parse_wires_flows() {
        let process = parse(LINEAR_BPMN).unwrap();
        let start = process.nodes.get("start").unwrap();
        assert_eq!(start.outgoing().len(), 1);
        let draft = process.nodes.get("draft").unwrap();
        assert_eq!(draft.incoming().len(), 1);
        assert_eq!(draft.outgoing().len(), 1);
    }

    #[test]
    fn parse_no_process() {
        let xml = r#"<?xml version="1.0"?><definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL"/>"#;
        assert!(matches!(parse(xml), Err(BpmnError::NoProcess)));
    }

    #[test]
    fn parse_invalid_xml() {
        assert!(parse("not xml").is_err());
    }

    #[test]
    fn compile_linear() {
        let process = parse(LINEAR_BPMN).unwrap();
        let dag = compile(&process).unwrap();
        assert_eq!(dag.name, "Linear Process");
        assert_eq!(dag.tasks.len(), 1);
        let task = &dag.tasks[0];
        assert_eq!(task.id, "draft");
        assert_eq!(task.specialist, "Draft document");
        assert!(task.depends_on.is_empty());
        assert!(!task.approval_required);
    }

    #[test]
    fn compile_parallel() {
        let process = parse(PARALLEL_BPMN).unwrap();
        let dag = compile(&process).unwrap();
        assert_eq!(dag.tasks.len(), 4);

        let tasks: HashMap<&str, &TaskDefinition> =
            dag.tasks.iter().map(|t| (t.id.as_str(), t)).collect();

        let prepare = tasks["prepare"];
        assert!(prepare.depends_on.is_empty());

        let a = tasks["analyze_a"];
        assert_eq!(a.depends_on, vec!["prepare"]);

        let b = tasks["analyze_b"];
        assert_eq!(b.depends_on, vec!["prepare"]);

        let merge = tasks["merge"];
        let mut merge_deps = merge.depends_on.clone();
        merge_deps.sort();
        assert_eq!(merge_deps, vec!["analyze_a", "analyze_b"]);
    }

    #[test]
    fn compile_user_task_sets_approval() {
        let process = parse(USER_TASK_BPMN).unwrap();
        let dag = compile(&process).unwrap();
        let tasks: HashMap<&str, &TaskDefinition> =
            dag.tasks.iter().map(|t| (t.id.as_str(), t)).collect();

        assert!(!tasks["draft"].approval_required);
        assert!(tasks["review"].approval_required);
        assert!(!tasks["publish"].approval_required);
        assert_eq!(tasks["publish"].depends_on, vec!["review"]);
    }

    #[test]
    fn compile_exclusive_gateway() {
        let xml = r##"<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://www.omg.org/spec/BPMN/20100524/MODEL"
             id="defs" name="Exclusive" targetNamespace="https://navra.dev">
  <process id="p1" name="Exclusive Process">
    <startEvent id="start"/>
    <serviceTask id="check" name="Check status"/>
    <exclusiveGateway id="gw" default="f_default"/>
    <serviceTask id="approve" name="Auto approve"/>
    <serviceTask id="escalate" name="Escalate"/>
    <endEvent id="end"/>
    <sequenceFlow id="f1" sourceRef="start" targetRef="check"/>
    <sequenceFlow id="f2" sourceRef="check" targetRef="gw"/>
    <sequenceFlow id="f_ok" sourceRef="gw" targetRef="approve">
      <conditionExpression>status == "ok"</conditionExpression>
    </sequenceFlow>
    <sequenceFlow id="f_default" sourceRef="gw" targetRef="escalate"/>
    <sequenceFlow id="f3" sourceRef="approve" targetRef="end"/>
    <sequenceFlow id="f4" sourceRef="escalate" targetRef="end"/>
  </process>
</definitions>"##;

        let process = parse(xml).unwrap();
        let dag = compile(&process).unwrap();
        let tasks: HashMap<&str, &TaskDefinition> =
            dag.tasks.iter().map(|t| (t.id.as_str(), t)).collect();

        assert_eq!(tasks["approve"].depends_on, vec!["check"]);
        assert_eq!(tasks["escalate"].depends_on, vec!["check"]);
    }

    #[test]
    fn compile_from_file() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../examples/workflows/document-review.bpmn"
        );
        if std::path::Path::new(path).exists() {
            let dag = load_bpmn_file(path).unwrap();
            assert!(!dag.tasks.is_empty());
        }
    }

    #[test]
    fn generate_bpmn_round_trip() {
        let process = parse(PARALLEL_BPMN).unwrap();
        let dag = compile(&process).unwrap();

        let mut statuses = HashMap::new();
        statuses.insert("prepare".to_string(), "done".to_string());
        statuses.insert("analyze_a".to_string(), "running".to_string());
        statuses.insert("analyze_b".to_string(), "pending".to_string());
        statuses.insert("merge".to_string(), "pending".to_string());

        let xml = generate_bpmn(&dag, &statuses);

        // Verify it's valid BPMN that can be re-parsed
        let reparsed = parse(&xml).unwrap();
        assert_eq!(reparsed.nodes.len(), 6); // 4 tasks + start + end

        // Verify status extension is present
        assert!(xml.contains("navra:status"));
        assert!(xml.contains("done"));
        assert!(xml.contains("running"));
    }

    #[test]
    fn generate_bpmn_user_task() {
        let process = parse(USER_TASK_BPMN).unwrap();
        let dag = compile(&process).unwrap();
        let xml = generate_bpmn(&dag, &HashMap::new());

        assert!(xml.contains("<userTask"));
        assert!(xml.contains("<serviceTask"));

        let reparsed = parse(&xml).unwrap();
        assert!(matches!(
            reparsed.nodes.get("review"),
            Some(BpmnNode::UserTask { .. })
        ));
    }
}
