//! DMN decision table policy engine integration.
//!
//! Provides an optional in-process DMN evaluator that acts as a policy gate
//! alongside TOML ACLs and Cedar. Business analysts author decision tables
//! in standard DMN editors; navra evaluates them at request time.

use dsntk_feel::Name;
use dsntk_feel::context::FeelContext;
use dsntk_feel::values::Value;
use dsntk_model::DmnElement;
use dsntk_model::NamedElement;
use dsntk_model_evaluator::ModelEvaluator;
use std::collections::HashMap;
use std::sync::Arc;

pub struct DmnEngine {
    evaluator: Arc<ModelEvaluator>,
    namespace: String,
    model_name: String,
    decision_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DmnDecision {
    Allow,
    Deny(String),
}

impl DmnEngine {
    pub fn from_file(path: &str, decision_name: &str) -> Result<Self, String> {
        let xml = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read DMN file '{path}': {e}"))?;
        Self::from_xml(&xml, decision_name)
    }

    pub fn from_xml(xml: &str, decision_name: &str) -> Result<Self, String> {
        let definitions =
            dsntk_model::parse(xml).map_err(|e| format!("Failed to parse DMN XML: {e}"))?;
        let namespace = definitions.namespace().to_string();
        let model_name = definitions.name().to_string();
        let evaluator = ModelEvaluator::new(&[definitions])
            .map_err(|e| format!("Failed to build DMN evaluator: {e}"))?;
        Ok(Self {
            evaluator,
            namespace,
            model_name,
            decision_name: decision_name.to_string(),
        })
    }

    pub fn evaluate(&self, context: &HashMap<String, String>) -> DmnDecision {
        let mut feel_ctx = FeelContext::new();
        for (key, value) in context {
            feel_ctx.set_entry(&Name::from(key.as_str()), Value::String(value.clone()));
        }

        let result = self.evaluator.evaluate_invocable(
            &self.namespace,
            &self.model_name,
            &self.decision_name,
            &feel_ctx,
        );

        Self::interpret_result(&result)
    }

    fn interpret_result(value: &Value) -> DmnDecision {
        match value {
            Value::String(s) => {
                let lower = s.to_lowercase();
                if lower == "allow" || lower == "permit" {
                    DmnDecision::Allow
                } else {
                    DmnDecision::Deny(s.clone())
                }
            }
            Value::Boolean(true) => DmnDecision::Allow,
            Value::Boolean(false) => DmnDecision::Deny("Denied by decision table".to_string()),
            Value::Context(ctx) => Self::interpret_context_result(ctx),
            Value::Null(msg) => {
                DmnDecision::Deny(msg.as_deref().unwrap_or("No matching rule").to_string())
            }
            other => DmnDecision::Deny(format!("Unexpected decision result: {other}")),
        }
    }

    fn interpret_context_result(ctx: &FeelContext) -> DmnDecision {
        let action_key = Name::from("action");
        let reason_key = Name::from("reason");

        let action = ctx.get_entry(&action_key).map(|v| match v {
            Value::String(s) => s.clone(),
            other => format!("{other}"),
        });

        let reason = ctx.get_entry(&reason_key).and_then(|v| match v {
            Value::String(s) => Some(s.clone()),
            Value::Null(_) => None,
            other => Some(format!("{other}")),
        });

        match action.as_deref() {
            Some(s) if s.eq_ignore_ascii_case("allow") || s.eq_ignore_ascii_case("permit") => {
                DmnDecision::Allow
            }
            Some(s) => DmnDecision::Deny(reason.unwrap_or_else(|| s.to_string())),
            None => DmnDecision::Deny(
                reason.unwrap_or_else(|| "No action field in decision result".to_string()),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_DMN: &str = r##"<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="https://www.omg.org/spec/DMN/20191111/MODEL/"
             id="definitions_001"
             name="ToolAccess"
             namespace="https://navra.dev/dmn/tool-access">
  <inputData id="input_tool_name" name="tool_name">
    <variable name="tool_name" typeRef="string"/>
  </inputData>
  <decision id="decision_001" name="Tool Access">
    <variable name="Tool Access" typeRef="string"/>
    <informationRequirement>
      <requiredInput href="#input_tool_name"/>
    </informationRequirement>
    <decisionTable id="dt_001" hitPolicy="FIRST">
      <input id="input_001">
        <inputExpression typeRef="string"><text>tool_name</text></inputExpression>
      </input>
      <output id="output_001" typeRef="string"/>
      <rule id="rule_001">
        <inputEntry id="ie_rule_001"><text>"exec_run"</text></inputEntry>
        <outputEntry id="oe_rule_001"><text>"deny"</text></outputEntry>
      </rule>
      <rule id="rule_002">
        <inputEntry id="ie_rule_002"><text>-</text></inputEntry>
        <outputEntry id="oe_rule_002"><text>"allow"</text></outputEntry>
      </rule>
    </decisionTable>
  </decision>
</definitions>"##;

    const CONTEXT_OUTPUT_DMN: &str = r##"<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="https://www.omg.org/spec/DMN/20191111/MODEL/"
             id="definitions_002"
             name="ToolAccessWithReason"
             namespace="https://navra.dev/dmn/tool-access-reason">
  <inputData id="input_tool_name" name="tool_name">
    <variable name="tool_name" typeRef="string"/>
  </inputData>
  <decision id="decision_002" name="Tool Access">
    <variable name="Tool Access"/>
    <informationRequirement>
      <requiredInput href="#input_tool_name"/>
    </informationRequirement>
    <decisionTable id="dt_002" hitPolicy="FIRST">
      <input id="input_002">
        <inputExpression typeRef="string"><text>tool_name</text></inputExpression>
      </input>
      <output id="out_action" name="action" typeRef="string"/>
      <output id="out_reason" name="reason" typeRef="string"/>
      <rule id="rule_003">
        <inputEntry id="ie_rule_003"><text>"git_push"</text></inputEntry>
        <outputEntry id="oe_action_003"><text>"deny"</text></outputEntry>
        <outputEntry id="oe_reason_003"><text>"Push requires approval"</text></outputEntry>
      </rule>
      <rule id="rule_004">
        <inputEntry id="ie_rule_004"><text>-</text></inputEntry>
        <outputEntry id="oe_action_004"><text>"allow"</text></outputEntry>
        <outputEntry id="oe_reason_004"><text>"-"</text></outputEntry>
      </rule>
    </decisionTable>
  </decision>
</definitions>"##;

    #[test]
    fn allow_by_default_rule() {
        let engine = DmnEngine::from_xml(SIMPLE_DMN, "Tool Access").unwrap();
        let mut ctx = HashMap::new();
        ctx.insert("tool_name".to_string(), "file_read".to_string());
        assert_eq!(engine.evaluate(&ctx), DmnDecision::Allow);
    }

    #[test]
    fn deny_exec_run() {
        let engine = DmnEngine::from_xml(SIMPLE_DMN, "Tool Access").unwrap();
        let mut ctx = HashMap::new();
        ctx.insert("tool_name".to_string(), "exec_run".to_string());
        assert!(matches!(engine.evaluate(&ctx), DmnDecision::Deny(_)));
    }

    #[test]
    fn context_output_deny_with_reason() {
        let engine = DmnEngine::from_xml(CONTEXT_OUTPUT_DMN, "Tool Access").unwrap();
        let mut ctx = HashMap::new();
        ctx.insert("tool_name".to_string(), "git_push".to_string());
        match engine.evaluate(&ctx) {
            DmnDecision::Deny(reason) => assert!(reason.contains("approval"), "reason: {reason}"),
            other => panic!("Expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn context_output_allow() {
        let engine = DmnEngine::from_xml(CONTEXT_OUTPUT_DMN, "Tool Access").unwrap();
        let mut ctx = HashMap::new();
        ctx.insert("tool_name".to_string(), "file_read".to_string());
        assert_eq!(engine.evaluate(&ctx), DmnDecision::Allow);
    }

    #[test]
    fn invalid_xml_returns_error() {
        assert!(DmnEngine::from_xml("not valid xml", "Decision").is_err());
    }

    #[test]
    fn nonexistent_file_returns_error() {
        assert!(DmnEngine::from_file("/nonexistent/policy.dmn", "Decision").is_err());
    }

    #[test]
    fn multi_input_decision() {
        let xml = r##"<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="https://www.omg.org/spec/DMN/20191111/MODEL/"
             id="definitions_003"
             name="MultiInput"
             namespace="https://navra.dev/dmn/multi-input">
  <inputData id="input_tool" name="tool_name">
    <variable name="tool_name" typeRef="string"/>
  </inputData>
  <inputData id="input_agent" name="agent_name">
    <variable name="agent_name" typeRef="string"/>
  </inputData>
  <decision id="decision_003" name="Access Check">
    <variable name="Access Check" typeRef="string"/>
    <informationRequirement>
      <requiredInput href="#input_tool"/>
    </informationRequirement>
    <informationRequirement>
      <requiredInput href="#input_agent"/>
    </informationRequirement>
    <decisionTable id="dt_003" hitPolicy="FIRST">
      <input id="in_tool">
        <inputExpression typeRef="string"><text>tool_name</text></inputExpression>
      </input>
      <input id="in_agent">
        <inputExpression typeRef="string"><text>agent_name</text></inputExpression>
      </input>
      <output id="out_003" typeRef="string"/>
      <rule id="rule_005">
        <inputEntry id="ie_tool_005"><text>"file_write"</text></inputEntry>
        <inputEntry id="ie_agent_005"><text>"untrusted"</text></inputEntry>
        <outputEntry id="oe_005"><text>"deny"</text></outputEntry>
      </rule>
      <rule id="rule_006">
        <inputEntry id="ie_tool_006"><text>-</text></inputEntry>
        <inputEntry id="ie_agent_006"><text>-</text></inputEntry>
        <outputEntry id="oe_006"><text>"allow"</text></outputEntry>
      </rule>
    </decisionTable>
  </decision>
</definitions>"##;

        let engine = DmnEngine::from_xml(xml, "Access Check").unwrap();

        let mut ctx = HashMap::new();
        ctx.insert("tool_name".to_string(), "file_write".to_string());
        ctx.insert("agent_name".to_string(), "untrusted".to_string());
        assert!(matches!(engine.evaluate(&ctx), DmnDecision::Deny(_)));

        let mut ctx2 = HashMap::new();
        ctx2.insert("tool_name".to_string(), "file_write".to_string());
        ctx2.insert("agent_name".to_string(), "trusted".to_string());
        assert_eq!(engine.evaluate(&ctx2), DmnDecision::Allow);
    }

    #[test]
    fn example_guardrails_file() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../policies/example-guardrails.dmn"
        );
        let engine = DmnEngine::from_file(path, "Tool Access").expect("example DMN should parse");

        let mut ctx = HashMap::new();
        ctx.insert("tool_name".to_string(), "file_read".to_string());
        ctx.insert("agent_name".to_string(), "claude".to_string());
        ctx.insert("permission_set".to_string(), "dev".to_string());
        ctx.insert("phase".to_string(), "input".to_string());
        ctx.insert("tool_output".to_string(), String::new());
        assert_eq!(engine.evaluate(&ctx), DmnDecision::Allow);

        let mut ctx_exec = HashMap::new();
        ctx_exec.insert("tool_name".to_string(), "exec_run".to_string());
        ctx_exec.insert("agent_name".to_string(), "claude".to_string());
        ctx_exec.insert("permission_set".to_string(), "dev".to_string());
        ctx_exec.insert("phase".to_string(), "input".to_string());
        ctx_exec.insert("tool_output".to_string(), String::new());
        assert!(matches!(engine.evaluate(&ctx_exec), DmnDecision::Deny(_)));

        let mut ctx_push = HashMap::new();
        ctx_push.insert("tool_name".to_string(), "git_push".to_string());
        ctx_push.insert("agent_name".to_string(), "claude".to_string());
        ctx_push.insert("permission_set".to_string(), "readonly".to_string());
        ctx_push.insert("phase".to_string(), "input".to_string());
        ctx_push.insert("tool_output".to_string(), String::new());
        match engine.evaluate(&ctx_push) {
            DmnDecision::Deny(reason) => {
                assert!(reason.contains("Readonly"), "reason: {reason}");
            }
            other => panic!("Expected Deny, got {other:?}"),
        }

        let mut ctx_push_dev = HashMap::new();
        ctx_push_dev.insert("tool_name".to_string(), "git_push".to_string());
        ctx_push_dev.insert("agent_name".to_string(), "claude".to_string());
        ctx_push_dev.insert("permission_set".to_string(), "dev".to_string());
        ctx_push_dev.insert("phase".to_string(), "input".to_string());
        ctx_push_dev.insert("tool_output".to_string(), String::new());
        assert_eq!(engine.evaluate(&ctx_push_dev), DmnDecision::Allow);

        // Post-call: output phase allows by default
        let mut ctx_output = HashMap::new();
        ctx_output.insert("tool_name".to_string(), "file_read".to_string());
        ctx_output.insert("agent_name".to_string(), "claude".to_string());
        ctx_output.insert("permission_set".to_string(), "dev".to_string());
        ctx_output.insert("phase".to_string(), "output".to_string());
        ctx_output.insert("tool_output".to_string(), "some file content".to_string());
        assert_eq!(engine.evaluate(&ctx_output), DmnDecision::Allow);
    }
}
