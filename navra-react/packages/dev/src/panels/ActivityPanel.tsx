import React, { useState } from "react";
import { Content, TextInput, FormGroup, Form } from "@patternfly/react-core";
import { AgentActivity } from "@navra/react";

export function ActivityPanel() {
  const [sessionId, setSessionId] = useState("");

  return (
    <>
      <Form>
        <FormGroup label="MCP Session ID" fieldId="activity-session-id">
          <TextInput
            id="activity-session-id"
            value={sessionId}
            onChange={(_e, val) => setSessionId(val)}
            placeholder="paste mcp-session-id header value"
          />
        </FormGroup>
      </Form>
      <br />
      <AgentActivity sessionId={sessionId || undefined} />
      {!sessionId && (
        <Content component="small">
          Enter a session ID to see live tool call events.
        </Content>
      )}
    </>
  );
}
