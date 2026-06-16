import React, { useState } from "react";
import {
  Content,
  TextInput,
  FormGroup,
  Form,
} from "@patternfly/react-core";
import { ApprovalQueue } from "@navra/react";

export function ApprovalPanel() {
  const [sessionId, setSessionId] = useState("");

  return (
    <>
      <Form>
        <FormGroup label="MCP Session ID" fieldId="session-id">
          <TextInput
            id="session-id"
            value={sessionId}
            onChange={(_e, val) => setSessionId(val)}
            placeholder="paste mcp-session-id header value"
          />
        </FormGroup>
      </Form>
      <br />
      <ApprovalQueue sessionId={sessionId || undefined} />
      {!sessionId && (
        <Content component="small">
          Enter a session ID from a running navra instance to see live
          approvals.
        </Content>
      )}
    </>
  );
}
