import { describe, expect, it } from "vitest";
import {
  mapNavraToAgUi,
  reduceAgentState,
  type AgentState,
  type AgUiEvent,
} from "./useNavraAgent";

const initialState: AgentState = {
  status: "idle",
  messages: "",
  toolCalls: [],
  reasoning: "",
  iterations: 0,
  events: [],
};

describe("mapNavraToAgUi", () => {
  it("maps text event to TEXT_MESSAGE_CONTENT", () => {
    const events = mapNavraToAgUi({ type: "text", content: "Hello world" });
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe("TEXT_MESSAGE_CONTENT");
    expect(events[0].content).toBe("Hello world");
  });

  it("maps tool_call to TOOL_CALL_START + TOOL_CALL_ARGS", () => {
    const events = mapNavraToAgUi({
      type: "tool_call",
      tool: "file_read",
      args: { path: "/tmp/test.txt" },
    });
    expect(events).toHaveLength(2);
    expect(events[0].type).toBe("TOOL_CALL_START");
    expect(events[0].toolName).toBe("file_read");
    expect(events[1].type).toBe("TOOL_CALL_ARGS");
    expect(events[1].args).toBe('{"path":"/tmp/test.txt"}');
  });

  it("maps tool_result to TOOL_CALL_END", () => {
    const events = mapNavraToAgUi({
      type: "tool_result",
      tool: "file_read",
      result: "file contents here",
      duration_ms: 42,
    });
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe("TOOL_CALL_END");
    expect(events[0].toolName).toBe("file_read");
    expect(events[0].result).toBe("file contents here");
    expect(events[0].durationMs).toBe(42);
  });

  it("maps thinking to REASONING_MESSAGE_CONTENT", () => {
    const events = mapNavraToAgUi({
      type: "thinking",
      iteration: 2,
      input_tokens: 100,
      output_tokens: 50,
    });
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe("REASONING_MESSAGE_CONTENT");
    expect(events[0].iteration).toBe(2);
    expect(events[0].inputTokens).toBe(100);
  });

  it("maps done to TEXT_MESSAGE_END + RUN_FINISHED", () => {
    const events = mapNavraToAgUi({
      type: "done",
      session_id: "sess-123",
      iterations: 3,
      usage: { input_tokens: 500, output_tokens: 200 },
    });
    expect(events).toHaveLength(2);
    expect(events[0].type).toBe("TEXT_MESSAGE_END");
    expect(events[1].type).toBe("RUN_FINISHED");
    expect(events[1].sessionId).toBe("sess-123");
    expect(events[1].iterations).toBe(3);
  });

  it("maps error to RUN_ERROR", () => {
    const events = mapNavraToAgUi({
      type: "error",
      message: "Something went wrong",
    });
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe("RUN_ERROR");
    expect(events[0].message).toBe("Something went wrong");
  });
});

describe("reduceAgentState", () => {
  const ts = Date.now();

  it("RUN_STARTED resets to running", () => {
    const state = reduceAgentState(initialState, {
      type: "RUN_STARTED",
      timestamp: ts,
    });
    expect(state.status).toBe("running");
    expect(state.messages).toBe("");
    expect(state.toolCalls).toEqual([]);
  });

  it("TEXT_MESSAGE_CONTENT appends text", () => {
    const s1 = reduceAgentState(
      { ...initialState, status: "running" },
      { type: "TEXT_MESSAGE_CONTENT", timestamp: ts, content: "Hello " },
    );
    expect(s1.messages).toBe("Hello ");

    const s2 = reduceAgentState(s1, {
      type: "TEXT_MESSAGE_CONTENT",
      timestamp: ts,
      content: "world",
    });
    expect(s2.messages).toBe("Hello world");
  });

  it("TOOL_CALL_START adds tool call entry", () => {
    const state = reduceAgentState(
      { ...initialState, status: "running" },
      {
        type: "TOOL_CALL_START",
        timestamp: ts,
        toolCallId: "tc-1",
        toolName: "file_read",
      },
    );
    expect(state.toolCalls).toHaveLength(1);
    expect(state.toolCalls[0].name).toBe("file_read");
    expect(state.toolCalls[0].status).toBe("running");
  });

  it("TOOL_CALL_ARGS populates args on running tool", () => {
    const withTool = reduceAgentState(
      { ...initialState, status: "running" },
      {
        type: "TOOL_CALL_START",
        timestamp: ts,
        toolCallId: "tc-1",
        toolName: "file_read",
      },
    );
    const state = reduceAgentState(withTool, {
      type: "TOOL_CALL_ARGS",
      timestamp: ts,
      toolCallId: "tc-1",
      args: '{"path":"/tmp"}',
    });
    expect(state.toolCalls[0].args).toBe('{"path":"/tmp"}');
  });

  it("TOOL_CALL_END completes a tool call", () => {
    const withTool = reduceAgentState(
      { ...initialState, status: "running" },
      {
        type: "TOOL_CALL_START",
        timestamp: ts,
        toolCallId: "tc-1",
        toolName: "shell_exec",
      },
    );
    const state = reduceAgentState(withTool, {
      type: "TOOL_CALL_END",
      timestamp: ts,
      toolName: "shell_exec",
      result: "exit 0",
      durationMs: 150,
    });
    expect(state.toolCalls[0].status).toBe("complete");
    expect(state.toolCalls[0].result).toBe("exit 0");
    expect(state.toolCalls[0].durationMs).toBe(150);
  });

  it("RUN_FINISHED sets finished status", () => {
    const state = reduceAgentState(
      { ...initialState, status: "running" },
      {
        type: "RUN_FINISHED",
        timestamp: ts,
        sessionId: "s-1",
        iterations: 5,
      },
    );
    expect(state.status).toBe("finished");
    expect(state.sessionId).toBe("s-1");
    expect(state.iterations).toBe(5);
  });

  it("RUN_ERROR sets error status", () => {
    const state = reduceAgentState(
      { ...initialState, status: "running" },
      { type: "RUN_ERROR", timestamp: ts, message: "timeout" },
    );
    expect(state.status).toBe("error");
    expect(state.error).toBe("timeout");
  });

  it("full event sequence produces correct final state", () => {
    const events: AgUiEvent[] = [
      { type: "RUN_STARTED", timestamp: ts },
      { type: "TEXT_MESSAGE_CONTENT", timestamp: ts, content: "Let me " },
      {
        type: "TOOL_CALL_START",
        timestamp: ts,
        toolCallId: "tc-1",
        toolName: "git_status",
      },
      {
        type: "TOOL_CALL_ARGS",
        timestamp: ts,
        toolCallId: "tc-1",
        args: "{}",
      },
      {
        type: "TOOL_CALL_END",
        timestamp: ts,
        toolName: "git_status",
        result: "clean",
        durationMs: 50,
      },
      { type: "TEXT_MESSAGE_CONTENT", timestamp: ts, content: "check." },
      {
        type: "REASONING_MESSAGE_CONTENT",
        timestamp: ts,
        iteration: 1,
        inputTokens: 200,
        outputTokens: 100,
      },
      { type: "TEXT_MESSAGE_END", timestamp: ts },
      {
        type: "RUN_FINISHED",
        timestamp: ts,
        sessionId: "s-1",
        iterations: 1,
      },
    ];

    let state = initialState;
    for (const event of events) {
      state = reduceAgentState(state, event);
    }

    expect(state.status).toBe("finished");
    expect(state.messages).toBe("Let me check.");
    expect(state.toolCalls).toHaveLength(1);
    expect(state.toolCalls[0].name).toBe("git_status");
    expect(state.toolCalls[0].status).toBe("complete");
    expect(state.sessionId).toBe("s-1");
    expect(state.events).toHaveLength(9);
  });
});
