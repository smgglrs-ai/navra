"""navra IFC defense for AgentDojo.

Implements gateway-level Information Flow Control as an AgentDojo
defense plugin. Tracks taint across tool calls and blocks write
operations when the session is tainted from external reads.

This mirrors navra's Bell-LaPadula "no write-down" enforcement:
- Reading external data (emails, files) taints the session
- Writing (send_email, create_file, append_to_file) is blocked
  when tainted
- Taint only rises, never drops (lattice monotonicity)

Unlike agent-level defenses (prompt injection detectors), this
operates at the tool-call boundary — it doesn't matter whether
the LLM was "tricked" by an injection; the gateway blocks the
write regardless.
"""

from agentdojo.agent_pipeline import AbortAgentError, BasePipelineElement

READ_TOOLS = frozenset({
    "get_unread_emails",
    "get_received_emails",
    "search_emails",
    "get_day_calendar_events",
    "search_calendar_events",
    "search_files_by_filename",
    "get_sent_emails",
    "get_draft_emails",
})

WRITE_TOOLS = frozenset({
    "send_email",
    "delete_email",
    "create_calendar_event",
    "cancel_calendar_event",
    "reschedule_calendar_event",
    "add_calendar_event_participants",
    "create_file",
    "append_to_file",
    "delete_file",
})


def _get_fn(tc):
    if isinstance(tc, dict):
        return tc.get("function", tc.get("name", ""))
    return getattr(tc, "function", getattr(tc, "name", ""))


def _get_tool_calls(msg):
    if isinstance(msg, dict):
        return msg.get("tool_calls", []) or []
    return getattr(msg, "tool_calls", []) or []


def _get_role(msg):
    if isinstance(msg, dict):
        return msg.get("role", "")
    return getattr(msg, "role", "")


class IFCDefense(BasePipelineElement):
    """Gateway-level IFC taint tracking defense."""

    def __init__(self):
        self.tainted = False
        self.taint_source = None
        self.blocked_calls = []

    def query(self, query, runtime, env, messages, extra_args=None):
        if extra_args is None:
            extra_args = {}

        for msg in messages:
            if _get_role(msg) == "assistant":
                for tc in _get_tool_calls(msg):
                    fn = _get_fn(tc)
                    if fn in READ_TOOLS and not self.tainted:
                        self.tainted = True
                        self.taint_source = fn

        for msg in reversed(messages):
            if _get_role(msg) == "assistant":
                for tc in _get_tool_calls(msg):
                    fn = _get_fn(tc)
                    if fn in WRITE_TOOLS and self.tainted:
                        self.blocked_calls.append((fn, self.taint_source))
                        raise AbortAgentError(
                            f"IFC BLOCKED: write tool '{fn}' denied — "
                            f"session tainted from '{self.taint_source}'"
                        )
                break

        return query, runtime, env, messages, extra_args
