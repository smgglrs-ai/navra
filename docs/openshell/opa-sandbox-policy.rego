# OPA policy for OpenShell sandbox network proxy.
#
# Applied by the OpenShell supervisor's HTTP CONNECT proxy to enforce
# network isolation for navra-managed agent sandboxes. Each sandbox
# runs in a network namespace where all outbound connections are
# tunneled through the proxy and evaluated against this policy.
#
# Default: deny all traffic. Only three destinations are allowed:
#   1. The navra gateway (MCP tool access + A2A teammate mesh)
#   2. The model endpoint (LLM inference)
#   3. The OpenShell gateway (control plane, credential delivery)
#
# Everything else is blocked — no internet, no lateral movement
# between sandboxes, no direct access to host services.
#
# Configuration is provided via OPA data document at
# `data.config.*` (injected by the supervisor at sandbox creation):
#
#   {
#     "navra_host": "10.0.0.2",
#     "navra_port": 9315,
#     "model_host": "10.0.0.3",
#     "model_port": 8080,
#     "gateway_host": "10.0.0.1",
#     "gateway_port": 50051
#   }
#
# Input document (provided per connection by the proxy):
#
#   {
#     "destination": {
#       "host": "10.0.0.2",
#       "port": 9315
#     },
#     "source": {
#       "sandbox_id": "legal-analyst-001"
#     }
#   }

package openshell.sandbox.network

import rego.v1

# Default deny: no connection is allowed unless an explicit rule
# matches. This is the critical security property — a missing rule
# means blocked traffic, not open traffic.
default allow := false

# Rule 1: Allow connections to the navra gateway.
#
# The agent process connects to navra over MCP (Streamable HTTP)
# for tool calls, and over A2A (HTTP) for teammate communication.
# This is the only way the agent can interact with tools and data.
allow if {
    input.destination.host == data.config.navra_host
    input.destination.port == data.config.navra_port
}

# Rule 2: Allow connections to the model endpoint.
#
# The agent (or navra on the agent's behalf) connects to the
# local model server (llama-server, Ollama, vLLM, etc.) for LLM
# inference. Without this, the agent cannot reason.
allow if {
    input.destination.host == data.config.model_host
    input.destination.port == data.config.model_port
}

# Rule 3: Allow connections to the OpenShell gateway.
#
# The supervisor's control plane endpoint for credential delivery,
# sandbox lifecycle management, and health reporting. navra uses
# this for the OpenShell runtime backend (gRPC) and credential
# delegation.
allow if {
    input.destination.host == data.config.gateway_host
    input.destination.port == data.config.gateway_port
}

# Explicit deny for documentation clarity.
#
# OPA's default-deny makes this redundant, but stating it explicitly
# makes the policy self-documenting and easier to audit.
deny if {
    not allow
}
