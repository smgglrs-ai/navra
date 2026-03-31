#!/usr/bin/env python3
"""Minimal MCP server over stdio for testing mcpd upstream proxy."""
import json
import sys

def handle(request):
    method = request.get("method")
    rid = request.get("id")

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2025-03-26",
            "capabilities": {"tools": {"listChanged": False}, "prompts": {"listChanged": False}},
            "serverInfo": {"name": "test-upstream", "version": "0.1.0"}
        }}
    elif method == "notifications/initialized":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    elif method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": [
            {"name": "echo", "description": "Echoes input", "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}}},
        ]}}
    elif method == "tools/call":
        name = request["params"]["name"]
        args = request["params"].get("arguments", {})
        if name == "echo":
            msg = args.get("message", "")
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": f"echo: {msg}"}],
            }}
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "content": [{"type": "text", "text": f"unknown tool: {name}"}], "isError": True
        }}
    elif method == "prompts/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"prompts": [
            {"name": "greeting", "description": "A greeting prompt"},
        ]}}
    elif method == "prompts/get":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "description": "Greeting",
            "messages": [{"role": "user", "content": {"type": "text", "text": "Hello from upstream!"}}]
        }}
    elif method == "resources/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"resources": []}}
    else:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"Method not found: {method}"}}

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    request = json.loads(line)
    response = handle(request)
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()
