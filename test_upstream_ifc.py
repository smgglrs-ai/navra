#!/usr/bin/env python3
"""MCP server over stdio for IFC adversarial benchmarking.

Provides doc_read (external read), doc_write (write), and doc_search
(external read) tools. doc_read returns whatever content is passed in
the 'content' argument — the test harness injects attack payloads here.
doc_write accepts content and returns success (navra should block it
when the session is tainted).

Tool naming matters: navra classifies tools by name heuristic.
- "read"/"search" in name → external read → taints session
- "write" in name → write tool → blocked under Deny policy when tainted
"""
import json
import sys

TOOLS = [
    {
        "name": "doc_read",
        "description": "Read a document and return its content.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Document path"},
                "content": {"type": "string", "description": "Content to return (for testing)"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "doc_write",
        "description": "Write content to a document.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Document path"},
                "content": {"type": "string", "description": "Content to write"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "doc_search",
        "description": "Search documents for a query string.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
            },
            "required": ["query"],
        },
    },
]


def handle(request):
    method = request.get("method")
    rid = request.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "test-upstream-ifc", "version": "0.1.0"},
            },
        }
    elif method == "notifications/initialized":
        return {"jsonrpc": "2.0", "id": rid, "result": {}}
    elif method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    elif method == "tools/call":
        name = request["params"]["name"]
        args = request["params"].get("arguments", {})

        if name == "doc_read":
            content = args.get("content", f"Content of {args.get('path', 'unknown')}")
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {"content": [{"type": "text", "text": content}]},
            }
        elif name == "doc_write":
            path = args.get("path", "unknown")
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "content": [{"type": "text", "text": f"Written to {path}"}]
                },
            }
        elif name == "doc_search":
            query = args.get("query", "")
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "content": [
                        {"type": "text", "text": f"Search results for: {query}"}
                    ]
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": rid,
            "result": {
                "content": [{"type": "text", "text": f"unknown tool: {name}"}],
                "isError": True,
            },
        }
    elif method in ("prompts/list", "resources/list"):
        key = "prompts" if "prompts" in method else "resources"
        return {"jsonrpc": "2.0", "id": rid, "result": {key: []}}
    else:
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    request = json.loads(line)
    response = handle(request)
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()
