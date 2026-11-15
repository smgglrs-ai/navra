#!/usr/bin/env python3
"""End-to-end teammate-spawn driver for a navra gateway running in
Kubernetes (see deploy/k8s/README.md).

Drives the MCP tool sequence team_create -> team_add -> team_message
-> team_result and prints the teammate's output. Each team_message
spawns a teammate as an agents.x-k8s.io Sandbox; the script polls
team_status until the teammate completes or fails.

Usage:
    python3 e2e-driver.py --endpoint http://localhost:9315/mcp \
        --token <navra-token> [--model qwen2.5:0.5b] \
        [--task "Summarize the repository structure"]

Port-forward the gateway first:
    kubectl -n navra port-forward svc/navra-gateway 9315:9315

Requires Python 3 (stdlib only).
"""

import argparse
import json
import re
import sys
import time
import urllib.request

SESSION = None


def post(endpoint, token, payload, timeout=30):
    global SESSION
    req = urllib.request.Request(endpoint, method="POST")
    req.add_header("content-type", "application/json")
    req.add_header("accept", "application/json, text/event-stream")
    req.add_header("authorization", f"Bearer {token}")
    if SESSION:
        req.add_header("mcp-session-id", SESSION)
    req.data = json.dumps(payload).encode()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if not SESSION and "mcp-session-id" in resp.headers:
                SESSION = resp.headers["mcp-session-id"]
            body = resp.read().decode()
            ctype = resp.headers.get("content-type", "")
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read().decode()[:300]}", file=sys.stderr)
        sys.exit(1)
    # SSE-framed responses carry the JSON in data: lines.
    if "text/event-stream" in ctype:
        for line in body.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:].strip())
        return None
    return json.loads(body) if body.strip() else None


def call(endpoint, token, name, args, timeout=30):
    result = post(
        endpoint,
        token,
        {
            "jsonrpc": "2.0",
            "id": call.n,
            "method": "tools/call",
            "params": {"name": name, "arguments": args},
        },
        timeout,
    )
    call.n += 1
    return result


call.n = 1


def tool_text(result):
    return result.get("result", {}).get("content", [{}])[0].get("text", "")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--endpoint", required=True, help="MCP endpoint URL")
    ap.add_argument("--token", required=True, help="navra agent token")
    ap.add_argument("--model", default="qwen2.5:0.5b", help="teammate model")
    ap.add_argument("--task", default="Say hello and report the single word: ready")
    ap.add_argument("--poll-secs", type=int, default=5, help="status poll interval")
    ap.add_argument("--timeout-secs", type=int, default=300, help="overall timeout")
    args = ap.parse_args()

    init = post(
        args.endpoint,
        args.token,
        {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "clientInfo": {"name": "e2e-driver", "version": "0"},
            },
        },
    )
    server = init.get("result", {}).get("serverInfo", {})
    print(f"initialize: {server.get('name')} v{server.get('version')}")
    post(args.endpoint, args.token, {"jsonrpc": "2.0", "method": "notifications/initialized"})

    r = call(args.endpoint, args.token, "team_create", {"name": "e2e"})
    m = re.search(r"team_id:\s*(\S+)", tool_text(r))
    if not m:
        print(f"team_create failed: {tool_text(r)}", file=sys.stderr)
        sys.exit(1)
    team_id = m.group(1)
    print(f"team_id: {team_id}")

    r = call(args.endpoint, args.token, "team_add",
             {"team_id": team_id, "name": "worker", "model": args.model, "locality": "local"})
    if '"isError": true' in json.dumps(r):
        print(f"team_add failed: {tool_text(r)}", file=sys.stderr)
        sys.exit(1)
    print("team_add: worker added")

    r = call(args.endpoint, args.token, "team_message",
             {"team_id": team_id, "to": "worker", "message": args.task}, timeout=60)
    print(f"team_message: {tool_text(r).splitlines()[0]}")

    deadline = time.time() + args.timeout_secs
    while time.time() < deadline:
        time.sleep(args.poll_secs)
        r = call(args.endpoint, args.token, "team_status", {"team_id": team_id})
        raw = tool_text(r)
        try:
            mates = json.loads(raw).get("teammates", [])
            if mates and mates[0].get("status") in ("completed", "failed"):
                print(f"teammate {mates[0]['status']} after "
                      f"{json.loads(raw).get('elapsed_secs', '?')}s")
                break
        except (json.JSONDecodeError, KeyError, IndexError):
            pass

    r = call(args.endpoint, args.token, "team_result",
             {"team_id": team_id, "teammate": "worker"})
    raw = tool_text(r)
    try:
        result = json.loads(raw)
        print(f"status: {result.get('status')}")
        print(f"output: {result.get('output')}")
        sys.exit(0 if result.get("status") == "done" else 1)
    except json.JSONDecodeError:
        print(raw)
        sys.exit(1)


if __name__ == "__main__":
    main()
