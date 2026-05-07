#!/usr/bin/env python3
"""
Multi-turn tool calling benchmark for llama.cpp KV cache quantization.

Sends multi-turn conversations with tool calls to llama-server's
OpenAI-compatible API, measuring success rate per turn across
different KV cache configurations.

Usage:
    # Start llama-server first, then:
    python3 tool_calling_bench.py --url http://127.0.0.1:8080 --runs 5
    python3 tool_calling_bench.py --url http://127.0.0.1:8080 --runs 5 --output results.json
"""

import argparse
import json
import sys
import time
import requests

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get current weather for a city",
            "parameters": {
                "type": "object",
                "properties": {
                    "city": {"type": "string", "description": "City name"},
                    "units": {
                        "type": "string",
                        "enum": ["celsius", "fahrenheit"],
                        "description": "Temperature units",
                    },
                },
                "required": ["city", "units"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_database",
            "description": "Search a database by query and filters",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "table": {"type": "string", "description": "Table name"},
                    "limit": {"type": "integer", "description": "Max results"},
                    "order_by": {
                        "type": "string",
                        "description": "Sort field",
                    },
                },
                "required": ["query", "table", "limit", "order_by"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_notification",
            "description": "Send a notification to a user",
            "parameters": {
                "type": "object",
                "properties": {
                    "user_id": {"type": "string", "description": "User ID"},
                    "message": {
                        "type": "string",
                        "description": "Notification text",
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["low", "medium", "high"],
                        "description": "Priority level",
                    },
                    "channel": {
                        "type": "string",
                        "enum": ["email", "sms", "push"],
                        "description": "Delivery channel",
                    },
                },
                "required": ["user_id", "message", "priority", "channel"],
            },
        },
    },
]

TOOL_RESULTS = {
    "get_weather": lambda args: json.dumps(
        {
            "temperature": 22,
            "units": args.get("units", "celsius"),
            "condition": "sunny",
            "humidity": 45,
            "city": args.get("city", "unknown"),
        }
    ),
    "search_database": lambda args: json.dumps(
        {
            "results": [
                {"id": 1, "name": "Alice", "score": 95},
                {"id": 2, "name": "Bob", "score": 88},
            ],
            "total": 2,
            "query": args.get("query", ""),
        }
    ),
    "send_notification": lambda args: json.dumps(
        {
            "status": "sent",
            "user_id": args.get("user_id", ""),
            "channel": args.get("channel", ""),
            "timestamp": "2026-05-07T15:00:00Z",
        }
    ),
}

TURN_PROMPTS = [
    "What's the weather like in Paris? Use celsius.",
    "Now search the users table for people named Alice, limit to 5 results, ordered by score.",
    "Send a high priority push notification to user_123 saying 'Meeting at 3pm'.",
    "What's the weather in Tokyo? Use fahrenheit.",
    "Search the orders table for recent purchases, limit 10, order by date.",
]

EXPECTED_TOOLS = [
    "get_weather",
    "search_database",
    "send_notification",
    "get_weather",
    "search_database",
]


def validate_tool_call(tool_call, expected_tool_name):
    """Validate a tool call has correct structure and tool name."""
    result = {
        "valid_json": False,
        "correct_tool": False,
        "valid_args": False,
        "tool_name": None,
        "args": None,
        "error": None,
    }

    try:
        fn = tool_call.get("function", {})
        name = fn.get("name", "")
        result["tool_name"] = name

        args_str = fn.get("arguments", "{}")
        if isinstance(args_str, str):
            args = json.loads(args_str)
        else:
            args = args_str
        result["args"] = args
        result["valid_json"] = True

        if name == expected_tool_name:
            result["correct_tool"] = True

        tool_def = next(
            (t for t in TOOLS if t["function"]["name"] == name), None
        )
        if tool_def:
            required = tool_def["function"]["parameters"].get("required", [])
            props = tool_def["function"]["parameters"].get("properties", {})
            all_present = all(k in args for k in required)
            types_ok = True
            for k, v in args.items():
                if k in props:
                    prop = props[k]
                    if prop.get("type") == "integer" and not isinstance(v, int):
                        types_ok = False
                    if "enum" in prop and v not in prop["enum"]:
                        types_ok = False
            result["valid_args"] = all_present and types_ok

    except (json.JSONDecodeError, KeyError, TypeError) as e:
        result["error"] = str(e)

    return result


def run_multi_turn(url, num_turns=5, verbose=False):
    """Run a multi-turn tool calling conversation and return per-turn results."""
    messages = [
        {
            "role": "system",
            "content": (
                "You are a helpful assistant. When the user asks you to "
                "do something, use the available tools. Always call a tool "
                "when appropriate. Do not explain what you will do, just "
                "call the tool directly."
            ),
        }
    ]

    turn_results = []

    for turn_idx in range(min(num_turns, len(TURN_PROMPTS))):
        prompt = TURN_PROMPTS[turn_idx]
        expected_tool = EXPECTED_TOOLS[turn_idx]

        messages.append({"role": "user", "content": prompt})

        try:
            resp = requests.post(
                f"{url}/v1/chat/completions",
                json={
                    "messages": messages,
                    "tools": TOOLS,
                    "tool_choice": "auto",
                    "temperature": 0.0,
                    "max_tokens": 512,
                },
                timeout=120,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            turn_results.append(
                {
                    "turn": turn_idx + 1,
                    "prompt": prompt,
                    "expected_tool": expected_tool,
                    "success": False,
                    "error": f"request failed: {e}",
                }
            )
            break

        choice = data.get("choices", [{}])[0]
        message = choice.get("message", {})
        finish_reason = choice.get("finish_reason", "")

        tool_calls = message.get("tool_calls", [])

        if not tool_calls:
            content = message.get("content", "")
            turn_results.append(
                {
                    "turn": turn_idx + 1,
                    "prompt": prompt,
                    "expected_tool": expected_tool,
                    "success": False,
                    "error": "no tool call generated",
                    "finish_reason": finish_reason,
                    "content_preview": content[:200] if content else "",
                }
            )
            if verbose:
                print(
                    f"  Turn {turn_idx + 1}: FAIL (no tool call, "
                    f"finish={finish_reason})"
                )
            messages.append({"role": "assistant", "content": content})
            continue

        tc = tool_calls[0]
        validation = validate_tool_call(tc, expected_tool)

        success = (
            validation["valid_json"]
            and validation["correct_tool"]
            and validation["valid_args"]
        )

        turn_results.append(
            {
                "turn": turn_idx + 1,
                "prompt": prompt,
                "expected_tool": expected_tool,
                "success": success,
                "validation": validation,
                "finish_reason": finish_reason,
                "num_tool_calls": len(tool_calls),
            }
        )

        if verbose:
            status = "OK" if success else "FAIL"
            tool_name = validation.get("tool_name", "?")
            print(
                f"  Turn {turn_idx + 1}: {status} "
                f"(called={tool_name}, expected={expected_tool})"
            )

        messages.append(
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": tc.get("id", f"call_{turn_idx}"),
                        "type": "function",
                        "function": {
                            "name": validation["tool_name"] or "",
                            "arguments": json.dumps(validation["args"] or {}),
                        },
                    }
                ],
            }
        )

        tool_name = validation["tool_name"] or ""
        if tool_name in TOOL_RESULTS and validation["args"]:
            tool_result = TOOL_RESULTS[tool_name](validation["args"])
        else:
            tool_result = json.dumps({"error": "unknown tool"})

        messages.append(
            {
                "role": "tool",
                "tool_call_id": tc.get("id", f"call_{turn_idx}"),
                "content": tool_result,
            }
        )

    return turn_results


def main():
    parser = argparse.ArgumentParser(
        description="Multi-turn tool calling benchmark"
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8080",
        help="llama-server URL (default: http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--runs", type=int, default=5, help="Number of runs (default: 5)"
    )
    parser.add_argument(
        "--turns", type=int, default=5, help="Turns per run (default: 5)"
    )
    parser.add_argument("--output", help="Output JSON file path")
    parser.add_argument(
        "--label", default="", help="Label for this config (e.g. 'q8_0-turbo3')"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )
    args = parser.parse_args()

    print(f"Target: {args.url}")
    print(f"Runs: {args.runs}, Turns per run: {args.turns}")
    if args.label:
        print(f"Label: {args.label}")
    print()

    try:
        health = requests.get(f"{args.url}/health", timeout=5)
        if health.status_code != 200:
            print(f"Server not healthy: {health.status_code}")
            sys.exit(1)
    except requests.ConnectionError:
        print(f"Cannot connect to {args.url}")
        sys.exit(1)

    all_runs = []
    per_turn_success = {}

    for run_idx in range(args.runs):
        print(f"Run {run_idx + 1}/{args.runs}:")
        results = run_multi_turn(
            args.url, num_turns=args.turns, verbose=args.verbose
        )
        all_runs.append(results)

        for r in results:
            turn = r["turn"]
            if turn not in per_turn_success:
                per_turn_success[turn] = {"success": 0, "total": 0}
            per_turn_success[turn]["total"] += 1
            if r["success"]:
                per_turn_success[turn]["success"] += 1

        time.sleep(1)

    print()
    print("=== Results ===")
    print(f"{'Turn':<6} {'Success':<10} {'Rate':<10}")
    print("-" * 26)
    total_success = 0
    total_attempts = 0
    for turn in sorted(per_turn_success.keys()):
        s = per_turn_success[turn]["success"]
        t = per_turn_success[turn]["total"]
        rate = s / t * 100 if t > 0 else 0
        total_success += s
        total_attempts += t
        print(f"{turn:<6} {s}/{t:<8} {rate:.0f}%")

    overall = total_success / total_attempts * 100 if total_attempts > 0 else 0
    print("-" * 26)
    print(f"{'Total':<6} {total_success}/{total_attempts:<8} {overall:.0f}%")

    if args.output:
        output = {
            "label": args.label,
            "url": args.url,
            "runs": args.runs,
            "turns": args.turns,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "per_turn_success": per_turn_success,
            "overall_rate": overall,
            "raw_runs": all_runs,
        }
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
