"""API proxy that logs token usage per request.

Forwards requests to the upstream API and records token counts to a JSONL log.
Supports:
  - Anthropic Messages API (direct passthrough)
  - OpenAI Chat Completions API (direct passthrough)
  - OpenAI Responses API (translated to Chat Completions for upstream)

The Responses API translation enables Codex CLI (which uses Responses API)
to work with upstream providers that only support Chat Completions.

Usage:
    python -m infra.token_proxy --port 8090 --upstream http://api.example.com/v1
"""

from __future__ import annotations

import argparse
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, Request, Response, WebSocket
from fastapi.responses import StreamingResponse
import uvicorn


app = FastAPI()

# Configured at startup
UPSTREAM_URL: str = ""
LOG_PATH: Path = Path("data/eval/token_log.jsonl")


def _log_usage(entry: dict):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry, default=str) + "\n")


# --- Responses API → Chat Completions translation ---

def _responses_input_to_messages(input_items) -> list[dict]:
    """Convert Responses API 'input' to Chat Completions 'messages'."""
    if isinstance(input_items, str):
        return [{"role": "user", "content": input_items}]

    messages = []
    for item in input_items:
        if isinstance(item, str):
            messages.append({"role": "user", "content": item})
            continue

        item_type = item.get("type", "message")
        role = item.get("role", "user")

        if item_type == "message" or "content" in item:
            content = item.get("content", "")
            if isinstance(content, list):
                text_parts = []
                for part in content:
                    if isinstance(part, str):
                        text_parts.append(part)
                    elif isinstance(part, dict):
                        if part.get("type") in ("input_text", "output_text", "text"):
                            text_parts.append(part.get("text", ""))
                content = "\n".join(text_parts) if text_parts else ""
            messages.append({"role": role, "content": content})

        elif item_type == "function_call":
            messages.append({
                "role": "assistant",
                "content": None,
                "tool_calls": [{
                    "id": item.get("call_id", f"call_{uuid.uuid4().hex[:8]}"),
                    "type": "function",
                    "function": {
                        "name": item.get("name", ""),
                        "arguments": item.get("arguments", ""),
                    }
                }]
            })

        elif item_type == "function_call_output":
            messages.append({
                "role": "tool",
                "tool_call_id": item.get("call_id", ""),
                "content": item.get("output", ""),
            })

        else:
            if item.get("content"):
                messages.append({"role": role, "content": str(item["content"])})

    # Merge consecutive assistant messages
    merged = []
    for msg in messages:
        if msg.get("role") == "assistant" and merged and merged[-1].get("role") == "assistant":
            prev = merged[-1]
            if msg.get("tool_calls"):
                prev.setdefault("tool_calls", []).extend(msg["tool_calls"])
            if msg.get("content") and not prev.get("content"):
                prev["content"] = msg["content"]
        else:
            merged.append(msg)

    # Validate tool_call / tool message pairing
    tool_response_ids = {
        msg["tool_call_id"]
        for msg in merged
        if msg.get("role") == "tool" and msg.get("tool_call_id")
    }
    for msg in merged:
        if msg.get("role") == "assistant" and msg.get("tool_calls"):
            msg["tool_calls"] = [
                tc for tc in msg["tool_calls"]
                if tc.get("id") in tool_response_ids
            ]
            if not msg["tool_calls"]:
                del msg["tool_calls"]
                if msg.get("content") is None:
                    msg["content"] = ""

    # Remove orphaned tool messages
    tool_call_ids = set()
    for msg in merged:
        if msg.get("role") == "assistant" and msg.get("tool_calls"):
            for tc in msg["tool_calls"]:
                tool_call_ids.add(tc.get("id"))
    merged = [
        msg for msg in merged
        if msg.get("role") != "tool" or msg.get("tool_call_id") in tool_call_ids
    ]

    return merged


def _convert_tools(tools: list | None) -> list | None:
    """Convert Responses API tools to Chat Completions tools."""
    if not tools:
        return None
    cc_tools = []
    for tool in tools:
        if tool.get("type") == "function":
            cc_tools.append({
                "type": "function",
                "function": {
                    "name": tool.get("name", ""),
                    "description": tool.get("description", ""),
                    "parameters": tool.get("parameters", {}),
                }
            })
    return cc_tools if cc_tools else None


def _cc_response_to_responses(cc_data: dict, model: str) -> dict:
    """Convert Chat Completions response to Responses API response."""
    resp_id = f"resp_{uuid.uuid4().hex[:24]}"
    output = []

    for choice in cc_data.get("choices", []):
        msg = choice.get("message", {})
        role = msg.get("role", "assistant")

        if msg.get("tool_calls"):
            for tc in msg["tool_calls"]:
                output.append({
                    "type": "function_call",
                    "id": f"fc_{uuid.uuid4().hex[:24]}",
                    "call_id": tc.get("id", f"call_{uuid.uuid4().hex[:8]}"),
                    "name": tc["function"]["name"],
                    "arguments": tc["function"].get("arguments", "{}"),
                })

        content = msg.get("content")
        if content:
            output.append({
                "type": "message",
                "id": f"msg_{uuid.uuid4().hex[:24]}",
                "role": role,
                "content": [{"type": "output_text", "text": content}],
            })

    cc_usage = cc_data.get("usage", {})
    cached = 0
    details = cc_usage.get("prompt_tokens_details", {})
    if isinstance(details, dict):
        cached = details.get("cached_tokens", 0)

    usage = {
        "input_tokens": cc_usage.get("prompt_tokens", 0),
        "input_tokens_details": {"cached_tokens": cached},
        "output_tokens": cc_usage.get("completion_tokens", 0),
        "total_tokens": cc_usage.get("total_tokens", 0),
    }

    return {
        "id": resp_id,
        "object": "response",
        "created_at": int(time.time()),
        "status": "completed",
        "model": model,
        "output": output,
        "usage": usage,
    }


def _sse_event(event_type: str, data: dict) -> str:
    payload = json.dumps({"type": event_type, **data})
    return f"event: {event_type}\ndata: {payload}\n\n"


# --- Routes ---

@app.api_route("/session/{session_id}/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_with_session(request: Request, session_id: str, path: str):
    """Route with session ID for per-container tracking."""
    return await _do_proxy(request, path, session_id)


@app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_bare(request: Request, path: str):
    """Route without session ID (uses source IP as fallback)."""
    source_ip = request.client.host if request.client else "unknown"
    return await _do_proxy(request, path, f"ip-{source_ip}")


async def _do_proxy(request: Request, path: str, session_id: str):
    body = await request.body()
    headers = dict(request.headers)
    headers.pop("host", None)

    request_id = str(uuid.uuid4())[:8]
    request_body = {}
    try:
        request_body = json.loads(body) if body else {}
    except json.JSONDecodeError:
        pass

    model = request_body.get("model", "unknown")
    if "/" in model and model != "unknown":
        request_body["model"] = model.split("/", 1)[-1]

    # Detect if this is a Responses API request
    is_responses = "responses" in path and request.method == "POST"

    if is_responses:
        return await _handle_responses_api(request_body, headers, session_id, request_id, model)

    # Regular proxy (Chat Completions or Anthropic)
    url = f"{UPSTREAM_URL}/{path}"

    for unsupported_key in ("thinking", "context_management", "output_config", "metadata"):
        request_body.pop(unsupported_key, None)

    is_openai = "chat/completions" in path
    if is_openai and request_body.get("stream"):
        if "stream_options" not in request_body:
            request_body["stream_options"] = {"include_usage": True}
        else:
            request_body["stream_options"]["include_usage"] = True

    if not is_openai:
        headers.setdefault("anthropic-beta", "prompt-caching-2024-07-31")

    body = json.dumps(request_body).encode()
    headers.pop("content-length", None)
    stream = request_body.get("stream", False)
    t0 = time.time()

    if stream:
        client = httpx.AsyncClient(timeout=300.0)
        upstream_req = client.build_request(
            method=request.method, url=url, headers=headers, content=body,
        )
        upstream_resp = await client.send(upstream_req, stream=True)

        usage_data: dict = {}
        output_text_chars = 0

        async def generate():
            nonlocal usage_data, output_text_chars
            try:
                async for chunk in upstream_resp.aiter_bytes():
                    for line in chunk.decode("utf-8", errors="ignore").split("\n"):
                        if not line.startswith("data: "):
                            continue
                        data_str = line[6:].strip()
                        if data_str == "[DONE]":
                            continue
                        try:
                            event = json.loads(data_str)
                            if is_openai:
                                u = event.get("usage")
                                if u and isinstance(u, dict) and u.get("total_tokens", 0) > 0:
                                    usage_data = u
                                choices = event.get("choices", [])
                                for c in choices:
                                    delta = c.get("delta", {})
                                    text = delta.get("content", "")
                                    if text:
                                        output_text_chars += len(text)
                            else:
                                evt_type = event.get("type", "")
                                if evt_type == "message_start":
                                    u = event.get("message", {}).get("usage", {})
                                    if u.get("input_tokens", 0) > 0:
                                        usage_data = u
                                elif evt_type == "message_delta":
                                    u = event.get("usage", {})
                                    if u.get("output_tokens", 0) > 0:
                                        usage_data.update(u)
                                elif evt_type == "content_block_delta":
                                    text = event.get("delta", {}).get("text", "")
                                    output_text_chars += len(text)
                        except json.JSONDecodeError:
                            pass
                    yield chunk
            finally:
                await upstream_resp.aclose()
                await client.aclose()
                _log_proxy_usage(usage_data, output_text_chars, request_body,
                                 session_id, request_id, model, True, t0, is_openai)

        return StreamingResponse(
            generate(),
            status_code=upstream_resp.status_code,
            media_type="text/event-stream",
        )
    else:
        async with httpx.AsyncClient(timeout=300.0) as client:
            resp = await client.request(
                method=request.method, url=url, headers=headers, content=body,
            )

        usage_data = {}
        try:
            resp_json = resp.json()
            usage_data = resp_json.get("usage", {})
        except (json.JSONDecodeError, ValueError):
            pass

        _log_proxy_usage(usage_data, 0, request_body,
                         session_id, request_id, model, False, t0, is_openai)

        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=dict(resp.headers),
        )


async def _handle_responses_api(request_body: dict, headers: dict,
                                session_id: str, request_id: str, model: str):
    """Translate Responses API → Chat Completions, call upstream, translate back."""
    t0 = time.time()

    messages = _responses_input_to_messages(request_body.get("input", []))
    instructions = request_body.get("instructions")
    if instructions:
        messages.insert(0, {"role": "system", "content": instructions})

    is_stream = request_body.get("stream", False)

    cc_body: dict = {
        "model": request_body.get("model", "gpt-4.1"),
        "messages": messages,
        "stream": is_stream,
    }
    if is_stream:
        cc_body["stream_options"] = {"include_usage": True}

    tools = _convert_tools(request_body.get("tools"))
    if tools:
        cc_body["tools"] = tools

    if request_body.get("temperature") is not None:
        cc_body["temperature"] = request_body["temperature"]
    if request_body.get("max_output_tokens") is not None:
        cc_body["max_tokens"] = request_body["max_output_tokens"]

    url = f"{UPSTREAM_URL}/chat/completions"
    body = json.dumps(cc_body).encode()
    fwd_headers = {
        "content-type": "application/json",
        "authorization": headers.get("authorization", ""),
    }

    if is_stream:
        client = httpx.AsyncClient(timeout=600.0)
        upstream_req = client.build_request(method="POST", url=url, headers=fwd_headers, content=body)
        upstream_resp = await client.send(upstream_req, stream=True)

        usage_data: dict = {}
        resp_id = f"resp_{uuid.uuid4().hex[:24]}"
        msg_id = f"msg_{uuid.uuid4().hex[:24]}"

        async def generate_responses_stream():
            nonlocal usage_data
            item_added = False
            full_text = ""
            fc_buffers: dict = {}

            yield _sse_event("response.created", {"response": {
                "id": resp_id, "object": "response", "status": "in_progress",
                "model": model, "output": [], "usage": {},
            }})

            try:
                async for chunk in upstream_resp.aiter_bytes():
                    for line in chunk.decode("utf-8", errors="ignore").split("\n"):
                        if not line.startswith("data: "):
                            if line.strip() == "data: [DONE]":
                                break
                            continue
                        data_str = line[6:].strip()
                        if data_str == "[DONE]":
                            break
                        try:
                            event = json.loads(data_str)
                        except json.JSONDecodeError:
                            continue

                        cc_usage = event.get("usage")
                        if cc_usage:
                            usage_data = cc_usage

                        for choice in event.get("choices", []):
                            delta = choice.get("delta", {})

                            text = delta.get("content")
                            if text:
                                if not item_added:
                                    yield _sse_event("response.output_item.added", {
                                        "output_index": 0,
                                        "item": {"type": "message", "id": msg_id,
                                                 "role": "assistant", "content": []},
                                    })
                                    yield _sse_event("response.content_part.added", {
                                        "output_index": 0, "content_index": 0,
                                        "part": {"type": "output_text", "text": ""},
                                    })
                                    item_added = True
                                full_text += text
                                yield _sse_event("response.output_text.delta", {
                                    "output_index": 0, "content_index": 0, "delta": text,
                                })

                            tool_calls = delta.get("tool_calls")
                            if tool_calls:
                                for tc in tool_calls:
                                    tc_id = tc.get("id")
                                    if tc_id and tc_id not in fc_buffers:
                                        fc_buffers[tc_id] = {
                                            "name": tc.get("function", {}).get("name", ""),
                                            "arguments": "",
                                        }
                                    args_delta = tc.get("function", {}).get("arguments", "")
                                    if args_delta:
                                        target_id = tc_id or (list(fc_buffers.keys())[-1] if fc_buffers else None)
                                        if target_id and target_id in fc_buffers:
                                            fc_buffers[target_id]["arguments"] += args_delta
            finally:
                await upstream_resp.aclose()
                await client.aclose()

            # Emit done events
            output = []
            out_idx = 0
            if item_added:
                yield _sse_event("response.output_text.done", {
                    "output_index": 0, "content_index": 0, "text": full_text,
                })
                yield _sse_event("response.content_part.done", {
                    "output_index": 0, "content_index": 0,
                    "part": {"type": "output_text", "text": full_text},
                })
                msg_item = {"type": "message", "id": msg_id, "role": "assistant",
                            "content": [{"type": "output_text", "text": full_text}]}
                yield _sse_event("response.output_item.done", {
                    "output_index": 0, "item": msg_item,
                })
                output.append(msg_item)
                out_idx = 1

            for call_id, fc in fc_buffers.items():
                fc_item = {
                    "type": "function_call",
                    "id": f"fc_{uuid.uuid4().hex[:24]}",
                    "call_id": call_id,
                    "name": fc["name"],
                    "arguments": fc["arguments"],
                }
                yield _sse_event("response.output_item.added", {
                    "output_index": out_idx, "item": fc_item,
                })
                yield _sse_event("response.output_item.done", {
                    "output_index": out_idx, "item": fc_item,
                })
                output.append(fc_item)
                out_idx += 1

            resp_usage = {
                "input_tokens": usage_data.get("prompt_tokens", 0),
                "output_tokens": usage_data.get("completion_tokens", 0),
                "total_tokens": usage_data.get("total_tokens", 0),
            }
            yield _sse_event("response.completed", {"response": {
                "id": resp_id, "object": "response", "status": "completed",
                "model": model, "output": output, "usage": resp_usage,
            }})

            _log_usage({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "session_id": session_id,
                "request_id": request_id,
                "model": model,
                "stream": True,
                "elapsed_sec": round(time.time() - t0, 2),
                "input_tokens": usage_data.get("prompt_tokens", 0),
                "output_tokens": usage_data.get("completion_tokens", 0),
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": (usage_data.get("prompt_tokens_details") or {}).get("cached_tokens", 0),
            })

        return StreamingResponse(
            generate_responses_stream(),
            status_code=200,
            media_type="text/event-stream",
        )
    else:
        # Non-streaming responses
        async with httpx.AsyncClient(timeout=600.0) as client:
            resp = await client.post(url, headers=fwd_headers, content=body)

        if resp.status_code != 200:
            return Response(content=resp.content, status_code=resp.status_code,
                            headers=dict(resp.headers))

        cc_data = resp.json()
        result = _cc_response_to_responses(cc_data, request_body.get("model", model))

        cc_usage = cc_data.get("usage", {})
        _log_usage({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "request_id": request_id,
            "model": model,
            "stream": False,
            "elapsed_sec": round(time.time() - t0, 2),
            "input_tokens": cc_usage.get("prompt_tokens", 0),
            "output_tokens": cc_usage.get("completion_tokens", 0),
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": (cc_usage.get("prompt_tokens_details") or {}).get("cached_tokens", 0),
        })

        return Response(
            content=json.dumps(result).encode(),
            status_code=200,
            media_type="application/json",
        )


def _log_proxy_usage(usage_data: dict, output_text_chars: int, request_body: dict,
                     session_id: str, request_id: str, model: str,
                     stream: bool, t0: float, is_openai: bool):
    elapsed = time.time() - t0
    input_tokens = usage_data.get("input_tokens", 0) or usage_data.get("prompt_tokens", 0)
    output_tokens = usage_data.get("output_tokens", 0) or usage_data.get("completion_tokens", 0)
    if output_tokens == 0 and output_text_chars > 0:
        output_tokens = max(1, output_text_chars // 4)
    if input_tokens == 0 and request_body.get("messages"):
        input_text = json.dumps(request_body["messages"])
        input_tokens = max(1, len(input_text) // 4)

    cache_creation = usage_data.get("cache_creation_input_tokens", 0)
    cache_read = usage_data.get("cache_read_input_tokens", 0)
    input_details = usage_data.get("input_tokens_details") or usage_data.get("prompt_tokens_details") or {}
    if isinstance(input_details, dict):
        openai_cached = input_details.get("cached_tokens", 0)
        if openai_cached and not cache_read:
            cache_read = openai_cached

    _log_usage({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "request_id": request_id,
        "model": model,
        "stream": stream,
        "elapsed_sec": round(elapsed, 2),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cache_creation_input_tokens": cache_creation,
        "cache_read_input_tokens": cache_read,
    })


# Reject WebSocket upgrades so Codex falls back to HTTP Responses API quickly
@app.websocket("/v1/{path:path}")
async def ws_reject(ws: WebSocket, path: str):
    await ws.close(code=1008, reason="WebSocket not supported, use HTTP")


@app.get("/health")
async def health():
    return {"status": "ok", "upstream": UPSTREAM_URL}


@app.get("/stats")
async def stats():
    """Return aggregated token stats from the log, grouped by session."""
    if not LOG_PATH.exists():
        return {"total_requests": 0}

    total_input = 0
    total_output = 0
    total_cache_creation = 0
    total_cache_read = 0
    total_requests = 0
    by_session: dict[str, dict] = {}
    by_model: dict[str, dict] = {}

    for line in LOG_PATH.read_text().splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        total_requests += 1
        inp = entry.get("input_tokens", 0)
        out = entry.get("output_tokens", 0)
        cc = entry.get("cache_creation_input_tokens", 0)
        cr = entry.get("cache_read_input_tokens", 0)
        total_input += inp
        total_output += out
        total_cache_creation += cc
        total_cache_read += cr

        session = entry.get("session_id", "unknown")
        if session not in by_session:
            by_session[session] = {"requests": 0, "input_tokens": 0, "output_tokens": 0,
                                   "cache_creation": 0, "cache_read": 0,
                                   "first_seen": entry.get("timestamp"), "last_seen": entry.get("timestamp")}
        by_session[session]["requests"] += 1
        by_session[session]["input_tokens"] += inp
        by_session[session]["output_tokens"] += out
        by_session[session]["cache_creation"] += cc
        by_session[session]["cache_read"] += cr
        by_session[session]["last_seen"] = entry.get("timestamp")

        model_name = entry.get("model", "unknown")
        if model_name not in by_model:
            by_model[model_name] = {"requests": 0, "input_tokens": 0, "output_tokens": 0,
                               "cache_creation": 0, "cache_read": 0}
        by_model[model_name]["requests"] += 1
        by_model[model_name]["input_tokens"] += inp
        by_model[model_name]["output_tokens"] += out
        by_model[model_name]["cache_creation"] += cc
        by_model[model_name]["cache_read"] += cr

    return {
        "total_requests": total_requests,
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "total_cache_creation_tokens": total_cache_creation,
        "total_cache_read_tokens": total_cache_read,
        "by_session": by_session,
        "by_model": by_model,
    }


def main():
    global UPSTREAM_URL, LOG_PATH

    parser = argparse.ArgumentParser(description="API token-logging proxy with Responses API translation")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--upstream", default="http://api.example.com/v1",
                        help="Upstream API base URL")
    parser.add_argument("--log", default="data/eval/token_log.jsonl",
                        help="Path to JSONL token log file")
    args = parser.parse_args()

    UPSTREAM_URL = args.upstream.rstrip("/")
    if UPSTREAM_URL.endswith("/v1"):
        UPSTREAM_URL = UPSTREAM_URL[:-3]
    UPSTREAM_URL = UPSTREAM_URL + "/v1"

    LOG_PATH = Path(args.log)
    print(f"Token proxy starting on {args.host}:{args.port}")
    print(f"Upstream: {UPSTREAM_URL}")
    print(f"Log: {LOG_PATH}")
    print("Responses API translation: enabled (→ chat/completions)")

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
