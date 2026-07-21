"""Minimal reverse proxy that rejects WebSocket upgrades and forwards HTTP.

Codex CLI first attempts WebSocket, then falls back to HTTP Responses API.
If the upstream returns 401 for WebSocket (instead of connection refused),
Codex interprets it as an auth error and never falls back. This proxy
explicitly rejects WebSocket upgrades so Codex immediately uses HTTP.

Usage:
    python -m infra.ws_reject_proxy --port 8090 --upstream http://api.example.com/v1
"""

import argparse
import httpx
from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import StreamingResponse
import uvicorn

app = FastAPI()
UPSTREAM_URL: str = ""


@app.websocket("/v1/{path:path}")
async def ws_reject(ws: WebSocket, path: str):
    await ws.close(code=1008, reason="WebSocket not supported, use HTTP")


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy(request: Request, path: str):
    url = f"{UPSTREAM_URL.rstrip('/')}/{path}" if not UPSTREAM_URL.endswith(f"/{path}") else UPSTREAM_URL
    # Rebuild URL properly
    url = f"{UPSTREAM_URL.rstrip('/v1').rstrip('/')}/v1/{path}" if "/v1" in UPSTREAM_URL else f"{UPSTREAM_URL.rstrip('/')}/{path}"

    headers = dict(request.headers)
    headers.pop("host", None)
    body = await request.body()

    async with httpx.AsyncClient(timeout=300) as client:
        if "stream" in body.decode(errors="ignore") and '"stream":true' in body.decode(errors="ignore").replace(" ", "").lower():
            # Streaming response
            async def stream():
                async with client.stream(
                    request.method, url, headers=headers, content=body
                ) as resp:
                    async for chunk in resp.aiter_bytes():
                        yield chunk
            return StreamingResponse(stream(), media_type="text/event-stream")
        else:
            resp = await client.request(request.method, url, headers=headers, content=body)
            return StreamingResponse(
                iter([resp.content]),
                status_code=resp.status_code,
                headers=dict(resp.headers),
            )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--upstream", required=True)
    args = parser.parse_args()

    global UPSTREAM_URL
    UPSTREAM_URL = args.upstream

    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
