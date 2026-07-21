#!/usr/bin/env python3
"""Execute a read-only eth_call against a contract (view/pure functions)."""

from __future__ import annotations

import argparse
import json

from infra.chain.metadata import resolve_rpc_url, _json_rpc


def main() -> None:
    parser = argparse.ArgumentParser(description="Call a contract view function")
    parser.add_argument("--chain", required=True, help="Chain name (e.g. bsc, ethereum)")
    parser.add_argument("--to", required=True, help="Contract address")
    parser.add_argument("--data", required=True, help="Calldata hex (e.g. 0x70a08231000...)")
    parser.add_argument("--block", default="latest", help="Block number or 'latest'")
    args = parser.parse_args()

    rpc_url = resolve_rpc_url(args.chain)
    if not rpc_url:
        print(json.dumps({"ok": False, "error": f"no RPC configured for chain: {args.chain}"}))
        return

    block = args.block if args.block == "latest" else hex(int(args.block))
    result = _json_rpc(rpc_url, "eth_call", [{"to": args.to, "data": args.data}, block])

    if result and "result" in result:
        print(json.dumps({"ok": True, "result": result["result"]}))
    else:
        error = result.get("error", {}).get("message", "unknown error") if result else "RPC failed"
        print(json.dumps({"ok": False, "error": error}))


if __name__ == "__main__":
    main()
