#!/usr/bin/env python3
"""Fetch a transaction call trace by tx hash via chain RPC."""

from __future__ import annotations

import argparse
import json
from typing import Any

from infra.chain.metadata import lookup_transaction_trace

INPUT_SELECTOR_LEN = 10  # "0x" + 4-byte selector


def _slim_node(node: dict[str, Any]) -> dict[str, Any]:
    """Strip gas fields, truncate input to selector, drop zero-value and empty output."""
    out: dict[str, Any] = {}
    out["to"] = node.get("to", "")
    call_type = node.get("type", "CALL")
    if call_type != "CALL":
        out["type"] = call_type

    raw_input = node.get("input", "")
    if raw_input and len(raw_input) > INPUT_SELECTOR_LEN:
        out["input"] = raw_input[:INPUT_SELECTOR_LEN]
    elif raw_input:
        out["input"] = raw_input

    error = node.get("error")
    if error:
        out["error"] = error
    revert = node.get("revertReason")
    if revert:
        out["revertReason"] = revert

    children = node.get("calls")
    if children:
        out["calls"] = [_slim_node(c) for c in children]

    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch a transaction call trace by hash")
    parser.add_argument(
        "--chain", required=True, help="Normalized chain name, e.g. ethereum or bsc"
    )
    parser.add_argument("--tx-hash", required=True, help="Transaction hash")
    parser.add_argument(
        "--trace-timeout",
        default="20s",
        help="RPC trace timeout hint passed to debug_traceTransaction",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Output full trace without slimming",
    )
    args = parser.parse_args()

    payload = lookup_transaction_trace(args.chain, args.tx_hash, trace_timeout=args.trace_timeout)
    if not payload.get("ok"):
        raise SystemExit(str(payload.get("error", "failed to fetch transaction trace")))

    if not args.raw and "trace" in payload:
        slim = _slim_node(payload["trace"])
        slim["from"] = payload["trace"].get("from", "")
        payload["trace"] = slim

    print(json.dumps(payload, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
