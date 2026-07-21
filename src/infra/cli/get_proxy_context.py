"""Infer proxy/implementation context for an address from a single attack tx trace."""

from __future__ import annotations

import argparse
import json
import re
from typing import Any

from infra.chain.metadata import lookup_runtime_code, lookup_transaction_trace

_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")


def _is_library_contract(chain: str, address: str, block: object = None) -> bool:
    """Check if an address is a Solidity library (bytecode starts with PUSH20 <self> ADDRESS EQ)."""
    try:
        bytecode = lookup_runtime_code(chain, address, block)
        if not bytecode:
            return False
        prefix = "0x73" + address.lower()[2:] + "3014"
        return bytecode.lower().startswith(prefix)
    except Exception:
        return False


def _iter_nodes(trace: object) -> list[dict[str, object]]:
    if isinstance(trace, list):
        return [item for item in trace if isinstance(item, dict)]
    if not isinstance(trace, dict):
        return []
    nodes = [trace]
    calls = trace.get("calls", [])
    if isinstance(calls, list):
        for child in calls:
            nodes.extend(_iter_nodes(child))
    return nodes


def lookup_proxy_context(chain: str, address: str, tx_hash: str, *, trace_timeout: str = "10s") -> dict[str, Any]:
    tracked = str(address).strip()
    result: dict[str, Any] = {
        "ok": False,
        "chain": str(chain).strip(),
        "address": tracked,
        "tx_hash": str(tx_hash).strip(),
        "address_role": "",
        "proxy_address": "",
        "implementation_address": "",
        "fixable": False,
        "delegatecall_matches": [],
    }
    if not _ADDRESS_RE.fullmatch(tracked):
        result["error"] = "invalid address"
        return result
    payload = lookup_transaction_trace(chain, tx_hash, trace_timeout=trace_timeout)
    result["trace_ok"] = bool(payload.get("ok"))
    result["trace_method"] = str(payload.get("trace_method", "")).strip()
    if not payload.get("ok"):
        result["error"] = str(payload.get("error", "trace lookup failed")).strip() or "trace lookup failed"
        return result
    tracked_lower = tracked.lower()
    matches: list[dict[str, str]] = []
    for node in _iter_nodes(payload.get("trace")):
        call_type = str(node.get("type") or node.get("callType") or node.get("call_type") or "").strip().lower()
        if call_type != "delegatecall":
            continue
        from_addr = str(node.get("from") or "").strip()
        to_addr = str(node.get("to") or "").strip()
        if not _ADDRESS_RE.fullmatch(from_addr) or not _ADDRESS_RE.fullmatch(to_addr):
            continue
        from_lower = from_addr.lower()
        to_lower = to_addr.lower()
        chain_name = str(chain).strip()
        if from_lower == tracked_lower and to_lower != tracked_lower:
            if _is_library_contract(chain_name, to_addr):
                continue
            matches.append(
                {
                    "address_role": "proxy",
                    "proxy_address": from_addr,
                    "implementation_address": to_addr,
                    "call_type": call_type,
                }
            )
        elif to_lower == tracked_lower and from_lower != tracked_lower:
            if _is_library_contract(chain_name, to_addr):
                continue
            matches.append(
                {
                    "address_role": "implementation",
                    "proxy_address": from_addr,
                    "implementation_address": to_addr,
                    "call_type": call_type,
                }
            )
    result["delegatecall_matches"] = matches[:10]
    if matches:
        best = matches[0]
        result["address_role"] = best["address_role"]
        result["proxy_address"] = best["proxy_address"]
        result["implementation_address"] = best["implementation_address"]
        result["fixable"] = True
    result["ok"] = True
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Infer proxy/implementation context from one attack tx trace")
    parser.add_argument("--chain", required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--tx-hash", required=True)
    parser.add_argument("--trace-timeout", default="10s")
    args = parser.parse_args()
    payload = lookup_proxy_context(args.chain, args.address, args.tx_hash, trace_timeout=args.trace_timeout)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
