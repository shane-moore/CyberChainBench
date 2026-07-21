#!/usr/bin/env python3
"""Look up function/event selectors via OpenChain and 4byte.directory APIs."""

from __future__ import annotations

import argparse
import json
import urllib.request
import urllib.error


def _lookup_openchain(hex_signatures: list[str], sig_type: str) -> dict[str, list[str]]:
    """Batch lookup via OpenChain signature database."""
    param = "function" if sig_type == "function" else "event"
    joined = ",".join(hex_signatures)
    url = f"https://api.openchain.xyz/signature-database/v1/lookup?{param}={joined}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read())

    if not data.get("ok"):
        return {}

    result_key = "function" if sig_type == "function" else "event"
    raw = data.get("result", {}).get(result_key, {})
    out: dict[str, list[str]] = {}
    for selector, entries in raw.items():
        if entries:
            out[selector] = [e["name"] for e in entries if e.get("name")]
    return out


def _lookup_4byte(hex_signature: str, sig_type: str) -> list[str]:
    """Fallback: single lookup via 4byte.directory."""
    base = "https://www.4byte.directory/api/v1"
    endpoint = f"{base}/event-signatures/" if sig_type == "event" else f"{base}/signatures/"
    url = f"{endpoint}?hex_signature={hex_signature}&format=json"
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "web3bug-tools/1.0"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read())
    results = data.get("results", [])
    return [r["text_signature"] for r in results if "text_signature" in r]


def lookup(hex_signatures: list[str], sig_type: str = "function") -> dict[str, list[str]]:
    """Return matching text signatures for one or more hex selectors."""
    # Try OpenChain first (supports batch)
    try:
        result = _lookup_openchain(hex_signatures, sig_type)
    except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError):
        result = {}

    # Fallback to 4byte for any selectors not resolved
    for sel in hex_signatures:
        if sel not in result or not result[sel]:
            try:
                matches = _lookup_4byte(sel, sig_type)
                if matches:
                    result[sel] = matches
            except (urllib.error.URLError, OSError, json.JSONDecodeError):
                pass

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Look up function/event selectors via signature databases"
    )
    parser.add_argument(
        "--hex-signature",
        required=True,
        nargs="+",
        help="One or more hex selectors to look up, e.g. 0xa9059cbb 0x23b872dd",
    )
    parser.add_argument(
        "--type",
        choices=["function", "event"],
        default="function",
        help="Signature type: function (4-byte) or event (32-byte topic0)",
    )
    args = parser.parse_args()

    result = lookup(args.hex_signature, args.type)

    output: list[dict] = []
    for sel in args.hex_signature:
        output.append({
            "hex_signature": sel,
            "type": args.type,
            "matches": result.get(sel, []),
        })

    print(json.dumps(output, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
