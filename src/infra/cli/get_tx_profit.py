#!/usr/bin/env python3
"""Compute attacker token inflow from a historical transaction receipt."""

from __future__ import annotations

import argparse
import json

from infra.tx_profit_eth import lookup_tx_attacker_profit_eth


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compute attacker net ETH-equivalent profit from a transaction receipt"
    )
    parser.add_argument("--chain", required=True, help="Normalized chain name, e.g. ethereum or bsc")
    parser.add_argument("--tx-hash", required=True, help="Transaction hash")
    parser.add_argument(
        "--attacker-address",
        default="",
        help="Optional attacker address override. Defaults to tx.from",
    )
    args = parser.parse_args()

    payload = lookup_tx_attacker_profit_eth(
        args.chain,
        args.tx_hash,
    )
    if not payload.get("ok"):
        raise SystemExit(json.dumps(payload, indent=2, ensure_ascii=False))
    print(json.dumps(payload, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
