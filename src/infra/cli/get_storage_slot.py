#!/usr/bin/env python3
"""Read a raw EVM storage slot via chain RPC."""

from __future__ import annotations

import argparse
import json
from infra.chain.metadata import lookup_storage_slot


def main() -> None:
    parser = argparse.ArgumentParser(description="Read a raw EVM storage slot via chain RPC")
    parser.add_argument(
        "--chain", required=True, help="Normalized chain name, e.g. ethereum or bsc"
    )
    parser.add_argument("--address", required=True, help="Target contract address")
    parser.add_argument("--slot", required=True, help="Storage slot index as hex or decimal")
    parser.add_argument("--block", type=int, default=None, help="Historical block number")
    args = parser.parse_args()

    value = lookup_storage_slot(args.chain, args.address, args.slot, args.block)
    if not value:
        raise SystemExit("failed to read storage slot; check RPC configuration and inputs")
    print(
        json.dumps(
            {
                "chain": args.chain,
                "address": args.address,
                "slot": args.slot,
                "block": args.block if args.block is not None else "latest",
                "value": value,
            },
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
