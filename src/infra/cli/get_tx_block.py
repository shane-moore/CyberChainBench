#!/usr/bin/env python3
"""Read the block number for a historical transaction."""

from __future__ import annotations

import argparse
import json

from infra.chain.metadata import lookup_tx_block


def main() -> None:
    parser = argparse.ArgumentParser(description="Read the block number for a historical transaction")
    parser.add_argument("--chain", required=True, help="Normalized chain name, e.g. ethereum or bsc")
    parser.add_argument("--tx-hash", required=True, help="Transaction hash")
    args = parser.parse_args()

    block_number = lookup_tx_block(args.chain, args.tx_hash)
    if block_number is None:
        raise SystemExit("failed to resolve transaction block number; check chain and tx hash")
    print(json.dumps({"chain": args.chain, "tx_hash": args.tx_hash, "block_number": block_number}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
