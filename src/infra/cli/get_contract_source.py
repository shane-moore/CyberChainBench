#!/usr/bin/env python3
"""Fetch verified source files for a contract from an Etherscan-family explorer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from infra.chain.metadata import lookup_verified_source


def _sanitize_filename(filename: str) -> str:
    return filename.replace("/", "_").replace("\\", "_")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch verified source files for a contract")
    parser.add_argument(
        "--chain", required=True, help="Normalized chain name, e.g. ethereum or bsc"
    )
    parser.add_argument("--address", required=True, help="Target contract address")
    parser.add_argument("--output-dir", type=Path, default=None, help="Optional output directory")
    args = parser.parse_args()

    payload = lookup_verified_source(args.chain, args.address)
    if not payload.get("ok"):
        raise SystemExit(str(payload.get("error", "failed to fetch verified source")))

    source_files = payload.get("source_files", {})
    if not isinstance(source_files, dict) or not source_files:
        raise SystemExit("verified source lookup returned no files")

    if args.output_dir is not None:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        saved_paths: dict[str, str] = {}
        for filename, content in source_files.items():
            out_path = args.output_dir / _sanitize_filename(str(filename))
            out_path.write_text(str(content) + ("\n" if not str(content).endswith("\n") else ""))
            saved_paths[str(filename)] = str(out_path)
        meta = {
            key: payload[key]
            for key in (
                "ok",
                "chain",
                "address",
                "contract_name",
                "compiler_version",
                "proxy_implementation",
            )
            if key in payload
        }
        meta["paths"] = saved_paths
        print(json.dumps(meta, indent=2, ensure_ascii=False))
        return

    print(json.dumps(payload, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
