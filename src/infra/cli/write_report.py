#!/usr/bin/env python3
"""Write a validated task report JSON to disk."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _parse_bool(value: str) -> bool:
    lowered = str(value).strip().lower()
    if lowered in {"true", "1", "yes", "y"}:
        return True
    if lowered in {"false", "0", "no", "n"}:
        return False
    raise argparse.ArgumentTypeError(f"invalid boolean: {value}")


def _write(output_path: Path, payload: dict[str, object]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="Write a validated task report JSON to disk")
    parser.add_argument("--task", required=True, choices=["detect", "exploit", "patch", "fix"])
    parser.add_argument("--output-path", type=Path, required=True)

    parser.add_argument("--summary", default="")
    parser.add_argument("--blocker", default="")

    parser.add_argument("--vulnerable", type=_parse_bool)
    parser.add_argument("--type")
    parser.add_argument("--file")
    parser.add_argument("--function")
    parser.add_argument("--description")

    parser.add_argument("--poc-written", type=_parse_bool)
    parser.add_argument("--validation-passed", type=_parse_bool)
    parser.add_argument("--exploit-path")

    parser.add_argument("--fixable", type=_parse_bool)
    parser.add_argument("--proxy-address", default="")
    parser.add_argument("--rationale", default="")
    parser.add_argument("--fixed-contract-path")
    args = parser.parse_args()

    if args.task == "detect":
        if args.vulnerable is None:
            raise SystemExit("detect report requires --vulnerable")
        if args.vulnerable:
            required = {
                "--type": args.type,
                "--file": args.file,
                "--function": args.function,
                "--description": args.description,
            }
            missing = [name for name, value in required.items() if not str(value or "").strip()]
            if missing:
                raise SystemExit("detect report missing required fields: " + ", ".join(missing))
            payload = {
                "vulnerable": True,
                "type": str(args.type),
                "file": str(args.file),
                "function": str(args.function),
                "description": str(args.description),
            }
        else:
            payload = {
                "vulnerable": False,
                "type": "",
                "file": "",
                "function": "",
                "description": "",
            }
        _write(args.output_path, payload)
        return

    if args.task == "exploit":
        if args.poc_written is None or args.validation_passed is None or not str(args.exploit_path or "").strip():
            raise SystemExit(
                "exploit report requires --poc-written, --validation-passed, and --exploit-path"
            )
        _write(
            args.output_path,
            {
                "poc_written": args.poc_written,
                "validation_passed": args.validation_passed,
                "exploit_path": args.exploit_path,
                "summary": args.summary,
            },
        )
        return

    if args.fixable is None:
        raise SystemExit("patch report requires --fixable")
    fixed_path = str(args.fixed_contract_path or "").strip()
    if args.fixable and not fixed_path:
        raise SystemExit("patch report requires --fixed-contract-path when --fixable true")
    _write(
        args.output_path,
        {
            "fixable": args.fixable,
            "proxy_address": args.proxy_address,
            "rationale": args.rationale,
            "fixed_contract_path": fixed_path,
            "summary": args.summary or args.blocker,
        },
    )


if __name__ == "__main__":
    main()
