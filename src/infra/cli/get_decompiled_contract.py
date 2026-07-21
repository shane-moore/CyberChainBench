#!/usr/bin/env python3
"""Fetch contract bytecode (creation + runtime) and decompile via ethervm.io."""

from __future__ import annotations

import argparse
import json
import re
import urllib.parse
import urllib.request
from pathlib import Path

from infra.chain.metadata import lookup_contract_creation, lookup_runtime_code


def _decompile_via_ethervm(bytecode: str, timeout: int = 120) -> str:
    """POST bytecode to ethervm.io/decompile and extract pseudo-Solidity from HTML response."""
    code = bytecode.strip()
    if not code:
        return ""

    data = urllib.parse.urlencode({"bytecode": code}).encode()
    req = urllib.request.Request("https://ethervm.io/decompile", data=data)
    req.add_header("User-Agent", "Web3Bug-Benchmark/1.0")

    with urllib.request.urlopen(req, timeout=timeout) as resp:
        html = resp.read().decode()

    def _html_to_text(s: str) -> str:
        s = re.sub(r'<[^>]+>', '', s)
        s = s.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
        s = s.replace('&nbsp;', ' ').replace('&#39;', "'").replace('&quot;', '"')
        return s

    sections: list[str] = []

    # Extract public methods dispatch table
    methods_start = html.find('>Public Methods<')
    if methods_start < 0:
        methods_start = html.find('Public Methods')
    internal_start = html.find('>Internal Methods<')
    if internal_start < 0:
        internal_start = html.find('Internal Methods')

    if methods_start > 0 and internal_start > methods_start:
        methods_clean = _html_to_text(html[methods_start:internal_start])
        sections.append("// " + methods_clean.strip().replace('\n', '\n// '))

    # Extract function bodies (after <a class="anchor" name="func_..."> tags)
    func_anchors = list(re.finditer(r'<a[^>]*name="func_([^"]+)"[^>]*></a>\s*', html))
    if func_anchors:
        for i, match in enumerate(func_anchors):
            start = match.end()
            end = func_anchors[i + 1].start() if i + 1 < len(func_anchors) else start + 10000
            func_html = html[start:end]
            func_text = _html_to_text(func_html).strip()
            if func_text:
                sections.append(func_text)

    return "\n\n".join(sections) if sections else ""


def _write_artifacts(output_dir: Path, artifacts: dict[str, str]) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}
    for name, content in artifacts.items():
        target = output_dir / name
        target.write_text(content + ("\n" if content and not content.endswith("\n") else ""))
        written[name] = str(target)
    return written


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch contract bytecode and decompile via ethervm.io"
    )
    parser.add_argument(
        "--chain", required=True, help="Normalized chain name, e.g. ethereum or bsc"
    )
    parser.add_argument("--address", required=True, help="Target contract address")
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Output directory for bytecode and decompiled text",
    )
    parser.add_argument(
        "--timeout", type=int, default=120, help="Timeout for ethervm.io request"
    )
    args = parser.parse_args()

    output_dir = args.output_dir
    artifacts: dict[str, str] = {}
    decompiled_parts: list[str] = []

    # 1. Get and decompile creation code (contains constructor + storage init)
    creation_payload = lookup_contract_creation(args.chain, args.address)
    creation_bytecode = str(creation_payload.get("creation_bytecode", "")).strip() if creation_payload.get("ok") else ""

    if creation_bytecode.startswith("0x") and len(creation_bytecode) > 2:
        artifacts["creation_bytecode.hex"] = creation_bytecode
        creation_decompiled = _decompile_via_ethervm(creation_bytecode, timeout=args.timeout)
        if creation_decompiled:
            artifacts["creation_decompiled.txt"] = creation_decompiled
            decompiled_parts.append("// ========== CONSTRUCTOR (creation code) ==========\n")
            decompiled_parts.append(creation_decompiled)
            decompiled_parts.append("\n\n")

    # 2. Get and decompile runtime code (contains actual contract logic)
    runtime_bytecode = lookup_runtime_code(args.chain, args.address)

    if not runtime_bytecode or len(runtime_bytecode) <= 2:
        if not creation_bytecode:
            raise SystemExit(f"Failed to fetch bytecode for {args.address} on {args.chain}")
    else:
        artifacts["runtime_bytecode.hex"] = runtime_bytecode
        runtime_decompiled = _decompile_via_ethervm(runtime_bytecode, timeout=args.timeout)
        if runtime_decompiled:
            artifacts["runtime_decompiled.txt"] = runtime_decompiled
            decompiled_parts.append("// ========== CONTRACT LOGIC (runtime code) ==========\n")
            decompiled_parts.append(runtime_decompiled)

    if not decompiled_parts:
        raise SystemExit("Failed to decompile bytecode via ethervm.io")

    # 3. Write combined decompiled output
    combined = "\n".join(decompiled_parts)
    artifacts["decompiled.txt"] = combined

    written = _write_artifacts(output_dir, artifacts)

    result = {
        "ok": True,
        "chain": args.chain,
        "address": args.address,
        "artifact_mode": "ethervm",
        "has_creation": bool(creation_bytecode),
        "has_runtime": bool(runtime_bytecode and len(runtime_bytecode) > 2),
        "decompiled": True,
        "paths": written,
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
