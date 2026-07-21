"""Contract and source-loading helpers for benchmark runner tasks."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from benchmark.tasks.patch.case import PatchCase as FixCase


def _extract_interfaces_from_exploit(exploit_code: str) -> str:
    """Strip contract bodies, keep interface definitions and header comments."""
    lines = exploit_code.split("\n")
    kept: list[str] = []
    in_contract = False
    brace_depth = 0

    for line in lines:
        if not in_contract:
            if line.lstrip().startswith("contract "):
                in_contract = True
                brace_depth = line.count("{") - line.count("}")
                continue
            kept.append(line)
        else:
            brace_depth += line.count("{") - line.count("}")
            if brace_depth <= 0:
                in_contract = False

    return "\n".join(kept)


def _verified_source_files(payload: dict[str, object]) -> dict[str, str]:
    source_files = payload.get("source_files", {})
    if not isinstance(source_files, dict):
        return {}
    result: dict[str, str] = {}
    for path, content in source_files.items():
        text = str(content)
        if not text.strip():
            continue
        result[Path(str(path)).name] = text
    return result


def _is_clara_code_analysis_input(case: Any) -> bool:
    if getattr(case, "source", "") != "Clara":
        return False
    vulnerable_paths = getattr(case, "contracts", {}).get("vulnerable", []) or []
    for raw_path in vulnerable_paths:
        text = str(raw_path).replace("\\", "/").strip()
        if "Clara/code_analysis/" in text:
            return True
    return False


def _get_contract_code(
    case: Any,
    base_dir: Path,
    *,
    note: Callable[[str], None] | None = None,
) -> dict[str, str]:
    contract_code = case.get_vulnerable_code(base_dir)

    if contract_code and _is_clara_code_analysis_input(case):
        if note is not None:
            note("  [dim]skipping Clara code_analysis PoC for exploit input[/dim]")
        return {}

    if case.source == "DeFiHackLabs":
        exploit_src = case.get_exploit_code(base_dir)
        if exploit_src:
            iface_code = _extract_interfaces_from_exploit(exploit_src)
            if iface_code.strip():
                if contract_code:
                    contract_code["interfaces.sol"] = iface_code
                else:
                    contract_code = {"interfaces.sol": iface_code}
                if note is not None:
                    note("  [dim]using interface defs from exploit file[/dim]")

    return contract_code


def _expected_fix_targets(
    case: FixCase,
    contract_code: dict[str, str],
    proxy_info: dict[str, object] | None = None,
) -> list[str]:
    expected: list[str] = []
    ignored = {"interfaces", "interfaces.sol"}

    def _push(value: str) -> None:
        text = str(value or "").strip()
        if text and text not in expected:
            expected.append(text)

    raw = getattr(case, "raw", {}) or {}
    _push(str(raw.get("target_contract_name", "")).strip())
    for name in contract_code:
        basename = Path(name).name
        if basename.lower() in ignored:
            continue
        _push(basename)
        if basename.endswith(".sol"):
            stem = basename[:-4]
            if stem.lower() not in ignored:
                _push(stem)

    if proxy_info:
        for key in ("implementation", "beacon_implementation", "minimal_proxy_target"):
            _push(str(proxy_info.get(key, "")).strip())

    return expected


def _lookup_fix_proxy_info(
    case: FixCase,
    *,
    lookup_proxy_info_fn: Callable[[str, str, object], dict[str, object]],
) -> dict[str, object] | None:
    proxy_address = str((case.remediation or {}).get("proxy_address", "")).strip()
    vulnerable_address = str(
        case.contracts.get("vulnerable_address", "")
        or case.ground_truth.get("vulnerable_address", "")
    ).strip()
    lookup_address = proxy_address or vulnerable_address
    if not lookup_address:
        return None

    chain = (
        str(
            case.chain_context.get("fork_chain", "")
            or case.chain_context.get("chain", "")
            or case.chain
        ).strip()
        or "ethereum"
    )
    block = case.chain_context.get("fork_block")
    if block is None:
        block = case.chain_context.get("block")

    try:
        info = lookup_proxy_info_fn(chain, lookup_address, block)
    except Exception as exc:
        return {
            "ok": False,
            "chain": chain,
            "address": lookup_address,
            "block": block if block not in (None, "") else "latest",
            "proxy_detected": False,
            "proxy_kind": "",
            "implementation": "",
            "beacon_implementation": "",
            "minimal_proxy_target": "",
            "admin": "",
            "notes": [f"proxy lookup failed: {exc}"],
            "error": str(exc),
        }
    if isinstance(info, dict) and proxy_address and vulnerable_address:
        info = dict(info)
        info.setdefault("proxy_address", proxy_address)
        if not str(info.get("implementation", "")).strip():
            info["implementation"] = vulnerable_address
    return info


def _get_fix_contract_code(
    case: FixCase,
    base_dir: Path,
    proxy_info: dict[str, object] | None = None,
    *,
    lookup_verified_source_fn: Callable[[str, str], dict[str, object]],
    note: Callable[[str], None] | None = None,
) -> dict[str, str]:
    contract_code = case.get_vulnerable_code(base_dir)
    raw = getattr(case, "raw", {}) or {}
    target_contract_name = str(raw.get("target_contract_name", "")).strip()

    chain = (
        str(
            case.chain_context.get("fork_chain", "")
            or case.chain_context.get("chain", "")
            or case.chain
        ).strip()
        or "ethereum"
    )

    candidate_addresses: list[str] = []
    vulnerable_address = str(case.contracts.get("vulnerable_address", "")).strip()
    if vulnerable_address:
        candidate_addresses.append(vulnerable_address)
    if proxy_info:
        implementation_address = str(
            proxy_info.get("implementation")
            or proxy_info.get("beacon_implementation")
            or proxy_info.get("minimal_proxy_target")
            or ""
        ).strip()
        if implementation_address and implementation_address not in candidate_addresses:
            candidate_addresses.append(implementation_address)

    for address in candidate_addresses:
        try:
            verified = lookup_verified_source_fn(chain, address)
        except Exception:
            verified = {}
        implementation_sources = _verified_source_files(verified)
        if implementation_sources:
            contract_names = {Path(name).stem for name in contract_code}
            should_replace = not contract_code or (
                bool(target_contract_name) and target_contract_name not in contract_names
            )
            if should_replace:
                contract_code = implementation_sources
                if note is not None:
                    lane = "implementation" if address != vulnerable_address else "vulnerable"
                    note(f"  [dim]using {lane} verified source from address {address}[/dim]")
                break

    if contract_code and case.source == "DeFiHackLabs":
        exploit_src = case.get_exploit_code(base_dir)
        if exploit_src:
            iface_code = _extract_interfaces_from_exploit(exploit_src)
            if iface_code.strip():
                contract_code.setdefault("interfaces.sol", iface_code)
                if note is not None:
                    note("  [dim]using interface defs from exploit file[/dim]")

    return contract_code
