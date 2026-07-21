"""Build detect benchmark cases from raw parsed data."""

from __future__ import annotations

from pathlib import Path

from benchmark.annotation_hints import attach_annotation_hints
from benchmark.pipeline.case_links import derive_case_link
from benchmark.pipeline.defihacklabs.ground_truth import find_function_in_source
from benchmark.pipeline.defihacklabs.ground_truth import extract_location as dfhl_extract_location
from benchmark.pipeline.defihacklabs.chain_context import build_chain_context
from infra.chain.metadata import (
    load_dfhl_source_metadata,
    merge_cached_chain_context,
    resolve_dfhl_vulnerable_sources,
)
from project_layout import resolve_repo_path


def _load_source_files(base_dir: Path, vulnerable_paths: list[str]) -> dict[str, str]:
    source_files: dict[str, str] = {}
    for rel_path in vulnerable_paths:
        path = resolve_repo_path(base_dir, rel_path)
        if not path.exists() or path.suffix.lower() != ".sol":
            continue
        key = Path(rel_path).name
        if key in source_files:
            key = rel_path
        source_files[key] = path.read_text(errors="replace")
    return source_files


def _refine_dfhl_ground_truth(
    *,
    base_dir: Path,
    vulnerable_paths: list[str],
    ground_truth: dict,
    contract_name: str,
) -> None:
    function_name = str(ground_truth.get("function", "")).strip()
    if not function_name or not vulnerable_paths:
        return

    source_files = _load_source_files(base_dir, vulnerable_paths)
    if not source_files:
        return

    refined = find_function_in_source(
        source_files,
        function_name,
        contract_name=contract_name or None,
    )
    if not refined:
        return

    refined_file = str(refined.get("file", "")).strip()
    if refined_file:
        ground_truth["file"] = Path(refined_file).name


def _looks_like_dfhl_source_location(
    *,
    ground_truth: dict,
    source_files: dict[str, str],
    contract_name: str,
) -> bool:
    function_name = str(ground_truth.get("function", "")).strip()
    if not function_name or not source_files:
        return False

    current_file = Path(str(ground_truth.get("file", "")).strip()).name
    if current_file and current_file not in source_files:
        return False

    refined = find_function_in_source(
        source_files,
        function_name,
        contract_name=contract_name or None,
    )
    return refined is not None


def _recover_dfhl_ground_truth_from_exploit(
    *,
    base_dir: Path,
    exploit_path: str,
    vulnerable_paths: list[str],
    ground_truth: dict,
    contract_name: str,
) -> None:
    if not exploit_path or not vulnerable_paths:
        return

    source_files = _load_source_files(base_dir, vulnerable_paths)
    if not source_files:
        return

    if _looks_like_dfhl_source_location(
        ground_truth=ground_truth,
        source_files=source_files,
        contract_name=contract_name,
    ):
        _refine_dfhl_ground_truth(
            base_dir=base_dir,
            vulnerable_paths=vulnerable_paths,
            ground_truth=ground_truth,
            contract_name=contract_name,
        )
        return

    extracted = dfhl_extract_location(resolve_repo_path(base_dir, exploit_path))
    if not isinstance(extracted, dict):
        return

    function_name = str(extracted.get("function", "")).strip()
    if not function_name:
        return

    refined = find_function_in_source(
        source_files,
        function_name,
        contract_name=contract_name or None,
    )
    if not refined:
        return

    ground_truth["function"] = function_name
    refined_file = str(refined.get("file", "")).strip()
    if refined_file:
        ground_truth["file"] = Path(refined_file).name


def build_detect_case(
    raw: dict, base_dir: Path, context_cache: dict[str, dict] | None = None
) -> dict | None:
    """Build a detect benchmark case.

    Minimum requirement:
      - Some analyzable contract artifact:
          vulnerable source paths, exploit-derived interfaces, or a vulnerable
          address that can be resolved to runtime bytecode/disassembly
      - Ground truth type
      - At least one localization anchor among file / function
    """
    contracts = raw.get("contracts", {})
    vulnerability_detail = raw.get("vulnerability_detail", {}) or {}
    vulnerable_paths = contracts.get("vulnerable", [])
    fallback_paths = vulnerable_paths or (
        [contracts.get("exploit", "")] if contracts.get("exploit") else []
    )
    if raw.get("source") == "DeFiHackLabs":
        vulnerable_paths = resolve_dfhl_vulnerable_sources(
            raw["id"],
            base_dir,
            fallback_paths,
            chain=str(raw.get("chain", "")),
            address=str(contracts.get("vulnerable_address", "")),
        )
    has_source = bool(vulnerable_paths)
    has_exploit = bool(contracts.get("exploit"))
    has_bytecode_fallback = bool(str(contracts.get("vulnerable_address", "")).strip())

    if not has_source and not has_exploit and not has_bytecode_fallback:
        return None

    # Build ground truth from detect task + expected_location
    detect_task = raw.get("tasks", {}).get("detect", {})
    ground_truth: dict = {
        "type": detect_task.get("expected_type", raw.get("category", "")),
    }

    source_metadata = (
        load_dfhl_source_metadata(
            raw["id"],
            base_dir,
            chain=str(raw.get("chain", "")),
            address=str(contracts.get("vulnerable_address", "")),
        )
        if raw.get("source") == "DeFiHackLabs"
        else {}
    )

    # Add expected_location if already present
    loc = detect_task.get("expected_location")
    if isinstance(loc, dict):
        if loc.get("file"):
            ground_truth["file"] = loc["file"]
        if loc.get("function"):
            ground_truth["function"] = loc["function"]

    # Try to extract location if not present
    if "function" not in ground_truth:
        extracted = None
        if raw.get("source") == "DeFiHackLabs" and has_exploit:
            sol_path = resolve_repo_path(base_dir, contracts["exploit"])
            extracted = dfhl_extract_location(sol_path)
        if extracted:
            for k, v in extracted.items():
                if k not in ground_truth:
                    ground_truth[k] = v

    # Fallback filename from known contract paths.
    if not ground_truth.get("file"):
        vulns = vulnerable_paths or []
        if vulns:
            ground_truth["file"] = Path(vulns[0]).name
        elif contracts.get("exploit"):
            ground_truth["file"] = Path(str(contracts["exploit"])).name

    if source_metadata:
        if source_metadata.get("contract_name"):
            ground_truth["contract"] = str(source_metadata["contract_name"])
        _recover_dfhl_ground_truth_from_exploit(
            base_dir=base_dir,
            exploit_path=str(contracts.get("exploit", "")).strip(),
            vulnerable_paths=vulnerable_paths,
            ground_truth=ground_truth,
            contract_name=str(source_metadata.get("contract_name", "")).strip(),
        )

    # Detect task quality bar: allow partial localization because some real
    # incidents only expose file-level or function-level anchors. The evaluator
    # already normalizes scoring over the available dimensions.
    if not ground_truth.get("file") and not ground_truth.get("function"):
        return None

    complete_location = bool(ground_truth.get("file")) and bool(ground_truth.get("function"))

    exploit_path = str(contracts.get("exploit", "")).strip()
    full_chain_context = build_chain_context(
        resolve_repo_path(base_dir, exploit_path) if exploit_path else None,
        chain=raw.get("chain", ""),
        description=raw.get("description", ""),
        references=vulnerability_detail.get("references", []),
        vulnerable_address=contracts.get("vulnerable_address", ""),
        existing=raw.get("chain_context", {}),
    )
    full_chain_context = merge_cached_chain_context(
        raw["id"], full_chain_context, context_cache or {}
    )

    vulnerable_address = str(contracts.get("vulnerable_address", "")).strip()
    if not vulnerable_address:
        vulnerable_addresses = [
            str(item).strip()
            for item in full_chain_context.get("vulnerable_addresses", [])
            if str(item).strip()
        ]
        if vulnerable_addresses:
            vulnerable_address = vulnerable_addresses[0]

    if vulnerable_address:
        ground_truth["vulnerable_address"] = vulnerable_address

    allowed_ground_truth_keys = {
        "type",
        "vulnerable_address",
        "vulnerable_contract",
        "file",
        "contract",
        "function",
    }
    ground_truth = {
        key: value for key, value in ground_truth.items() if key in allowed_ground_truth_keys
    }

    result = {
        "id": raw["id"],
        "name": raw["name"],
        "source": raw["source"],
        "case_link": derive_case_link(raw),
        "category": raw.get("category", "") or str(ground_truth.get("type", "")).strip(),
        "chain": raw.get("chain", "") or str(full_chain_context.get("fork_chain", "")).strip(),
        "contracts": {
            "vulnerable": vulnerable_paths,
            "vulnerable_address": vulnerable_address,
        },
        "cross_chain": bool(raw.get("cross_chain", False)),
        "chains_involved": raw.get("chains_involved", []),
        "date": raw.get("date", ""),
        "description": raw.get("description", ""),
        "analysis_inputs": {
            "has_source": has_source,
        },
        "chain_context": {
            "chain": raw.get("chain", "") or str(full_chain_context.get("fork_chain", "")).strip(),
            "target_addresses": [vulnerable_address] if vulnerable_address else [],
        },
        "ground_truth": ground_truth,
        "ground_truth_quality": {
            "has_file": bool(ground_truth.get("file")),
            "has_function": bool(ground_truth.get("function")),
            "has_line": False,
            "complete_location": complete_location,
        },
    }
    return attach_annotation_hints("detect", result, raw_case=raw)
