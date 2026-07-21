"""Build patch benchmark cases from raw parsed data."""

from __future__ import annotations

from pathlib import Path

from benchmark.annotation_hints import attach_annotation_hints
from benchmark.pipeline.case_links import derive_case_link
from benchmark.tasks.detect.builder import build_detect_case
from benchmark.tasks.exploit.builder import _merge_attack_tx_context
from benchmark.tasks.patch.remediation import normalize_fix_remediation
from benchmark.pipeline.defihacklabs.chain_context import build_chain_context, build_state_context
from infra.chain.metadata import (
    extract_case_attack_txs,
    load_dfhl_source_metadata,
    merge_cached_chain_context,
    resolve_dfhl_vulnerable_sources,
)
from project_layout import resolve_repo_path


def _normalize_fix_ground_truth(
    raw: dict, base_dir: Path, context_cache: dict[str, dict] | None
) -> tuple[dict, dict]:
    detect_case = build_detect_case(raw, base_dir, context_cache=context_cache)
    analysis_inputs = {"has_source": bool(raw.get("contracts", {}).get("vulnerable", []))}
    ground_truth = {
        "type": str(
            raw.get("tasks", {}).get("detect", {}).get("expected_type") or raw.get("category", "")
        ).strip()
    }

    if detect_case:
        analysis_inputs = dict(detect_case.get("analysis_inputs", {}) or analysis_inputs)
        ground_truth = dict(detect_case.get("ground_truth", {}) or ground_truth)

    location = raw.get("tasks", {}).get("detect", {}).get("expected_location")
    if isinstance(location, dict):
        if location.get("file") and not ground_truth.get("file"):
            ground_truth["file"] = location["file"]
        if location.get("function") and not ground_truth.get("function"):
            ground_truth["function"] = location["function"]
        line_range = location.get("line_range")
        if isinstance(line_range, list) and line_range and not ground_truth.get("line_range"):
            ground_truth["line_range"] = [int(item) for item in line_range if isinstance(item, int)]

    vulnerable_address = str(
        ground_truth.get("vulnerable_address", "")
        or ground_truth.get("vulnerable_contract", "")
        or raw.get("contracts", {}).get("vulnerable_address", "")
    ).strip()
    ground_truth.pop("vulnerable_contract", None)
    ground_truth.pop("line", None)
    if vulnerable_address:
        ground_truth["vulnerable_address"] = vulnerable_address

    return analysis_inputs, ground_truth


def build_patch_case(
    raw: dict, base_dir: Path, context_cache: dict[str, dict] | None = None
) -> dict | None:
    """Build a fix benchmark case.

    Requirement:
      - either a reusable verification exploit path, or
      - at least one historical attack transaction that can seed a replay-oriented
        fail-to-pass lane later

    Historical attack transactions remain useful annotation context, but the
    current runtime still gets the most reliable verification from an executable
    PoC when one is available.
    """
    contracts = raw.get("contracts", {})
    tasks = raw.get("tasks", {})
    vulnerability_detail = raw.get("vulnerability_detail", {}) or {}
    attack_txs = extract_case_attack_txs(raw)

    exploit_path = str(
        contracts.get("exploit")
        or tasks.get("exploit", {}).get("reference_exploit")
        or raw.get("reference_exploit", "")
    ).strip()
    if not exploit_path and not attack_txs:
        return None

    chain_context = build_chain_context(
        resolve_repo_path(base_dir, exploit_path) if exploit_path else None,
        chain=raw.get("chain", ""),
        description=raw.get("description", ""),
        references=vulnerability_detail.get("references", []),
        vulnerable_address=contracts.get("vulnerable_address", ""),
        existing=raw.get("chain_context", {}),
    )
    chain_context = merge_cached_chain_context(raw["id"], chain_context, context_cache or {})
    chain_context = _merge_attack_tx_context(raw, chain_context)
    state_context = build_state_context(
        resolve_repo_path(base_dir, exploit_path) if exploit_path else None,
        chain_context=chain_context,
        existing=raw.get("state_context", {}),
    )
    analysis_inputs, ground_truth = _normalize_fix_ground_truth(raw, base_dir, context_cache)
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
    vulnerable_address = str(
        ground_truth.get("vulnerable_address", "") or contracts.get("vulnerable_address", "")
    ).strip()
    if vulnerable_address and "vulnerable_address" not in ground_truth:
        ground_truth["vulnerable_address"] = vulnerable_address

    fallback_paths = contracts.get("vulnerable", []) or (
        [contracts.get("exploit", "")] if contracts.get("exploit") else []
    )
    vulnerable_paths = (
        resolve_dfhl_vulnerable_sources(
            raw["id"],
            base_dir,
            fallback_paths,
            chain=str(raw.get("chain", "")),
            address=vulnerable_address,
        )
        if raw.get("source") == "DeFiHackLabs"
        else [str(path).strip() for path in fallback_paths if str(path).strip()]
    )
    vulnerable_filenames = [Path(path).name for path in vulnerable_paths if str(path).strip()]
    ground_truth_file = str(ground_truth.get("file", "")).strip()
    if vulnerable_filenames and ground_truth_file not in vulnerable_filenames:
        ground_truth["file"] = vulnerable_filenames[0]
        ground_truth.pop("function", None)
        ground_truth.pop("line", None)
        ground_truth.pop("line_range", None)
    contracts_payload = {
        "vulnerable": vulnerable_paths,
        "vulnerable_address": vulnerable_address,
    }

    result = {
        "id": raw["id"],
        "name": raw["name"],
        "source": raw["source"],
        "case_link": derive_case_link(raw),
        "category": raw["category"],
        "chain": raw.get("chain", ""),
        "language": raw.get("language", ""),
        "vm_family": raw.get("vm_family", ""),
        "cross_chain": bool(raw.get("cross_chain", False)),
        "chains_involved": raw.get("chains_involved", []),
        "date": raw.get("date", ""),
        "description": raw.get("description", ""),
        "analysis_inputs": analysis_inputs,
        "chain_context": chain_context,
        "ground_truth": ground_truth,
        "state_context": state_context,
        "contracts": contracts_payload,
        "remediation": normalize_fix_remediation(
            tasks.get("patch", tasks.get("fix", {})).get("remediation"),
            contracts=contracts_payload,
        ),
        "source_origin": source_metadata.get("source_origin", ""),
        "compiler_version": source_metadata.get("compiler_version", ""),
        "target_contract_name": source_metadata.get("contract_name", ""),
        "source_dir": source_metadata.get("source_dir", ""),
    }
    return attach_annotation_hints("patch", result, raw_case=raw)


# Backwards-compatible alias
build_fix_case = build_patch_case
