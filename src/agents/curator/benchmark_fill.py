"""Standalone merged detect-minimal + remediation curator."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from . import shared as _shared


def _iter_trace_nodes(trace: object) -> list[dict[str, object]]:
    if isinstance(trace, list):
        return [item for item in trace if isinstance(item, dict)]
    if not isinstance(trace, dict):
        return []
    nodes = [trace]
    calls = trace.get("calls", [])
    if isinstance(calls, list):
        for child in calls:
            nodes.extend(_iter_trace_nodes(child))
    return nodes


def _summarize_trace_for_remediation(trace: object) -> dict[str, Any]:
    delegatecall_edges: list[dict[str, str]] = []
    for node in _iter_trace_nodes(trace):
        call_type = str(node.get("type") or node.get("callType") or node.get("call_type") or "").strip().lower()
        if call_type != "delegatecall":
            continue
        from_addr = str(node.get("from") or "").strip()
        to_addr = str(node.get("to") or "").strip()
        if not from_addr or not to_addr:
            continue
        delegatecall_edges.append(
            {
                "from": from_addr,
                "to": to_addr,
                "call_type": call_type,
            }
        )
    return {
        "delegatecall_edge_count": len(delegatecall_edges),
        "delegatecall_edges": delegatecall_edges[:12],
    }


def _infer_remediation_from_trace_preview(
    vulnerable_address: str,
    trace_preview: dict[str, Any],
) -> dict[str, str]:
    vulnerable = str(vulnerable_address or "").strip().lower()
    if not vulnerable or not isinstance(trace_preview, dict):
        return {}
    edges = trace_preview.get("delegatecall_edges")
    if not isinstance(edges, list):
        return {}
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        call_type = str(edge.get("call_type") or "").strip().lower()
        from_addr = str(edge.get("from") or "").strip()
        to_addr = str(edge.get("to") or "").strip()
        if call_type != "delegatecall" or not from_addr or not to_addr:
            continue
        if from_addr.lower() == vulnerable and to_addr.lower() != vulnerable:
            return {
                "proxy_address": from_addr,
                "implementation_address": to_addr,
            }
        if to_addr.lower() == vulnerable and from_addr.lower() != vulnerable:
            return {
                "proxy_address": from_addr,
                "implementation_address": to_addr,
            }
    return {}



def _set_change(working: dict[str, Any], changes: dict[str, Any], path: str, value: Any) -> None:
    current = _shared._get_nested_value(working, path)
    if current == value:
        return
    _shared._set_nested_value(working, path, deepcopy(value))
    changes[path] = deepcopy(value)


def enforce_benchmark_case_trace_remediation(
    report: dict[str, Any],
    *,
    raw_case: dict[str, Any],
) -> dict[str, Any]:
    current_report = deepcopy(report)
    evidence = dict(current_report.get("evidence", {}) or {})
    trace_preview = evidence.get("attack_tx_trace_preview") or {}

    updated_manual_case = deepcopy(current_report.get("suggested_manual_case", {}))
    if not isinstance(updated_manual_case, dict):
        return current_report
    updated_review_case = deepcopy(current_report.get("suggested_review_case", updated_manual_case))
    if not isinstance(updated_review_case, dict):
        updated_review_case = deepcopy(updated_manual_case)

    current_vulnerable = str(
        _shared._get_nested_value(updated_manual_case, "vulnerable_address") or ""
    ).strip()
    remediation_match = _infer_remediation_from_trace_preview(current_vulnerable, trace_preview)

    deterministic_changes: dict[str, Any] = {}
    if remediation_match:
        implementation_address = str(remediation_match.get("implementation_address", "")).strip()
        proxy_address = str(remediation_match.get("proxy_address", "")).strip()
        if implementation_address:
            _set_change(
                updated_manual_case,
                deterministic_changes,
                "vulnerable_address",
                implementation_address,
            )
            _set_change(
                updated_review_case,
                deterministic_changes,
                "vulnerable_address",
                implementation_address,
            )
        if proxy_address:
            _set_change(
                updated_manual_case,
                deterministic_changes,
                "fixable",
                True,
            )
            _set_change(
                updated_review_case,
                deterministic_changes,
                "fixable",
                True,
            )
            _set_change(
                updated_manual_case,
                deterministic_changes,
                "proxy_address",
                proxy_address,
            )
            _set_change(
                updated_review_case,
                deterministic_changes,
                "proxy_address",
                proxy_address,
            )
    else:
        _set_change(
            updated_manual_case,
            deterministic_changes,
            "fixable",
            False,
        )
        _set_change(
            updated_review_case,
            deterministic_changes,
            "fixable",
            False,
        )
        if updated_manual_case.pop("proxy_address", None) is not None:
            deterministic_changes["proxy_address"] = ""
        updated_review_case.pop("proxy_address", None)

    normalized_manual_case = _shared.normalize_task_case("benchmark_case", updated_manual_case)
    refreshed_review_case = deepcopy(updated_review_case)
    refreshed_review_case.pop("annotation_hints", None)
    refreshed_review_case = _shared.attach_annotation_hints(
        "benchmark_case", refreshed_review_case, raw_case=raw_case
    )
    current_report["suggested_manual_case"] = normalized_manual_case
    current_report["suggested_review_case"] = refreshed_review_case
    current_report["remaining_annotation_hints"] = _shared._remaining_missing_annotation_hints(
        normalized_manual_case
    )
    current_report["changed_fields"] = _shared._filter_changed_fields_for_task(
        "benchmark_case",
        _shared._recompute_changed_fields(
            raw_case,
            normalized_manual_case,
            list(dict(current_report.get("changed_fields", {}) or {})) + list(deterministic_changes),
        ),
    )
    evidence["deterministic_remediation_enforcement"] = {
        "status": "matched" if remediation_match else "fallback_not_fixable",
        "match": remediation_match,
        "applied_paths": list(deterministic_changes),
    }
    current_report["evidence"] = evidence
    return current_report



def build_benchmark_case_report(
    base_dir: Path, case: dict[str, Any], *, case_path: Path | None = None
) -> dict[str, Any]:
    working = _shared._coerce_fill_seed_case("benchmark_case", case)
    changes: dict[str, Any] = {}
    evidence: dict[str, Any] = {}

    source = str(working.get("source", "")).strip()
    case_id = str(working.get("id", "")).strip()

    _shared._apply_dfhl_case_link(base_dir, working, changes, evidence)

    reference_material = _shared._expand_reference_material(str(working.get("case_link", "")))
    if reference_material:
        evidence["reference_material"] = {
            "reference_urls": reference_material.get("reference_urls", []),
            "texts": list(reference_material.get("texts", []))[:1],
        }

    normalized = _shared.normalize_task_case("benchmark_case", working)
    refreshed_review_case = _shared.attach_annotation_hints(
        "benchmark_case", deepcopy(normalized), raw_case=case
    )

    return {
        "task": "benchmark_case",
        "case_id": case_id,
        "source": source,
        "case_path": str(case_path) if case_path else "",
        "changed_fields": _shared._filter_changed_fields_for_task(
            "benchmark_case",
            _shared._recompute_changed_fields(case, normalized, ["case_link"]),
        ),
        "evidence": evidence,
        "remaining_annotation_hints": _shared._remaining_missing_annotation_hints(normalized),
        "suggested_review_case": refreshed_review_case,
        "suggested_manual_case": normalized,
    }


class BenchmarkCurator(_shared.Curator):
    """Standalone merged detect-minimal + remediation curator wrapper."""

    TASK = "benchmark_case"

    def build_report(
        self, case: dict[str, Any], *, case_path: Path | None = None
    ) -> dict[str, Any]:
        return super().build_report(self.TASK, case, case_path=case_path)

    def build_prompt_bundle(
        self,
        case: dict[str, Any],
        *,
        case_path: Path | None = None,
        report: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        return super().build_prompt_bundle(self.TASK, case, case_path=case_path, report=report)

    def build_reason_text(
        self,
        case: dict[str, Any],
        *,
        case_path: Path | None = None,
        report: dict[str, Any] | None = None,
    ) -> str:
        return super().build_reason_text(self.TASK, case, case_path=case_path, report=report)
