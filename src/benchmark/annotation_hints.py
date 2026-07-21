"""Structured hints for benchmark fields that are missing or inferred."""

from __future__ import annotations

from copy import deepcopy

_TASK_HINT_SPECS: dict[str, tuple[dict[str, object], ...]] = {
    "detect": (
        {
            "path": "ground_truth.file",
            "label": "TODO_GROUND_TRUTH_FILE",
            "expected_schema": {"type": "string", "example": "Vault.sol"},
            "hint": "Primary vulnerable source file basename used for detect localization.",
        },
        {
            "path": "ground_truth.function",
            "label": "TODO_GROUND_TRUTH_FUNCTION",
            "expected_schema": {"type": "string", "example": "withdraw"},
            "hint": "Primary vulnerable function name used for detect localization.",
        },
    ),
    "exploit": (
        {
            "path": "chain_context.attack_txs",
            "label": "TODO_CHAIN_CONTEXT_ATTACK_TXS",
            "expected_schema": {
                "type": "array",
                "items": {"type": "string"},
                "example": ["0xabc123..."],
            },
            "hint": "Historical exploit transaction hashes used for replay-oriented exploit tasks.",
        },
        {
            "path": "success_criteria",
            "label": "TODO_SUCCESS_CRITERIA",
            "expected_schema": {
                "type": "string",
                "example": "Replay the historical exploit and end with a positive attacker balance delta.",
            },
            "hint": "Human-readable exploit success oracle for reference and manual review.",
        },
    ),
    "patch": (
        {
            "path": "remediation.proxy_address",
            "source_paths": (
                "remediation.proxy_address",
                "tasks.patch.remediation.proxy_address",
                "tasks.fix.remediation.proxy_address",
            ),
            "flag_if_inferred": True,
            "label": "TODO_REMEDIATION_PROXY_ADDRESS",
            "expected_schema": {
                "type": "string",
                "example": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            },
            "hint": "Proxy contract address that delegatecalls into the implementation and would be upgraded.",
        },
    ),
    "benchmark_case": (
        {
            "path": "file",
            "label": "TODO_FILE",
            "skip_unless_equals": {"has_public_source": True},
            "expected_schema": {"type": "string", "example": "Vault.sol"},
            "hint": "Primary vulnerable source file basename for the canonical benchmark case.",
        },
        {
            "path": "function",
            "label": "TODO_FUNCTION",
            "expected_schema": {"type": "string", "example": "withdraw"},
            "hint": "Primary vulnerable function name for the canonical benchmark case.",
        },
        {
            "path": "proxy_address",
            "source_paths": ("proxy_address",),
            "flag_if_inferred": True,
            "skip_unless_equals": {"fixable": True},
            "label": "TODO_PROXY_ADDRESS",
            "expected_schema": {
                "type": "string",
                "example": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            },
            "hint": "Proxy contract address for a case that is fixable via proxy upgrade.",
        },
    ),
}

# Backwards-compatible alias: "fix" task shares the same hint specs as "patch"
_TASK_HINT_SPECS["fix"] = _TASK_HINT_SPECS["patch"]


def _is_missing(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, dict)):
        return len(value) == 0
    return False


def _get_path(data: object, path: str) -> object:
    current = data
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _get_source_value(raw_case: dict, spec: dict[str, object], path: str) -> object:
    source_paths = spec.get("source_paths")
    if isinstance(source_paths, (list, tuple)):
        for candidate in source_paths:
            if not isinstance(candidate, str):
                continue
            value = _get_path(raw_case, candidate)
            if not _is_missing(value):
                return value
        return None
    return _get_path(raw_case, path)


def attach_annotation_hints(task: str, case: dict, *, raw_case: dict | None = None) -> dict:
    """Attach task-specific hints for fields that are missing or inferred."""
    result = deepcopy(case)
    raw_payload = raw_case if isinstance(raw_case, dict) else {}
    hints = dict(result.get("annotation_hints", {}) or {})

    for spec in _TASK_HINT_SPECS.get(task, ()):
        path = str(spec["path"])
        skip_paths = spec.get("skip_if_present", ())
        if isinstance(skip_paths, (list, tuple)):
            skip = False
            for candidate in skip_paths:
                if not isinstance(candidate, str):
                    continue
                if not _is_missing(_get_path(result, candidate)):
                    skip = True
                    break
            if skip:
                continue

        skip_unless_equals = spec.get("skip_unless_equals")
        if isinstance(skip_unless_equals, dict):
            should_skip = False
            for candidate, expected in skip_unless_equals.items():
                if not isinstance(candidate, str):
                    continue
                current = _get_path(result, candidate)
                if current != expected:
                    should_skip = True
                    break
            if should_skip:
                continue

        value = _get_path(result, path)
        status = ""

        if _is_missing(value):
            status = "missing"
        elif bool(spec.get("flag_if_inferred")) and raw_payload:
            source_value = _get_source_value(raw_payload, spec, path)
            if _is_missing(source_value):
                status = "inferred_default"

        if not status:
            continue

        hint = {
            "label": str(spec["label"]),
            "status": status,
            "expected_schema": deepcopy(spec["expected_schema"]),
            "hint": str(spec["hint"]),
        }
        if status == "inferred_default":
            hint["current_value"] = deepcopy(value)
        hints[path] = hint

    if hints:
        result["annotation_hints"] = hints
    else:
        result.pop("annotation_hints", None)
    return result
