"""Derive a stable incident/report link for benchmark cases."""

from __future__ import annotations

from pathlib import PurePosixPath

_EXPLORER_MARKERS = (
    "etherscan.io",
    "bscscan.com",
    "arbiscan.io",
    "basescan.org",
    "snowtrace.io",
    "ftmscan.com",
    "polygonscan.com",
    "optimistic.etherscan.io",
    "gnosisscan.io",
    "blastscan.io",
    "celoscan.io",
    "lineascan.build",
)
_DEBUG_MARKERS = (
    "phalcon.blocksec.com",
    "app.blocksec.com",
    "dashboard.tenderly.co",
    "tenderly.co",
)
_DFHL_REPO_BLOB_ROOT = "https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main"
_DFHL_DATA_PREFIX = "data/sources/DeFiHackLabs/"
_DFHL_LEGACY_PREFIX = "upstream/DeFiHackLabs/"  # legacy paths still resolved via project_layout


def _as_str(value: object) -> str:
    return str(value).strip() if value is not None else ""


def _string_list(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    result: list[str] = []
    for value in values:
        normalized = _as_str(value)
        if normalized and normalized not in result:
            result.append(normalized)
    return result


def _is_http_url(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith("http://") or lowered.startswith("https://")


def _is_explorer_url(value: str) -> bool:
    lowered = value.lower()
    if any(marker in lowered for marker in _EXPLORER_MARKERS):
        return True
    return "/tx/" in lowered or "/address/" in lowered


def _is_debug_url(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in _DEBUG_MARKERS)


def _dfhl_repo_case_link(case: dict) -> str:
    contracts = case.get("contracts", {}) if isinstance(case.get("contracts"), dict) else {}
    tasks = case.get("tasks", {}) if isinstance(case.get("tasks"), dict) else {}
    exploit_task = tasks.get("exploit", {}) if isinstance(tasks.get("exploit"), dict) else {}
    source_dir = _as_str(case.get("source_dir", ""))
    candidates = [
        _as_str(case.get("case_link", "")),
        _as_str(contracts.get("exploit", "")),
        _as_str(exploit_task.get("reference_exploit", "")),
        _as_str(case.get("reference_exploit", "")),
        source_dir,
    ]
    for candidate in candidates:
        if candidate.startswith(_DFHL_REPO_BLOB_ROOT):
            return candidate
        if candidate.startswith(_DFHL_DATA_PREFIX):
            relative = PurePosixPath(candidate).relative_to(_DFHL_DATA_PREFIX.rstrip("/"))
            return f"{_DFHL_REPO_BLOB_ROOT}/{relative.as_posix()}"
        if not candidate.startswith(_DFHL_LEGACY_PREFIX):
            continue
        relative = PurePosixPath(candidate).relative_to(_DFHL_LEGACY_PREFIX.rstrip("/"))
        return f"{_DFHL_REPO_BLOB_ROOT}/{relative.as_posix()}"
    return ""


def derive_case_link(case: dict) -> str:
    """Return the most useful human-facing incident/report link for a case."""
    clara = case.get("clara", {}) if isinstance(case.get("clara"), dict) else {}
    vulnerability_detail = (
        case.get("vulnerability_detail", {})
        if isinstance(case.get("vulnerability_detail"), dict)
        else {}
    )
    chain_context = (
        case.get("chain_context", {}) if isinstance(case.get("chain_context"), dict) else {}
    )

    if _as_str(case.get("source", "")) == "DeFiHackLabs":
        if candidate := _dfhl_repo_case_link(case):
            return candidate

    direct_candidates = [
        _as_str(case.get("case_link", "")),
        _as_str(case.get("reference", "")),
        _as_str(clara.get("page_url", "")),
    ]
    for candidate in direct_candidates:
        if _is_http_url(candidate):
            return candidate

    references = [
        candidate
        for candidate in _string_list(vulnerability_detail.get("references", []))
        if _is_http_url(candidate)
    ]
    for candidate in references:
        if not _is_explorer_url(candidate) and not _is_debug_url(candidate):
            return candidate
    for candidate in references:
        if not _is_debug_url(candidate):
            return candidate

    for key in ("explorer_urls", "debug_urls"):
        for candidate in _string_list(chain_context.get(key, [])):
            if _is_http_url(candidate):
                return candidate
    return ""
