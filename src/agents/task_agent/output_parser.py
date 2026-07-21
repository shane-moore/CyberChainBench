"""Response parsing and normalization helpers for task-agent outputs."""

from __future__ import annotations

import json as _json
import re as _re

from prompts.taxonomy import (
    DETECT_TYPE_ALIASES as _DETECT_TYPE_ALIASES,
    normalize_detect_type_label as _normalize_detect_type_label,
)

_DETECT_ERROR_MARKERS = [
    "[timeout]",
    "[exit code:",
    "invalid_json_schema",
    "openai codex v",
    "session id:",
    "mcp startup:",
]

_DETECT_NO_VULN_PHRASES = [
    "no vulnerabilit",
    "no security issue",
    "no issue found",
    "no issues found",
    "no bug",
    "no flaw",
    "appears safe",
    "appears secure",
    "looks safe",
    "looks secure",
    "is safe",
    "is secure",
    "no exploit",
    "not vulnerable",
    "cannot find any vulnerabilit",
    "could not find any vulnerabilit",
    "did not find any vulnerabilit",
    "don't see any vulnerabilit",
    "no significant vulnerabilit",
]

_FIX_MODE_ALIASES = {
    "proxy_upgrade": "proxy_upgrade",
    "proxy": "proxy_upgrade",
    "upgrade": "proxy_upgrade",
    "upgradeable": "proxy_upgrade",
    "not_fixable": "not_fixable",
    "unfixable": "not_fixable",
}


def extract_json_response(text: str) -> dict | None:
    """Extract the JSON object from an LLM response."""
    m = _re.search(r"```(?:json)?\s*\n?(\{.*?\})\s*```", text, _re.DOTALL)
    if m:
        try:
            return _json.loads(m.group(1))
        except _json.JSONDecodeError:
            pass

    m = _re.search(r"\{[\s\S]*\}", text)
    if m:
        try:
            return _json.loads(m.group(0))
        except _json.JSONDecodeError:
            pass

    return None


def extract_vuln_type(text: str) -> str | None:
    """Extract vulnerability type from a detect response."""
    data = extract_json_response(text)
    if data:
        vs = data.get("vulnerabilities")
        if isinstance(vs, list) and vs and isinstance(vs[0], dict) and vs[0].get("type"):
            return vs[0]["type"].strip().lower()
        v = data.get("vulnerability")
        if isinstance(v, dict) and v.get("type"):
            return v["type"].strip().lower()

    patterns = [
        r"\*\*Type\*\*[:\s]*([^\n]+)",
        r'"type"[:\s]*"([^"]+)"',
        r"Type[:\s]*([^\n]+)",
    ]
    for pat in patterns:
        m = _re.search(pat, text, _re.IGNORECASE)
        if m:
            return m.group(1).strip().lower().rstrip(".")
    return None


def extract_code_block(text: str) -> str | None:
    """Extract the first solidity code block from a response."""
    m = _re.search(r"```(?:solidity)?\s*\n(.*?)```", text, _re.DOTALL)
    return m.group(1).strip() if m else None


def extract_named_code_blocks(text: str) -> dict[str, str]:
    """Extract FILE: path + solidity fenced code blocks from a response."""
    matches = _re.finditer(
        r"FILE:\s*([^\n`]+?)\s*\n```(?:solidity)?\s*\n(.*?)```",
        text,
        _re.DOTALL | _re.IGNORECASE,
    )
    result: dict[str, str] = {}
    for match in matches:
        path = match.group(1).strip().strip("`")
        code = match.group(2).strip()
        if path and code:
            result[path] = code
    return result


def normalize_fix_mode(value: object) -> str | None:
    raw = str(value or "").strip().lower()
    if not raw:
        return None
    normalized = raw.replace("-", "_").replace(" ", "_")
    return _FIX_MODE_ALIASES.get(normalized, normalized)


def _coerce_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "y"}:
            return True
        if normalized in {"false", "no", "n"}:
            return False
    return None


def _normalize_detect_type(value: object, *, fallback_text: str = "") -> str:
    normalized = _normalize_detect_type_label(value)
    if normalized:
        return normalized

    fallback = extract_vuln_type(fallback_text)
    if fallback:
        normalized = _normalize_detect_type_label(fallback)
        return normalized if normalized in _DETECT_TYPE_ALIASES.values() else "other"
    lowered_fallback = str(fallback_text or "").strip().lower()
    for alias, normalized in _DETECT_TYPE_ALIASES.items():
        if alias in lowered_fallback:
            return normalized
    return "other"


def _extract_detect_file(text: str) -> str:
    patterns = [
        r"\b([A-Za-z0-9_./-]+\.sol)\b",
        r"file\s*[:=]\s*([A-Za-z0-9_./-]+\.sol)\b",
    ]
    for pat in patterns:
        match = _re.search(pat, text, _re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return "(missing)"


def _extract_detect_function(text: str) -> str:
    patterns = [
        r"\b(constructor)\b",
        r"function\s+([A-Za-z_][A-Za-z0-9_]*)",
        r"(?:in|within|inside|at)\s+(?:the\s+)?(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\b",
        r"([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    ]
    for pat in patterns:
        match = _re.search(pat, text, _re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return "(missing)"


def _extract_detect_severity(text: str) -> str:
    patterns = [
        r"\bseverity\s*[:=]\s*(critical|high|medium|low)\b",
        r"\b(critical|high|medium|low)\s+severity\b",
    ]
    for pattern in patterns:
        match = _re.search(pattern, text, _re.IGNORECASE)
        if match:
            return match.group(1).strip().lower()
    return ""


def _clean_detect_description(text: str) -> str:
    cleaned = _re.sub(r"```[\s\S]*?```", " ", str(text or ""))
    cleaned = _re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned:
        return "Model reported a vulnerability but did not provide a structured description."
    if len(cleaned) > 240:
        return cleaned[:237].rstrip() + "..."
    return cleaned


def _looks_like_detect_error_output(text: str) -> bool:
    lowered = str(text or "").lower()
    return any(marker in lowered for marker in _DETECT_ERROR_MARKERS)


def _has_no_vulnerability_phrase(text: str) -> bool:
    lowered = str(text or "").lower()
    return any(phrase in lowered for phrase in _DETECT_NO_VULN_PHRASES)


def _normalize_detect_vulnerability(
    item: dict[str, object] | None, *, fallback_text: str
) -> dict[str, object]:
    item = item or {}
    file_value = str(item.get("file", "")).strip() or _extract_detect_file(fallback_text)
    function_value = str(item.get("function", "")).strip() or _extract_detect_function(
        fallback_text
    )
    severity_value = str(item.get("severity", "")).strip().lower() or _extract_detect_severity(
        fallback_text
    )
    description_value = str(item.get("description", "")).strip() or _clean_detect_description(
        fallback_text
    )
    payload = {
        "type": _normalize_detect_type(item.get("type"), fallback_text=fallback_text),
        "file": file_value or "(missing)",
        "function": function_value or "(missing)",
        "description": description_value,
    }
    if severity_value in {"critical", "high", "medium", "low"}:
        payload["severity"] = severity_value
    return payload


def rewrite_detect_response_as_json(text: str) -> str:
    """Coerce a detect response into the flat detect schema JSON string."""
    raw = str(text or "").strip()
    parsed = extract_json_response(raw)
    vulnerable: bool | None = None
    normalized: dict[str, object] | None = None

    if isinstance(parsed, dict):
        vulnerable = _coerce_bool(parsed.get("vulnerable"))
        if all(key in parsed for key in ("type", "file", "function", "description")):
            normalized = {
                "type": _normalize_detect_type(parsed.get("type"), fallback_text=raw),
                "file": str(parsed.get("file", "")).strip(),
                "function": str(parsed.get("function", "")).strip(),
                "description": str(parsed.get("description", "")).strip(),
            }
        elif isinstance(parsed.get("vulnerabilities"), list) and parsed.get("vulnerabilities"):
            first = next((item for item in parsed["vulnerabilities"] if isinstance(item, dict)), None)
            if first is not None:
                normalized = _normalize_detect_vulnerability(first, fallback_text=raw)
        elif isinstance(parsed.get("vulnerability"), dict):
            normalized = _normalize_detect_vulnerability(parsed["vulnerability"], fallback_text=raw)

    if vulnerable is None:
        if _looks_like_detect_error_output(raw):
            vulnerable = False
        elif _has_no_vulnerability_phrase(raw):
            vulnerable = False
        else:
            vulnerable = True if raw else False

    if vulnerable and normalized is None:
        normalized = _normalize_detect_vulnerability(None, fallback_text=raw)

    if not vulnerable:
        payload = {
            "vulnerable": False,
            "type": "",
            "file": "",
            "function": "",
            "description": "",
        }
    else:
        payload = {
            "vulnerable": True,
            "type": str((normalized or {}).get("type", "")).strip(),
            "file": str((normalized or {}).get("file", "")).strip(),
            "function": str((normalized or {}).get("function", "")).strip(),
            "description": str((normalized or {}).get("description", "")).strip(),
        }
    return _json.dumps(payload, separators=(",", ":"))


def _normalize_optional_fix_text(value: object) -> str:
    text = str(value or "").strip()
    if text.lower() in {"unknown", "none", "n/a", "na", "null", "nil"}:
        return ""
    return text


def extract_fix_plan(text: str) -> dict[str, object]:
    """Extract simplified fixability metadata from an agent response."""
    data = extract_json_response(text) or {}
    if not isinstance(data, dict):
        data = {}

    fixable = _coerce_bool(data.get("fixable"))
    if fixable is None:
        mode = normalize_fix_mode(data.get("fix_mode") or data.get("mode"))
        if mode == "proxy_upgrade":
            fixable = True
        elif mode == "not_fixable":
            fixable = False

    proxy_address = str(data.get("proxy_address", "")).strip()
    rationale = str(data.get("rationale") or data.get("reasoning") or "").strip()

    raw_targets = data.get("target_contracts") or data.get("targets") or []
    target_contracts: list[str] = []
    if isinstance(raw_targets, list):
        target_contracts = [str(item).strip() for item in raw_targets if str(item).strip()]
    elif isinstance(raw_targets, str) and raw_targets.strip():
        target_contracts = [raw_targets.strip()]

    if not proxy_address:
        match = _re.search(r"proxy_address\s*[:=]\s*([^\n,}]+)", text, _re.IGNORECASE)
        if match:
            proxy_address = match.group(1).strip().strip('"')

    if fixable is None:
        match = _re.search(r"fixable\s*[:=]\s*(true|false|yes|no)", text, _re.IGNORECASE)
        if match:
            fixable = _coerce_bool(match.group(1))

    if not rationale:
        match = _re.search(r"(?:rationale|reasoning)\s*[:=]\s*([^\n]+)", text, _re.IGNORECASE)
        if match:
            rationale = match.group(1).strip()

    return {
        "fixable": fixable,
        "fix_possible": fixable,
        "proxy_address": proxy_address,
        "rationale": rationale,
        "target_contracts": target_contracts,
    }


__all__ = [
    "extract_json_response",
    "extract_vuln_type",
    "extract_code_block",
    "extract_named_code_blocks",
    "normalize_fix_mode",
    "rewrite_detect_response_as_json",
    "extract_fix_plan",
]
