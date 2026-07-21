from __future__ import annotations

from pathlib import Path
import re


def _normalize_hint(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.endswith(".sol"):
        text = text[:-4]
    return text.lower()


def _parse_named_units(solidity_code: str) -> list[tuple[str, str]]:
    matches: list[tuple[str, str]] = []
    pattern = re.compile(
        r"^\s*(?:(abstract)\s+)?(contract|library|interface)\s+(\w+)\b",
        flags=re.MULTILINE,
    )
    for abstract_kw, kind, name in pattern.findall(solidity_code):
        normalized_kind = "contract" if kind == "contract" else kind
        if abstract_kw:
            normalized_kind = "contract"
        matches.append((normalized_kind, name))
    return matches


def _parse_import_stems(solidity_code: str) -> list[str]:
    stems: list[str] = []
    pattern = re.compile(
        r"^\s*import\s+(?:[^\"']+\s+from\s+)?[\"']([^\"']+)[\"']\s*;",
        flags=re.MULTILINE,
    )
    for path_text in pattern.findall(solidity_code):
        stem = Path(path_text).stem.strip()
        if stem:
            stems.append(stem)
    return list(dict.fromkeys(stems))


def select_fixed_contract_name(
    solidity_code: str,
    *,
    target_hints: list[str] | None = None,
) -> str | None:
    units = _parse_named_units(solidity_code)
    normalized_hints = {
        normalized
        for item in (target_hints or [])
        if (normalized := _normalize_hint(item))
    }

    if normalized_hints:
        for _, name in units:
            if name.lower() in normalized_hints:
                return name

    if units:
        for kind, name in units:
            if kind == "interface":
                continue
            if name.startswith("I") or name.endswith("Test"):
                continue
            return name
        return units[0][1]

    import_stems = _parse_import_stems(solidity_code)
    if normalized_hints:
        for stem in import_stems:
            if stem.lower() in normalized_hints:
                return stem

    if len(import_stems) == 1:
        return import_stems[0]
    return None
