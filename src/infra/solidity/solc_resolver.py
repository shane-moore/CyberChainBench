from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path


def extract_solc_version(version_text: str) -> str:
    match = re.search(r"(\d+\.\d+\.\d+)", version_text or "")
    return match.group(1) if match else ""


def normalize_supported_solc_version(version_text: str) -> str:
    normalized = extract_solc_version(version_text)
    if not normalized:
        return ""
    major, minor, patch = (int(part) for part in normalized.split("."))
    if (major, minor, patch) < (0, 4, 11):
        return "0.4.11"
    return normalized


def infer_solc_version_from_source_text(source_text: str) -> str:
    match = re.search(r"pragma\s+solidity\s+([^;]+);", source_text or "")
    return normalize_supported_solc_version(match.group(1) if match else "")


def _candidate_paths(version: str) -> list[Path]:
    return [
        Path.home() / '.solcx' / f'solc-v{version}',
        Path('/opt/solc') / f'solc-v{version}',
    ]


@lru_cache(maxsize=64)
def get_or_install_solc(version_text: str) -> str:
    version = normalize_supported_solc_version(version_text)
    if not version:
        return ""

    for candidate in _candidate_paths(version):
        if candidate.exists():
            return str(candidate)

    try:
        import solcx
        from solcx.install import get_executable
    except ImportError:
        return ""

    try:
        solcx.install_solc(version, show_progress=False)
    except Exception:
        return ""

    try:
        executable = Path(get_executable(version))
        if executable.exists():
            return str(executable)
    except Exception:
        pass

    for candidate in _candidate_paths(version):
        if candidate.exists():
            return str(candidate)
    return ""
