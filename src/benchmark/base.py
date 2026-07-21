"""Shared base class for all benchmark case types."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from infra.chain.metadata import resolve_dfhl_vulnerable_sources
from project_layout import PARSER_PREPROCESSED_DIR, resolve_repo_path


@dataclass
class _CaseBase:
    id: str
    name: str
    source: str
    case_link: str
    category: str
    severity: str
    chain: str
    date: str
    description: str
    contracts: dict
    language: str = ""
    vm_family: str = ""
    cross_chain: bool = False
    chains_involved: list[str] = field(default_factory=list)
    chain_context: dict = field(default_factory=dict)
    state_context: dict = field(default_factory=dict)
    annotation_hints: dict = field(default_factory=dict)
    raw: dict = field(repr=False, default_factory=dict)

    def _resolve_vulnerable_source_paths(self, base_dir: Path) -> list[str]:
        explicit = [str(path) for path in self.contracts.get("vulnerable", []) if str(path).strip()]
        if explicit:
            return explicit

        exploit_path = str(self.contracts.get("exploit", "")).strip()
        fallback_paths = [exploit_path] if exploit_path else []
        if self.source == "DeFiHackLabs":
            resolved = resolve_dfhl_vulnerable_sources(
                self.id,
                base_dir,
                fallback_paths,
                chain=self.chain,
                address=str(self.contracts.get("vulnerable_address", "")).strip(),
            )
            if resolved:
                return resolved

        parser_root = resolve_repo_path(base_dir, PARSER_PREPROCESSED_DIR)
        if not parser_root.exists():
            return []

        for raw_case_path in sorted(parser_root.rglob(f"{self.id}.json")):
            try:
                payload = json.loads(raw_case_path.read_text())
            except json.JSONDecodeError:
                continue
            contracts = payload.get("contracts", {}) or {}
            if not isinstance(contracts, dict):
                continue
            vulnerable = [
                str(path) for path in contracts.get("vulnerable", []) if str(path).strip()
            ]
            if vulnerable:
                return vulnerable
        return []

    def get_vulnerable_code(self, base_dir: Path) -> dict[str, str]:
        """Read all vulnerable contract source files. Returns {filename: content}."""
        result = {}
        for rel_path in self._resolve_vulnerable_source_paths(base_dir):
            full_path = resolve_repo_path(base_dir, rel_path)
            if full_path.exists():
                result[full_path.name] = full_path.read_text(errors="replace")
        return result

    def get_exploit_code(self, base_dir: Path) -> str | None:
        """Read the exploit / reference exploit file if available."""
        exploit_path = self.contracts.get("exploit", "")
        if not exploit_path:
            return None
        full_path = resolve_repo_path(base_dir, exploit_path)
        if full_path.exists():
            return full_path.read_text(errors="replace")
        return None
