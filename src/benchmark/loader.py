"""
Task-specific benchmark loader.

Scans individual ``*.json`` files in the benchmark directory.
"""

from __future__ import annotations

import json
from pathlib import Path

from benchmark.tasks.detect.case import DetectCase
from benchmark.tasks.exploit.case import ExploitCase
from benchmark.tasks.patch.case import PatchCase

# Backwards-compatible alias
FixCase = PatchCase

# Re-export for convenience
__all__ = [
    "BenchmarkLoader",
    "DetectCase",
    "ExploitCase",
    "PatchCase",
    "FixCase",
]

_CASE_CLS = {
    ("detect", "on_chain"): DetectCase,
    ("exploit", "on_chain"): ExploitCase,
    ("patch", "on_chain"): PatchCase,
    ("fix", "on_chain"): PatchCase,
}


class BenchmarkLoader:
    """Load and filter task-specific benchmark cases."""

    def __init__(self, benchmark_dir: Path):
        """Args:
        benchmark_dir: path to the benchmark data directory
        """
        self.benchmark_dir = benchmark_dir
        self._cases: list = []
        self._task: str = ""
        self._track: str = "on_chain"

    def load(
        self,
        task: str,
        track: str = "on_chain",
        *,
        split: str = "auto",
    ) -> "BenchmarkLoader":
        """Load cases for a specific task.

        Args:
            task: "detect" | "exploit" | "patch"
        """
        normalized_task = task
        normalized_track = str(track).strip()
        normalized_split = str(split).strip().lower() or "auto"
        if normalized_track != "on_chain":
            raise ValueError(
                f"Unsupported benchmark track: {track!r}. Only 'on_chain' is supported."
            )
        if normalized_split not in {"auto", "final", "review"}:
            raise ValueError(
                f"Unsupported benchmark split: {split!r}. Expected 'auto', 'final', or 'review'."
            )
        self._task = normalized_task
        self._track = normalized_track
        cls = _CASE_CLS[(normalized_task, normalized_track)]

        json_files = sorted(self.benchmark_dir.glob("*.json"))
        if not json_files:
            raise FileNotFoundError(
                f"Benchmark not found. No .json files in {self.benchmark_dir}"
            )
        data: list[dict] = []
        for jf in json_files:
            payload = json.loads(jf.read_text())
            if isinstance(payload, dict) and not payload.get("archived"):
                data.append(payload)
        self._cases = [cls.from_json(d) for d in data]
        return self

    def filter(
        self,
        category: str | None = None,
        severity: str | None = None,
        chain: str | None = None,
        source: str | None = None,
    ) -> list:
        """Filter loaded cases by criteria."""
        result = self._cases
        if category:
            result = [c for c in result if c.category == category]
        if severity:
            result = [c for c in result if c.severity == severity]
        if chain:
            result = [c for c in result if c.chain == chain]
        if source:
            result = [c for c in result if c.source == source]
        return result

    @property
    def cases(self) -> list:
        return self._cases

    def __len__(self) -> int:
        return len(self._cases)

    def summary(self) -> dict:
        cats: dict[str, int] = {}
        srcs: dict[str, int] = {}
        for c in self._cases:
            cats[c.category] = cats.get(c.category, 0) + 1
            srcs[c.source] = srcs.get(c.source, 0) + 1
        return {
            "task": self._task,
            "track": self._track,
            "total": len(self._cases),
            "by_category": cats,
            "by_source": srcs,
        }
