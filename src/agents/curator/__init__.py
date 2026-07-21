"""Curator runtimes for review-case backfilling."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .shared import Curator
from .benchmark_fill import BenchmarkCurator


def build_curator(task: str, base_dir: Path, **kwargs: Any) -> Curator:
    task_name = str(task).strip().lower()
    mapping = {
        "benchmark_case": BenchmarkCurator,
    }
    try:
        agent_cls = mapping[task_name]
    except KeyError as exc:
        raise ValueError(f"unsupported fill task: {task}") from exc
    return agent_cls(base_dir, **kwargs)


__all__ = [
    "Curator",
    "BenchmarkCurator",
    "build_curator",
]
