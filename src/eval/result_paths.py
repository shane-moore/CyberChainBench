"""Helpers for benchmark result file paths."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path



def default_results_dir(
    base_dir: Path,
    task: str,
    track: str,
    *,
    stamp: str | None = None,
) -> Path:
    run_stamp = stamp or datetime.now().strftime("%Y%m%d_%H%M%S")
    return base_dir / "data" / "eval" / task / f"batch_{run_stamp}"


def default_results_path(
    base_dir: Path,
    task: str,
    track: str,
    *,
    stamp: str | None = None,
) -> Path:
    """Compatibility helper returning the index.json path inside the run dir."""
    return default_results_dir(base_dir, task, track, stamp=stamp) / "index.json"
