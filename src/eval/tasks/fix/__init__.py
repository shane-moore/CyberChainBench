"""Backwards-compatible shim for the renamed ``patch`` task package.

The task was renamed ``fix`` -> ``patch``. This package re-exports the patch
implementation under the legacy ``eval.tasks.fix`` import path so existing
imports (and any external tooling) keep working.
"""

from __future__ import annotations

from eval.tasks.patch import (  # noqa: F401
    FixScore,
    PatchScore,
    evaluate_fix,
    evaluate_patch,
    write_fix_score_artifact,
    write_patch_score_artifact,
)
from eval.tasks.patch import attack_replay  # noqa: F401

__all__ = [
    "FixScore",
    "PatchScore",
    "evaluate_fix",
    "evaluate_patch",
    "write_fix_score_artifact",
    "write_patch_score_artifact",
    "attack_replay",
]
