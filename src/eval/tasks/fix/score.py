"""Backwards-compatible shim — see ``eval.tasks.patch.score``."""

from __future__ import annotations

from eval.tasks.patch.score import (  # noqa: F401
    FixScore,
    PatchScore,
    serialize_fix_score,
    serialize_patch_score,
    write_fix_score_artifact,
    write_patch_score_artifact,
)
