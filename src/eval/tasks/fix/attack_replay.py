"""Backwards-compatible shim — see ``eval.tasks.patch.attack_replay``."""

from __future__ import annotations

from eval.tasks.patch.attack_replay import *  # noqa: F401,F403
from eval.tasks.patch.attack_replay import (  # noqa: F401
    validate_fix_attack_transactions,
    validate_patch_attack_transactions,
)
