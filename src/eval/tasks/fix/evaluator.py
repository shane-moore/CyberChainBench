"""Backwards-compatible shim — see ``eval.tasks.patch.evaluator``."""

from __future__ import annotations

from eval.tasks.patch.evaluator import *  # noqa: F401,F403
from eval.tasks.patch.evaluator import (  # noqa: F401
    _select_fixed_contract_name,
    evaluate_fix,
    evaluate_patch,
)
