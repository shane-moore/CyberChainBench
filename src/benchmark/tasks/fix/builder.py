"""Backwards-compatible shim — see ``benchmark.tasks.patch.builder``."""

from __future__ import annotations

from benchmark.tasks.patch.builder import *  # noqa: F401,F403
from benchmark.tasks.patch.builder import (  # noqa: F401
    build_fix_case,
    build_patch_case,
)
