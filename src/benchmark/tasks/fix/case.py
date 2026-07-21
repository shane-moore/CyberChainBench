"""Backwards-compatible shim — see ``benchmark.tasks.patch.case``."""

from __future__ import annotations

from benchmark.tasks.patch.case import *  # noqa: F401,F403
from benchmark.tasks.patch.case import FixCase, PatchCase  # noqa: F401
