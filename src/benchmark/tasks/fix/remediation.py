"""Backwards-compatible shim — see ``benchmark.tasks.patch.remediation``."""

from __future__ import annotations

from benchmark.tasks.patch.remediation import *  # noqa: F401,F403
from benchmark.tasks.patch.remediation import normalize_fix_remediation  # noqa: F401
