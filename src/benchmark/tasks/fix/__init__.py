"""Backwards-compatible shim for the renamed ``patch`` task package.

Re-exports ``benchmark.tasks.patch`` under the legacy ``benchmark.tasks.fix``
import path. The task was renamed ``fix`` -> ``patch``.
"""

from __future__ import annotations
