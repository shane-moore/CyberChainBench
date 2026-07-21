from __future__ import annotations

from pathlib import Path

# Used by infra.* helpers to locate the repository root when invoked from
# arbitrary working directories.
PROJECT_ROOT = Path(__file__).resolve().parents[1]

