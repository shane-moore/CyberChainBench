"""Task-agent transport helpers."""

from __future__ import annotations

import os


def use_mcp_transport() -> bool:
    value = os.environ.get("TASK_AGENT_USE_MCP", "").strip().lower()
    if not value:
        return True
    return value in {"1", "true", "yes"}
