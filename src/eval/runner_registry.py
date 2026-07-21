"""Shared registry and config helpers for the benchmark runner."""

from __future__ import annotations

from datetime import datetime
from functools import partial
from pathlib import Path

from agents.task_agent.cli_coding_agent import CLI_FAMILY_SPECS, CliCodingAgent
from agents.task_agent.mock_agent import MockAgent
from project_root import PROJECT_ROOT

AGENT_REGISTRY: dict[str, object] = {
    "mock": MockAgent,
    "claude_code": partial(
        CliCodingAgent,
        model=str(CLI_FAMILY_SPECS["claude_code"]["default_model"]),
        cli_family="claude_code",
        dangerously_skip_permissions=True,
    ),
    "codex_cli": partial(
        CliCodingAgent,
        model=str(CLI_FAMILY_SPECS["codex_cli"]["default_model"]),
        cli_family="codex_cli",
    ),
    "aider": partial(
        CliCodingAgent,
        model=str(CLI_FAMILY_SPECS["aider"]["default_model"]),
        cli_family="aider",
    ),
    "gemini_cli": partial(
        CliCodingAgent,
        model=str(CLI_FAMILY_SPECS["gemini_cli"]["default_model"]),
        cli_family="gemini_cli",
    ),
    "opencode": partial(
        CliCodingAgent,
        model=str(CLI_FAMILY_SPECS["opencode"]["default_model"]),
        cli_family="opencode",
    ),
    "openhands": partial(
        CliCodingAgent,
        model=str(CLI_FAMILY_SPECS["openhands"]["default_model"]),
        cli_family="openhands",
    ),
}

TRACK_LABELS: dict[str, str] = {
    "on_chain": "On-Chain Incident Track",
}

CLI_AGENT_KEYS = {"claude_code", "codex_cli", "aider", "gemini_cli", "opencode", "openhands"}
DEFAULT_ARTIFACT_BATCH_ID = f"adhoc_{datetime.now().strftime('%Y%m%d_%H%M%S')}"


def normalize_task_track(task: str, track: str) -> tuple[str, str]:
    return task, track


def build_agent_kwargs(
    agent_key: str,
    base_dir: Path,
    kwargs: dict | None = None,
) -> dict:
    init_kwargs = dict(kwargs or {})
    if agent_key in CLI_AGENT_KEYS:
        init_kwargs.setdefault("cwd", PROJECT_ROOT)
    elif agent_key == "mock":
        init_kwargs.setdefault("base_dir", base_dir)
    return init_kwargs
