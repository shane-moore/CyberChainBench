"""Generate workspace-local MCP configuration files for agent CLIs."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path


def _restrict_permissions(path: Path) -> None:
    """Restrict a secret-bearing config file to owner read/write only."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except OSError:
        pass


def _server_command(repo_root: Path) -> str:
    import shutil

    # MCP server requires Python 3.11+ (mcp package).  The eval runner may
    # be invoked with an older interpreter, so we prefer an explicit 3.11+.
    for candidate in ("python3.11", "python3.12", "python3.13"):
        path = shutil.which(candidate)
        if path:
            return path
    return sys.executable


def _server_args(
    repo_root: Path,
    workspace: Path,
    task_type: str | None,
) -> list[str]:
    """Build CLI args for the MCP server.

    ``task_type`` is a plain string (``"detect"`` / ``"exploit"`` / ``"patch"``)
    or ``None``.  Callers that hold a ``TaskType`` enum should pass ``.value``.
    """
    args = [
        "-m",
        "web3mcp.server",
        "--workspace",
        str(workspace),
        "--repo-root",
        str(repo_root),
    ]
    if task_type is not None:
        args.extend(["--task", str(task_type)])
    return args


_MCP_ENV_PROPAGATE = [
    "PATH", "USER",
    "ETHERSCAN_API_KEY", "ETHERSCAN_API_KEYS",
    "DUNE_API_KEY", "HEIMDALL_BIN",
]


def _server_env(repo_root: Path) -> dict[str, str]:
    """Environment variables to set for the MCP server subprocess."""
    import os

    env: dict[str, str] = {}
    for key in _MCP_ENV_PROPAGATE:
        value = os.environ.get(key, "").strip()
        if value:
            env[key] = value
    repo_src = str((repo_root / "src").resolve())
    existing = os.environ.get("PYTHONPATH", "").strip()
    env["PYTHONPATH"] = f"{repo_src}:{existing}" if existing else repo_src
    return env


# ---------------------------------------------------------------------------
# Claude Code: .mcp.json
# ---------------------------------------------------------------------------

def write_claude_mcp_config(
    workspace: Path,
    repo_root: Path,
    task_type: str | None = None,
) -> Path:
    """Write a workspace-local .mcp.json for Claude Code.

    Returns the path to the generated config file.
    """
    config = {
        "mcpServers": {
            "web3bug_tools": {
                "command": _server_command(repo_root),
                "args": _server_args(repo_root, workspace, task_type),
                "env": _server_env(repo_root),
            }
        }
    }
    config_path = workspace / ".mcp.json"
    config_path.write_text(
        json.dumps(config, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    # Contains ETHERSCAN_API_KEY(S)/DUNE_API_KEY — keep it owner-only and out of
    # any shared artifact bundle (see infra.secrets.SECRET_ARTIFACT_NAMES).
    _restrict_permissions(config_path)
    return config_path


# ---------------------------------------------------------------------------
# Codex CLI: .codex/config.toml
# ---------------------------------------------------------------------------

def write_codex_mcp_config(
    workspace: Path,
    repo_root: Path,
    task_type: str | None = None,
) -> Path:
    """Write a workspace-local .codex/config.toml with an MCP server entry.

    Returns the path to the generated config file.
    """
    cmd = _server_command(repo_root)
    args = _server_args(repo_root, workspace, task_type)
    env = _server_env(repo_root)

    # Build TOML manually to avoid adding a toml dependency.
    args_toml = ", ".join(f'"{a}"' for a in args)
    env_lines = "\n".join(f'  {k} = "{v}"' for k, v in env.items())
    toml_content = f"""\
[mcp_servers.web3bug_tools]
command = "{cmd}"
args = [{args_toml}]

[mcp_servers.web3bug_tools.env]
{env_lines}
"""
    config_dir = workspace / ".codex"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "config.toml"
    config_path.write_text(toml_content, encoding="utf-8")
    # Contains ETHERSCAN_API_KEY(S)/DUNE_API_KEY in plaintext TOML.
    _restrict_permissions(config_path)
    return config_path
