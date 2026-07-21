"""Shared tool execution runtime for both file-IPC broker and MCP server."""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# Task type constants — plain strings to avoid circular imports with
# agents.task_agent.base.TaskType.
TASK_DETECT = "detect"
TASK_EXPLOIT = "exploit"
TASK_PATCH = "patch"
TASK_FIX = TASK_PATCH  # backwards-compat alias
TASK_FILL = "fill"


# ---------------------------------------------------------------------------
# Tool specification registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolSpec:
    module: str
    path_flags: tuple[str, ...] = ()
    timeout_seconds: int = 900
    needs_base_dir: bool = False


TOOL_SPECS: dict[str, ToolSpec] = {
    "get_contract_source": ToolSpec(
        module="infra.cli.get_contract_source",
        path_flags=("--output-dir",),
        timeout_seconds=300,
    ),
    "get_decompiled_contract": ToolSpec(
        module="infra.cli.get_decompiled_contract",
        path_flags=("--output-dir",),
        timeout_seconds=300,
    ),
    "get_tx_block": ToolSpec(module="infra.cli.get_tx_block", timeout_seconds=120),
    "get_tx_trace": ToolSpec(module="infra.cli.get_tx_trace", timeout_seconds=300),
    "get_tx_profit": ToolSpec(module="infra.cli.get_tx_profit", timeout_seconds=300),
    "get_proxy_context": ToolSpec(module="infra.cli.get_proxy_context", timeout_seconds=300),
    "get_storage_slot": ToolSpec(module="infra.cli.get_storage_slot", timeout_seconds=300),
    "eth_call": ToolSpec(module="infra.cli.eth_call", timeout_seconds=120),
    "run_exploit_test": ToolSpec(
        module="infra.cli.run_exploit_test",
        path_flags=("--exploit-path", "--artifact-dir", "--json-output"),
        timeout_seconds=1200,
        needs_base_dir=True,
    ),
    "validate_exploit": ToolSpec(
        module="infra.cli.validate_exploit",
        path_flags=("--exploit-path", "--artifact-dir"),
        timeout_seconds=1200,
        needs_base_dir=True,
    ),
    "validate_patch": ToolSpec(
        module="infra.cli.validate_patch",
        path_flags=("--fixed-path", "--artifact-dir"),
        timeout_seconds=1500,
        needs_base_dir=True,
    ),
    "validate_fix": ToolSpec(
        module="infra.cli.validate_patch",
        path_flags=("--fixed-path", "--artifact-dir"),
        timeout_seconds=1500,
        needs_base_dir=True,
    ),
    "write_report": ToolSpec(
        module="infra.cli.write_report",
        path_flags=("--output-path",),
        timeout_seconds=60,
    ),
}

TOOL_ALIASES: dict[str, str] = {}

TASK_TOOL_ALLOWLIST: dict[str, set[str]] = {
    TASK_DETECT: {
        "get_contract_source",
        "get_decompiled_contract",
        "get_storage_slot",
        "eth_call",
    },
    TASK_EXPLOIT: {
        "get_contract_source",
        "get_decompiled_contract",
        "get_storage_slot",
        "eth_call",
        "validate_exploit",
    },
    TASK_PATCH: {
        "get_contract_source",
        "get_decompiled_contract",
        "get_tx_trace",
        "get_storage_slot",
        "eth_call",
        "validate_patch",
    },
    TASK_FILL: {
        "get_contract_source",
        "get_decompiled_contract",
        "get_tx_block",
        "get_tx_trace",
        "get_tx_profit",
        "get_proxy_context",
        "get_storage_slot",
        "write_report",
    },
}


# ---------------------------------------------------------------------------
# Execution context
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolContext:
    """Immutable context scoping every tool execution to a workspace."""

    repo_root: Path
    workspace_root: Path
    task_type: str | None = None
    allowed_exploit_chain: str = ""


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def is_within_workspace(path: Path, workspace: Path) -> bool:
    try:
        path.resolve().relative_to(workspace.resolve())
    except ValueError:
        return False
    return True


def resolve_workspace_path(path_text: str, workspace: Path) -> Path:
    candidate = Path(path_text)
    resolved = candidate.resolve() if candidate.is_absolute() else (workspace / candidate).resolve()
    if not is_within_workspace(resolved, workspace):
        raise ValueError(f"path must stay inside the case workspace: {path_text}")
    return resolved


def resolve_path_flags(
    args: list[str], path_flags: tuple[str, ...], workspace: Path
) -> list[str]:
    resolved: list[str] = []
    index = 0
    while index < len(args):
        token = str(args[index])
        resolved.append(token)
        if token in path_flags:
            if index + 1 >= len(args):
                raise ValueError(f"missing value for {token}")
            resolved.append(str(resolve_workspace_path(args[index + 1], workspace)))
            index += 2
            continue
        index += 1
    return resolved


# ---------------------------------------------------------------------------
# Argument helpers
# ---------------------------------------------------------------------------

def apply_tool_defaults(
    tool_name: str, args: list[str], workspace: Path, repo_root: Path
) -> list[str]:
    normalized = list(args)
    if tool_name == "get_contract_source" and "--output-dir" not in normalized:
        normalized.extend(["--output-dir", str(workspace / "verified_source")])
    elif (
        tool_name in {"get_contract_creation", "get_decompiled_contract", "disassemble_contract"}
        and "--output-dir" not in normalized
    ):
        normalized.extend(["--output-dir", str(workspace / "runtime_artifacts")])
    elif tool_name == "run_exploit_test":
        if "--artifact-dir" not in normalized:
            normalized.extend(["--artifact-dir", str(workspace / "validation_artifacts")])
        if "--json-output" not in normalized:
            normalized.extend(
                [
                    "--json-output",
                    str(workspace / "validation_artifacts" / "run_exploit_test.json"),
                ]
            )
    elif tool_name.startswith("validate_") and "--artifact-dir" not in normalized:
        normalized.extend(["--artifact-dir", str(workspace / "validation_artifacts")])
    if TOOL_SPECS[tool_name].needs_base_dir and "--base-dir" not in normalized:
        normalized.extend(["--base-dir", str(repo_root)])
    benchmark_dir = os.environ.get("W3BB_BENCHMARK_DIR", "").strip()
    if tool_name in {"run_exploit_test", "validate_exploit", "validate_patch", "validate_fix"} and benchmark_dir and "--benchmark-dir" not in normalized:
        normalized.extend(["--benchmark-dir", benchmark_dir])
    if tool_name in {"run_exploit_test", "validate_exploit", "validate_patch", "validate_fix"} and "--foundry-root" not in normalized:
        normalized.extend(["--foundry-root", str(repo_root)])
    return normalized


def extract_flag_value(args: list[str], *flags: str) -> str:
    for index, token in enumerate(args):
        if token in flags and index + 1 < len(args):
            return str(args[index + 1]).strip()
    return ""


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------

def prepend_pythonpath(repo_root: Path) -> dict[str, str]:
    env = dict(os.environ)
    repo_src = str((repo_root / "src").resolve())
    existing = str(env.get("PYTHONPATH", "")).strip()
    env["PYTHONPATH"] = f"{repo_src}{os.pathsep}{existing}" if existing else repo_src
    return env


# ---------------------------------------------------------------------------
# Exploit chain loader
# ---------------------------------------------------------------------------

def load_exploit_case_chain(workspace: Path, repo_root: Path | None = None) -> str:
    case_input = workspace / "CASE_INPUT.txt"
    if not case_input.exists():
        return ""
    try:
        for line in case_input.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("chain:"):
                return line.split(":", 1)[1].strip().lower()
    except OSError:
        return ""
    return ""


# ---------------------------------------------------------------------------
# Core execution
# ---------------------------------------------------------------------------

@dataclass
class ToolResult:
    returncode: int
    stdout: str
    stderr: str
    command: list[str] | None = None

    def to_dict(self) -> dict[str, object]:
        d: dict[str, object] = {
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }
        if self.command is not None:
            d["command"] = self.command
        return d


def execute_tool(tool_name: str, args: list[str], *, context: ToolContext) -> ToolResult:
    """Execute a workspace tool and return the result.

    This is the single entry point used by both the file-IPC broker
    and the MCP server.
    """
    resolved_name = TOOL_ALIASES.get(tool_name, tool_name)

    if resolved_name not in TOOL_SPECS:
        return ToolResult(
            returncode=2,
            stdout="",
            stderr=f"unsupported tool: {tool_name}",
        )

    if context.task_type:
        allowed = TASK_TOOL_ALLOWLIST.get(context.task_type)
        if allowed is not None and resolved_name not in allowed:
            return ToolResult(
                returncode=2,
                stdout="",
                stderr=f"tool not allowed for task {context.task_type}: {resolved_name}",
            )

    spec = TOOL_SPECS[resolved_name]

    try:
        processed = list(args)
        processed = apply_tool_defaults(resolved_name, processed, context.workspace_root, context.repo_root)

        # Exploit-mode chain restriction
        if (
            context.task_type == TASK_EXPLOIT
            and resolved_name == "get_proxy_info"
            and context.allowed_exploit_chain
        ):
            requested_chain = extract_flag_value(processed, "--chain").lower()
            if requested_chain and requested_chain != context.allowed_exploit_chain:
                raise ValueError(
                    "get_proxy_info is restricted to the exploit case chain in exploit mode"
                )

        processed = resolve_path_flags(processed, spec.path_flags, context.workspace_root)
    except ValueError as exc:
        return ToolResult(returncode=2, stdout="", stderr=str(exc))

    command = [sys.executable, "-m", spec.module, *processed]
    try:
        completed = subprocess.run(
            command,
            cwd=context.repo_root,
            env=prepend_pythonpath(context.repo_root),
            capture_output=True,
            text=True,
            timeout=spec.timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return ToolResult(
            returncode=124,
            stdout=str(getattr(exc, "stdout", "") or ""),
            stderr=str(getattr(exc, "stderr", "") or ""),
            command=command,
        )

    return ToolResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        command=command,
    )


def list_tools() -> list[str]:
    return sorted(TOOL_SPECS)
