"""Temporary per-case workspaces for agent evaluation runs."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Iterable

from project_layout import EVAL_DETECT_WORKSPACE_DIR, EVAL_EXPLOIT_WORKSPACE_DIR, EVAL_PATCH_WORKSPACE_DIR

WORKSPACE_OWNER_FILE = ".owner_pid"


def _reset_workspace_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)


def _workspace_slug(value: str) -> str:
    text = "".join(ch if ch.isalnum() else "-" for ch in str(value or "").strip().lower())
    text = "-".join(part for part in text.split("-") if part)
    return text or "unknown"


def create_agent_case_workspace(
    base_dir: Path,
    *,
    task: str,
    case_id: str,
    model: str,
    case_input_text: str = "",
    output_name: str = "",
) -> Path:
    task_root = {
        "detect": EVAL_DETECT_WORKSPACE_DIR,
        "exploit": EVAL_EXPLOIT_WORKSPACE_DIR,
        "patch": EVAL_PATCH_WORKSPACE_DIR,
        "fix": EVAL_PATCH_WORKSPACE_DIR,
    }[task]
    workspace_dir = base_dir / task_root / f"{_workspace_slug(case_id)}-{os.getpid()}"
    _reset_workspace_dir(workspace_dir)
    for dirname in ("verified_source", "runtime_artifacts", "validation_artifacts"):
        (workspace_dir / dirname).mkdir(parents=True, exist_ok=True)
    (workspace_dir / WORKSPACE_OWNER_FILE).write_text(f"{os.getpid()}\n")

    if case_input_text:
        (workspace_dir / "CASE_INPUT.txt").write_text(case_input_text.strip() + "\n")

    lines = [
        "Temporary evaluation workspace for one case.",
        f"task: {task}",
        f"case_id: {case_id}",
        f"model: {model}",
        "workspace_root: .",
        "repo_root: .",
    ]
    if output_name:
        lines.append(f"final_output: {output_name}")
    lines.extend(
        [
            "verified_source_dir: verified_source",
            "runtime_artifacts_dir: runtime_artifacts",
            "validation_artifacts_dir: validation_artifacts",
            "Harness cleanup policy: this workspace is deleted after the case evaluation finishes.",
            "Persist anything needed for scoring in the designated output file or validation_artifacts directory before finishing.",
        ]
    )
    (workspace_dir / "WORKSPACE.txt").write_text("\n".join(lines) + "\n")
    return workspace_dir


def cleanup_agent_case_workspace(workspace_dir: str | Path | None) -> None:
    if not workspace_dir:
        return
    path = Path(workspace_dir)
    shutil.rmtree(path, ignore_errors=True)


def _read_workspace_owner_pid(workspace_dir: Path) -> int | None:
    marker = workspace_dir / WORKSPACE_OWNER_FILE
    if not marker.exists():
        return None
    try:
        return int(marker.read_text().strip())
    except (OSError, ValueError):
        return None


def _pid_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def cleanup_agent_case_workspaces(
    base_dir: Path,
    *,
    include_owner_pids: Iterable[int] | None = None,
) -> int:
    """Delete all stale per-case evaluation workspaces under agent_cases/.

    This intentionally leaves the shared Foundry eval workspace intact while
    removing abandoned per-case directories from earlier interrupted runs.
    Active workspaces owned by a still-running process are preserved.
    Returns the number of case directories removed.
    """

    roots = [
        (base_dir / EVAL_DETECT_WORKSPACE_DIR).resolve(),
        (base_dir / EVAL_EXPLOIT_WORKSPACE_DIR).resolve(),
        (base_dir / EVAL_PATCH_WORKSPACE_DIR).resolve(),
    ]

    forced_owner_pids = {int(pid) for pid in (include_owner_pids or []) if int(pid) > 0}

    removed = 0
    for task_dir in roots:
        if not task_dir.exists():
            continue
        for child in list(task_dir.iterdir()):
            if not child.is_dir():
                child.unlink(missing_ok=True)
                continue
            owner_pid = _read_workspace_owner_pid(child)
            if owner_pid is not None and owner_pid in forced_owner_pids:
                shutil.rmtree(child, ignore_errors=True)
                removed += 1
                continue
            if owner_pid is not None and _pid_is_running(owner_pid):
                continue
            shutil.rmtree(child, ignore_errors=True)
            removed += 1
        task_dir.mkdir(parents=True, exist_ok=True)

    return removed
