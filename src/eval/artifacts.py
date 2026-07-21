from __future__ import annotations

import shutil
from pathlib import Path


def copy_session_log_to_artifact(
    artifact_dir: Path,
    session_log_path: str | Path | None,
    session_log_text: str = "",
) -> str:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    dst = artifact_dir / "cli_session.log"
    if session_log_path:
        src = Path(session_log_path)
        if src.exists() and src.is_file():
            shutil.copyfile(src, dst)
            return str(dst)
    if session_log_text:
        dst.write_text(session_log_text)
        return str(dst)
    return ""


def write_raw_response_artifact(artifact_dir: Path, raw_response: str) -> str:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    dst = artifact_dir / "raw_response.txt"
    dst.write_text(raw_response)
    return str(dst)
