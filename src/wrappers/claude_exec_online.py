#!/usr/bin/env python3
"""Wrapper that locates the real claude binary, loads .env, and exec's it."""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent

NODE20_BIN = Path.home() / ".nvm" / "versions" / "node" / "v20.20.2" / "bin"


def _load_dotenv() -> None:
    env_file = ROOT_DIR / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip())


def _resolve_claude_bin() -> str:
    custom = os.environ.get("CLAUDE_CODE_BIN", "")
    if custom and os.access(custom, os.X_OK):
        return custom

    for candidate in [
        Path.home() / ".local" / "bin" / "claude",
        NODE20_BIN / "claude",
    ]:
        if candidate.exists() and os.access(str(candidate), os.X_OK):
            return str(candidate)

    found = shutil.which("claude")
    if found:
        return found

    print("[claude-code] Could not find claude binary.", file=sys.stderr)
    sys.exit(2)


def main() -> None:
    _load_dotenv()

    if NODE20_BIN.is_dir():
        os.environ["PATH"] = f"{NODE20_BIN}:{os.environ.get('PATH', '')}"

    real_bin = _resolve_claude_bin()
    os.execvp(real_bin, [real_bin] + sys.argv[1:])


if __name__ == "__main__":
    main()
