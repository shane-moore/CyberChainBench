#!/usr/bin/env python3
"""Wrapper that locates the real codex binary, handles auth/profile, and exec's it."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent


def _load_dotenv() -> None:
    env_file = ROOT_DIR / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, val = line.partition("=")
            os.environ.setdefault(key.strip(), val.strip())


def _prefer_node_runtime() -> None:
    candidates = [
        os.environ.get("CODEX_NODE_PREFIX", ""),
        str(Path.home() / ".nvm" / "versions" / "node" / "current" / "bin"),
        str(Path.home() / ".nvm" / "versions" / "node" / "v20.20.2" / "bin"),
    ]
    for c in candidates:
        if not c or not Path(c, "node").exists():
            continue
        if c not in os.environ.get("PATH", ""):
            os.environ["PATH"] = f"{c}:{os.environ.get('PATH', '')}"
        return


def _resolve_codex_bin() -> str:
    custom = os.environ.get("REAL_CODEX_BIN", "")
    if custom:
        return custom

    for candidate in [
        "/Applications/Codex.app/Contents/Resources/codex",
        str(Path.home() / ".local" / "bin" / "codex"),
        str(Path.home() / ".cargo" / "bin" / "codex"),
    ]:
        if os.access(candidate, os.X_OK):
            return candidate

    found = shutil.which("codex")
    if found:
        return found

    print(
        "[codex-cli] Could not find the real codex binary.\n"
        "[codex-cli] Set REAL_CODEX_BIN, add codex to PATH, or install it under ~/.local/bin/codex.",
        file=sys.stderr,
    )
    sys.exit(2)


def _maybe_default_codex_profile(real_bin: str) -> None:
    if os.environ.get("CODEX_PROFILE"):
        return
    api_key = os.environ.get("LLM_API_KEY", "")
    if not api_key:
        return

    profile_name = os.environ.get("DEFAULT_CODEX_PROFILE", "project_llm")
    for config_path in [
        Path.home() / ".codex" / "config.toml",
        Path.home() / ".config" / "codex" / "config.toml",
    ]:
        if not config_path.exists():
            continue
        text = config_path.read_text()
        if f"[profiles.{profile_name}]" in text and f"[model_providers.{profile_name}]" in text:
            os.environ["CODEX_PROFILE"] = profile_name
            return


def _ensure_codex_api_auth(real_bin: str) -> None:
    if os.environ.get("CODEX_PROFILE") and os.environ.get("LLM_API_KEY"):
        return

    api_key = os.environ.get("LLM_API_KEY", "")
    if not api_key:
        print(
            "[codex-cli] Refusing to run with ChatGPT-backed Codex login.\n"
            "[codex-cli] Set LLM_API_KEY so Codex CLI can authenticate via API key.\n"
            "[codex-cli] Or set CODEX_PROFILE + LLM_API_KEY to use a custom Codex model provider.",
            file=sys.stderr,
        )
        sys.exit(2)

    os.environ["OPENAI_API_KEY"] = api_key

    try:
        status = subprocess.run(
            [real_bin, "login", "status"],
            capture_output=True, text=True, timeout=15,
        )
        if "Logged in using API key" in (status.stdout + status.stderr):
            return
    except Exception:
        pass

    try:
        result = subprocess.run(
            [real_bin, "login", "--with-api-key"],
            input=api_key, capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            raise RuntimeError("non-zero exit")
    except Exception:
        print(
            "[codex-cli] Failed to authenticate Codex CLI with LLM_API_KEY.\n"
            "[codex-cli] codex_cli benchmark runs are blocked unless API-key auth succeeds.",
            file=sys.stderr,
        )
        sys.exit(2)


def _build_exec_cmd(real_bin: str, argv: list[str]) -> list[str]:
    has_bypass = "--dangerously-bypass-approvals-and-sandbox" in argv
    has_reasoning = False
    has_profile = "--profile" in argv

    prev = ""
    for arg in argv:
        if prev == "-c" and arg.startswith("model_reasoning_effort="):
            has_reasoning = True
            break
        prev = arg

    cmd = [real_bin, "exec"]
    profile = os.environ.get("CODEX_PROFILE", "")
    if profile and not has_profile:
        cmd += ["--profile", profile]
    if not has_reasoning:
        cmd += ["-c", 'model_reasoning_effort="low"']
    if not has_bypass:
        cmd.append("--dangerously-bypass-approvals-and-sandbox")
    for arg in argv:
        if not has_bypass and arg == "--full-auto":
            continue
        cmd.append(arg)
    return cmd


def main() -> None:
    _load_dotenv()
    _prefer_node_runtime()

    real_bin = _resolve_codex_bin()
    argv = sys.argv[1:]

    if not argv or argv[0] != "exec":
        os.execvp(real_bin, [real_bin] + argv)

    argv = argv[1:]  # drop "exec"

    _maybe_default_codex_profile(real_bin)
    _ensure_codex_api_auth(real_bin)

    cmd = _build_exec_cmd(real_bin, argv)
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main()
