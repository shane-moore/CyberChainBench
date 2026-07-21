"""Helpers for keeping runtime secrets out of logs and shared artifacts.

Evaluation runs need real secrets at runtime (LLM API keys, Etherscan keys,
archive RPC URLs), but those values must never end up in logs or in artifacts
that get shared/archived. This module centralizes:

- ``redact_command`` / ``redact_text``: scrub secret values before logging.
- ``SECRET_ARTIFACT_NAMES``: file (base)names that contain plaintext secrets
  and must be excluded when archiving a workspace.
- ``is_secret_key``: classify an env var name as secret-bearing.
"""

from __future__ import annotations

import os
import re

# Substrings that mark an env var name as secret-bearing.
_SECRET_NAME_PARTS = ("_KEY", "_KEYS", "_TOKEN", "_SECRET", "_RPC_URL", "API_KEY")

# Specific names that don't match the generic patterns above.
_SECRET_NAME_EXACT = {"DUNE_API_KEY"}

# Files written under a workspace that contain plaintext secrets. These must be
# excluded from any archive/artifact bundle that may be shared externally.
SECRET_ARTIFACT_NAMES = (
    ".env.runtime",
    ".mcp.json",
    "config.toml",  # under .codex/
    "_openhands_config.toml",
)

# Session logs may capture secret-bearing argv/config; archive only after
# redaction (suffix match so e.g. _exploit_cli_session.log is covered).
SECRET_ARTIFACT_SUFFIXES = ("_cli_session.log",)


def is_secret_key(name: str) -> bool:
    """Return True if an env var name should be treated as a secret."""
    upper = name.upper()
    if upper in _SECRET_NAME_EXACT:
        return True
    return any(part in upper for part in _SECRET_NAME_PARTS)


def _secret_values_from_env() -> list[str]:
    values: list[str] = []
    for key, value in os.environ.items():
        if not value or len(value) < 6:
            continue
        if is_secret_key(key):
            values.append(value)
            # RPC URLs often embed the key in a path segment; also scrub the
            # comma-separated members of *_KEYS lists.
            if "," in value:
                values.extend(part for part in value.split(",") if len(part) >= 6)
    # Longest first so substrings don't leave partial leaks behind.
    return sorted(set(values), key=len, reverse=True)


def redact_text(text: str, extra_values: list[str] | None = None) -> str:
    """Replace any known secret values appearing in ``text`` with a marker."""
    if not text:
        return text
    redacted = text
    for value in (extra_values or []) + _secret_values_from_env():
        if value and value in redacted:
            redacted = redacted.replace(value, "***REDACTED***")
    # Also catch ``KEY=value`` / ``key="value"`` forms for secret-named keys even
    # when the value isn't currently in os.environ (e.g. read from .env).
    redacted = re.sub(
        r'((?:[A-Z0-9_]*(?:API_KEY|_KEYS?|_TOKEN|_SECRET|_RPC_URL))\s*[=:]\s*"?)([^\s"\']+)',
        r"\1***REDACTED***",
        redacted,
    )
    return redacted


def redact_command(command: list[str], extra_values: list[str] | None = None) -> str:
    """Render an argv list as a string with secret values redacted."""
    return redact_text(" ".join(str(part) for part in command), extra_values)


def is_secret_artifact(name: str) -> bool:
    """Return True if a filename should be excluded from shared artifacts."""
    if name in SECRET_ARTIFACT_NAMES:
        return True
    return any(name.endswith(suffix) for suffix in SECRET_ARTIFACT_SUFFIXES)
