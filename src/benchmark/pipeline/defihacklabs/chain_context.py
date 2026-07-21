"""Extract structured historical chain context for on-chain incident cases."""

from __future__ import annotations

import re
from pathlib import Path

CHAIN_FORK_MAP: dict[str, str] = {
    "mainnet": "ethereum",
    "bsc": "bsc",
    "fantom": "fantom",
    "polygon": "polygon",
    "arbitrum": "arbitrum",
    "optimism": "optimism",
    "avalanche": "avalanche",
    "base": "base",
    "gnosis": "gnosis",
    "blast": "blast",
    "celo": "celo",
    "moonriver": "moonriver",
    "linea": "linea",
    "mantle": "mantle",
    "sei": "sei",
}

_URL_RE = re.compile(r"https?://[^\s<>\"]+")
_TX_RE = re.compile(r"(?<![0-9a-fA-F])0x[0-9a-fA-F]{64}(?![0-9a-fA-F])")
_ADDR_RE = re.compile(r"(?<![0-9a-fA-F])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])")
_FORK_RE = re.compile(r'createSelectFork\(\s*"(\w+)"(?:\s*,\s*([\d_]+))?\s*\)')
_SETUP_RE = re.compile(r"function\s+setUp\s*\(\s*\)\s*[^{]*\{")

_DEBUG_HINTS = (
    "tenderly.co",
    "dashboard.tenderly.co",
    "phalcon.blocksec.com",
    "blocksec.com",
)

_EXPLORER_HINTS = (
    "etherscan.io",
    "bscscan.com",
    "polygonscan.com",
    "arbiscan.io",
    "optimistic.etherscan.io",
    "snowtrace.io",
    "ftmscan.com",
    "basescan.org",
    "basescan.io",
    "gnosisscan.io",
    "blastscan.io",
    "celoscan.io",
    "lineascan.build",
    "moonscan.io",
)

_BOOTSTRAP_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("warp", re.compile(r"\b(?:vm|cheat|cheats|hevm)\.warp\s*\(")),
    ("roll", re.compile(r"\b(?:vm|cheat|cheats|hevm)\.roll\s*\(")),
    ("store", re.compile(r"\b(?:vm|cheat|cheats|hevm)\.store\s*\(")),
    ("etch", re.compile(r"\b(?:vm|cheat|cheats|hevm)\.etch\s*\(")),
    ("transact", re.compile(r"\b(?:vm|cheat|cheats|hevm)\.transact\s*\(")),
    ("deal", re.compile(r"\bdeal\s*\(")),
)


def _dedupe_keep_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        item = value.strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _coerce_int(value: object) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).replace("_", "").strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _clean_url(url: str) -> str:
    cleaned = url.strip()
    while cleaned and cleaned[-1] in ").,;]>":
        cleaned = cleaned[:-1]
    return cleaned


def _extract_urls(text: str) -> list[str]:
    return _dedupe_keep_order(
        [_clean_url(match.group(0)) for match in _URL_RE.finditer(text or "")]
    )


def _extract_comment_blob(content: str) -> str:
    parts: list[str] = []
    for match in re.finditer(r"/\*.*?\*/", content, re.DOTALL):
        parts.append(match.group(0))
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            parts.append(stripped)
    return "\n".join(parts)


def _extract_fork_metadata(content: str) -> tuple[str, str]:
    match = _FORK_RE.search(content)
    if not match:
        return "", ""
    alias = match.group(1).strip()
    fork_chain = CHAIN_FORK_MAP.get(alias.lower(), alias.lower())
    return alias, fork_chain


def _extract_function_body(content: str, function_name: str) -> str:
    pattern = re.compile(r"function\s+" + re.escape(function_name) + r"\s*\([^)]*\)\s*[^{]*\{")
    match = pattern.search(content)
    if not match:
        return ""

    depth = 1
    idx = match.end()
    start = idx
    while idx < len(content):
        char = content[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return content[start:idx]
        idx += 1
    return ""


def _extract_tx_hashes(text: str) -> list[str]:
    return _dedupe_keep_order([match.group(0) for match in _TX_RE.finditer(text or "")])


def _extract_addresses(text: str) -> list[str]:
    return _dedupe_keep_order([match.group(0) for match in _ADDR_RE.finditer(text or "")])


def _extract_bootstrap_actions(content: str) -> list[dict[str, str]]:
    setup_body = _extract_function_body(content, "setUp")
    if not setup_body:
        return []

    actions: list[dict[str, str]] = []
    for raw_line in setup_body.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if "createSelectFork" in stripped:
            continue
        for kind, pattern in _BOOTSTRAP_PATTERNS:
            if pattern.search(stripped):
                actions.append(
                    {
                        "kind": kind,
                        "snippet": stripped,
                        "source": "reference_exploit.setUp",
                    }
                )
                break

    deduped: list[dict[str, str]] = []
    seen: set[str] = set()
    for action in actions:
        snippet = action["snippet"]
        if snippet in seen:
            continue
        seen.add(snippet)
        deduped.append(action)
    return deduped


def _dedupe_actions(actions: list[dict[str, str]]) -> list[dict[str, str]]:
    deduped: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for action in actions:
        if not isinstance(action, dict):
            continue
        kind = str(action.get("kind", "")).strip()
        snippet = str(action.get("snippet", "")).strip()
        source = str(action.get("source", "")).strip()
        note = str(action.get("note", "")).strip()
        if not kind or not snippet:
            continue
        key = (kind, snippet)
        if key in seen:
            continue
        seen.add(key)
        normalized = {"kind": kind, "snippet": snippet, "source": source}
        if note:
            normalized["note"] = note
        deduped.append(normalized)
    return deduped


def _infer_repro_tier(base_fork: dict[str, object], bootstrap: list[dict[str, str]]) -> str:
    del base_fork, bootstrap
    return "environment_dependent"


def _is_debug_url(url: str) -> bool:
    lowered = url.lower()
    return (
        any(hint in lowered for hint in _DEBUG_HINTS)
        or "/debugger" in lowered
        or "/debug" in lowered
    )


def _is_explorer_url(url: str) -> bool:
    lowered = url.lower()
    return (
        any(hint in lowered for hint in _EXPLORER_HINTS)
        or "/tx/" in lowered
        or "/address/" in lowered
        or "/block/" in lowered
    )


def build_chain_context(
    exploit_path: Path | None,
    *,
    chain: str = "",
    description: str = "",
    references: list[str] | None = None,
    vulnerable_address: str = "",
    existing: dict | None = None,
) -> dict:
    """Build a normalized chain context object.

    The result is intentionally lightweight and serializable so it can be stored
    directly in task case JSON and passed to model prompts.
    """
    existing = existing if isinstance(existing, dict) else {}

    exploit_text = ""
    comment_blob = ""
    fork_rpc_alias = ""
    fork_chain = ""

    if exploit_path and exploit_path.exists():
        exploit_text = exploit_path.read_text(errors="replace")
        comment_blob = _extract_comment_blob(exploit_text)
        fork_rpc_alias, fork_chain = _extract_fork_metadata(exploit_text)

    references = [str(item).strip() for item in (references or []) if str(item).strip()]
    discovered_urls = _dedupe_keep_order(
        references + _extract_urls(description) + _extract_urls(comment_blob)
    )

    explorer_urls = _dedupe_keep_order(
        [str(item) for item in existing.get("explorer_urls", []) if str(item).strip()]
        + [url for url in discovered_urls if _is_explorer_url(url) and not _is_debug_url(url)]
    )
    debug_urls = _dedupe_keep_order(
        [str(item) for item in existing.get("debug_urls", []) if str(item).strip()]
        + [url for url in discovered_urls if _is_debug_url(url)]
    )

    discovered_attack_txs = _dedupe_keep_order(
        _extract_tx_hashes("\n".join(discovered_urls))
        + _extract_tx_hashes(comment_blob)
        + _extract_tx_hashes(description)
    )
    attack_txs = _dedupe_keep_order(
        [str(item) for item in existing.get("attack_txs", []) if str(item).strip()]
        + discovered_attack_txs
    )

    vulnerable_addresses = _dedupe_keep_order(
        [str(item) for item in existing.get("vulnerable_addresses", []) if str(item).strip()]
        + ([vulnerable_address.strip()] if vulnerable_address.strip() else [])
    )
    related_addresses = _dedupe_keep_order(
        [str(item) for item in existing.get("related_addresses", []) if str(item).strip()]
        + _extract_addresses(comment_blob)
        + _extract_addresses(description)
    )

    normalized_fork_chain = (
        str(existing.get("fork_chain", "")).strip() or fork_chain or chain.strip()
    )
    normalized_alias = str(existing.get("fork_rpc_alias", "")).strip() or fork_rpc_alias
    source_hint = str(existing.get("source_hint", "")).strip() or (
        "reference_exploit" if exploit_path else ""
    )

    return {
        "fork_rpc_alias": normalized_alias,
        "fork_chain": normalized_fork_chain,
        "attack_txs": attack_txs,
        "explorer_urls": explorer_urls,
        "debug_urls": debug_urls,
        "vulnerable_addresses": vulnerable_addresses,
        "related_addresses": related_addresses,
        "source_hint": source_hint,
    }


def build_state_context(
    exploit_path: Path | None,
    *,
    chain_context: dict | None = None,
    existing: dict | None = None,
) -> dict:
    """Build an execution-oriented state context for on-chain evaluation."""
    chain_context = chain_context if isinstance(chain_context, dict) else {}
    existing = existing if isinstance(existing, dict) else {}

    bootstrap_actions = _dedupe_actions(list(existing.get("bootstrap", [])))
    if exploit_path and exploit_path.exists():
        exploit_text = exploit_path.read_text(errors="replace")
        bootstrap_actions = _dedupe_actions(
            bootstrap_actions + _extract_bootstrap_actions(exploit_text)
        )

    existing_base = (
        existing.get("base_fork", {}) if isinstance(existing.get("base_fork"), dict) else {}
    )
    base_fork = {
        "rpc_alias": str(existing_base.get("rpc_alias", "")).strip()
        or str(chain_context.get("fork_rpc_alias", "")).strip(),
        "chain": str(existing_base.get("chain", "")).strip()
        or str(chain_context.get("fork_chain", "")).strip(),
    }

    preconditions = [
        str(item).strip() for item in existing.get("preconditions", []) if str(item).strip()
    ]
    external_dependencies = [
        str(item).strip() for item in existing.get("external_dependencies", []) if str(item).strip()
    ]

    repro_tier = str(existing.get("repro_tier", "")).strip() or _infer_repro_tier(
        base_fork, bootstrap_actions
    )
    return {
        "repro_tier": repro_tier,
        "base_fork": base_fork,
        "bootstrap": bootstrap_actions,
        "preconditions": preconditions,
        "external_dependencies": external_dependencies,
    }
