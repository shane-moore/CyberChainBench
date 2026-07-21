"""Pure utility helpers shared by on-chain metadata lookups."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from project_layout import canonicalize_repo_relative

from .metadata_constants import CHAIN_RPC_ALIASES, _MINIMAL_PROXY_RE


def _dedupe_keep_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        item = str(value).strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _clean_optional_text(value: object) -> str:
    text = str(value or "").strip()
    if text.lower() in {"none", "null"}:
        return ""
    return text


def _normalize_paths(base_dir: Path, values: Iterable[str]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        text = text if Path(text).is_absolute() else canonicalize_repo_relative(text)
        path = Path(text)
        if path.is_absolute():
            try:
                normalized.append(str(path.relative_to(base_dir)))
            except ValueError:
                normalized.append(str(path))
        else:
            normalized.append(text)
    return _dedupe_keep_order(normalized)


def _normalize_chain_name(chain: str) -> str:
    normalized = str(chain).strip().lower().replace(" ", "-")
    return CHAIN_RPC_ALIASES.get(normalized, normalized)


def _normalize_logs_block_param(value: str | int | None, default: str) -> str:
    if value in (None, ""):
        return default
    if isinstance(value, int):
        return str(max(value, 0))
    text = str(value).strip().lower()
    if not text:
        return default
    if text == "latest":
        return "latest"
    if text.isdigit():
        return str(max(int(text), 0))
    raise ValueError(f"unsupported block value for logs endpoint: {value}")


def _load_metadata(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _normalize_storage_slot(slot: str | int) -> str:
    if isinstance(slot, int):
        if slot < 0:
            raise ValueError("slot must be non-negative")
        return hex(slot)

    text = str(slot).strip().lower()
    if not text:
        raise ValueError("slot is required")
    if text.startswith("0x"):
        try:
            return hex(int(text, 16))
        except ValueError as exc:
            raise ValueError(f"invalid hex slot: {slot}") from exc
    if text.isdigit():
        return hex(int(text, 10))
    raise ValueError(f"unsupported slot format: {slot}")


def _normalize_block_tag(block: str | int | None) -> str:
    if block is None or str(block).strip() == "":
        return "latest"
    if isinstance(block, int):
        if block < 0:
            raise ValueError("block must be non-negative")
        return hex(block)

    text = str(block).strip().lower()
    if text in {"latest", "pending", "safe", "finalized", "earliest"}:
        return text
    if text.startswith("0x"):
        try:
            return hex(int(text, 16))
        except ValueError as exc:
            raise ValueError(f"invalid hex block tag: {block}") from exc
    if text.isdigit():
        return hex(int(text, 10))
    raise ValueError(f"unsupported block tag: {block}")


def _rpc_error_message(response: dict | None) -> str:
    if not isinstance(response, dict):
        return ""
    error = response.get("error")
    if isinstance(error, dict):
        message = str(error.get("message", "")).strip()
        if message:
            return message
    if isinstance(error, str):
        return error.strip()
    return ""


def _word_to_address(value: str) -> str:
    text = str(value).strip().lower()
    if not text.startswith("0x"):
        return ""
    body = text[2:]
    if not body:
        return ""
    if len(body) < 40:
        body = body.zfill(40)
    address = body[-40:]
    if not address or int(address, 16) == 0:
        return ""
    return "0x" + address


def _extract_minimal_proxy_target(bytecode: str) -> str:
    text = str(bytecode).strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if not text:
        return ""
    match = _MINIMAL_PROXY_RE.search(text)
    if not match:
        return ""
    return "0x" + match.group(1)
