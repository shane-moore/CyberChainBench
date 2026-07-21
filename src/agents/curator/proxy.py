"""Proxy-related receipt-log heuristics for benchmark filling."""

from __future__ import annotations

from typing import Any

UPGRADED_TOPIC0 = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"
ADMIN_CHANGED_TOPIC0 = "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f"
BEACON_UPGRADED_TOPIC0 = "0x1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e"

_EVENT_NAMES = {
    UPGRADED_TOPIC0: "Upgraded(address)",
    ADMIN_CHANGED_TOPIC0: "AdminChanged(address,address)",
    BEACON_UPGRADED_TOPIC0: "BeaconUpgraded(address)",
}


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


def _word_to_address(value: str) -> str:
    text = str(value).strip().lower()
    if not text.startswith("0x"):
        return ""
    body = text[2:]
    if len(body) < 40:
        body = body.zfill(40)
    if len(body) < 40:
        return ""
    candidate = body[-40:]
    try:
        if int(candidate, 16) == 0:
            return ""
    except ValueError:
        return ""
    return "0x" + candidate


def _decode_hex_int(value: Any) -> int | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    try:
        if text.startswith("0x"):
            return int(text, 16)
        return int(text)
    except ValueError:
        return None


def _data_words(data: str) -> list[str]:
    text = str(data or "").strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if not text:
        return []
    if len(text) % 64 != 0:
        text = text[: len(text) - (len(text) % 64)]
    return [f"0x{text[i:i + 64]}" for i in range(0, len(text), 64)]


def _decode_addresses_from_data(data: str) -> list[str]:
    return _dedupe_keep_order([_word_to_address(word) for word in _data_words(data)])


def extract_proxy_log_matches(receipt: dict[str, Any], tx_hash: str = "") -> list[dict[str, Any]]:
    """Return structured matches for common proxy-related receipt logs."""
    logs = receipt.get("logs", []) if isinstance(receipt, dict) else []
    if not isinstance(logs, list):
        return []

    receipt_block = _decode_hex_int(receipt.get("blockNumber"))
    matches: list[dict[str, Any]] = []
    for index, raw_log in enumerate(logs):
        if not isinstance(raw_log, dict):
            continue
        topics = raw_log.get("topics", [])
        if not isinstance(topics, list) or not topics:
            continue

        topic0 = str(topics[0]).strip().lower()
        if topic0 not in _EVENT_NAMES:
            continue

        log_address = str(raw_log.get("address", "")).strip()
        if not log_address:
            continue

        match: dict[str, Any] = {
            "tx_hash": str(tx_hash).strip(),
            "block_number": receipt_block,
            "log_index": _decode_hex_int(raw_log.get("logIndex")) or index,
            "event_topic0": topic0,
            "event_name": _EVENT_NAMES[topic0],
            "proxy_candidate": log_address,
        }

        if topic0 == UPGRADED_TOPIC0:
            implementation = _word_to_address(str(topics[1]).strip()) if len(topics) > 1 else ""
            if implementation:
                match["implementation"] = implementation
        elif topic0 == BEACON_UPGRADED_TOPIC0:
            beacon = _word_to_address(str(topics[1]).strip()) if len(topics) > 1 else ""
            if beacon:
                match["beacon"] = beacon
        elif topic0 == ADMIN_CHANGED_TOPIC0:
            addresses = _decode_addresses_from_data(str(raw_log.get("data", "")))
            if len(addresses) >= 1:
                match["previous_admin"] = addresses[0]
            if len(addresses) >= 2:
                match["new_admin"] = addresses[1]

        matches.append(match)
    return matches
