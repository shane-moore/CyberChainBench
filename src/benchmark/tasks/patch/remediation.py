"""Shared fix-remediation normalization for fix benchmark cases."""

from __future__ import annotations

import re

ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")


def _normalize_proxy_address(value: object) -> str:
    text = str(value or "").strip()
    return text if ADDRESS_RE.fullmatch(text) else ""


def _derive_proxy_address(raw: dict) -> str:
    direct = _normalize_proxy_address(
        raw.get("proxy_address") or raw.get("proxy") or raw.get("proxy_contract")
    )
    if direct:
        return direct
    for key in ("target_contracts", "targets"):
        values = raw.get(key)
        if not isinstance(values, list):
            continue
        for item in values:
            candidate = _normalize_proxy_address(item)
            if candidate:
                return candidate
    return ""


def normalize_fix_remediation(
    remediation: dict | None,
    *,
    verification: dict | None = None,
    contracts: dict | None = None,
) -> dict:
    raw = remediation if isinstance(remediation, dict) else {}
    _ = verification if isinstance(verification, dict) else {}
    _ = contracts if isinstance(contracts, dict) else {}

    proxy_address = _derive_proxy_address(raw)
    if not proxy_address:
        return {}
    return {"proxy_address": proxy_address}
