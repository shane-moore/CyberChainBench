#!/usr/bin/env python3
"""Compatibility helpers for legacy fix replay imports."""

from __future__ import annotations

from pathlib import Path
import re

from infra.chain.metadata import lookup_contract_creation


def _parse_int(value: object) -> int | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.startswith("0x"):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


def _coerce_transaction_payload(
    tx: dict[str, object], *, fallback_block: int | None = None
) -> dict[str, object] | None:
    tx_hash = str(tx.get("hash", "")).strip()
    caller_value = tx.get("from")
    to_value = tx.get("to")
    input_value = tx.get("input")
    caller = "" if caller_value is None else str(caller_value).strip()
    to_addr = "" if to_value is None else str(to_value).strip()
    calldata = "0x" if input_value is None else str(input_value).strip() or "0x"
    if caller.lower() == "none":
        caller = ""
    if to_addr.lower() == "none":
        to_addr = ""
    block_number = _parse_int(tx.get("blockNumber")) or fallback_block
    value_wei = _parse_int(tx.get("value")) or 0
    if not tx_hash or not caller or block_number is None:
        return None
    if not to_addr and not calldata:
        return None
    return {
        "tx_hash": tx_hash,
        "from": caller,
        "to": to_addr,
        "input": calldata,
        "value_wei": value_wei,
        "block_number": block_number,
        "is_creation": not to_addr,
    }


def _pick_case_chain(case) -> str:
    chain_context = (
        case.chain_context if isinstance(getattr(case, "chain_context", None), dict) else {}
    )
    return str(chain_context.get("fork_chain") or getattr(case, "chain", "") or "ethereum").strip()


def _pick_case_contract_address(case) -> str:
    ground_truth = getattr(case, "ground_truth", None)
    if not isinstance(ground_truth, dict):
        ground_truth = {}
    return str(
        getattr(case, "contracts", {}).get("vulnerable_address", "")
        or ground_truth.get("vulnerable_address", "")
        or getattr(case, "contract_address", "")
        or ""
    ).strip()


def _resolve_case_creation_block(case, *, chain: str, address: str) -> int | None:
    chain_context = (
        case.chain_context if isinstance(getattr(case, "chain_context", None), dict) else {}
    )
    explicit = _parse_int(chain_context.get("creation_block"))
    if explicit is not None:
        return explicit
    creation = lookup_contract_creation(chain, address)
    block_number = _parse_int(creation.get("block_number")) if isinstance(creation, dict) else None
    return block_number


def _solidity_hex_bytes(hex_value: str) -> str:
    text = str(hex_value or "").strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    return text


def _solidity_address_expr(address: str, *, payable: bool = False) -> str:
    text = str(address or "").strip()
    if not text:
        raise ValueError("address is required")
    value = int(text, 16)
    expr = f"address(uint160({value}))"
    if payable:
        expr = f"payable({expr})"
    return expr


def _parse_contract_names(solidity_code: str) -> list[str]:
    concrete = re.findall(r"^\s*contract\s+(\w+)\b", solidity_code, flags=re.MULTILINE)
    return concrete or re.findall(r"^\s*(?:abstract\s+)?contract\s+(\w+)\b", solidity_code, flags=re.MULTILINE)


def _select_fixed_contract_name(
    solidity_code: str,
    *,
    target_hints: list[str] | None = None,
) -> str | None:
    matches = _parse_contract_names(solidity_code)
    if not matches:
        return None
    normalized_hints = {
        (lambda s: s[:-4] if s.endswith(".sol") else s)(str(item).strip()).lower()
        for item in (target_hints or [])
        if str(item).strip()
    }
    if normalized_hints:
        for name in matches:
            if name.lower() in normalized_hints:
                return name
    for name in matches:
        if not name.startswith("I") and not name.endswith("Test"):
            return name
    return matches[0]


def _prepare_fixed_code_line(case, base_dir: Path, fixed_code: str) -> tuple[str | None, str, str]:
    from infra.cli.validate_patch import _prepare_fixed_code_line as _shared_prepare_fixed_code_line
    return _shared_prepare_fixed_code_line(case, base_dir, fixed_code)
