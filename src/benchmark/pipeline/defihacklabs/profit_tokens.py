"""Heuristics for extracting profit-token metadata from reference exploits."""

from __future__ import annotations

import re
from pathlib import Path

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
_FUNDING_TOKEN_RE = re.compile(r"\bfundingToken\s*=\s*(.+?);")
_DECL_WITH_ADDRESS_RE = re.compile(
    r"(?P<type>[A-Za-z_][A-Za-z0-9_<>]*)\s+"
    r"(?:(?:public|private|internal|external|constant|immutable|payable)\s+)*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>[^;]*?(?P<address>0x[a-fA-F0-9]{40})[^;]*);"
)

_NATIVE_TOKEN_INFO: dict[str, tuple[str, str]] = {
    "ethereum": ("ETH", "coingecko:ethereum"),
    "arbitrum": ("ETH", "coingecko:ethereum"),
    "optimism": ("ETH", "coingecko:ethereum"),
    "base": ("ETH", "coingecko:ethereum"),
    "blast": ("ETH", "coingecko:ethereum"),
    "linea": ("ETH", "coingecko:ethereum"),
    "bsc": ("BNB", "coingecko:binancecoin"),
    "fantom": ("FTM", "coingecko:fantom"),
    "polygon": ("MATIC", "coingecko:polygon-ecosystem-token"),
    "avalanche": ("AVAX", "coingecko:avalanche-2"),
    "gnosis": ("XDAI", "coingecko:xdai"),
    "moonriver": ("MOVR", "coingecko:moonriver"),
    "celo": ("CELO", "coingecko:celo"),
    "sei": ("SEI", "coingecko:sei-network"),
    "mantle": ("MNT", "coingecko:mantle"),
}

_COMMON_SYMBOL_PRICE_IDS: dict[str, str] = {
    "ETH": "coingecko:ethereum",
    "WETH": "coingecko:ethereum",
    "STETH": "coingecko:staked-ether",
    "WSTETH": "coingecko:wrapped-steth",
    "RETH": "coingecko:rocket-pool-eth",
    "CBETH": "coingecko:coinbase-wrapped-staked-eth",
    "BNB": "coingecko:binancecoin",
    "WBNB": "coingecko:binancecoin",
    "BTC": "coingecko:bitcoin",
    "WBTC": "coingecko:wrapped-bitcoin",
    "MATIC": "coingecko:polygon-ecosystem-token",
    "POL": "coingecko:polygon-ecosystem-token",
    "AVAX": "coingecko:avalanche-2",
    "WAVAX": "coingecko:avalanche-2",
    "FTM": "coingecko:fantom",
    "CELO": "coingecko:celo",
    "SEI": "coingecko:sei-network",
    "MOVR": "coingecko:moonriver",
    "XDAI": "coingecko:xdai",
    "USDC": "coingecko:usd-coin",
    "USDT": "coingecko:tether",
    "DAI": "coingecko:dai",
    "BUSD": "coingecko:binance-usd",
    "FDUSD": "coingecko:first-digital-usd",
}


def _normalize_chain(chain: str) -> str:
    return str(chain or "").strip().lower()


def _normalize_symbol(symbol: str) -> str:
    cleaned = str(symbol or "").strip().replace("$", "")
    if not cleaned:
        return ""
    cleaned = cleaned.split(".")[-1]
    cleaned = re.sub(r"[^A-Za-z0-9]", "", cleaned)
    return cleaned.upper()


def _strip_wrappers(expr: str) -> str:
    value = str(expr or "").strip()
    previous = None
    while value != previous:
        previous = value
        value = re.sub(
            r"^(?:address|payable|IERC20|IERC20Metadata|ERC20|TokenHelper)\s*\((.*)\)$",
            r"\1",
            value,
        )
        value = value.strip()
    return value


def _extract_identifier(expr: str) -> str:
    stripped = _strip_wrappers(expr)
    if "." in stripped:
        stripped = stripped.split(".")[-1]
    match = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", stripped)
    return match.group(0) if match else ""


def _extract_literal_address(expr: str) -> str:
    stripped = _strip_wrappers(expr)
    match = _ADDRESS_RE.search(stripped)
    return match.group(0).lower() if match else ""


def _load_content(exploit_path: Path | None) -> str:
    if not exploit_path or not exploit_path.exists():
        return ""
    return exploit_path.read_text(errors="replace")


def _build_identifier_address_map(content: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for match in _DECL_WITH_ADDRESS_RE.finditer(content):
        name = match.group("name")
        address = match.group("address").lower()
        if not name or not address:
            continue
        mapping[name] = address
    return mapping


def _collect_token_candidates(content: str, chain: str) -> list[dict[str, str]]:
    normalized_chain = _normalize_chain(chain)
    candidates: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for match in _DECL_WITH_ADDRESS_RE.finditer(content):
        type_name = match.group("type")
        name = match.group("name")
        address = match.group("address").lower()
        if not address or address == ZERO_ADDRESS:
            continue
        lowered_name = name.lower()
        lowered_type = type_name.lower()
        if any(
            token in lowered_name
            for token in ("attacker", "victim", "owner", "router", "pair", "pool", "contract")
        ):
            continue
        token_like = (
            "token" in lowered_type
            or "erc20" in lowered_type
            or lowered_type.startswith("i")
            or _normalize_symbol(name) in _COMMON_SYMBOL_PRICE_IDS
        )
        if not token_like:
            continue
        price_id = f"{normalized_chain}:{address}" if normalized_chain else ""
        symbol = _normalize_symbol(name)
        key = (price_id, symbol)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            {
                "kind": "erc20",
                "symbol": symbol,
                "address": address,
                "price_id": price_id,
                "source": f"source_decl:{name}",
            }
        )
    return candidates


def extract_primary_profit_token(exploit_path: Path | None, *, chain: str = "") -> dict[str, str]:
    content = _load_content(exploit_path)
    normalized_chain = _normalize_chain(chain)
    if not content:
        return {
            "kind": "unknown",
            "symbol": "",
            "address": "",
            "price_id": "",
            "source": "",
        }

    identifier_map = _build_identifier_address_map(content)
    funding_match = _FUNDING_TOKEN_RE.search(content)
    if not funding_match:
        return {
            "kind": "unknown",
            "symbol": "",
            "address": "",
            "price_id": "",
            "source": "",
        }

    expr = funding_match.group(1).strip()
    literal_address = _extract_literal_address(expr)
    identifier = _extract_identifier(expr)

    if literal_address == ZERO_ADDRESS or expr.replace(" ", "") in {
        "address(0)",
        "0",
        "address(0x0)",
    }:
        symbol, price_id = _NATIVE_TOKEN_INFO.get(normalized_chain, ("ETH", "coingecko:ethereum"))
        return {
            "kind": "native",
            "symbol": symbol,
            "address": "",
            "price_id": price_id,
            "source": "fundingToken",
        }

    if literal_address:
        symbol = _normalize_symbol(identifier or "")
        return {
            "kind": "erc20",
            "symbol": symbol,
            "address": literal_address,
            "price_id": f"{normalized_chain}:{literal_address}" if normalized_chain else "",
            "source": "fundingToken",
        }

    if identifier:
        address = identifier_map.get(identifier, "")
        symbol = _normalize_symbol(identifier)
        if address:
            return {
                "kind": "erc20",
                "symbol": symbol,
                "address": address,
                "price_id": f"{normalized_chain}:{address}" if normalized_chain else "",
                "source": f"fundingToken->{identifier}",
            }
        if symbol in _COMMON_SYMBOL_PRICE_IDS:
            return {
                "kind": "symbol",
                "symbol": symbol,
                "address": "",
                "price_id": _COMMON_SYMBOL_PRICE_IDS[symbol],
                "source": f"fundingToken->{identifier}",
            }

    return {
        "kind": "unknown",
        "symbol": _normalize_symbol(identifier),
        "address": "",
        "price_id": "",
        "source": "fundingToken",
    }


def extract_profit_token_candidates(
    exploit_path: Path | None, *, chain: str = ""
) -> list[dict[str, str]]:
    content = _load_content(exploit_path)
    primary = extract_primary_profit_token(exploit_path, chain=chain)
    candidates: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(candidate: dict[str, str]) -> None:
        price_id = str(candidate.get("price_id", "")).strip()
        symbol = _normalize_symbol(candidate.get("symbol", ""))
        key = (price_id, symbol)
        if not price_id or key in seen:
            return
        seen.add(key)
        normalized = dict(candidate)
        normalized["symbol"] = symbol
        candidates.append(normalized)

    if primary.get("price_id"):
        add(primary)

    for candidate in _collect_token_candidates(content, chain):
        add(candidate)

    return candidates
