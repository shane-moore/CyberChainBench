from __future__ import annotations

from pathlib import Path
from typing import Any

from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_utils import keccak

# Cache: (chain, token, block_number) -> (price_per_unit | None, source, notes)
_UNIT_PRICE_CACHE: dict[tuple[str, str, int], tuple[float | None, str, list[str]]] = {}

from infra.chain.metadata import (
    _iter_call_trace_nodes,
    _json_rpc,
    lookup_transaction_receipt,
    lookup_transaction_trace,
    resolve_rpc_url,
)
from project_root import PROJECT_ROOT

_TRANSFER_EVENT_TOPIC0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
_WETH_DEPOSIT_TOPIC0 = "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c"
_WETH_WITHDRAWAL_TOPIC0 = "0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65"
_DECIMALS_SELECTOR = "0x313ce567"
_SYMBOL_SELECTOR = "0x95d89b41"
_ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

_GET_PAIR_SELECTOR = "0xe6a43905"
_TOKEN0_SELECTOR = "0x0dfe1681"
_TOKEN1_SELECTOR = "0xd21220a7"
_GET_RESERVES_SELECTOR = "0x0902f1ac"
_TOTAL_SUPPLY_SELECTOR = "0x18160ddd"
_BALANCE_OF_SELECTOR = "0x70a08231"
_ERC4626_ASSET_SELECTOR = "0x38d52e0f"
_ERC4626_CONVERT_SELECTOR = "0x07a2d13a"
_GET_POOL_SELECTOR = "0x1698ee82"
_SLOT0_SELECTOR = "0x3850c7bd"
_LIQUIDITY_SELECTOR = "0x1a686502"

_CHAIN_WETH: dict[str, str] = {
    "ethereum": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
    "mainnet": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
    "bsc": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
    "bnb": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",
    "polygon": "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270",
    "arbitrum": "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",
    "optimism": "0x4200000000000000000000000000000000000006",
    "base": "0x4200000000000000000000000000000000000006",
    "fantom": "0x21be370d5312f44cb42ce377bc9b8a0cef1a4c83",
    "avalanche": "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7",
    "gnosis": "0xe91d153e0b41518a2ce8dd3d7944fa863463a97d",
    "blast": "0x4300000000000000000000000000000000000004",
    "moonriver": "0x98878b06940ae243284ca214f92bb71a2b032b8a",
    "linea": "0xe5d7c2a44ffddf6b295a15c148167daaaf5cf34f",
    "mantle": "0x78c1b0c915c4faa5fffa6cabf0219da63d7f4cb8",
    "sei": "0xe30fedd158a2e3b13e9badaeabafc5516e95e8c7",
}

# Primary stablecoin per chain (USDT or USDC, 18 or 6 decimals).
_CHAIN_STABLECOINS: dict[str, list[tuple[str, int]]] = {
    "ethereum": [
        ("0xdac17f958d2ee523a2206206994597c13d831ec7", 6),   # USDT
        ("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6),   # USDC
    ],
    "mainnet": [
        ("0xdac17f958d2ee523a2206206994597c13d831ec7", 6),
        ("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6),
    ],
    "bsc": [
        ("0x55d398326f99059ff775485246999027b3197955", 18),   # BSC-USD (USDT)
        ("0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d", 18),   # USDC
    ],
    "bnb": [
        ("0x55d398326f99059ff775485246999027b3197955", 18),
        ("0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d", 18),
    ],
    "polygon": [
        ("0xc2132d05d31c914a87c6611c10748aeb04b58e8f", 6),   # USDT
        ("0x2791bca1f2de4661ed88a30c99a7a9449aa84174", 6),   # USDC.e
    ],
    "arbitrum": [
        ("0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9", 6),   # USDT
        ("0xaf88d065e77c8cc2239327c5edb3a432268e5831", 6),   # USDC
    ],
    "optimism": [
        ("0x94b008aa00579c1307b0ef2c499ad98a8ce58e58", 6),   # USDT
        ("0x0b2c639c533813f4aa9d7837caf62653d097ff85", 6),   # USDC (native)
        ("0x7f5c764cbc14f9669b88837ca1490cca17c31607", 6),   # USDC.e (bridged)
        ("0xda10009cbd5d07dd0cecc66161fc93d7c9000da1", 18),  # DAI
    ],
    "fantom": [
        ("0x049d68029688eabf473097a2fc38ef61633a3c7a", 6),   # fUSDT
        ("0x04068da6c83afcfa0e13ba15a6696662335d5b75", 6),   # USDC
    ],
    "base": [
        ("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", 6),   # USDC
    ],
    "avalanche": [
        ("0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7", 6),   # USDT
        ("0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e", 6),   # USDC
    ],
    "gnosis": [
        ("0xddafbb505ad214d7b80b1f830fccc89b60fb7a83", 6),   # USDC
    ],
    "blast": [
        ("0x4300000000000000000000000000000000000003", 18),  # USDB
    ],
    "moonriver": [
        ("0xe3f5a90f9cb311505cd691a46596599aa1a0ad7d", 6),   # USDT
        ("0xe3f5a90f9cb311505cd691a46596599aa1a0ad7d", 6),   # USDC
    ],
    "linea": [
        ("0xa219439258ca9da29e9cc4ce5596924745e12b93", 6),   # USDT
        ("0x176211869ca2b568f2a7d4ee941e073becab48e0", 6),   # USDC.e
    ],
    "mantle": [
        ("0x09bc4e0d864854c6afb6eb9a9cdf58ac190d0df9", 6),   # USDC
        ("0x201eba5cc46d216ce6dc03f6a759e8e766e956ae", 6),   # USDT
    ],
    "sei": [
        ("0x3894085ef7ff0f0aedf52e2a2704928d1ec074f1", 6),   # USDC
        ("0xb75d0b03c06a926e488e2659df1a861f860bd3d1", 6),   # USDT
    ],
}

_CHAIN_V2_FACTORIES: dict[str, list[tuple[str, str]]] = {
    "ethereum": [
        ("uniswap_v2", "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"),
        ("sushiswap", "0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac"),
    ],
    "mainnet": [
        ("uniswap_v2", "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"),
        ("sushiswap", "0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac"),
    ],
    "bsc": [
        ("pancakeswap_v2", "0xca143ce32fe78f1f7019d7d551a6402fc5350c73"),
    ],
    "bnb": [
        ("pancakeswap_v2", "0xca143ce32fe78f1f7019d7d551a6402fc5350c73"),
    ],
    "polygon": [
        ("quickswap_v2", "0x5757371414417b8c6caad45baef941abc7d3ab32"),
        ("sushiswap", "0xc35DADB65012eC5796536bD9864eD8773aBc74C4"),
    ],
    "arbitrum": [
        ("sushiswap", "0xc35DADB65012eC5796536bD9864eD8773aBc74C4"),
    ],
    "optimism": [
        ("uniswap_v2", "0x0c3c1c532F1e39EdF36BE9Fe0bE1410313E074Bf"),
    ],
    "base": [
        ("uniswap_v2", "0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6"),
    ],
    "fantom": [
        ("spookyswap", "0x152eE697f2E276fA89E96742e9bB9aB1F2E61bE3"),
    ],
    "avalanche": [
        ("traderjoe", "0x9Ad6C38BE94206cA50bb0d90783181834C76657d"),
    ],
    "gnosis": [
        ("honeyswap", "0xA818b4F111Ccac7AA31D0BCc0806d64F2E0737D7"),
    ],
    "blast": [
        ("thruster_v2", "0xb4A7D971D0ADea1c73198C97d7ab3f9CE4aaFA13"),
    ],
    "moonriver": [
        ("solarbeam", "0x049581aEB6Fe262727f290165C29BDAB065a1B68"),
    ],
    "linea": [
        ("lynex", "0xBc7695Fd00E3b32D08124b7a4287493aEE99f9ee"),
    ],
    "mantle": [
        ("fusionx_v2", "0xE5020961fA51ffd3662CDf307dEf18F9a87Cce7c"),
    ],
    "sei": [
        ("dragonswap", "0x23A56CaE5e0B13C701f1E22A24583cB8E0B18539"),
    ],
}

_UNISWAP_V3_FACTORY: dict[str, str] = {
    "ethereum": "0x1f98431c8ad98523631ae4a59f267346ea31f984",
    "mainnet": "0x1f98431c8ad98523631ae4a59f267346ea31f984",
}
_UNISWAP_V3_FEES = (500, 3000, 10000)

_CHAIN_V2_ROUTERS: dict[str, list[tuple[str, str]]] = {
    "ethereum": [
        ("uniswap_v2_router", "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"),
        ("sushiswap_router", "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f"),
    ],
    "mainnet": [
        ("uniswap_v2_router", "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"),
        ("sushiswap_router", "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f"),
    ],
    "bsc": [
        ("pancakeswap_v2_router", "0x10ed43c718714eb63d5aa57b78b54704e256024e"),
    ],
    "bnb": [
        ("pancakeswap_v2_router", "0x10ed43c718714eb63d5aa57b78b54704e256024e"),
    ],
    "polygon": [
        ("quickswap_v2_router", "0xa5e0829caced8ffdd4de3c43696c57f7d7a678ff"),
        ("sushiswap_router", "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506"),
    ],
    "arbitrum": [
        ("sushiswap_router", "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506"),
    ],
    "optimism": [
        ("uniswap_v2_router", "0x4A7b5Da61326A6379179b40d00F57E5bbDC962c2"),
    ],
    "base": [
        ("uniswap_v2_router", "0x4752ba5DBc23f44D87826276BF6Fd6b1C372aD24"),
    ],
    "fantom": [
        ("spookyswap_router", "0xF491e7B69E4244ad4002BC14e878a34207E38c29"),
    ],
    "avalanche": [
        ("traderjoe_router", "0x60aE616a2155Ee3d9A68541Ba4544862310933d4"),
    ],
    "gnosis": [
        ("honeyswap_router", "0x1C232F01118CB8B424793ae03F870aa7D0ac7f77"),
    ],
    "blast": [
        ("thruster_v2_router", "0x98994a9A7a2570367554589189dC9772241650f6"),
    ],
    "moonriver": [
        ("solarbeam_router", "0xAA30eF758139ae4a7f798112902Bf6d65612045f"),
    ],
    "linea": [
        ("lynex_router", "0x610D2f07b7EdC67565160F587F37636194C34E74"),
    ],
    "mantle": [
        ("fusionx_v2_router", "0x1B6B10369d1d498da74233AD74b7b2526fF03612"),
    ],
    "sei": [
        ("dragonswap_router", "0xa4cF2B6Eb40C8E8d0935f91F13A34CC33aB7b44b"),
    ],
}

_CHAIN_V3_QUOTERS: dict[str, str] = {
    "ethereum": "0xb27308f9f90d607463bb33ea1bebb41c27ce5ab6",
    "mainnet": "0xb27308f9f90d607463bb33ea1bebb41c27ce5ab6",
    "optimism": "0xb27308f9f90d607463bb33ea1bebb41c27ce5ab6",
    "arbitrum": "0xb27308f9f90d607463bb33ea1bebb41c27ce5ab6",
    "polygon": "0xb27308f9f90d607463bb33ea1bebb41c27ce5ab6",
    "base": "0x3d4e44eb1374240ce5f1b871ab261cd16335b76a",
    "avalanche": "0xbe0e001a5553eaaf5b8b71e9e1cf2e20996aadd1",
    "blast": "0x6Cdcd65f03408A6B7C4e352CEcB25e4dE0476Fec",
}

_GET_AMOUNTS_OUT_SELECTOR = "0x" + keccak(text="getAmountsOut(uint256,address[])")[:4].hex()
_QUOTE_EXACT_INPUT_SINGLE_SELECTOR = "0x" + keccak(text="quoteExactInputSingle(address,address,uint24,uint256,uint160)")[:4].hex()


def _normalize_address(value: str) -> str:
    text = str(value or "").strip()
    if text.startswith("0x") and len(text) == 42:
        return text.lower()
    return ""


def _topic_to_address(topic: str) -> str:
    normalized = str(topic or "").strip().lower()
    if normalized.startswith("0x") and len(normalized) >= 42:
        return "0x" + normalized[-40:]
    return ""


def _hex_to_int(value: str) -> int:
    text = str(value or "").strip().lower()
    if not text:
        return 0
    if text.startswith("0x"):
        try:
            return int(text, 16)
        except ValueError:
            return 0
    try:
        return int(text)
    except ValueError:
        return 0


def _stringify_amounts(flows: dict[str, int]) -> dict[str, str]:
    return {token: str(amount) for token, amount in flows.items() if amount != 0}


def _decode_symbol_result(raw: str) -> str:
    text = str(raw or "").strip().lower()
    if not text.startswith("0x"):
        return ""
    payload = text[2:]
    if not payload:
        return ""
    try:
        data = bytes.fromhex(payload)
    except ValueError:
        return ""
    if len(data) == 32:
        return data.rstrip(b"").decode("utf-8", errors="ignore").strip()
    if len(data) >= 96:
        offset = int.from_bytes(data[:32], "big")
        if offset + 64 <= len(data):
            start = offset
            length = int.from_bytes(data[start : start + 32], "big")
            body_start = start + 32
            body_end = body_start + length
            if body_end <= len(data):
                return data[body_start:body_end].decode("utf-8", errors="ignore").strip()
    return ""


def _extract_native_value_flows_from_trace(
    chain: str,
    trace: object,
) -> dict[str, int]:
    """Walk a callTracer trace tree and return per-address native value net flows (wei).

    Positive = net received, negative = net sent.  The result is keyed by
    normalised address and denominated in the chain's native token represented
    as the corresponding WETH address so it can be merged directly into the
    ERC-20 ``by_address`` dict.
    """
    nodes = _iter_call_trace_nodes(trace)
    flows: dict[str, int] = {}
    for node in nodes:
        value_hex = str(node.get("value") or "0x0").strip()
        value_wei = _hex_to_int(value_hex)
        if value_wei <= 0:
            continue
        call_type = str(
            node.get("type") or node.get("callType") or node.get("call_type") or ""
        ).strip().upper()
        if call_type in ("DELEGATECALL", "STATICCALL"):
            continue
        from_addr = _normalize_address(str(node.get("from") or ""))
        to_addr = _normalize_address(str(node.get("to") or ""))
        if from_addr:
            flows[from_addr] = flows.get(from_addr, 0) - value_wei
        if to_addr:
            flows[to_addr] = flows.get(to_addr, 0) + value_wei
    return flows


def _inject_native_flows_into_by_address(
    by_address: dict[str, dict[str, int]],
    native_flows: dict[str, int],
    weth_address: str,
) -> None:
    """Merge native value flows into the per-address ERC-20 flow dict as WETH."""
    if not weth_address or not native_flows:
        return
    for addr, delta in native_flows.items():
        if delta == 0:
            continue
        bucket = by_address.setdefault(addr, {})
        bucket[weth_address] = bucket.get(weth_address, 0) + delta


def _extract_address_token_flows(receipt: dict[str, Any]) -> tuple[dict[str, dict[str, int]], int]:
    logs = receipt.get("logs") if isinstance(receipt, dict) else None
    if not isinstance(logs, list):
        return {}, 0

    all_weth = set(_CHAIN_WETH.values())
    by_address: dict[str, dict[str, int]] = {}
    transfer_log_count = 0
    for entry in logs:
        if not isinstance(entry, dict):
            continue
        topics = entry.get("topics")
        if not isinstance(topics, list) or not topics:
            continue
        topic0 = str(topics[0] or "").strip().lower()
        token = _normalize_address(str(entry.get("address", "")))
        if topic0 == _TRANSFER_EVENT_TOPIC0 and len(topics) >= 3:
            transfer_log_count += 1
            from_addr = _topic_to_address(str(topics[1]))
            to_addr = _topic_to_address(str(topics[2]))
            amount = _hex_to_int(str(entry.get("data", "0x0")))
            if not token or amount <= 0:
                continue
            if amount > (1 << 200):
                continue
            if to_addr:
                dst = by_address.setdefault(to_addr, {})
                dst[token] = dst.get(token, 0) + amount
            if from_addr:
                src = by_address.setdefault(from_addr, {})
                src[token] = src.get(token, 0) - amount
        elif topic0 in (_WETH_DEPOSIT_TOPIC0, _WETH_WITHDRAWAL_TOPIC0) and len(topics) >= 2 and token in all_weth:
            who = _topic_to_address(str(topics[1]))
            amount = _hex_to_int(str(entry.get("data", "0x0")))
            if not who or amount <= 0 or amount > (1 << 200):
                continue
            acct = by_address.setdefault(who, {})
            if topic0 == _WETH_DEPOSIT_TOPIC0:
                acct[token] = acct.get(token, 0) + amount
            else:
                acct[token] = acct.get(token, 0) - amount
    return by_address, transfer_log_count


def _eth_call(chain: str, token_address: str, selector: str) -> str:
    rpc_url = resolve_rpc_url(chain)
    token = _normalize_address(token_address)
    if not rpc_url or not token:
        return ""
    response = _json_rpc(rpc_url, "eth_call", [{"to": token, "data": selector}, "latest"])
    if not isinstance(response, dict):
        return ""
    return str(response.get("result", "")).strip()


def _lookup_token_decimals(chain: str, token_address: str) -> int | None:
    raw = _eth_call(chain, token_address, _DECIMALS_SELECTOR)
    if not raw or raw == "0x":
        return None
    value = _hex_to_int(raw)
    if value < 0 or value > 255:
        return None
    return value


def _lookup_token_symbol(chain: str, token_address: str) -> str:
    raw = _eth_call(chain, token_address, _SYMBOL_SELECTOR)
    if not raw or raw == "0x":
        return ""
    return _decode_symbol_result(raw).strip().upper()


def _normalize_token_amounts(chain: str, token_flows: dict[str, str]) -> tuple[dict[str, float], dict[str, int], dict[str, str], list[str]]:
    normalized: dict[str, float] = {}
    decimals_by_token: dict[str, int] = {}
    symbols_by_token: dict[str, str] = {}
    notes: list[str] = []
    for token, raw_amount_text in token_flows.items():
        token_address = _normalize_address(token)
        if not token_address:
            continue
        raw_amount = int(str(raw_amount_text))
        decimals = _lookup_token_decimals(chain, token_address)
        if decimals is None:
            decimals = 18
            notes.append(f"missing decimals for {token_address}; defaulted to 18")
        symbol = _lookup_token_symbol(chain, token_address)
        if symbol:
            symbols_by_token[token_address] = symbol
        decimals_by_token[token_address] = decimals
        normalized[token_address] = raw_amount / float(10 ** decimals)
    return normalized, decimals_by_token, symbols_by_token, notes


def _eth_call_at_block(chain: str, to: str, data: str, block_number: int | None) -> str:
    rpc_url = resolve_rpc_url(chain)
    address = _normalize_address(to)
    if not rpc_url or not address:
        return ""
    block_tag: str | int = "latest"
    if isinstance(block_number, int) and block_number > 0:
        block_tag = hex(block_number)
    response = _json_rpc(rpc_url, "eth_call", [{"to": address, "data": data}, block_tag])
    if not isinstance(response, dict):
        return ""
    return str(response.get("result", "")).strip()


def _pad_address(address: str) -> str:
    normalized = _normalize_address(address)
    if not normalized:
        return ""
    return normalized[2:].rjust(64, "0")


def _pad_uint24(value: int) -> str:
    return hex(int(value))[2:].rjust(64, "0")


def _decode_address(raw: str) -> str:
    text = str(raw or "").strip().lower()
    if not text.startswith("0x") or len(text) < 42:
        return ""
    return "0x" + text[-40:]


def _lookup_pair(chain: str, factory: str, token_a: str, token_b: str, block_number: int | None) -> str:
    payload = _GET_PAIR_SELECTOR + _pad_address(token_a) + _pad_address(token_b)
    return _decode_address(_eth_call_at_block(chain, factory, payload, block_number))


def _lookup_pair_token(chain: str, pair: str, selector: str, block_number: int | None) -> str:
    return _decode_address(_eth_call_at_block(chain, pair, selector, block_number))


def _lookup_pair_reserves(chain: str, pair: str, block_number: int | None) -> tuple[int, int] | None:
    raw = _eth_call_at_block(chain, pair, _GET_RESERVES_SELECTOR, block_number)
    text = str(raw or "").strip().lower()
    if not text.startswith("0x") or len(text) < 2 + 64 * 3:
        return None
    payload = text[2:]
    try:
        reserve0 = int(payload[0:64], 16)
        reserve1 = int(payload[64:128], 16)
    except ValueError:
        return None
    return reserve0, reserve1


def _lookup_v3_pool(chain: str, factory: str, token_a: str, token_b: str, fee: int, block_number: int | None) -> str:
    payload = _GET_POOL_SELECTOR + _pad_address(token_a) + _pad_address(token_b) + _pad_uint24(fee)
    return _decode_address(_eth_call_at_block(chain, factory, payload, block_number))


def _lookup_v3_slot0_sqrt_price_x96(chain: str, pool: str, block_number: int | None) -> int | None:
    raw = _eth_call_at_block(chain, pool, _SLOT0_SELECTOR, block_number)
    text = str(raw or "").strip().lower()
    if not text.startswith("0x") or len(text) < 66:
        return None
    try:
        return int(text[2:66], 16)
    except ValueError:
        return None


def _lookup_v3_liquidity(chain: str, pool: str, block_number: int | None) -> int | None:
    raw = _eth_call_at_block(chain, pool, _LIQUIDITY_SELECTOR, block_number)
    text = str(raw or "").strip().lower()
    if not text.startswith("0x") or len(text) < 66:
        return None
    try:
        return int(text[2:66], 16)
    except ValueError:
        return None


def _quote_amount_out_v2(amount_in: float, reserve_in: float, reserve_out: float) -> float:
    if amount_in <= 0 or reserve_in <= 0 or reserve_out <= 0:
        return 0.0
    amount_in_with_fee = amount_in * 997.0
    return (amount_in_with_fee * reserve_out) / (reserve_in * 1000.0 + amount_in_with_fee)


def _quote_amount_out_v3_spot(
    amount_in: float,
    *,
    sqrt_price_x96: int,
    token_is_token0: bool,
    token_decimals: int,
    native_decimals: int,
) -> float:
    if amount_in <= 0 or sqrt_price_x96 <= 0:
        return 0.0
    price_token1_per_token0 = (sqrt_price_x96 * sqrt_price_x96) / float(2**192)
    if token_is_token0:
        price_native_per_token = price_token1_per_token0 * float(10 ** (token_decimals - native_decimals))
    else:
        if price_token1_per_token0 == 0:
            return 0.0
        price_native_per_token = (1.0 / price_token1_per_token0) * float(10 ** (token_decimals - native_decimals))
    return max(amount_in * price_native_per_token, 0.0)


def _quote_v2_router(chain: str, router: str, token: str, wrapped_native: str, amount_raw: int, block_number: int | None) -> float | None:
    path_payload = abi_encode(["uint256", "address[]"], [int(amount_raw), [token, wrapped_native]]).hex()
    raw = _eth_call_at_block(chain, router, _GET_AMOUNTS_OUT_SELECTOR + path_payload, block_number)
    text = str(raw or "").strip().lower()
    if not text.startswith("0x") or len(text) < 2:
        return None
    try:
        amounts = abi_decode(["uint256[]"], bytes.fromhex(text[2:]))[0]
    except Exception:
        return None
    if not amounts or len(amounts) < 2:
        return None
    out_raw = int(amounts[-1])
    return out_raw / float(10**18)


def _quote_v3_quoter(chain: str, quoter: str, token: str, wrapped_native: str, amount_raw: int, fee: int, block_number: int | None) -> float | None:
    payload = abi_encode(["address", "address", "uint24", "uint256", "uint160"], [token, wrapped_native, int(fee), int(amount_raw), 0]).hex()
    raw = _eth_call_at_block(chain, quoter, _QUOTE_EXACT_INPUT_SINGLE_SELECTOR + payload, block_number)
    text = str(raw or "").strip().lower()
    if not text.startswith("0x") or len(text) < 66:
        return None
    try:
        out_raw = int(text[2:66], 16)
    except ValueError:
        return None
    return out_raw / float(10**18)


def _try_erc4626_underlying_price(
    chain: str, token: str, *, block_number: int | None,
) -> tuple[float | None, str, list[str]]:
    """If *token* is an ERC-4626 vault, price 1 share via its underlying asset."""
    asset_addr = _decode_address(
        _eth_call_at_block(chain, token, _ERC4626_ASSET_SELECTOR, block_number)
    )
    if not asset_addr or asset_addr == _ZERO_ADDRESS:
        return None, "", []
    token_decimals = _lookup_token_decimals(chain, token) or 18
    one_share_raw = 10 ** token_decimals
    payload = _ERC4626_CONVERT_SELECTOR + hex(one_share_raw)[2:].rjust(64, "0")
    raw = _eth_call_at_block(chain, token, payload, block_number)
    text = str(raw or "").strip().lower()
    if not text.startswith("0x") or len(text) < 66:
        return None, "", []
    try:
        underlying_raw = int(text[2:66], 16)
    except ValueError:
        return None, "", []
    asset_decimals = _lookup_token_decimals(chain, asset_addr) or 18
    underlying_amount = underlying_raw / float(10 ** asset_decimals)
    if underlying_amount <= 0:
        return None, "", []
    asset_price, asset_source, asset_notes = _lookup_unit_price(
        chain, asset_addr, block_number=block_number,
    )
    if asset_price is None:
        return None, "", asset_notes
    return (
        underlying_amount * asset_price,
        f"erc4626_vault:{asset_addr}:{asset_source}",
        asset_notes,
    )


def _try_lp_underlying_price(
    chain: str, token: str, *, block_number: int | None,
) -> tuple[float | None, str, list[str]]:
    """If *token* is a Uniswap-V2-style LP, price 1 LP share via reserves."""
    token0 = _decode_address(
        _eth_call_at_block(chain, token, _TOKEN0_SELECTOR, block_number)
    )
    token1 = _decode_address(
        _eth_call_at_block(chain, token, _TOKEN1_SELECTOR, block_number)
    )
    if not token0 or not token1:
        return None, "", []
    reserves = _lookup_pair_reserves(chain, token, block_number)
    if reserves is None:
        return None, "", []
    reserve0, reserve1 = reserves
    raw_supply = _eth_call_at_block(chain, token, _TOTAL_SUPPLY_SELECTOR, block_number)
    text = str(raw_supply or "").strip().lower()
    if not text.startswith("0x") or len(text) < 66:
        return None, "", []
    try:
        total_supply = int(text[2:66], 16)
    except ValueError:
        return None, "", []
    if total_supply <= 0:
        return None, "", []
    lp_decimals = _lookup_token_decimals(chain, token) or 18
    dec0 = _lookup_token_decimals(chain, token0) or 18
    dec1 = _lookup_token_decimals(chain, token1) or 18
    share_frac = float(10 ** lp_decimals) / float(total_supply)
    amount0 = (reserve0 * share_frac) / float(10 ** dec0)
    amount1 = (reserve1 * share_frac) / float(10 ** dec1)
    notes: list[str] = []
    total_native = 0.0
    quoted_any = False
    for underlying, amount in [(token0, amount0), (token1, amount1)]:
        price, source, n = _lookup_unit_price(chain, underlying, block_number=block_number)
        notes.extend(n)
        if price is not None:
            total_native += amount * price
            quoted_any = True
    if not quoted_any:
        return None, "", notes
    # If only one side quoted, double it (standard 50/50 LP approximation)
    price0, _, _ = _lookup_unit_price(chain, token0, block_number=block_number)
    price1, _, _ = _lookup_unit_price(chain, token1, block_number=block_number)
    if (price0 is None) != (price1 is None):
        total_native *= 2.0
        notes.append("only one LP side quotable; doubled for 50/50 approximation")
    return total_native, f"lp_underlying:{token0}+{token1}", notes


def _lookup_unit_price(chain: str, token_address: str, *, block_number: int | None) -> tuple[float | None, str, list[str]]:
    """Get the native-coin price for 1 unit of token. Cached by (chain, token, block)."""
    normalized_chain = str(chain or "").strip().lower()
    wrapped_native = _CHAIN_WETH.get(normalized_chain, "")
    if not wrapped_native:
        return None, "", [f"unsupported chain for native quote: {chain}"]
    token = _normalize_address(token_address)
    if not token or token == wrapped_native:
        return 1.0, "wrapped_native", []

    # Shortcut: known stablecoins → price = 1 USD / native_usd_price
    for stable_addr, _sd in _CHAIN_STABLECOINS.get(normalized_chain, []):
        if token == stable_addr:
            native_usd, _ = _native_to_usd_price(chain, block_number=block_number)
            if native_usd and native_usd > 0:
                return 1.0 / native_usd, "stablecoin_shortcut", []
            break

    cache_key = (normalized_chain, token, int(block_number or 0))
    cached = _UNIT_PRICE_CACHE.get(cache_key)
    if cached is not None:
        return cached

    # Quote 1 full unit of the token
    token_decimals = _lookup_token_decimals(chain, token) or 18
    one_unit_raw = 10 ** token_decimals
    best_quote: float | None = None
    best_source = ""
    notes: list[str] = []

    quoter = _CHAIN_V3_QUOTERS.get(normalized_chain, "")
    if quoter:
        for fee in _UNISWAP_V3_FEES:
            quoted = _quote_v3_quoter(chain, quoter, token, wrapped_native, one_unit_raw, fee, block_number)
            if quoted is not None and quoted > 0 and (best_quote is None or quoted > best_quote):
                best_quote = quoted
                best_source = f"uniswap_v3_quoter:{fee}:{quoter}"

    for source, router in _CHAIN_V2_ROUTERS.get(normalized_chain, []):
        quoted = _quote_v2_router(chain, router, token, wrapped_native, one_unit_raw, block_number)
        if quoted is not None and quoted > 0 and (best_quote is None or quoted > best_quote):
            best_quote = quoted
            best_source = f"{source}:{router}"

    # Fallback: decompose vault shares or LP tokens into underlying assets
    if best_quote is None:
        # Temporarily cache as None to prevent infinite recursion
        _UNIT_PRICE_CACHE[cache_key] = (None, "", [])
        for try_fn in (_try_erc4626_underlying_price, _try_lp_underlying_price):
            fb_price, fb_source, fb_notes = try_fn(chain, token, block_number=block_number)
            notes.extend(fb_notes)
            if fb_price is not None and fb_price > 0:
                best_quote = fb_price
                best_source = fb_source
                break

    if best_quote is None:
        notes.append(f"missing router/quoter native quote for {token}")
    result = (best_quote, best_source, notes)
    _UNIT_PRICE_CACHE[cache_key] = result
    return result


def _quote_actual_amount_native(chain: str, token_address: str, raw_amount: int, *, block_number: int | None) -> tuple[float | None, str, list[str]]:
    """Quote the actual raw token amount through AMM routers (accounts for price impact)."""
    normalized_chain = str(chain or "").strip().lower()
    wrapped_native = _CHAIN_WETH.get(normalized_chain, "")
    if not wrapped_native:
        return None, "", [f"unsupported chain for native quote: {chain}"]
    token = _normalize_address(token_address)
    if not token:
        return None, "", []
    if token == wrapped_native:
        return abs(raw_amount) / float(10**18), "wrapped_native", []
    _UINT256_MAX = (1 << 256) - 1
    abs_raw = abs(int(raw_amount))
    if abs_raw == 0:
        return 0.0, "", []
    if abs_raw > _UINT256_MAX:
        return None, "", [f"raw amount {abs_raw} exceeds uint256, skipping actual-amount quote"]
    best_quote: float | None = None
    best_source = ""
    notes: list[str] = []
    quoter = _CHAIN_V3_QUOTERS.get(normalized_chain, "")
    if quoter:
        for fee in _UNISWAP_V3_FEES:
            quoted = _quote_v3_quoter(chain, quoter, token, wrapped_native, abs_raw, fee, block_number)
            if quoted is not None and quoted > 0 and (best_quote is None or quoted > best_quote):
                best_quote = quoted
                best_source = f"uniswap_v3_quoter:{fee}:{quoter}"
    for source, router in _CHAIN_V2_ROUTERS.get(normalized_chain, []):
        quoted = _quote_v2_router(chain, router, token, wrapped_native, abs_raw, block_number)
        if quoted is not None and quoted > 0 and (best_quote is None or quoted > best_quote):
            best_quote = quoted
            best_source = f"{source}:{router}"
    return best_quote, best_source, notes


def _token_to_native_quote(chain: str, token_address: str, amount: float, *, block_number: int | None, raw_amount: int | None = None) -> tuple[float | None, str, list[str]]:
    if raw_amount is not None:
        quoted, source, notes = _quote_actual_amount_native(chain, token_address, raw_amount, block_number=block_number)
        if quoted is not None:
            return quoted, source, notes
    unit_price, source, notes = _lookup_unit_price(chain, token_address, block_number=block_number)
    if unit_price is None:
        return None, source, notes
    return amount * unit_price, source, notes


def _native_to_usd_price(chain: str, *, block_number: int | None) -> tuple[float | None, str]:
    """Quote 1 unit of native coin (WETH/WBNB/...) to USD via stablecoin pairs."""
    normalized_chain = str(chain or "").strip().lower()
    wrapped_native = _CHAIN_WETH.get(normalized_chain, "")
    stablecoins = _CHAIN_STABLECOINS.get(normalized_chain, [])
    if not wrapped_native or not stablecoins:
        return None, ""

    # Quote 1 native coin worth of WETH
    one_native_raw = 10**18  # WETH is always 18 decimals

    best_price: float | None = None
    best_source = ""

    for stable_address, stable_decimals in stablecoins:
        # Try V3 quoter: WETH → stablecoin
        quoter = _CHAIN_V3_QUOTERS.get(normalized_chain, "")
        if quoter:
            for fee in _UNISWAP_V3_FEES:
                quoted = _quote_v3_quoter(chain, quoter, wrapped_native, stable_address, one_native_raw, fee, block_number)
                if quoted is not None and quoted > 0:
                    usd_out = quoted / float(10 ** (18 - stable_decimals)) if stable_decimals != 18 else quoted
                    if best_price is None or usd_out > best_price:
                        best_price = usd_out
                        best_source = f"uniswap_v3:{fee}:WETH->{stable_address[:10]}"

        # Try V2 routers: WETH → stablecoin
        for source, router in _CHAIN_V2_ROUTERS.get(normalized_chain, []):
            path_payload = abi_encode(
                ["uint256", "address[]"],
                [one_native_raw, [wrapped_native, stable_address]],
            ).hex()
            raw = _eth_call_at_block(chain, router, _GET_AMOUNTS_OUT_SELECTOR + path_payload, block_number)
            text = str(raw or "").strip().lower()
            if not text.startswith("0x") or len(text) < 2:
                continue
            try:
                amounts = abi_decode(["uint256[]"], bytes.fromhex(text[2:]))[0]
            except Exception:
                continue
            if not amounts or len(amounts) < 2:
                continue
            usd_out = int(amounts[-1]) / float(10**stable_decimals)
            if usd_out > 0 and (best_price is None or usd_out > best_price):
                best_price = usd_out
                best_source = f"{source}:WETH->{stable_address[:10]}"

    return best_price, best_source


def lookup_tx_attacker_profit_eth(chain: str, tx_hash: str, *, attacker_address: str = "", base_dir: Path | None = None) -> dict[str, Any]:
    resolved_base = base_dir or PROJECT_ROOT
    receipt = lookup_transaction_receipt(chain, tx_hash)
    if not receipt:
        return {
            "ok": False,
            "chain": str(chain).strip(),
            "tx_hash": str(tx_hash).strip(),
            "error": "failed to fetch transaction receipt",
        }

    block_number = _hex_to_int(str(receipt.get("blockNumber", "0x0")))
    by_address, transfer_log_count = _extract_address_token_flows(receipt)

    # Augment with native value transfers from call trace (captures ETH/BNB/etc.)
    normalized_chain = str(chain).strip().lower()
    weth_for_chain = _CHAIN_WETH.get(normalized_chain, "")
    if weth_for_chain:
        trace_result = lookup_transaction_trace(chain, tx_hash)
        if trace_result.get("ok") and trace_result.get("trace"):
            native_flows = _extract_native_value_flows_from_trace(
                chain, trace_result["trace"]
            )
            _inject_native_flows_into_by_address(by_address, native_flows, weth_for_chain)

    all_account_profit_native: dict[str, float] = {}
    all_account_positive_token_flows: dict[str, dict[str, str]] = {}
    all_account_negative_token_flows: dict[str, dict[str, str]] = {}
    best_address = ""
    best_flows: dict[str, int] = {}
    best_positive_amounts: dict[str, float] = {}
    best_negative_amounts: dict[str, float] = {}
    best_decimals_by_token: dict[str, int] = {}
    best_token_symbols: dict[str, str] = {}
    best_token_profit_native: dict[str, float] = {}
    best_token_cost_native: dict[str, float] = {}
    best_token_quote_sources: dict[str, str] = {}
    best_unquoted_tokens: list[str] = []
    best_notes: list[str] = []
    best_profit_native = 0.0
    best_positive_raw_sum = -1
    quote_block_number = max(int(block_number) - 1, 0) if isinstance(block_number, int) else block_number

    _KNOWN_BURN_ADDRESSES = {
        _ZERO_ADDRESS,
        "0x000000000000000000000000000000000000dead",
        "0x0000000000000000000000000000000000000001",
    }
    _known_routers: set[str] = set()
    for _router_list in _CHAIN_V2_ROUTERS.values():
        for _, router_addr in _router_list:
            _known_routers.add(router_addr.lower())
    _all_token_addresses = {token.lower() for flows in by_address.values() for token in flows}
    _skip_as_attacker = _KNOWN_BURN_ADDRESSES | _known_routers | {weth_for_chain} | _all_token_addresses

    for address, flows in by_address.items():
        if address == _ZERO_ADDRESS:
            continue
        non_zero_flows = {token: str(amount) for token, amount in flows.items() if amount != 0}
        if not non_zero_flows:
            continue

        token_amounts_all, decimals_by_token, token_symbols, decimal_notes = _normalize_token_amounts(
            str(chain).strip(), non_zero_flows
        )
        positive_amounts = {token: amount for token, amount in token_amounts_all.items() if amount > 0}
        negative_amounts = {token: abs(amount) for token, amount in token_amounts_all.items() if amount < 0}
        token_profit_native: dict[str, float] = {}
        token_cost_native: dict[str, float] = {}
        token_quote_sources: dict[str, str] = {}
        unquoted_tokens: list[str] = []
        notes = [*decimal_notes]
        positive_native = 0.0
        negative_native = 0.0

        for token_address, amount in positive_amounts.items():
            raw = flows.get(token_address)
            quoted, source, quote_notes = _token_to_native_quote(str(chain).strip(), token_address, amount, block_number=quote_block_number, raw_amount=raw)
            notes.extend(quote_notes)
            if quoted is None:
                unquoted_tokens.append(token_address)
                continue
            token_profit_native[token_address] = quoted
            if source:
                token_quote_sources[token_address] = source
            positive_native += quoted

        for token_address, amount in negative_amounts.items():
            raw = flows.get(token_address)
            quoted, source, quote_notes = _token_to_native_quote(str(chain).strip(), token_address, amount, block_number=quote_block_number, raw_amount=raw)
            notes.extend(quote_notes)
            if quoted is None:
                unquoted_tokens.append(token_address)
                continue
            token_cost_native[token_address] = quoted
            if source and token_address not in token_quote_sources:
                token_quote_sources[token_address] = source
            negative_native += quoted

        positive_raw_sum = sum(amount for amount in flows.values() if amount > 0)
        if positive_raw_sum > 0 and not token_profit_native and positive_native == 0.0:
            notes.append("positive inflow detected but native quote unavailable; defaulted profit to 0")
        net_profit_native = positive_native - negative_native
        if net_profit_native < 0 and positive_native > 0 and negative_native > 0:
            hard_assets = {weth_for_chain} | {addr for addr, _ in _CHAIN_STABLECOINS.get(normalized_chain, [])}
            pos_all_hard = all(t in hard_assets for t in positive_amounts)
            neg_none_hard = all(t not in hard_assets for t in negative_amounts)
            if pos_all_hard and neg_none_hard:
                notes.append(
                    f"overriding negative net ({net_profit_native:.6f}) to positive-only "
                    f"({positive_native:.6f}): outflows are non-base tokens whose AMM quote "
                    f"exceeds actual realized value"
                )
                net_profit_native = positive_native
        all_account_profit_native[address] = net_profit_native
        all_account_positive_token_flows[address] = {token: str(amount) for token, amount in flows.items() if amount > 0}
        all_account_negative_token_flows[address] = {token: str(amount) for token, amount in flows.items() if amount < 0}
        should_replace = False
        if address not in _skip_as_attacker:
            if not best_address:
                should_replace = True
            elif net_profit_native > best_profit_native:
                should_replace = True
            elif net_profit_native == best_profit_native and positive_raw_sum > best_positive_raw_sum:
                should_replace = True

        if should_replace:
            best_address = address
            best_flows = flows
            best_positive_amounts = positive_amounts
            best_negative_amounts = negative_amounts
            best_decimals_by_token = decimals_by_token
            best_token_symbols = token_symbols
            best_token_profit_native = token_profit_native
            best_token_cost_native = token_cost_native
            best_token_quote_sources = token_quote_sources
            best_unquoted_tokens = unquoted_tokens
            best_notes = notes
            best_profit_native = net_profit_native
            best_positive_raw_sum = positive_raw_sum

    top_raw_positive_sum = sum(amount for amount in best_flows.values() if amount > 0)

    # Convert native-coin profit to USD
    native_price_usd, native_usd_source = _native_to_usd_price(
        str(chain).strip(), block_number=quote_block_number,
    )
    attacker_profit_usd: float | None = None
    if best_unquoted_tokens:
        best_notes.append(
            f"attacker_profit set to null: {len(best_unquoted_tokens)} token(s) could not be quoted: "
            + ", ".join(best_unquoted_tokens[:5])
        )
    elif native_price_usd is not None:
        attacker_profit_usd = best_profit_native * native_price_usd

    return {
        "ok": True,
        "chain": str(chain).strip(),
        "tx_hash": str(tx_hash).strip(),
        "block_number": block_number,
        "quote_block_number": quote_block_number,
        "attacker_address": best_address,
        "attacker_source": "top_profit_address",
        "transfer_log_count": transfer_log_count,
        "matched_transfer_log_count": len([amount for amount in best_flows.values() if amount != 0]),
        "net_token_flows": _stringify_amounts(best_flows),
        "positive_token_flows": {token: str(amount) for token, amount in best_flows.items() if amount > 0},
        "negative_token_flows": {token: str(amount) for token, amount in best_flows.items() if amount < 0},
        "token_amounts": best_positive_amounts,
        "negative_token_amounts": best_negative_amounts,
        "token_decimals": best_decimals_by_token,
        "token_symbols": best_token_symbols,
        "token_profit_native": best_token_profit_native,
        "token_cost_native": best_token_cost_native,
        "token_quote_sources": best_token_quote_sources,
        "unquoted_tokens": best_unquoted_tokens,
        "attacker_profit": attacker_profit_usd if attacker_profit_usd is not None else None,
        "native_price_usd": native_price_usd,
        "native_usd_source": native_usd_source,
        "account_profit_usd": {addr: (p * native_price_usd if native_price_usd else None) for addr, p in all_account_profit_native.items()},
        "account_positive_token_flows": all_account_positive_token_flows,
        "account_negative_token_flows": all_account_negative_token_flows,
        "top_profit_positive_sum": str(top_raw_positive_sum),
        "notes": best_notes,
        "base_dir": str(resolved_base),
    }
