"""Constants shared by on-chain metadata helpers."""

from __future__ import annotations

import re

from project_layout import BENCHMARK_CACHE_DIR, DEFIHACKLABS_DIR

DEFAULT_CONTEXT_CACHE = BENCHMARK_CACHE_DIR / "chain_context.json"
DFHL_VERIFIED_SOURCE_ASSET_ROOT = DEFIHACKLABS_DIR / "verified_source_by_address"
DFHL_RECOVERED_SOURCE_ASSET_ROOT = DEFIHACKLABS_DIR / "recovered_source_by_address"
DFHL_VERIFIED_SOURCE_ROOT = DEFIHACKLABS_DIR / "verified_source"
DFHL_RECOVERED_SOURCE_ROOT = DEFIHACKLABS_DIR / "recovered_source"

CHAIN_RPC_ENV_VARS: dict[str, tuple[str, ...]] = {
    "ethereum": ("ETH_RPC_URL", "MAINNET_RPC_URL"),
    "bsc": (
        "BSC_ARCHIVE_RPC_URL",
        "BNB_SMART_CHAIN_ARCHIVE_RPC_URL",
        "BSC_RPC_URL",
        "BNB_SMART_CHAIN_RPC_URL",
    ),
    "fantom": ("FANTOM_RPC_URL", "FTM_RPC_URL"),
    "polygon": ("POLYGON_RPC_URL", "MATIC_RPC_URL"),
    "arbitrum": ("ARBITRUM_RPC_URL", "ARBITRUM_ONE_RPC_URL"),
    "optimism": ("OPTIMISM_RPC_URL",),
    "avalanche": ("AVALANCHE_RPC_URL", "AVAX_RPC_URL"),
    "base": ("BASE_RPC_URL",),
    "blast": ("BLAST_RPC_URL",),
    "gnosis": ("GNOSIS_RPC_URL", "XDAI_RPC_URL"),
    "moonriver": ("MOONRIVER_RPC_URL",),
    "celo": ("CELO_RPC_URL",),
    "linea": ("LINEA_RPC_URL",),
    "mantle": ("MANTLE_RPC_URL",),
    "sei": ("SEI_RPC_URL",),
}

CHAIN_TRACE_RPC_ENV_VARS: dict[str, tuple[str, ...]] = {
    "ethereum": ("ETH_TRACE_RPC_URL", "MAINNET_TRACE_RPC_URL"),
    "bsc": (
        "BSC_TRACE_RPC_URL",
        "BNB_SMART_CHAIN_TRACE_RPC_URL",
    ),
    "fantom": ("FANTOM_TRACE_RPC_URL", "FTM_TRACE_RPC_URL"),
    "polygon": ("POLYGON_TRACE_RPC_URL", "MATIC_TRACE_RPC_URL"),
    "arbitrum": ("ARBITRUM_TRACE_RPC_URL", "ARBITRUM_ONE_TRACE_RPC_URL"),
    "optimism": ("OPTIMISM_TRACE_RPC_URL",),
    "avalanche": ("AVALANCHE_TRACE_RPC_URL", "AVAX_TRACE_RPC_URL"),
    "base": ("BASE_TRACE_RPC_URL",),
    "blast": ("BLAST_TRACE_RPC_URL",),
    "gnosis": ("GNOSIS_TRACE_RPC_URL", "XDAI_TRACE_RPC_URL"),
    "moonriver": ("MOONRIVER_TRACE_RPC_URL",),
    "celo": ("CELO_TRACE_RPC_URL",),
    "linea": ("LINEA_TRACE_RPC_URL",),
    "mantle": ("MANTLE_TRACE_RPC_URL",),
    "sei": ("SEI_TRACE_RPC_URL",),
}

CHAIN_RPC_ALIASES: dict[str, str] = {
    "mainnet": "ethereum",
    "eth": "ethereum",
    "bnb": "bsc",
    "bnb-smart-chain": "bsc",
    "binance-smart-chain": "bsc",
    "ftm": "fantom",
    "matic": "polygon",
    "arb": "arbitrum",
    "op": "optimism",
    "avax": "avalanche",
}

EXPLORER_CHAIN_IDS: dict[str, int] = {
    "ethereum": 1,
    "bsc": 56,
    "polygon": 137,
    "arbitrum": 42161,
    "optimism": 10,
    "avalanche": 43114,
    "fantom": 250,
    "base": 8453,
    "gnosis": 100,
    "blast": 81457,
    "celo": 42220,
}

ETHERSCAN_V2_BASE = "https://api.etherscan.io/v2/api"
DUNE_API_BASE = "https://api.dune.com/api/v1"
DUNE_SCHEMA_BY_CHAIN: dict[str, str] = {
    "ethereum": "ethereum",
    "bsc": "bnb",
    "polygon": "polygon",
    "arbitrum": "arbitrum",
    "optimism": "optimism",
    "avalanche": "avalanche_c",
    "fantom": "fantom",
    "base": "base",
    "gnosis": "gnosis",
    "blast": "blast",
    "celo": "celo",
}
EXPLORER_ADDRESS_HOSTS: dict[str, str] = {
    "ethereum": "etherscan.io",
    "bsc": "bscscan.com",
    "polygon": "polygonscan.com",
    "arbitrum": "arbiscan.io",
    "optimism": "optimistic.etherscan.io",
    "avalanche": "snowtrace.io",
    "fantom": "ftmscan.com",
    "base": "basescan.org",
    "gnosis": "gnosisscan.io",
    "blast": "blastscan.io",
    "celo": "celoscan.io",
}

ERC1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
ERC1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
ERC1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
IMPLEMENTATION_SELECTOR = "0x5c60da1b"
_MINIMAL_PROXY_RE = re.compile(r"363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3")
