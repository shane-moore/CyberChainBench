"""Merge per-source benchmark cases into one normalized collection.

This module intentionally sits *after* the source-specific parsers:
  - DeFiHackLabs parser
  - Clara parser

The goal is to keep those parsers separate while exposing one merged,
schema-stable representation for downstream scripts.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Iterable

from benchmark.pipeline.clara.parse import extract_all as extract_clara_cases
from benchmark.pipeline.defihacklabs.parse import extract_all as extract_dfhl_cases
from benchmark.pipeline.case_links import derive_case_link
from benchmark.pipeline.paths import PARSER_PREPROCESSED_DIR, RAW_ALL_CASES_PATH
from project_layout import CLARA_DIR, DEFIHACKLABS_DIR


def _load_json_array(path: Path) -> list[dict]:
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    return data if isinstance(data, list) else []


def _wanted_sources(source: str) -> set[str]:
    if source == "defihacklabs":
        return {"DeFiHackLabs"}
    if source == "clara":
        return {"Clara"}
    return {"DeFiHackLabs", "Clara"}


def _as_str(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "y"}:
            return True
        if lowered in {"0", "false", "no", "n", ""}:
            return False
    return bool(value)


def _as_int_or_none(value: object) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _string_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [_as_str(item) for item in value if _as_str(item)]
    if isinstance(value, tuple):
        return [_as_str(item) for item in value if _as_str(item)]
    text = _as_str(value)
    return [text] if text else []


def _int_list(value: object) -> list[int]:
    if not isinstance(value, list):
        return []
    out: list[int] = []
    for item in value:
        parsed = _as_int_or_none(item)
        if parsed is not None:
            out.append(parsed)
    return out


def _dict_or_empty(value: object) -> dict:
    return value if isinstance(value, dict) else {}


_CHAIN_HINTS: dict[str, tuple[str, ...]] = {
    "ethereum": ("ethereum", "eth mainnet", "mainnet", "etherscan.io"),
    "bsc": ("bsc", "bnb smart chain", "binance smart chain", "bscscan.com"),
    "fantom": ("fantom", "ftm", "ftmscan.com"),
    "polygon": ("polygon", "matic", "polygonscan.com"),
    "arbitrum": ("arbitrum", "arbiscan.io"),
    "optimism": ("optimism", "optimistic.etherscan.io"),
    "avalanche": ("avalanche", "avax", "snowtrace.io"),
    "base": ("base", "basescan.org", "basescan.io"),
    "blast": ("blast", "blastscan.io"),
    "gnosis": ("gnosis", "xdai", "gnosisscan.io"),
    "moonriver": ("moonriver", "moonscan.io"),
    "celo": ("celo", "celoscan.io"),
    "linea": ("linea", "lineascan.build"),
    "mantle": ("mantle",),
    "sei": ("sei",),
    "aptos": ("aptos",),
    "sui": ("sui",),
    "solana": ("solana",),
    "starknet": ("starknet",),
}

_CROSS_CHAIN_MARKERS = (
    "cross chain",
    "cross-chain",
    "crosschain",
    "bridge exploit",
    "bridge attack",
    "bridge vulnerability",
)

_LANGUAGE_BY_EXTENSION = {
    ".sol": "solidity",
    ".vy": "vyper",
    ".move": "move",
    ".rs": "rust",
    ".cairo": "cairo",
    ".sw": "sway",
    ".tact": "tact",
    ".fc": "func",
    ".tsol": "solidity",
}

_VM_BY_LANGUAGE = {
    "solidity": "evm",
    "vyper": "evm",
    "huff": "evm",
    "yul": "evm",
    "move": "move-vm",
    "rust": "svm",
    "cairo": "starknet",
    "sway": "fuelvm",
    "func": "tvm",
    "tact": "tvm",
}


def _dedupe_keep_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        item = _as_str(value).strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _infer_language(case: dict, contracts: dict) -> str:
    paths: list[str] = []
    for key in ("vulnerable", "fixed"):
        paths.extend(_string_list(contracts.get(key, [])))
    paths.extend(
        _string_list(
            [
                contracts.get("exploit", ""),
                case.get("reference_exploit", ""),
                case.get("forge_test_cmd", ""),
            ]
        )
    )

    for path_text in paths:
        suffix = Path(path_text).suffix.lower()
        if suffix in _LANGUAGE_BY_EXTENSION:
            return _LANGUAGE_BY_EXTENSION[suffix]

    source = _as_str(case.get("source", ""))
    if source in {"DeFiHackLabs", "Clara"}:
        return "solidity"
    return ""


def _infer_vm_family(language: str, chain: str, chains_involved: list[str]) -> str:
    if language in _VM_BY_LANGUAGE:
        return _VM_BY_LANGUAGE[language]
    known = [chain.strip(), *chains_involved]
    if any(
        item in _CHAIN_HINTS and item not in {"aptos", "sui", "solana", "starknet"}
        for item in known
    ):
        return "evm"
    if any(item in {"aptos", "sui"} for item in known):
        return "move-vm"
    if "solana" in known:
        return "svm"
    if "starknet" in known:
        return "starknet"
    return ""


def _infer_chains_involved(case: dict, chain_context: dict) -> list[str]:
    values: list[str] = []
    primary = _as_str(case.get("chain", "")).strip().lower()
    if primary:
        values.append(primary)

    fork_chain = _as_str(chain_context.get("fork_chain", "")).strip().lower()
    if fork_chain:
        values.append(fork_chain)

    text_blob = "\n".join(
        [
            _as_str(case.get("name", "")),
            _as_str(case.get("description", "")),
            _as_str(case.get("report_section", "")),
            _as_str(case.get("reference", "")),
            _as_str(_dict_or_empty(case.get("contest")).get("type", "")),
            _as_str(_dict_or_empty(case.get("vulnerability_detail")).get("type_raw", "")),
            "\n".join(_string_list(chain_context.get("explorer_urls", []))),
            "\n".join(_string_list(chain_context.get("debug_urls", []))),
        ]
    ).lower()

    for chain_name, hints in _CHAIN_HINTS.items():
        if any(hint in text_blob for hint in hints):
            values.append(chain_name)

    return _dedupe_keep_order(values)


def _infer_cross_chain(case: dict, chain_context: dict, chains_involved: list[str]) -> bool:
    text_blob = "\n".join(
        [
            _as_str(case.get("name", "")),
            _as_str(case.get("description", "")),
            _as_str(case.get("report_section", "")),
            _as_str(_dict_or_empty(case.get("contest")).get("type", "")),
            _as_str(_dict_or_empty(case.get("vulnerability_detail")).get("type_raw", "")),
        ]
    ).lower()

    if any(marker in text_blob for marker in _CROSS_CHAIN_MARKERS):
        return True
    return len(chains_involved) > 1


def normalize_case(raw: dict) -> dict:
    """Normalize one raw case into the merged schema.

    Type-safe defaults are used:
      - missing strings -> ""
      - missing arrays -> []
      - missing booleans -> False
      - missing numeric locations -> null
    """
    case = deepcopy(raw)

    contest_raw = _dict_or_empty(case.get("contest"))

    contracts_raw = _dict_or_empty(case.get("contracts"))

    vuln_raw = _dict_or_empty(case.get("vulnerability_detail"))

    tasks_raw = _dict_or_empty(case.get("tasks"))
    detect_raw = _dict_or_empty(tasks_raw.get("detect"))
    exploit_raw = _dict_or_empty(tasks_raw.get("exploit"))
    fix_raw = _dict_or_empty(tasks_raw.get("patch") or tasks_raw.get("fix"))

    expected_location_raw = _dict_or_empty(detect_raw.get("expected_location"))

    clara_raw = _dict_or_empty(case.get("clara"))
    chain_context_raw = _dict_or_empty(case.get("chain_context"))

    tx_hashes = _string_list(clara_raw.get("tx_hashes", case.get("tx_hashes", [])))
    victim_addresses = _string_list(
        clara_raw.get("victim_addresses", case.get("victim_addresses", []))
    )
    manual_validated = _as_bool(
        clara_raw.get("manual_validated", case.get("manual_validated", False))
    )

    expected_location = {
        "file": _as_str(expected_location_raw.get("file", "")),
        "function": _as_str(expected_location_raw.get("function", "")),
        "line": _as_int_or_none(expected_location_raw.get("line")),
        "line_range": _int_list(expected_location_raw.get("line_range", [])),
    }

    contracts = {
        "vulnerable": _string_list(contracts_raw.get("vulnerable", [])),
        "vulnerable_address": _as_str(contracts_raw.get("vulnerable_address", "")),
        "exploit": _as_str(
            contracts_raw.get(
                "exploit",
                exploit_raw.get("reference_exploit", case.get("reference_exploit", "")),
            )
        ),
        "fixed": _string_list(contracts_raw.get("fixed", [])),
    }

    tasks = {
        "detect": {
            "expected_type": _as_str(detect_raw.get("expected_type", case.get("category", ""))),
            "expected_label": _as_str(
                detect_raw.get("expected_label", case.get("expected_label", ""))
            ),
            "expected_location": expected_location,
        },
        "exploit": {
            "forge_test_cmd": _as_str(
                exploit_raw.get("forge_test_cmd", case.get("forge_test_cmd", ""))
            ),
            "success_criteria": _as_str(
                exploit_raw.get("success_criteria", case.get("success_criteria", ""))
            ),
            "reference_exploit": _as_str(
                exploit_raw.get(
                    "reference_exploit",
                    case.get("reference_exploit", contracts["exploit"]),
                )
            ),
        },
        "patch": {
            "fix_description": _as_str(
                fix_raw.get("fix_description", case.get("fix_description", ""))
            ),
            "verification": (
                fix_raw.get("verification", {})
                if isinstance(fix_raw.get("verification", {}), dict)
                else {}
            ),
            "remediation": (
                fix_raw.get("remediation", {})
                if isinstance(fix_raw.get("remediation", {}), dict)
                else {}
            ),
        },
    }

    vulnerability_detail = {
        "type_raw": _as_str(vuln_raw.get("type_raw", "")),
        "references": _string_list(vuln_raw.get("references", [])),
        "root_cause": _as_str(vuln_raw.get("root_cause", "")),
        "attack_vector": _as_str(vuln_raw.get("attack_vector", "")),
        "impact": _as_str(vuln_raw.get("impact", "")),
    }

    clara = {
        "incident_id": _as_str(clara_raw.get("incident_id", "")),
        "page_url": _as_str(clara_raw.get("page_url", case.get("reference", ""))),
        "page_description": _as_str(clara_raw.get("page_description", "")),
        "window_label": _as_str(clara_raw.get("window_label", "")),
        "tx_hashes": tx_hashes,
        "victim_addresses": victim_addresses,
        "manual_validated": manual_validated,
    }

    attack_txs = _string_list(chain_context_raw.get("attack_txs", []))
    for item in _string_list(chain_context_raw.get("attack_tx_hashes", [])):
        if item and item not in attack_txs:
            attack_txs.append(item)

    chain_context = {
        "fork_rpc_alias": _as_str(chain_context_raw.get("fork_rpc_alias", "")),
        "fork_chain": _as_str(chain_context_raw.get("fork_chain", case.get("chain", ""))),
        "fork_block": _as_int_or_none(chain_context_raw.get("fork_block")),
        "attack_txs": attack_txs,
        "explorer_urls": _string_list(chain_context_raw.get("explorer_urls", [])),
        "debug_urls": _string_list(chain_context_raw.get("debug_urls", [])),
        "vulnerable_addresses": _string_list(chain_context_raw.get("vulnerable_addresses", [])),
        "related_addresses": _string_list(chain_context_raw.get("related_addresses", [])),
        "source_hint": _as_str(chain_context_raw.get("source_hint", "")),
    }

    chains_involved = _infer_chains_involved(case, chain_context)
    language = _as_str(case.get("language", "")).strip().lower() or _infer_language(case, contracts)
    vm_family = _as_str(case.get("vm_family", "")).strip().lower() or _infer_vm_family(
        language,
        _as_str(case.get("chain", "")).strip().lower(),
        chains_involved,
    )
    cross_chain = _as_bool(
        case.get("cross_chain", _infer_cross_chain(case, chain_context, chains_involved))
    )

    case.update(
        {
            "id": _as_str(case.get("id", "")),
            "name": _as_str(case.get("name", "")),
            "source": _as_str(case.get("source", "")),
            "category": _as_str(case.get("category", "")),
            "severity": _as_str(case.get("severity", "")),
            "chain": _as_str(case.get("chain", "")),
            "language": language,
            "vm_family": vm_family,
            "cross_chain": cross_chain,
            "chains_involved": chains_involved,
            "date": _as_str(case.get("date", "")),
            "report_date": _as_str(case.get("report_date", "")),
            "loss": _as_str(case.get("loss", "")),
            "profit": _as_str(case.get("profit", "")),
            "description": _as_str(case.get("description", "")),
            "report_section": _as_str(case.get("report_section", "")),
            "reference": _as_str(case.get("reference", clara.get("page_url", ""))),
            "contest": {
                "id": _as_str(contest_raw.get("id", "")),
                "name": _as_str(contest_raw.get("name", "")),
                "type": _as_str(contest_raw.get("type", "")),
                "award_pool": _as_str(contest_raw.get("award_pool", "")),
            },
            "bug_label": _as_str(case.get("bug_label", "")),
            "chain_context": chain_context,
            "contracts": contracts,
            "vulnerability_detail": vulnerability_detail,
            "tasks": tasks,
            "expected_label": tasks["detect"]["expected_label"],
            "forge_test_cmd": tasks["exploit"]["forge_test_cmd"],
            "reference_exploit": tasks["exploit"]["reference_exploit"],
            "success_criteria": tasks["exploit"]["success_criteria"],
            "fix_description": tasks["patch"]["fix_description"],
            "tx_hashes": tx_hashes,
            "victim_addresses": victim_addresses,
            "manual_validated": manual_validated,
            "clara": clara,
        }
    )
    case["case_link"] = derive_case_link(case)
    return case


def merge_case_collections(*collections: Iterable[dict]) -> list[dict]:
    merged_by_id: dict[str, dict] = {}
    for collection in collections:
        for case in collection:
            if not isinstance(case, dict):
                continue
            case_id = _as_str(case.get("id", ""))
            if not case_id:
                continue
            merged_by_id[case_id] = normalize_case(case)
    return sorted(merged_by_id.values(), key=lambda item: item["id"])


def load_raw_cases(base: Path, source: str) -> list[dict]:
    wanted = _wanted_sources(source)
    parser_root = base / PARSER_PREPROCESSED_DIR
    raw_by_id: dict[str, dict] = {}

    source_indices = [
        parser_root / "defihacklabs" / "case_links.json",
        parser_root / "clara" / "case_links.json",
    ]
    for idx in source_indices:
        for case in _load_json_array(idx):
            if case.get("source") in wanted and case.get("id"):
                raw_by_id[case["id"]] = case

    for path in sorted(parser_root.rglob("*.json")):
        if path.name in {"index.json", "all_cases.json"}:
            continue
        case = json.loads(path.read_text())
        if case.get("source") in wanted and case.get("id"):
            raw_by_id[case["id"]] = case

    return merge_case_collections(raw_by_id.values())


def collect_raw_cases(
    base: Path,
    source: str,
    *,
    emit_parser_output: bool = False,
) -> list[dict]:
    """Collect normalized raw cases directly from upstream sources."""
    collections: list[list[dict]] = []
    wanted = _wanted_sources(source)
    parser_root = base / PARSER_PREPROCESSED_DIR

    if "DeFiHackLabs" in wanted:
        output_dir = parser_root / "defihacklabs" if emit_parser_output else None
        collections.append(extract_dfhl_cases(base / DEFIHACKLABS_DIR, output_dir))
    if "Clara" in wanted:
        output_dir = parser_root / "clara" if emit_parser_output else None
        collections.append(extract_clara_cases(base / CLARA_DIR, output_dir))

    merged = merge_case_collections(*collections)
    return merged


def write_merged_cases(path: Path, cases: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cases, indent=2, ensure_ascii=False) + "\n")


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Merge source-specific benchmark cases into one normalized file"
    )
    parser.add_argument(
        "--source",
        choices=["all", "defihacklabs", "clara"],
        default="all",
    )
    parser.add_argument("--base-dir", type=Path, default=Path("."))
    parser.add_argument(
        "--output",
        type=Path,
        default=RAW_ALL_CASES_PATH,
    )
    args = parser.parse_args()

    merged = collect_raw_cases(args.base_dir, args.source, emit_parser_output=True)
    print(f"[merge] source={args.source} cases={len(merged)}")


if __name__ == "__main__":
    main()
