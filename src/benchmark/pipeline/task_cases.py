"""Load and index unified benchmark-case outputs."""

from __future__ import annotations

import json
import ast
from copy import deepcopy
from functools import lru_cache
from pathlib import Path

from benchmark.annotation_hints import attach_annotation_hints
from infra.chain.metadata import lookup_verified_source
from benchmark.tasks.patch.remediation import normalize_fix_remediation
from benchmark.pipeline.case_links import derive_case_link
from benchmark.pipeline.paths import manual_cases_path, manual_root
from project_layout import BENCHMARK_DRAFT_DIR


def _detect_ground_truth_quality(case: dict) -> dict:
    ground_truth = case.get("ground_truth", {}) or {}
    has_file = bool(ground_truth.get("file"))
    has_function = bool(ground_truth.get("function"))
    return {
        "has_file": has_file,
        "has_function": has_function,
        "has_line": False,
        "complete_location": has_file and has_function,
    }




def _coerce_string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, tuple):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        for parser in (json.loads, ast.literal_eval):
            try:
                parsed = parser(text)
            except Exception:
                continue
            if isinstance(parsed, (list, tuple)):
                return [str(item).strip() for item in parsed if str(item).strip()]
        return [text]
    return []

@lru_cache(maxsize=2048)
def _has_verified_public_source(chain: str, address: str) -> bool:
    normalized_chain = str(chain or "").strip()
    target = str(address or "").strip()
    if not normalized_chain or not target:
        return False
    try:
        payload = lookup_verified_source(normalized_chain, target)
    except Exception:
        return False
    return bool(payload.get("ok") and dict(payload.get("source_files", {}) or {}))


def _normalize_attack_txs(chain_context_raw: dict) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    raw_items = _coerce_string_list(chain_context_raw.get("attack_txs", []))
    raw_items.extend(_coerce_string_list(chain_context_raw.get("attack_tx_hashes", [])))
    for item in raw_items:
        tx_hash = str(item).strip()
        if not tx_hash:
            continue
        lowered = tx_hash.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        ordered.append(tx_hash)
    return ordered


def _normalize_task_chain_context(
    task: str, chain_context_raw: dict, *, fallback_chain: str
) -> dict:
    chain_value = str(chain_context_raw.get("chain", "") or chain_context_raw.get("fork_chain", "")).strip()
    if not chain_value or chain_value == "unknown":
        chain_value = str(fallback_chain).strip()
    normalized: dict[str, object] = {}
    if task == "detect":
        normalized["chain"] = chain_value
    else:
        normalized["fork_chain"] = str(
            chain_context_raw.get("fork_chain", "") or chain_value
        ).strip()
        normalized["chain"] = chain_value
        fork_rpc_alias = str(chain_context_raw.get("fork_rpc_alias", "")).strip()
        if fork_rpc_alias:
            normalized["fork_rpc_alias"] = fork_rpc_alias

    attack_txs = _normalize_attack_txs(chain_context_raw)
    if attack_txs:
        normalized["attack_txs"] = attack_txs

    for key in ("target_addresses", "explorer_urls", "debug_urls", "vulnerable_addresses"):
        values = chain_context_raw.get(key)
        if not isinstance(values, list):
            continue
        items = [str(item).strip() for item in values if str(item).strip()]
        if items:
            normalized[key] = items

    source_hint = str(chain_context_raw.get("source_hint", "")).strip()
    if source_hint:
        normalized["source_hint"] = source_hint
    return normalized


def _normalize_detect_case(case: dict) -> dict:
    normalized = deepcopy(case)
    contracts = dict(normalized.get("contracts", {}) or {})
    chain_context_raw = dict(normalized.get("chain_context", {}) or {})
    ground_truth_raw = dict(normalized.get("ground_truth", {}) or {})

    location = ground_truth_raw.get("location")
    if isinstance(location, dict):
        for key in ("file", "contract", "function"):
            if key not in ground_truth_raw and key in location:
                ground_truth_raw[key] = location[key]

    contract_name = str(
        ground_truth_raw.get("contract", "") or normalized.get("target_contract_name", "")
    ).strip()
    vulnerable_address = str(
        contracts.get("vulnerable_address", "")
        or ground_truth_raw.get("vulnerable_address", "")
        or ground_truth_raw.get("vulnerable_contract", "")
    ).strip()
    chain_value = str(
        chain_context_raw.get("chain", "") or chain_context_raw.get("fork_chain", "")
    ).strip()
    if not chain_value or chain_value == "unknown":
        chain_value = str(normalized.get("chain", "")).strip()

    ground_truth: dict[str, str] = {}
    ground_truth_type = str(
        ground_truth_raw.get("type", "") or normalized.get("category", "") or "other"
    ).strip()
    if ground_truth_type:
        ground_truth["type"] = ground_truth_type
    if contract_name:
        ground_truth["contract"] = contract_name
    for key in ("file", "function"):
        value = str(ground_truth_raw.get(key, "")).strip()
        if value:
            ground_truth[key] = value

    result = {
        "id": str(normalized.get("id", "")).strip(),
        "name": str(normalized.get("name", "")).strip(),
        "source": str(normalized.get("source", "")).strip(),
        "case_link": derive_case_link(normalized),
        "ground_truth": ground_truth,
    }
    if chain_value and chain_value != "unknown":
        result["chain"] = chain_value
    if vulnerable_address:
        result["contracts"] = {"vulnerable_address": vulnerable_address}
    return attach_annotation_hints("detect", result, raw_case=case)


def _normalize_exploit_case(case: dict) -> dict:
    normalized = deepcopy(case)
    normalized["case_link"] = derive_case_link(normalized)
    normalized["cross_chain"] = bool(normalized.get("cross_chain", False))
    chain_context = dict(normalized.get("chain_context", {}) or {})
    attack_txs = [
        str(item).strip() for item in chain_context.get("attack_txs", []) if str(item).strip()
    ]
    for item in chain_context.get("attack_tx_hashes", []) or []:
        tx_hash = str(item).strip()
        if tx_hash and tx_hash not in attack_txs:
            attack_txs.append(tx_hash)
    if attack_txs:
        chain_context["attack_txs"] = attack_txs
    chain_context.pop("attack_tx_hashes", None)
    normalized["chain_context"] = _normalize_task_chain_context(
        "exploit",
        chain_context,
        fallback_chain=str(normalized.get("chain", "")).strip(),
    )
    contracts = dict(normalized.get("contracts", {}) or {})
    contracts.pop("exploit", None)
    normalized["contracts"] = contracts
    ground_truth = dict(normalized.get("ground_truth", {}) or {})
    vulnerable_address = str(
        ground_truth.get("vulnerable_address", "")
        or ground_truth.get("vulnerable_contract", "")
        or contracts.get("vulnerable_address", "")
    ).strip()
    ground_truth.pop("vulnerable_contract", None)
    if vulnerable_address and not str(ground_truth.get("vulnerable_address", "")).strip():
        ground_truth["vulnerable_address"] = vulnerable_address
    normalized["ground_truth"] = ground_truth
    result = {
        key: value
        for key, value in normalized.items()
        if key
        in {
            "id",
            "name",
            "source",
            "case_link",
            "category",
            "chain",
            "language",
            "vm_family",
            "cross_chain",
            "chains_involved",
            "date",
            "description",
            "contracts",
            "chain_context",
            "state_context",
            "ground_truth",
            "loss",
            "reported_profit",
            "profit_token",
            "forge_test_cmd",
            "success_criteria",
            "exploitability",
            "source_origin",
            "compiler_version",
            "target_contract_name",
            "source_dir",
        }
    }
    return attach_annotation_hints("exploit", result, raw_case=case)


def _normalize_fix_case(case: dict) -> dict:
    normalized = deepcopy(case)
    normalized["case_link"] = derive_case_link(normalized)
    normalized["cross_chain"] = bool(normalized.get("cross_chain", False))
    chain_context = dict(normalized.get("chain_context", {}) or {})
    attack_txs = [
        str(item).strip() for item in chain_context.get("attack_txs", []) if str(item).strip()
    ]
    for item in chain_context.get("attack_tx_hashes", []) or []:
        tx_hash = str(item).strip()
        if tx_hash and tx_hash not in attack_txs:
            attack_txs.append(tx_hash)
    if attack_txs:
        chain_context["attack_txs"] = attack_txs
    chain_context.pop("attack_tx_hashes", None)
    normalized["chain_context"] = _normalize_task_chain_context(
        "patch",
        chain_context,
        fallback_chain=str(normalized.get("chain", "")).strip(),
    )
    normalized.setdefault("state_context", {})
    contracts = dict(normalized.get("contracts", {}) or {})
    contracts.pop("exploit", None)
    normalized["contracts"] = contracts
    verification = normalized.get("verification", {}) or {}
    exploit_path = ""
    if isinstance(verification, dict):
        exploit_path = str(verification.get("exploit_path", "")).strip()

    ground_truth = dict(normalized.get("ground_truth", {}) or {})
    vulnerable_address = str(
        ground_truth.get("vulnerable_address", "")
        or ground_truth.get("vulnerable_contract", "")
        or contracts.get("vulnerable_address", "")
    ).strip()
    ground_truth.pop("vulnerable_contract", None)
    ground_truth.pop("line", None)
    if not ground_truth.get("type"):
        ground_truth["type"] = str(normalized.get("category", "")).strip()
    if vulnerable_address and not str(ground_truth.get("vulnerable_address", "")).strip():
        ground_truth["vulnerable_address"] = vulnerable_address
    normalized["ground_truth"] = ground_truth
    normalized["analysis_inputs"] = {
        "has_source": bool(contracts.get("vulnerable", [])),
    }
    normalized["remediation"] = normalize_fix_remediation(
        normalized.get("remediation"),
        verification=verification if isinstance(verification, dict) else None,
        contracts=contracts,
    )
    normalized.pop("vulnerability_description", None)
    normalized.pop("verification", None)
    normalized.pop("ground_truth_quality", None)
    normalized.pop("runtime_bytecode_path", None)
    normalized.pop("disassembly_path", None)
    result = {
        key: value
        for key, value in normalized.items()
        if key
        in {
            "id",
            "name",
            "source",
            "case_link",
            "category",
            "chain",
            "language",
            "vm_family",
            "cross_chain",
            "chains_involved",
            "date",
            "description",
            "analysis_inputs",
            "contracts",
            "chain_context",
            "ground_truth",
            "state_context",
            "remediation",
            "source_origin",
            "compiler_version",
            "target_contract_name",
            "source_dir",
        }
    }
    return attach_annotation_hints("patch", result, raw_case=case)


def _normalize_benchmark_case_case(case: dict) -> dict:
    detect_case = _normalize_detect_case(case)
    detect_case.pop("annotation_hints", None)

    raw_case = deepcopy(case)
    contracts = dict(raw_case.get("contracts", {}) or {})
    verification = raw_case.get("verification")
    if not isinstance(verification, dict):
        verification = None

    remediation_raw = raw_case.get("remediation") if isinstance(raw_case.get("remediation"), dict) else {}
    normalized_proxy = normalize_fix_remediation(
        remediation_raw,
        verification=verification,
        contracts=contracts,
    )

    chain_context_raw = dict(raw_case.get("chain_context", {}) or {})
    attack_txs = _coerce_string_list(raw_case.get("attack_txs", []))
    attack_txs = attack_txs or _normalize_attack_txs(chain_context_raw)
    ground_truth = dict(detect_case.get("ground_truth", {}) or {})
    detect_contracts = dict(detect_case.get("contracts", {}) or {})

    vulnerable_address = str(
        raw_case.get("vulnerable_address", "")
        or detect_case.get("vulnerable_address", "")
        or detect_contracts.get("vulnerable_address", "")
        or ground_truth.get("vulnerable_address", "")
        or ground_truth.get("vulnerable_contract", "")
    ).strip()
    type_value = str(raw_case.get("type", "") or ground_truth.get("type", "")).strip()
    file_value = str(raw_case.get("file", "") or ground_truth.get("file", "")).strip()
    function_value = str(raw_case.get("function", "") or ground_truth.get("function", "")).strip()

    proxy_address = str(raw_case.get("proxy_address", "") or normalized_proxy.get("proxy_address", "")).strip()
    chain_value = str(detect_case.get("chain", "")).strip()
    block_value_raw = (
        raw_case.get("block_number")
        if raw_case.get("block_number") not in (None, "")
        else raw_case.get("block")
    )
    if block_value_raw in (None, ""):
        block_value_raw = chain_context_raw.get("fork_block")
    try:
        block_number = int(block_value_raw) if block_value_raw not in (None, "") else None
    except (TypeError, ValueError):
        block_number = None
    raw_has_public_source = raw_case.get("has_public_source")
    if isinstance(raw_has_public_source, bool):
        has_public_source = raw_has_public_source
    elif vulnerable_address and chain_value and _has_verified_public_source(chain_value, vulnerable_address):
        has_public_source = True
    else:
        has_public_source = bool(
            str(raw_case.get("source_dir", "")).strip()
            or str(raw_case.get("source_origin", "")).strip()
            or contracts.get("vulnerable")
        )
    raw_fixable = raw_case.get("fixable")
    if isinstance(raw_fixable, bool):
        fixable = raw_fixable
    else:
        fixable = bool(proxy_address)
    if not fixable:
        proxy_address = ""

    attack_profit_raw = raw_case.get("attack_profit") if isinstance(raw_case.get("attack_profit"), dict) else {}
    attacker_profit = raw_case.get("attacker_profit", None)
    if attacker_profit in ("", []):
        attacker_profit = None
    if attacker_profit is None and attack_profit_raw:
        candidate = attack_profit_raw.get("attacker_profit") or attack_profit_raw.get("attacker_profit_usd")
        if isinstance(candidate, (int, float)) or candidate is None:
            attacker_profit = candidate

    result = {
        "id": str(detect_case.get("id", "")).strip(),
        "name": str(detect_case.get("name", "")).strip(),
        "source": str(detect_case.get("source", "")).strip(),
        "case_link": str(detect_case.get("case_link", "")).strip(),
    }
    if chain_value and chain_value != "unknown":
        result["chain"] = chain_value
    if block_number is not None:
        result["block_number"] = block_number
    if attack_txs:
        result["attack_txs"] = attack_txs
    if vulnerable_address:
        result["vulnerable_address"] = vulnerable_address
    result["has_public_source"] = bool(has_public_source)
    result["fixable"] = bool(fixable)
    if proxy_address:
        result["proxy_address"] = proxy_address
    if file_value:
        result["file"] = Path(file_value).name
    if function_value:
        result["function"] = function_value
    if type_value:
        result["type"] = type_value
    if isinstance(attacker_profit, (int, float)) or attacker_profit is None:
        result["attacker_profit"] = attacker_profit

    return attach_annotation_hints("benchmark_case", result, raw_case=case)


def normalize_task_case(task: str, case: dict) -> dict:
    if task == "detect":
        return _normalize_detect_case(case)
    if task == "benchmark_case":
        return _normalize_benchmark_case_case(case)
    if task == "exploit":
        return _normalize_exploit_case(case)
    if task in ("fix", "patch"):
        return _normalize_fix_case(case)
    return deepcopy(case)


def load_manual_task_cases(base_dir: Path, task: str) -> list[dict]:
    root = base_dir / manual_root(task)
    if not root.exists():
        return []

    cases_by_id: dict[str, dict] = {}
    for path in sorted(root.rglob("*.json")):
        if path.name in {"index.json", "cases.json"}:
            continue
        payload = json.loads(path.read_text())
        if not isinstance(payload, dict):
            raise ValueError(f"Manual task case must be an object: {path}")
        case_id = str(payload.get("id") or path.stem).strip()
        if not case_id:
            raise ValueError(f"Manual task case missing case id: {path}")
        if case_id in cases_by_id:
            raise ValueError(f"Duplicate manual task case for {case_id}: {path}")
        cases_by_id[case_id] = normalize_task_case(task, payload)

    return sorted(cases_by_id.values(), key=lambda case: case["id"])


def write_manual_task_index(base_dir: Path, task: str) -> list[dict]:
    cases = load_manual_task_cases(base_dir, task)
    index_path = base_dir / manual_cases_path(task)
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text(json.dumps(cases, indent=2, ensure_ascii=False) + "\n")
    return cases


def benchmark_case_output_root() -> Path:
    return BENCHMARK_DRAFT_DIR / "benchmark_case"


def benchmark_case_index_path() -> Path:
    return benchmark_case_output_root() / "cases.json"


def load_benchmark_case_output_cases(base_dir: Path) -> list[dict]:
    root = base_dir / benchmark_case_output_root()
    if not root.exists():
        return []

    cases_by_id: dict[str, dict] = {}
    for path in sorted(root.rglob("*.json")):
        if path.name in {"index.json", "cases.json"}:
            continue
        payload = json.loads(path.read_text())
        if not isinstance(payload, dict):
            raise ValueError(f"Benchmark case output must be an object: {path}")
        case_id = str(payload.get("id") or path.stem).strip()
        if not case_id:
            raise ValueError(f"Benchmark case output missing case id: {path}")
        if case_id in cases_by_id:
            raise ValueError(f"Duplicate benchmark case output for {case_id}: {path}")
        cases_by_id[case_id] = normalize_task_case("benchmark_case", payload)

    return sorted(cases_by_id.values(), key=lambda case: case["id"])


def write_benchmark_case_output_index(base_dir: Path) -> list[dict]:
    cases = load_benchmark_case_output_cases(base_dir)
    index_path = base_dir / benchmark_case_index_path()
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text(json.dumps(cases, indent=2, ensure_ascii=False) + "\n")
    return cases
