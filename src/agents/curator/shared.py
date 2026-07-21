"""Curator that materializes unified cases from input cases."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from eth_utils import keccak
from copy import deepcopy
from functools import lru_cache
import os
import json
from pathlib import Path
import re
import subprocess
import threading
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from agents.task_agent.base import BaseAgent
from agents.task_agent.base import TaskType
from agents.task_agent.cli_execution import run_prompt
from agents.task_agent.cli_workspace import (
    prepare_workspace,
)
from benchmark.annotation_hints import attach_annotation_hints
from benchmark.pipeline.defihacklabs.ground_truth import find_function_in_source
from benchmark.pipeline.defihacklabs.ground_truth import extract_location as dfhl_extract_location
from benchmark.pipeline.task_cases import normalize_task_case
from benchmark.pipeline.paths import manual_case_path
from benchmark.tasks.patch.case import PatchCase as FixCase
from prompts.taxonomy import DETECT_VULNERABILITY_TYPES, normalize_detect_type_label
from infra.chain import metadata as on_chain_metadata
from infra.chain.metadata import (
    decompile_bytecode,
    load_dfhl_source_metadata,
    lookup_contract_creation,
    lookup_verified_source,
)
from project_layout import CLARA_DIR, resolve_repo_path
from prompts.curator import CURATOR_PROMPT, CURATOR_SCHEMA
from prompts.fill_reviewer import FILL_REVIEWER_PROMPT, FILL_REVIEWER_SCHEMA

TX_HASH_RE = re.compile(r"0x[a-fA-F0-9]{64}")
ADDRESS_RE = re.compile(r"(?<![0-9a-fA-F])0x[a-fA-F0-9]{40}(?![0-9a-fA-F])")
URL_RE = re.compile(r"https?://[^\s<>\")']+")
BLOCK_HINT_RE = re.compile(r"Block height B[^0-9]{0,20}(\d+)", re.IGNORECASE)
NUMBER_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])\d[\d,]*(?:\.\d+)?\s+([A-Za-z][A-Za-z0-9._-]{1,63})")
FUNCTION_SNIPPET_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
CREATE_FORK_RE = re.compile(
    r"create(?:Select)?Fork\(\s*(?P<alias_expr>[^,\n)]+)(?:\s*,\s*(?P<expr>[^)\n]+))?\s*\)"
)
IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
STRING_LITERAL_RE = re.compile(r'^"(?P<value>[^"]+)"$')
CASE_LINK_DATE_RE = re.compile(r"#(?P<ymd>\d{8})-")
GITHUB_BLOB_RE = re.compile(
    r"^https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/blob/(?P<ref>[^/]+)/(?P<path>[^#]+?)(?:#(?P<anchor>[^#]+))?$"
)
MARKDOWN_HEADING_RE = re.compile(r"^(?P<level>#{1,6})\s+(?P<title>.+?)\s*$")
TX_URL_RE = re.compile(r"/tx/(0x[a-fA-F0-9]{64})(?:[/?#]|$)")

CHAIN_FORK_MAP: dict[str, str] = {
    "mainnet": "ethereum",
    "eth": "ethereum",
    "ethereum": "ethereum",
    "bsc": "bsc",
    "bnb": "bsc",
    "binance-smart-chain": "bsc",
    "fantom": "fantom",
    "polygon": "polygon",
    "matic": "polygon",
    "arbitrum": "arbitrum",
    "arb": "arbitrum",
    "optimism": "optimism",
    "avalanche": "avalanche",
    "avax": "avalanche",
    "base": "base",
    "blast": "blast",
    "gnosis": "gnosis",
    "celo": "celo",
    "moonriver": "moonriver",
    "linea": "linea",
    "mantle": "mantle",
    "sei": "sei",
}

EXPLORER_DOMAIN_TO_CHAIN: tuple[tuple[str, str], ...] = (
    ("etherscan.io", "ethereum"),
    ("bscscan.com", "bsc"),
    ("polygonscan.com", "polygon"),
    ("arbiscan.io", "arbitrum"),
    ("optimistic.etherscan.io", "optimism"),
    ("snowtrace.io", "avalanche"),
    ("ftmscan.com", "fantom"),
    ("basescan.org", "base"),
    ("basescan.io", "base"),
    ("blastscan.io", "blast"),
    ("gnosisscan.io", "gnosis"),
    ("celoscan.io", "celo"),
    ("lineascan.build", "linea"),
    ("moonscan.io", "moonriver"),
)

DETECT_TAXONOMY_SET = set(DETECT_VULNERABILITY_TYPES)
DEFAULT_FILL_TAXONOMY_PATHS = ("category", "ground_truth.type")
FILL_TAXONOMY_PATHS = DEFAULT_FILL_TAXONOMY_PATHS
TASK_FILL_ALLOWED_PATHS: dict[str, frozenset[str]] = {
    "benchmark_case": frozenset(
        {
            "case_link",
            "attack_txs",
            "chain",
            "block_number",
            "vulnerable_address",
            "has_public_source",
            "fixable",
            "proxy_address",
            "file",
            "function",
            "type",
            "attacker_profit",
        }
    ),
}
TASK_FILL_TAXONOMY_PATHS: dict[str, tuple[str, ...]] = {
    "benchmark_case": ("type",),
}

CASE_LINK_INDEX_RELATIVE_PATHS: tuple[Path, ...] = (
    Path("data/sources/preprocessed/defihacklabs/case_links.json"),
)

LOCAL_DFHL_SOURCE_ROOTS: tuple[Path, ...] = (
    Path("data/sources/DeFiHackLabs/verified_source_by_address"),
    Path("data/sources/DeFiHackLabs/recovered_source_by_address"),
    Path("data/sources/DeFiHackLabs/verified_source"),
    Path("data/sources/DeFiHackLabs/recovered_source"),
)

PROMPT_REPO_RELATIVE_PREFIXES: tuple[str, ...] = (
    "data/",
    "tmp/",
    "benchmark/",
    "runtime/",
    "archive/",
)
PROMPT_REPO_PATH_KEYS: frozenset[str] = frozenset(
    {
        "exploit",
        "reference_exploit",
        "case_path",
        "review_case_path",
        "manual_case_path",
        "source_dir",
        "workspace_dir",
    }
)
PROMPT_REPO_PATH_LIST_KEYS: frozenset[str] = frozenset({"vulnerable"})


DEPRECATED_CHAIN_CONTEXT_PATHS = {
    "chain_context.block",
    "chain_context.fork_block",
    "state_context.base_fork.block",
}

FINAL_BENCHMARK_PATHS_TO_DROP = {
    "contracts.exploit",
    "exploit",
    "reference_exploit",
}


def _json_block(payload: Any) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)


def _extract_fill_tool_context(case: dict[str, Any], report: dict[str, Any]) -> dict[str, str]:
    """Extract chain/address/block/tx from case data for dynamic tool guide."""
    chain_context = case.get("chain_context") if isinstance(case.get("chain_context"), dict) else {}
    contracts = case.get("contracts") if isinstance(case.get("contracts"), dict) else {}
    chain = (
        str(case.get("chain") or chain_context.get("fork_chain") or chain_context.get("chain") or "").strip()
    )
    vulnerable_address = str(
        contracts.get("vulnerable_address")
        or _get_nested_value(case, "ground_truth.vulnerable_address")
        or ""
    ).strip()
    block_number = str(
        chain_context.get("fork_block") or chain_context.get("block") or ""
    ).strip()
    attack_txs = chain_context.get("attack_txs", [])
    if not isinstance(attack_txs, list):
        attack_txs = []
    attack_tx = str(attack_txs[0]).strip() if attack_txs else ""
    return {
        "chain": chain,
        "contract_address": vulnerable_address,
        "block_number": block_number,
        "attack_tx": attack_tx,
    }


def _sanitize_no_source_function(payload: dict[str, Any]) -> dict[str, Any]:
    """Clear non-selector function for no-source cases so the model is forced to look up the 4-byte selector."""
    if payload.get("has_public_source") is False:
        func = str(payload.get("function") or "").strip()
        if func and not func.startswith("0x"):
            payload = dict(payload)
            payload["function"] = None
    return payload


def _render_fill_case_input_text(
    *,
    case_id: str,
    review_case_payload: dict[str, Any],
    manual_case_payload: dict[str, Any],
    case_materials: dict[str, Any],
) -> str:
    """Build CASE_INPUT.txt content for the curator workspace."""
    manual_case_payload = _sanitize_no_source_function(manual_case_payload)
    sections = [
        f"Case id: {case_id}",
        "",
        "Input case JSON:",
        _json_block(review_case_payload),
        "",
        "Current canonical output JSON:",
        _json_block(manual_case_payload),
        "",
        "Case materials:",
        _json_block(case_materials),
    ]
    return "\n".join(sections)


def _render_curator_prompt(
    *,
    task: str,
    case_id: str,
    review_case_payload: dict[str, Any],
    manual_case_payload: dict[str, Any],
    report: dict[str, Any],
    case_path: str = "",
    manual_case_path: str = "",
    tool_guide: str = "",
) -> str:
    from agents.task_agent.cli_workspace import render_fill_tool_guide
    evidence = report.get("evidence", {}) if isinstance(report, dict) else {}
    tool_context = _extract_fill_tool_context(
        report.get("suggested_review_case", {}),
        report,
    )
    effective_tool_guide = tool_guide or render_fill_tool_guide(**tool_context)
    from prompts.curator import render_type_descriptions
    return CURATOR_PROMPT.format(
        tool_guide=effective_tool_guide,
        type_descriptions=render_type_descriptions(),
        output_schema=CURATOR_SCHEMA.strip(),
    )


def _stage_fill_workspace_inputs(base_dir: Path, case: dict[str, Any], work_dir: Path | None) -> dict[str, Any]:
    staged_case = deepcopy(case)
    if work_dir is None:
        return staged_case
    exploit_path, exploit_text = _load_reference_exploit_text(base_dir, case)
    if exploit_path is None or not exploit_text.strip():
        return staged_case
    path = work_dir / "reference_exploit.sol"
    path.write_text(exploit_text if exploit_text.endswith("\n") else exploit_text + "\n", encoding="utf-8")
    staged_rel = "reference_exploit.sol"
    staged_case["exploit"] = staged_rel
    staged_case["reference_exploit"] = staged_rel
    contracts = staged_case.get("contracts", {}) if isinstance(staged_case.get("contracts"), dict) else {}
    contracts = dict(contracts)
    contracts["exploit"] = staged_rel
    staged_case["contracts"] = contracts
    return staged_case


def _render_curator_revision_prompt(
    *,
    task: str,
    case_id: str,
    review_case_payload: dict[str, Any],
    manual_case_payload: dict[str, Any],
    report: dict[str, Any],
    reviewer_feedback: dict[str, Any],
    case_path: str = "",
    manual_case_path: str = "",
    tool_guide: str = "",
) -> str:
    base_prompt = _render_curator_prompt(
        task=task,
        case_id=case_id,
        review_case_payload=review_case_payload,
        manual_case_payload=manual_case_payload,
        report=report,
        case_path=case_path,
        manual_case_path=manual_case_path,
        tool_guide=tool_guide,
    ).rstrip()
    return (
        f"{base_prompt}\n\n"
        "Reviewer feedback from the previous verification round:\n"
        f"{_json_block(reviewer_feedback)}\n\n"
        "Revision instructions:\n"
        "- Reconsider only the fields implicated by the reviewer issues.\n"
        "- If stronger evidence supports a better replacement value, update those fields in `proposed_case`.\n"
        "- If you cannot support a better value, keep the current benchmark value instead of repeating the same weak guess.\n"
        "- Do not restate unrelated unchanged fields beyond the required `proposed_case` object.\n"
        "- Keep the output strictly machine-readable JSON following the same schema.\n"
    )


def _render_verify_curator_prompt(
    *,
    task: str,
    case_id: str,
    review_payload: dict[str, Any] | None,
    review_payload_path: str = "",
) -> str:
    if review_payload_path:
        review_input_block = (
            "Review report JSON path:\n"
            f"{str(review_payload_path).strip()}\n\n"
            "Compact review payload JSON:\n"
            f"{_json_block(review_payload or {})}\n\n"
            "Review instructions:\n"
            "- Prefer reading the JSON file directly before making your decision.\n"
            "- If file access is unavailable in your execution environment, use the inline compact payload below instead.\n"
            "- Use the file or inline payload as the source of truth for changed fields, evidence, and the proposed final case."
        )
    else:
        review_input_block = (
            "Compact review payload JSON:\n"
            f"{_json_block(review_payload or {})}"
        )
    return FILL_REVIEWER_PROMPT.format(
        task=str(task).strip() or "(unknown)",
        case_id=str(case_id).strip() or "(unknown)",
        review_input_block=review_input_block.strip(),
        output_schema=FILL_REVIEWER_SCHEMA.strip(),
    )


def _preview_list(values: list[str], *, limit: int = 5) -> str:
    items = [str(value).strip() for value in values if str(value).strip()]
    if not items:
        return "[]"
    preview = items[:limit]
    if len(items) > limit:
        preview = preview + [f"... (+{len(items) - limit} more)"]
    return json.dumps(preview, ensure_ascii=False)


def _render_fix_remediation_tool_guide(
    *, has_local_source: bool, local_source_dir: str = ""
) -> str:
    del has_local_source, local_source_dir
    lines = [
        "Use the smallest investigation needed to classify remediation.",
        "Do not write patches, compile code, run validation, or replay exploits.",
        "Decide only between proxy_upgrade and not_fixable.",
        "For proxy discovery, do not use proxy-info lookup, logs, or source inspection.",
        "1. Start from the implementation address already present in the case.",
        "2. Use the historical attack transactions to inspect traces for delegatecall edges into that implementation.",
        "3. Look for delegatecall edges where from = proxy and to = implementation.",
        "4. If a delegatecall is found, set fixable=true and proxy_address=from.",
        "5. If no such delegatecall is found in the inspected traces, set fixable=false and clear proxy_address.",
        "Prefer at most 1 tool call total.",
        "Set target_contracts only to the proxy address when proxy_upgrade is supported.",
    ]
    return "\n".join(lines).strip()


def _minimal_fix_reasoning_context_lines(case: FixCase, base_dir: Path) -> list[str]:
    del base_dir
    chain = (
        str(
            case.chain_context.get("fork_chain", "")
            or case.chain_context.get("chain", "")
            or case.chain
        ).strip()
        or "ethereum"
    )
    vulnerable_address = str(
        case.ground_truth.get("vulnerable_address", "")
        or case.contracts.get("vulnerable_address", "")
    ).strip()
    contract_name = str(case.ground_truth.get("contract", "")).strip()
    vulnerability_type = (
        str(case.ground_truth.get("type", "") or case.category).strip() or "unknown"
    )
    candidate_file = str(case.ground_truth.get("file", "")).strip()
    candidate_function = str(case.ground_truth.get("function", "")).strip()
    exploit_path = str(case.contracts.get("exploit", "")).strip()
    attack_txs = case.attack_transactions
    source_files = sorted(
        {
            Path(str(path)).name
            for path in (case.contracts.get("vulnerable", []) or [])
            if str(path).strip()
        }
    )

    return [
        f"Case id: {case.id}",
        f"Incident: {case.name}",
        f"Reference link: {case.case_link}",
        f"Fork chain: {chain}",
        f"Vulnerable address: {vulnerable_address or 'unknown'}",
        f"Vulnerable contract name: {contract_name or 'unknown'}",
        f"Vulnerability type: {vulnerability_type}",
        f"Candidate file: {candidate_file or 'unknown'}",
        f"Candidate function: {candidate_function or 'unknown'}",
        f"Exploit path: {exploit_path or 'unknown'}",
        f"Attack txs ({len(attack_txs)}): {_preview_list(attack_txs, limit=2)}",
        f"Has local source: {'yes' if source_files else 'no'}",
        f"Local source files ({len(source_files)}): {_preview_list(source_files, limit=6)}",
    ]


def _is_missing(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, dict)):
        return len(value) == 0
    return False


def _dedupe_keep_order(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = str(value).strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _set_nested_value(data: dict[str, Any], path: str, value: Any) -> None:
    current = data
    parts = path.split(".")
    for part in parts[:-1]:
        child = current.get(part)
        if not isinstance(child, dict):
            child = {}
            current[part] = child
        current = child
    current[parts[-1]] = value


def _get_nested_value(data: dict[str, Any], path: str) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _apply_if_missing(case: dict[str, Any], path: str, value: Any, changes: dict[str, Any]) -> None:
    if _is_missing(value):
        return
    current = _get_nested_value(case, path)
    if not _is_missing(current):
        return
    _set_nested_value(case, path, value)
    changes[path] = value


def _apply_if_missing_or_unknown(
    case: dict[str, Any], path: str, value: Any, changes: dict[str, Any]
) -> None:
    if _is_missing(value):
        return
    current = _get_nested_value(case, path)
    if isinstance(current, str) and current.strip().lower() == "unknown":
        _set_nested_value(case, path, value)
        changes[path] = value
        return
    if not _is_missing(current):
        return
    _set_nested_value(case, path, value)
    changes[path] = value


def _extract_date_from_case_link(case_link: str) -> str:
    match = CASE_LINK_DATE_RE.search(str(case_link or "").strip())
    if not match:
        return ""
    raw = match.group("ymd")
    return f"{raw[0:4]}-{raw[4:6]}-{raw[6:8]}"


def _coerce_fill_seed_case(task: str, case: dict[str, Any]) -> dict[str, Any]:
    working = deepcopy(case)
    task_name = str(task).strip().lower()

    contracts = working.get("contracts")
    if not isinstance(contracts, dict):
        contracts = {}
        working["contracts"] = contracts
    top_level_exploit = str(working.get("exploit", "")).strip()
    if top_level_exploit and not str(contracts.get("exploit", "")).strip():
        contracts["exploit"] = top_level_exploit
    contracts.setdefault("vulnerable", [])

    category = str(working.get("category") or "").strip() or "other"
    chain = (
        str(
            working.get("chain")
            or _get_nested_value(working, "chain_context.fork_chain")
            or _get_nested_value(working, "chain_context.chain")
            or ""
        ).strip()
        or "unknown"
    )
    case_link = str(working.get("case_link", "")).strip()

    working.setdefault("description", "")
    working.setdefault("cross_chain", False)
    if not str(working.get("date", "")).strip() and case_link:
        derived_date = _extract_date_from_case_link(case_link)
        if derived_date:
            working["date"] = derived_date
    if "chains_involved" not in working and chain and chain != "unknown":
        working["chains_involved"] = [chain]
    working["category"] = category
    working["chain"] = chain

    analysis_inputs = working.get("analysis_inputs")
    if not isinstance(analysis_inputs, dict):
        analysis_inputs = {}
        working["analysis_inputs"] = analysis_inputs
    analysis_inputs.setdefault(
        "has_source", bool(contracts.get("vulnerable") or contracts.get("exploit"))
    )

    chain_context = working.get("chain_context")
    if not isinstance(chain_context, dict):
        chain_context = {}
        working["chain_context"] = chain_context
    chain_context.setdefault("fork_chain", chain)
    chain_context.setdefault("chain", chain)

    ground_truth = working.get("ground_truth")
    if not isinstance(ground_truth, dict):
        ground_truth = {}
        working["ground_truth"] = ground_truth
    ground_truth.setdefault("type", category)

    working.setdefault("state_context", {})
    working.setdefault("remediation", {})

    return working


@lru_cache(maxsize=4)
def _load_clara_snapshot_index(base_dir: Path) -> dict[str, dict[str, Any]]:
    """Parse Clara incidents.jsonl once into a dict keyed by public_incident_id."""
    manifest = resolve_repo_path(base_dir, CLARA_DIR / "incidents.jsonl")
    if not manifest.exists():
        return {}
    index: dict[str, dict[str, Any]] = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        incident_id = str(row.get("public_incident_id", "")).strip().lower()
        if incident_id:
            index[incident_id] = row
    return index


def _load_clara_snapshot_row(base_dir: Path, case_id: str) -> dict[str, Any]:
    if not case_id.startswith("clr-"):
        return {}
    prefix = case_id.split("clr-", 1)[1].strip().lower()
    index = _load_clara_snapshot_index(base_dir)
    for incident_id, row in index.items():
        if incident_id.startswith(prefix):
            return row
    return {}


def _fetch_url_text(url: str) -> str:
    target = str(url).strip()
    if not target:
        return ""
    request = urllib.request.Request(
        target,
        headers={"User-Agent": "web3bug-benchmark-manual-fill-assistant/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.read().decode("utf-8", errors="replace")
    except (OSError, urllib.error.URLError):
        return ""


def _extract_urls_from_text(text: str) -> list[str]:
    return _dedupe_keep_order(URL_RE.findall(text or ""))


def _extract_addresses_from_text(text: str) -> list[str]:
    return _dedupe_keep_order(ADDRESS_RE.findall(text or ""))


def extract_vulnerable_address_from_exploit_sol(sol_path: Path) -> str:
    try:
        exploit_code = sol_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""

    for match in re.finditer(
        r"//.*?Vuln(?:erable)?\s+Contract.*?(0x[0-9a-fA-F]{40})",
        exploit_code,
        re.IGNORECASE,
    ):
        return match.group(1)

    interface_match = re.search(
        r"\bI[A-Za-z0-9_]+\s+[A-Za-z0-9_]+\s*=\s*I[A-Za-z0-9_]+\(\s*(?:payable\()?"
        r"(0x[0-9a-fA-F]{40})",
        exploit_code,
    )
    if interface_match:
        return interface_match.group(1)

    return ""


def _iter_call_trace_nodes(node: Any) -> list[dict[str, Any]]:
    if not isinstance(node, dict):
        return []
    nodes = [node]
    calls = node.get("calls", [])
    if isinstance(calls, list):
        for child in calls:
            nodes.extend(_iter_call_trace_nodes(child))
    return nodes


def _trace_delegatecall_proxy_matches(
    trace: Any,
    implementation_address: str,
    *,
    tx_hash: str,
    source_hint: str,
    trace_method: str,
) -> list[dict[str, Any]]:
    implementation = str(implementation_address).strip().lower()
    if not implementation:
        return []

    matches: list[dict[str, Any]] = []
    for node in _iter_call_trace_nodes(trace):
        call_type = str(node.get("type") or node.get("callType") or "").strip().lower()
        from_addr = str(node.get("from") or "").strip()
        to_addr = str(node.get("to") or "").strip()
        if call_type != "delegatecall":
            continue
        if to_addr.lower() != implementation:
            continue
        if not from_addr or from_addr.lower() == implementation:
            continue
        if not ADDRESS_RE.fullmatch(from_addr):
            continue
        matches.append(
            {
                "proxy_address": from_addr,
                "implementation_address": implementation_address,
                "tx_hash": tx_hash,
                "source_hint": source_hint,
                "trace_method": trace_method,
                "call_type": call_type,
            }
        )
    return matches


def _infer_delegatecall_proxy_from_traces(
    chain: str,
    implementation_address: str,
    *,
    tx_hashes: list[str] | None = None,
    block_number: int | None = None,
    recent_offset: int = 5,
) -> dict[str, Any]:
    payload = on_chain_metadata.lookup_delegatecall_proxy(
        chain,
        implementation_address,
        tx_hashes=list(tx_hashes or []),
        block_number=block_number,
        recent_offset=recent_offset,
        trace_timeout="10s",
    )
    return payload if isinstance(payload, dict) else {}


def _github_anchor_slug(text: str) -> str:
    slug = str(text or "").strip().lower()
    slug = re.sub(r"[^\w\- ]", "", slug)
    return slug.replace(" ", "-")


def _github_blob_to_raw_url(url: str) -> tuple[str, str]:
    target = str(url or "").strip()
    if not target:
        return "", ""
    parsed = urllib.parse.urlsplit(target)
    match = GITHUB_BLOB_RE.match(
        urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    )
    if not match:
        return "", ""
    raw_url = (
        f"https://raw.githubusercontent.com/"
        f"{match.group('owner')}/{match.group('repo')}/{match.group('ref')}/{match.group('path')}"
    )
    anchor = str(parsed.fragment or match.group("anchor") or "").strip()
    return raw_url, anchor


def _extract_markdown_section_from_anchor(markdown: str, anchor: str) -> str:
    normalized_anchor = str(anchor or "").strip().lower()
    if not markdown or not normalized_anchor:
        return ""

    lines = markdown.splitlines()
    headings: list[tuple[int, int, str]] = []
    for idx, line in enumerate(lines):
        match = MARKDOWN_HEADING_RE.match(line)
        if not match:
            continue
        level = len(match.group("level"))
        slug = _github_anchor_slug(match.group("title"))
        headings.append((idx, level, slug))

    for pos, (start_idx, level, slug) in enumerate(headings):
        if slug != normalized_anchor:
            continue
        end_idx = len(lines)
        for next_idx, next_level, next_slug in headings[pos + 1 :]:
            if next_level < level:
                end_idx = next_idx
                break
            if next_level == level and not lines[next_idx].lstrip("#").strip().lower().startswith("lost"):
                end_idx = next_idx
                break
        return "\n".join(lines[start_idx:end_idx]).strip()
    return ""


def _extract_reference_urls_from_markdown_section(section_text: str) -> list[str]:
    section = str(section_text or "")
    if not section:
        return []
    start = None
    for marker in ("\nLink reference", "\nReferences", "\nReference"):
        idx = section.find(marker)
        if idx >= 0:
            start = idx
            break
    candidate = section[start:] if start is not None else section
    return _extract_urls_from_text(candidate)


def _extract_tx_hash_from_url(url: str) -> str:
    match = TX_URL_RE.search(str(url or "").strip())
    if not match:
        return ""
    return match.group(1)


_TWITTER_URL_RE = re.compile(r"https?://(?:www\.)?(?:twitter\.com|x\.com)/")
_MEDIUM_MAIN_RE = re.compile(r"https?://(?:www\.)?medium\.com/")
_MEDIUM_SUB_RE = re.compile(r"https?://(?!www\.)([a-zA-Z0-9_-]+)\.medium\.com/")


def _rewrite_reference_url(url: str) -> str:
    """Rewrite URLs to use mirrors that return readable content."""
    if _TWITTER_URL_RE.search(url):
        return _TWITTER_URL_RE.sub("https://api.fxtwitter.com/", url)
    m = _MEDIUM_SUB_RE.search(url)
    if m:
        user = m.group(1)
        return _MEDIUM_SUB_RE.sub(f"https://scribe.rip/@{user}/", url)
    if _MEDIUM_MAIN_RE.search(url):
        return _MEDIUM_MAIN_RE.sub("https://scribe.rip/", url)
    return url


def _fetch_twitter_text(url: str) -> str:
    """Fetch tweet text via fxtwitter API, return empty string on failure."""
    raw = _fetch_url_text(url)
    if not raw:
        return ""
    try:
        data = json.loads(raw)
        tweet = data.get("tweet")
        if isinstance(tweet, dict):
            return str(tweet.get("text", ""))
    except (json.JSONDecodeError, TypeError):
        pass
    return ""


_REFERENCE_MATERIAL_CACHE: dict[str, dict[str, Any]] = {}
_REFERENCE_MATERIAL_LOCK = threading.Lock()


def _expand_reference_material(case_link: str) -> dict[str, Any]:
    link = str(case_link or "").strip()
    if not link:
        return {}

    with _REFERENCE_MATERIAL_LOCK:
        if link in _REFERENCE_MATERIAL_CACHE:
            return deepcopy(_REFERENCE_MATERIAL_CACHE[link])

    result: dict[str, Any] = {
        "case_link": link,
        "reference_urls": [],
        "fetched_urls": [],
        "tx_hashes": [],
        "addresses": [],
        "texts": [],
    }

    raw_url, anchor = _github_blob_to_raw_url(link)
    section_text = ""
    if raw_url and anchor:
        markdown = _fetch_url_text(raw_url)
        section_text = _extract_markdown_section_from_anchor(markdown, anchor)
        if section_text:
            result["section_source"] = "github_markdown_section"
            result["section_url"] = raw_url
            result["texts"].append(section_text)
            result["reference_urls"] = _extract_reference_urls_from_markdown_section(section_text)
            result["tx_hashes"] = _dedupe_keep_order(
                result["tx_hashes"] + _extract_tx_hashes_from_text(section_text)
            )
            result["addresses"] = _dedupe_keep_order(
                result["addresses"] + _extract_addresses_from_text(section_text)
            )

    if not result["reference_urls"] and not (raw_url and anchor):
        fetched = _fetch_url_text(link)
        if fetched:
            result["texts"].append(fetched)
            result["reference_urls"] = _extract_urls_from_text(fetched)
            result["tx_hashes"] = _dedupe_keep_order(
                result["tx_hashes"] + _extract_tx_hashes_from_text(fetched)
            )
            result["addresses"] = _dedupe_keep_order(
                result["addresses"] + _extract_addresses_from_text(fetched)
            )

    ranked_urls = sorted(
        result["reference_urls"],
        key=lambda item: (
            0 if "/tx/" in item else 1,
            0 if any(domain in item for domain, _ in EXPLORER_DOMAIN_TO_CHAIN) else 1,
            item,
        ),
    )

    # Separate tx-hash URLs (no fetch needed) from URLs that need fetching.
    urls_to_fetch: list[str] = []
    fetched_urls: list[str] = []
    texts = list(result["texts"])
    tx_hashes = list(result["tx_hashes"])
    addresses = list(result["addresses"])
    for ref_url in ranked_urls[:4]:
        fetched_urls.append(ref_url)
        tx_from_url = _extract_tx_hash_from_url(ref_url)
        if tx_from_url:
            tx_hashes = _dedupe_keep_order(tx_hashes + [tx_from_url])
        else:
            urls_to_fetch.append(_rewrite_reference_url(ref_url))

    # Fetch remaining reference URLs in parallel.
    if urls_to_fetch:

        def _fetch_ref_url(url: str) -> str:
            if "api.fxtwitter.com" in url:
                return _fetch_twitter_text(url)
            return _fetch_url_text(url)

        with ThreadPoolExecutor(max_workers=min(len(urls_to_fetch), 4)) as pool:
            future_to_url = {pool.submit(_fetch_ref_url, url): url for url in urls_to_fetch}
            for future in as_completed(future_to_url):
                fetched = future.result()
                if not fetched:
                    continue
                texts.append(fetched)
                tx_hashes = _dedupe_keep_order(
                    tx_hashes + _extract_tx_hashes_from_text(fetched)
                )
                addresses = _dedupe_keep_order(
                    addresses + _extract_addresses_from_text(fetched)
                )

    result["reference_urls"] = ranked_urls
    result["fetched_urls"] = fetched_urls
    result["texts"] = texts
    result["tx_hashes"] = tx_hashes
    result["addresses"] = addresses

    with _REFERENCE_MATERIAL_LOCK:
        _REFERENCE_MATERIAL_CACHE[link] = deepcopy(result)

    return result


@lru_cache(maxsize=8)
def _load_dfhl_case_link_index(base_dir: Path) -> dict[str, dict[str, dict[str, str]]]:
    by_id: dict[str, dict[str, str]] = {}
    by_exploit: dict[str, dict[str, str]] = {}

    for rel_path in CASE_LINK_INDEX_RELATIVE_PATHS:
        path = resolve_repo_path(base_dir, rel_path)
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, list):
            continue
        for item in payload:
            if not isinstance(item, dict):
                continue
            case_link = str(item.get("case_link", "")).strip()
            if not case_link:
                continue
            case_id = str(item.get("id", "")).strip()
            exploit = str(item.get("exploit", "")).strip()
            entry = {
                "case_link": case_link,
                "id": case_id,
                "exploit": exploit,
            }
            if case_id:
                by_id[case_id] = entry
            if exploit:
                by_exploit[exploit] = entry
        break

    return {"by_id": by_id, "by_exploit": by_exploit}


@lru_cache(maxsize=4)
def _load_local_dfhl_source_index_by_address(base_dir: Path) -> dict[str, dict[str, Any]]:
    by_address: dict[str, dict[str, Any]] = {}
    resolved_base = base_dir.resolve()
    for root_rel in LOCAL_DFHL_SOURCE_ROOTS:
        root = resolve_repo_path(resolved_base, root_rel)
        if not root.exists():
            continue
        for metadata_path in root.rglob("_metadata.json"):
            try:
                payload = json.loads(metadata_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            address = str(payload.get("address", "")).strip().lower()
            if not address:
                continue
            if address in by_address:
                continue
            case_dir = metadata_path.parent
            files = payload.get("files", [])
            if not isinstance(files, list) or not files:
                files = [
                    path.name for path in case_dir.glob("*.sol") if path.name != "_metadata.json"
                ]
            source_files: dict[str, str] = {}
            for file_name in files:
                file_path = case_dir / str(file_name)
                if not file_path.exists() or file_path.suffix.lower() != ".sol":
                    continue
                key = file_path.name
                if key in source_files:
                    key = str(file_name)
                source_files[key] = file_path.read_text(encoding="utf-8", errors="replace")
            if not source_files:
                continue
            by_address[address] = {
                "chain": str(payload.get("chain", "")).strip(),
                "contract_name": str(payload.get("contract_name", "")).strip(),
                "source_files": source_files,
                "source_dir": str(case_dir.relative_to(resolved_base)),
            }
    return by_address


def _lookup_local_dfhl_source_by_address(base_dir: Path, address: str) -> dict[str, Any]:
    target = str(address or "").strip().lower()
    if not target:
        return {}
    return dict(_load_local_dfhl_source_index_by_address(base_dir.resolve()).get(target, {}))


def _lookup_dfhl_source_with_fallback(
    base_dir: Path,
    *,
    chain: str,
    address: str,
) -> dict[str, Any]:
    target = str(address or "").strip()
    if not target:
        return {}

    local_payload = _lookup_local_dfhl_source_by_address(base_dir, target)
    if local_payload:
        payload = dict(local_payload)
        payload["source"] = "local_source_by_address"
        return payload

    verified = lookup_verified_source(chain, target)
    verified_files = dict(verified.get("source_files", {}) or {}) if isinstance(verified, dict) else {}
    if verified.get("ok") and verified_files:
        return {
            "chain": str(verified.get("chain", chain)).strip(),
            "contract_name": str(verified.get("contract_name", "")).strip(),
            "source_files": verified_files,
            "source_dir": "",
            "source": "verified_source",
        }

    creation = lookup_contract_creation(chain, target)
    creation_bytecode = str(creation.get("creation_bytecode", "")).strip() if isinstance(creation, dict) else ""
    if not creation.get("ok") or not creation_bytecode.startswith("0x") or len(creation_bytecode) <= 2:
        return {}

    decompiled = decompile_bytecode(creation_bytecode)
    if not decompiled:
        return {}

    return {
        "chain": str(chain).strip(),
        "contract_name": str(verified.get("contract_name", "")).strip(),
        "source_files": {"creation_decompiled.txt": decompiled},
        "source_dir": "",
        "source": "creation_decompiled",
    }


def _normalize_tx_selector(input_data: object) -> str:
    text = str(input_data or "").strip().lower()
    if text.startswith("0x") and len(text) >= 10:
        return text[:10]
    return ""


def _canonical_solidity_param_type(param: str) -> str:
    cleaned = re.sub(r"\b(memory|storage|calldata|payable|indexed)\b", " ", str(param or ""))
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned:
        return ""
    parts = cleaned.split(" ")
    if len(parts) > 1 and IDENTIFIER_RE.match(parts[-1]):
        cleaned = " ".join(parts[:-1]).strip()
    return cleaned


def _infer_function_from_selector(
    source_files: dict[str, str],
    selector: str,
    *,
    contract_name: str = "",
) -> dict[str, str]:
    normalized_selector = _normalize_tx_selector(selector)
    if not normalized_selector or not source_files:
        return {}

    candidates: list[dict[str, str]] = []
    for fname, content in source_files.items():
        for match in re.finditer(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)", content):
            function_name = match.group(1)
            raw_params = match.group(2)
            param_types: list[str] = []
            ok = True
            if raw_params.strip():
                for chunk in raw_params.split(","):
                    param_type = _canonical_solidity_param_type(chunk)
                    if not param_type:
                        ok = False
                        break
                    param_types.append(param_type)
            if not ok:
                continue
            signature = f"{function_name}({','.join(param_types)})"
            computed_selector = "0x" + keccak(text=signature).hex()[:8]
            if computed_selector != normalized_selector:
                continue
            candidates.append(
                {
                    "file": fname,
                    "function": function_name,
                    "signature": signature,
                }
            )

    if not candidates:
        return {}
    if contract_name:
        prioritized = [
            item
            for item in candidates
            if contract_name.lower() in item["file"].lower()
            or Path(item["file"]).stem.lower() == contract_name.lower()
        ]
        if len(prioritized) == 1:
            return prioritized[0]
        if prioritized:
            candidates = prioritized
    unique_functions = {item["function"] for item in candidates}
    if len(unique_functions) == 1:
        return candidates[0]
    if len(candidates) == 1:
        return candidates[0]
    return {}


def _reconcile_detect_ground_truth_with_address_source(
    base_dir: Path,
    working: dict[str, Any],
    changes: dict[str, Any],
    evidence: dict[str, Any],
    *,
    chain: str,
    address: str,
    exploit_path: Path | None,
    evidence_key: str,
    tx_selector: str = "",
) -> bool:
    target = str(address or "").strip()
    if not target:
        return False

    source_payload = _lookup_dfhl_source_with_fallback(base_dir, chain=chain, address=target)
    source_files = dict(source_payload.get("source_files", {}) or {})
    if not source_files:
        return False

    ground_truth = working.get("ground_truth") if isinstance(working.get("ground_truth"), dict) else {}
    contract_name = str(ground_truth.get("contract", "") or source_payload.get("contract_name", "")).strip()
    if contract_name:
        _record_determination(
            evidence,
            "contract_name_determination",
            {
                "value": contract_name,
                "source": str(source_payload.get("source", "")).strip() or "address_source",
                "address": target,
            },
        )
    selector_match = _infer_function_from_selector(source_files, tx_selector, contract_name=contract_name)
    if selector_match and not str(ground_truth.get("function", "")).strip():
        _record_determination(
            evidence,
            "function_determination",
            {
                "value": selector_match["function"],
                "source": "attack_tx_selector_match",
                "address": target,
                "selector": tx_selector,
                "contract_name": contract_name,
            },
        )
        _update_detect_ground_truth_field(working, changes, "ground_truth.function", selector_match["function"])
        if selector_match.get("file"):
            _record_determination(
                evidence,
                "file_determination",
                {
                    "value": Path(selector_match["file"]).name,
                    "source": "attack_tx_selector_match",
                    "address": target,
                    "selector": tx_selector,
                    "contract_name": contract_name,
                },
            )
            _update_detect_ground_truth_field(working, changes, "ground_truth.file", Path(selector_match["file"]).name)
        evidence[f"{evidence_key}_selector_match"] = selector_match

    return _reconcile_detect_ground_truth_with_source_files(
        working,
        changes,
        evidence,
        source_files,
        contract_name=contract_name,
        exploit_path=exploit_path,
        evidence_key=evidence_key,
        evidence_source=str(source_payload.get("source", "")).strip() or "address_source",
    )


def _resolve_dfhl_case_link(base_dir: Path, case: dict[str, Any]) -> tuple[str, str]:
    if str(case.get("source", "")).strip() != "DeFiHackLabs":
        return "", ""

    index = _load_dfhl_case_link_index(base_dir.resolve())
    case_id = str(case.get("id", "")).strip()
    if case_id:
        matched = index["by_id"].get(case_id)
        if matched:
            return str(matched.get("case_link", "")).strip(), "id"

    contracts = case.get("contracts", {}) if isinstance(case.get("contracts"), dict) else {}
    exploit = str(contracts.get("exploit", "")).strip()
    if exploit:
        matched = index["by_exploit"].get(exploit)
        if matched:
            return str(matched.get("case_link", "")).strip(), "exploit"

    return "", ""


def _apply_dfhl_case_link(
    base_dir: Path, case: dict[str, Any], changes: dict[str, Any], evidence: dict[str, Any]
) -> None:
    resolved_link, match_by = _resolve_dfhl_case_link(base_dir, case)
    if not resolved_link:
        return

    current_link = str(case.get("case_link", "")).strip()
    if current_link == resolved_link:
        return

    case["case_link"] = resolved_link
    changes["case_link"] = resolved_link
    evidence["case_link_index"] = {
        "match_by": match_by,
        "previous": current_link,
        "resolved": resolved_link,
    }


def _extract_tx_hashes_from_text(text: str) -> list[str]:
    return _dedupe_keep_order(TX_HASH_RE.findall(text or ""))


def _extract_block_hint(*texts: str) -> int | None:
    for text in texts:
        match = BLOCK_HINT_RE.search(text or "")
        if not match:
            continue
        try:
            return int(match.group(1))
        except ValueError:
            continue
    return None


def _find_local_source_file(base_dir: Path, case: dict[str, Any]) -> Path | None:
    contracts = case.get("contracts", {}) if isinstance(case.get("contracts"), dict) else {}
    vulnerable = contracts.get("vulnerable", [])
    ground_truth = (
        case.get("ground_truth", {}) if isinstance(case.get("ground_truth"), dict) else {}
    )
    target_name = Path(str(ground_truth.get("file", "")).strip()).name
    target_contract = str(ground_truth.get("contract", "")).strip()
    exploit_rel = str(contracts.get("exploit", "")).strip()

    candidates: list[Path] = []
    if isinstance(vulnerable, list):
        for entry in vulnerable:
            rel = str(entry).strip()
            if not rel:
                continue
            path = resolve_repo_path(base_dir, rel).resolve()
            if path.exists():
                candidates.append(path)

    exploit_path = resolve_repo_path(base_dir, exploit_rel).resolve() if exploit_rel else None
    if exploit_path is not None and exploit_path.exists():
        candidates.append(exploit_path)

    if target_name:
        for path in candidates:
            if path.name == target_name:
                return path

    if target_contract:
        lowered_target = target_contract.lower()
        for path in candidates:
            if path.stem.lower() == lowered_target:
                return path

    return candidates[0] if candidates else None


def _parse_numeric_expr(text: str) -> int | None:
    value = str(text or "").replace("_", "").strip().rstrip(";")
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _normalize_chain_name(value: str) -> str:
    key = str(value or "").strip().lower()
    if not key:
        return ""
    return CHAIN_FORK_MAP.get(key, key)


def _parse_string_expr(content: str, expr: str, *, depth: int = 0) -> str:
    if depth > 4:
        return ""
    value = str(expr or "").strip().rstrip(",").rstrip(";")
    if not value:
        return ""

    literal = STRING_LITERAL_RE.fullmatch(value)
    if literal:
        return str(literal.group("value") or "").strip()

    if IDENTIFIER_RE.fullmatch(value):
        assign = re.search(rf"\b{re.escape(value)}\s*=\s*(?P<expr>[^;]+);", content)
        if assign:
            return _parse_string_expr(content, assign.group("expr"), depth=depth + 1)

    return ""


def _extract_fork_metadata_from_reference_exploit(exploit_text: str) -> str:
    match = CREATE_FORK_RE.search(exploit_text or "")
    if not match:
        return ""
    return _normalize_chain_name(
        _parse_string_expr(exploit_text, match.group("alias_expr") or "")
    )


def _infer_chain_from_urls(*urls: str) -> str:
    for url in urls:
        lowered = str(url or "").strip().lower()
        if not lowered:
            continue
        for domain, chain in EXPLORER_DOMAIN_TO_CHAIN:
            if domain in lowered:
                return chain
        tx_path = re.search(r"/tx/([a-z]+)/0x[a-f0-9]{64}", lowered)
        if tx_path:
            return _normalize_chain_name(tx_path.group(1))
    return ""


def _extract_function_name_from_text(*texts: str) -> str:
    ignored = {"setup", "test", "testexploit", "testpoc", "gtag"}
    for text in texts:
        for match in FUNCTION_SNIPPET_RE.finditer(text or ""):
            name = str(match.group(1) or "").strip()
            if not name or name.lower() in ignored:
                continue
            return name
    return ""


def _load_reference_exploit_text(base_dir: Path, case: dict[str, Any]) -> tuple[Path | None, str]:
    contracts = case.get("contracts", {}) if isinstance(case.get("contracts"), dict) else {}
    exploit_rel = str(
        contracts.get("exploit", "")
        or case.get("exploit", "")
        or case.get("reference_exploit", "")
    ).strip()
    if not exploit_rel:
        return None, ""
    exploit_path = resolve_repo_path(base_dir, exploit_rel).resolve()
    if not exploit_path.exists():
        return None, ""
    return exploit_path, exploit_path.read_text(encoding="utf-8", errors="replace")


def _infer_function_line(source_path: Path | None, function_name: str) -> int | None:
    if source_path is None or not source_path.exists():
        return None
    name = str(function_name).strip()
    if not name:
        return None

    code = source_path.read_text(encoding="utf-8", errors="replace")
    if name in {"constructor", "fallback", "receive"}:
        match = re.search(rf"\b{re.escape(name)}\s*\(", code)
    else:
        match = re.search(rf"\bfunction\s+{re.escape(name)}\s*\(", code)
    if not match:
        return None
    return code[: match.start()].count("\n") + 1


def _detect_ground_truth_quality(case: dict[str, Any]) -> dict[str, bool]:
    ground_truth = (
        case.get("ground_truth", {}) if isinstance(case.get("ground_truth"), dict) else {}
    )
    has_file = bool(str(ground_truth.get("file", "")).strip())
    has_function = bool(str(ground_truth.get("function", "")).strip())
    return {
        "has_file": has_file,
        "has_function": has_function,
        "has_line": False,
        "complete_location": has_file and has_function,
    }


def _canonical_detect_taxonomy_label(value: object) -> str:
    normalized = normalize_detect_type_label(value)
    if not normalized:
        return ""
    return normalized if normalized in DETECT_TAXONOMY_SET else "accounting-error"


def _normalize_detect_taxonomy_fields(
    working: dict[str, Any],
    changes: dict[str, Any],
    *,
    case_link: str = "",
    reference_material: dict[str, Any] | None = None,
    exploit_text: str = "",
    snapshot_row: dict[str, Any] | None = None,
    update_category: bool = True,
) -> None:
    _ = case_link
    _ = reference_material
    _ = exploit_text
    _ = snapshot_row

    original_category = str(working.get("category", "")).strip()
    normalized_category = _canonical_detect_taxonomy_label(original_category)

    ground_truth = working.get("ground_truth")
    if not isinstance(ground_truth, dict):
        ground_truth = {}
        working["ground_truth"] = ground_truth

    original_type = str(ground_truth.get("type", "")).strip()
    normalized_type = _canonical_detect_taxonomy_label(original_type)

    if normalized_category and not normalized_type:
        normalized_type = normalized_category
    elif normalized_type and not normalized_category:
        normalized_category = normalized_type

    if update_category and normalized_category and normalized_category != original_category:
        working["category"] = normalized_category
        changes["category"] = normalized_category

    if normalized_type and normalized_type != original_type:
        ground_truth["type"] = normalized_type
        changes["ground_truth.type"] = normalized_type


def _load_detect_source_files(base_dir: Path, case: dict[str, Any]) -> dict[str, str]:
    contracts = case.get("contracts", {}) if isinstance(case.get("contracts"), dict) else {}
    vulnerable = contracts.get("vulnerable", [])
    if not isinstance(vulnerable, list):
        return {}

    source_files: dict[str, str] = {}
    for entry in vulnerable:
        rel = str(entry).strip()
        if not rel:
            continue
        path = resolve_repo_path(base_dir, rel)
        if not path.exists() or path.suffix.lower() != ".sol":
            continue
        key = path.name
        if key in source_files:
            key = rel
        source_files[key] = path.read_text(encoding="utf-8", errors="replace")
    return source_files


def _update_detect_ground_truth_field(
    working: dict[str, Any], changes: dict[str, Any], path: str, value: Any
) -> None:
    current = _get_nested_value(working, path)
    if current == value:
        return
    _set_nested_value(working, path, value)
    changes[path] = value


def _record_determination(evidence: dict[str, Any], key: str, payload: dict[str, Any]) -> None:
    if not isinstance(evidence, dict) or not isinstance(payload, dict):
        return
    value = str(payload.get("value", "")).strip()
    if not value:
        return
    evidence[key] = payload


def _sync_benchmark_case_determinations(
    report: dict[str, Any],
    *,
    fallback_source: str,
) -> dict[str, Any]:
    updated = deepcopy(report)
    final_case = updated.get("suggested_manual_case", {})
    if not isinstance(final_case, dict):
        return updated
    evidence = dict(updated.get("evidence", {}) or {})

    field_specs = (
        ("vulnerable_address", "vulnerable_address_determination"),
        ("file", "file_determination"),
        ("function", "function_determination"),
        ("type", "type_determination"),
    )
    for path, key in field_specs:
        value = str(_get_nested_value(final_case, path) or "").strip()
        if not value:
            continue
        payload = dict(evidence.get(key, {}) or {})
        payload["value"] = value
        payload.setdefault("source", fallback_source)
        if path in {"file", "function", "type"}:
            payload.setdefault(
                "address",
                str(_get_nested_value(final_case, "vulnerable_address") or "").strip(),
            )
        evidence[key] = payload

    updated["evidence"] = evidence
    return updated


def _reconcile_detect_ground_truth_with_source_files(
    working: dict[str, Any],
    changes: dict[str, Any],
    evidence: dict[str, Any],
    source_files: dict[str, str],
    *,
    contract_name: str = "",
    exploit_path: Path | None = None,
    evidence_key: str,
    evidence_source: str,
) -> bool:
    if not source_files:
        return False

    ground_truth = working.get("ground_truth")
    if not isinstance(ground_truth, dict):
        return False

    function_name = str(ground_truth.get("function", "")).strip()
    current_file = Path(str(ground_truth.get("file", "")).strip()).name

    def _refine(name: str) -> dict[str, Any] | None:
        if not name:
            return None
        return find_function_in_source(
            source_files,
            name,
            contract_name=contract_name or None,
        )

    current_refined = _refine(function_name)
    file_matches_source = not current_file or current_file in source_files
    if current_refined and file_matches_source:
        refined_file = str(current_refined.get("file", "")).strip()
        _record_determination(
            evidence,
            "function_determination",
            {
                "value": function_name,
                "source": evidence_source,
                "address": str(_get_nested_value(working, "contracts.vulnerable_address") or "").strip(),
                "contract_name": contract_name,
            },
        )
        if refined_file:
            _record_determination(
                evidence,
                "file_determination",
                {
                    "value": Path(refined_file).name,
                    "source": evidence_source,
                    "address": str(_get_nested_value(working, "contracts.vulnerable_address") or "").strip(),
                    "contract_name": contract_name,
                },
            )
            _update_detect_ground_truth_field(
                working, changes, "ground_truth.file", Path(refined_file).name
            )
        if current_refined.get("line") is not None:
            _update_detect_ground_truth_field(
                working, changes, "ground_truth.line", int(current_refined["line"])
            )
        line_range = current_refined.get("line_range")
        if isinstance(line_range, list) and line_range:
            normalized_range = [int(item) for item in line_range if isinstance(item, int)]
            _update_detect_ground_truth_field(
                working, changes, "ground_truth.line_range", normalized_range
            )
        evidence[evidence_key] = {
            "previous_file": current_file,
            "previous_function": function_name,
            "contract_name": contract_name,
            "source": evidence_source,
            "resolved_file": Path(refined_file).name if refined_file else "",
        }
        return True

    if exploit_path is None:
        return False

    extracted = dfhl_extract_location(exploit_path)
    if not isinstance(extracted, dict):
        return False

    extracted_function = str(extracted.get("function", "")).strip()
    refined = _refine(extracted_function)
    if not refined:
        return False

    _record_determination(
        evidence,
        "function_determination",
        {
            "value": extracted_function,
            "source": f"exploit_location_plus_{evidence_source}",
            "address": str(_get_nested_value(working, "contracts.vulnerable_address") or "").strip(),
            "contract_name": contract_name,
        },
    )
    _update_detect_ground_truth_field(working, changes, "ground_truth.function", extracted_function)
    refined_file = str(refined.get("file", "")).strip()
    if refined_file:
        _record_determination(
            evidence,
            "file_determination",
            {
                "value": Path(refined_file).name,
                "source": f"exploit_location_plus_{evidence_source}",
                "address": str(_get_nested_value(working, "contracts.vulnerable_address") or "").strip(),
                "contract_name": contract_name,
            },
        )
        _update_detect_ground_truth_field(
            working, changes, "ground_truth.file", Path(refined_file).name
        )
    if refined.get("line") is not None:
        _update_detect_ground_truth_field(
            working, changes, "ground_truth.line", int(refined["line"])
        )
    line_range = refined.get("line_range")
    if isinstance(line_range, list) and line_range:
        normalized_range = [int(item) for item in line_range if isinstance(item, int)]
        _update_detect_ground_truth_field(
            working, changes, "ground_truth.line_range", normalized_range
        )
    evidence[evidence_key] = {
        "previous_file": current_file,
        "previous_function": function_name,
        "contract_name": contract_name,
        "recovered_from_exploit": extracted_function,
        "source": evidence_source,
        "resolved_file": Path(refined_file).name if refined_file else "",
    }
    return True


def _reconcile_detect_ground_truth_with_source(
    base_dir: Path,
    working: dict[str, Any],
    changes: dict[str, Any],
    evidence: dict[str, Any],
) -> None:
    if str(working.get("source", "")).strip() != "DeFiHackLabs":
        return

    source_files = _load_detect_source_files(base_dir, working)
    if not source_files:
        return

    case_id = str(working.get("id", "")).strip()
    vulnerable_address = str(
        _get_nested_value(working, "contracts.vulnerable_address")
        or _get_nested_value(working, "ground_truth.vulnerable_address")
        or ""
    ).strip()
    source_metadata = (
        load_dfhl_source_metadata(
            case_id,
            base_dir,
            chain=str(working.get("chain", "")),
            address=vulnerable_address,
        )
        if case_id
        else {}
    )
    contract_name = str(
        (working.get("ground_truth", {}) or {}).get("contract", "")
        or source_metadata.get("contract_name", "")
    ).strip()
    exploit_path, _ = _load_reference_exploit_text(base_dir, working)
    _reconcile_detect_ground_truth_with_source_files(
        working,
        changes,
        evidence,
        source_files,
        contract_name=contract_name,
        exploit_path=exploit_path,
        evidence_key="detect_source_reconciliation",
        evidence_source="local_vulnerable_sources",
    )


def _normalize_symbol(symbol: str) -> str:
    cleaned = str(symbol).strip().strip(",.;:()[]{}")
    return cleaned.upper()


def _extract_profit_symbols_from_text(text: str) -> list[str]:
    candidates: list[str] = []
    for raw in NUMBER_TOKEN_RE.findall(text or ""):
        symbol = _normalize_symbol(raw)
        if not symbol:
            continue
        candidates.append(symbol)
    return _dedupe_keep_order(candidates)


def _extract_clara_profit_candidates(
    snapshot_row: dict[str, Any], attack_context: dict[str, Any]
) -> list[str]:
    if not isinstance(snapshot_row, dict):
        return []

    text = " ".join(
        part
        for part in [
            str(snapshot_row.get("root_cause_html", "")).strip(),
            str(snapshot_row.get("root_cause_text", "")).strip(),
            str(snapshot_row.get("page_description", "")).strip(),
            str(snapshot_row.get("loss_badge", "")).strip(),
        ]
        if part
    )
    if not text:
        return []

    adversary_candidates = {
        str(item).strip().lower()
        for key in ("attack_senders", "attack_targets", "attack_created_contracts")
        for item in (
            attack_context.get(key, []) if isinstance(attack_context.get(key), list) else []
        )
        if str(item).strip()
    }
    match = re.search(r"Adversary address[^0-9a-fA-F]*(0x[a-fA-F0-9]{40})", text, re.IGNORECASE)
    if match:
        adversary_candidates.add(match.group(1).lower())

    candidates: list[str] = []
    delta_re = re.compile(
        r'"holder":\s*"(?P<holder>0x[a-fA-F0-9]{40})".*?"delta":\s*"(?P<delta>-?\d+)".*?"contract_name":\s*"(?P<name>[^"]+)"',
        re.DOTALL,
    )
    for item in delta_re.finditer(text):
        holder = item.group("holder").lower()
        if adversary_candidates and holder not in adversary_candidates:
            continue
        try:
            delta = int(item.group("delta"))
        except ValueError:
            continue
        if delta <= 0:
            continue
        candidates.append(_normalize_symbol(item.group("name")))

    if candidates:
        return _dedupe_keep_order(candidates)
    return _extract_profit_symbols_from_text(
        str(snapshot_row.get("loss_badge", ""))
        + " "
        + str(snapshot_row.get("page_description", ""))
    )


def build_manual_fill_report(
    base_dir: Path, task: str, case: dict[str, Any], *, case_path: Path | None = None
) -> dict[str, Any]:
    task_name = str(task).strip().lower()
    if task_name == "benchmark_case":
        from .benchmark_fill import build_benchmark_case_report

        return build_benchmark_case_report(base_dir, case, case_path=case_path)
    raise ValueError(f"unsupported fill task: {task}")


def _task_type_for_name(task: str) -> TaskType:
    task_name = str(task).strip().lower()
    if task_name == "benchmark_case":
        return TaskType.FILL
    raise ValueError(f"unsupported fill task: {task}")


def _parse_json_object(raw: str) -> dict[str, Any]:
    text = str(raw or "").strip()
    if not text:
        raise ValueError("empty reviewer output")

    decoder = json.JSONDecoder()

    # Collect all candidate start positions for '{' and try from the last one
    # first, since the final JSON object in the stream is most likely the
    # agent's answer (earlier ones are tool results, file reads, etc.).
    brace_positions: list[int] = []
    idx = 0
    while True:
        pos = text.find("{", idx)
        if pos < 0:
            break
        brace_positions.append(pos)
        idx = pos + 1

    last_error: Exception | None = None
    # Try from the end first — the agent's final answer is usually the last JSON
    for pos in reversed(brace_positions):
        candidate = text[pos:]
        try:
            payload, _ = decoder.raw_decode(candidate)
        except json.JSONDecodeError as exc:
            last_error = exc
            continue
        if not isinstance(payload, dict):
            continue
        # Prefer payloads that look like curator output
        if "proposed_case" in payload or "summary" in payload or "verdict" in payload:
            return payload

    # Fallback: try from the first '{' forward
    for pos in brace_positions:
        candidate = text[pos:]
        try:
            payload, _ = decoder.raw_decode(candidate)
        except json.JSONDecodeError as exc:
            last_error = exc
            continue
        if isinstance(payload, dict):
            return payload

    if last_error is not None:
        raise last_error
    raise ValueError("expected reviewer JSON object")


def _parse_json_literal_text(raw: str) -> Any:
    text = str(raw or "").strip()
    if not text:
        return ""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


_BENCHMARK_REVIEW_SCOPED_PATHS = {"attack_txs", "file", "function", "type"}


def _filter_review_payload_scope(task: str, payload: dict[str, Any]) -> dict[str, Any]:
    task_name = str(task).strip().lower()
    if task_name != "benchmark_case":
        return payload
    issues = payload.get("issues", [])
    filtered = []
    if isinstance(issues, list):
        for item in issues:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path", "")).strip()
            if path in _BENCHMARK_REVIEW_SCOPED_PATHS:
                filtered.append(item)
    updated = dict(payload)
    updated["issues"] = filtered
    if not filtered:
        updated["verdict"] = "accept"
        if not str(updated.get("reason", "")).strip():
            updated["reason"] = "No scoped reviewer issues for attack_txs, file, function, or type."
    return updated


def _normalize_review_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("expected reviewer JSON object")

    raw_verdict = str(payload.get("verdict", "")).strip().lower()
    verdict_map = {
        "accept": "accept",
        "accepted": "accept",
        "pass": "accept",
        "approve": "accept",
        "approved": "accept",
        "reject": "reject",
        "rejected": "reject",
        "needs_review": "reject",
        "fail": "reject",
    }
    verdict = verdict_map.get(raw_verdict, "")
    if not verdict:
        raise ValueError("expected reviewer verdict accept/reject")

    reason = (
        str(payload.get("reason", "")).strip()
        or str(payload.get("summary", "")).strip()
        or "(no reviewer reason)"
    )

    normalized_issues: list[dict[str, str]] = []
    raw_issues = payload.get("issues", [])
    if isinstance(raw_issues, list):
        for item in raw_issues:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path", "")).strip() or "review"
            message = (
                str(item.get("message", "")).strip()
                or str(item.get("recommendation", "")).strip()
                or "(no reviewer issue message)"
            )
            action = str(item.get("action", "")).strip().lower()
            if not action:
                severity = str(item.get("severity", "")).strip().lower()
                if severity == "error":
                    action = "drop"
                elif severity == "warning":
                    action = "revise"
            if action not in {"drop", "revise", "needs_human"}:
                action = "revise"
            normalized_issues.append({"path": path, "message": message, "action": action})

    return {"verdict": verdict, "reason": reason, "issues": normalized_issues}


def _normalize_fill_payload(
    task: str,
    payload: dict[str, Any],
    *,
    current_case: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("expected curator JSON object")

    raw_error = payload.get("error")
    if isinstance(raw_error, dict):
        error_message = str(raw_error.get("message", "")).strip() or str(raw_error).strip()
        raise ValueError(error_message or "curator returned error payload")

    def _normalize_text_list(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        out: list[str] = []
        for item in value:
            text = str(item).strip()
            if text:
                out.append(text)
        return out

    task_name = str(task).strip().lower()
    if task_name != "benchmark_case":
        raise ValueError(f"unsupported fill task schema: {task_name}")

    summary = str(payload.get("summary", "")).strip() or "(no fill summary)"
    required_fields = ("summary", "proposed_case")
    missing_fields = [field for field in required_fields if field not in payload]
    if missing_fields:
        raise ValueError("expected curator fields: " + ", ".join(missing_fields))

    proposed_case = payload.get("proposed_case", {})
    if not isinstance(proposed_case, dict):
        raise ValueError("expected proposed_case object")

    normalized_changes: list[dict[str, Any]] = []
    for path in sorted(TASK_FILL_ALLOWED_PATHS.get("benchmark_case", ())):
        if path not in proposed_case:
            continue
        value = proposed_case.get(path)
        current_value = current_case.get(path)
        if current_value == value:
            continue
        normalized_changes.append({
            "path": path,
            "value": value,
            "note": "proposed directly in flat benchmark output",
        })

    remaining_unknowns = _normalize_text_list(payload.get("remaining_unknowns", []))

    # Self-validation: flag field-consistency issues
    consistency_warnings = _check_fill_field_consistency(proposed_case)
    if consistency_warnings:
        remaining_unknowns.extend(
            f"[self-check] {w}" for w in consistency_warnings
        )

    return {
        "summary": summary,
        "proposed_case": proposed_case,
        "recommended_changes": normalized_changes,
        "remaining_unknowns": remaining_unknowns,
    }


def _extract_selectors_from_bytecode(bytecode: str) -> set[str]:
    """Extract all 4-byte PUSH4 selectors from EVM bytecode."""
    code = bytecode.strip()
    if code.startswith("0x"):
        code = code[2:]
    selectors: set[str] = set()
    i = 0
    while i < len(code) - 9:
        opcode = int(code[i:i + 2], 16) if code[i:i + 2] else 0
        if opcode == 0x63:  # PUSH4
            sel = "0x" + code[i + 2:i + 10]
            if len(sel) == 10:
                selectors.add(sel.lower())
            i += 10
        elif 0x60 <= opcode <= 0x7F:  # PUSH1..PUSH32
            push_bytes = opcode - 0x5F
            i += 2 + push_bytes * 2
        else:
            i += 2
    return selectors


def _compute_selector_via_cast(func_name: str, on_chain_selectors: set[str] | None = None) -> str | None:
    """Try to compute a 4-byte selector from a human-readable function name.

    When *on_chain_selectors* is provided, only return a selector that actually
    exists in the contract bytecode.  This avoids false positives from guessing
    argument types.
    """
    import shutil

    name = func_name.strip()
    if not name:
        return None

    if "(" in name:
        candidates = [name]
    else:
        candidates = [
            f"{name}()",
            f"{name}(uint256)",
            f"{name}(address)",
            f"{name}(address,uint256)",
            f"{name}(uint256,address)",
            f"{name}(bytes)",
            f"{name}(bytes,bytes,uint64)",
            f"{name}(uint256,uint256)",
            f"{name}(address,address)",
            f"{name}(address,address,uint256)",
            f"{name}(address,uint256,uint256)",
            f"{name}(uint256,address,uint256)",
            f"{name}(bool)",
            f"{name}(uint256,bytes)",
            f"{name}(address,bytes)",
            f"{name}(address,address,uint256,uint256)",
            f"{name}(address,uint256,uint256,uint256)",
            f"{name}(uint256,uint256,uint256)",
            f"{name}(address[],uint256[],uint256[],bytes)",
            f"{name}(address,uint256,uint256,bytes)",
            f"{name}(address,address,uint256,bytes)",
        ]

    cast_bin = shutil.which("cast")
    for sig in candidates:
        sel: str | None = None
        if cast_bin:
            try:
                proc = subprocess.run(
                    [cast_bin, "sig", sig],
                    capture_output=True, text=True, timeout=5,
                )
                if proc.returncode == 0:
                    raw = proc.stdout.strip()
                    if raw.startswith("0x") and len(raw) == 10:
                        sel = raw.lower()
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
        if sel is None:
            try:
                sel_bytes = keccak(text=sig)[:4]
                sel = "0x" + sel_bytes.hex()
            except Exception:
                continue

        if on_chain_selectors is not None:
            if sel in on_chain_selectors:
                return sel
        else:
            return sel

    return None


def _check_fill_field_consistency(proposed: dict[str, Any]) -> list[str]:
    """Lightweight self-validation for curator output field consistency."""
    warnings: list[str] = []
    attack_txs = proposed.get("attack_txs")
    has_txs = isinstance(attack_txs, list) and len(attack_txs) > 0

    if has_txs and proposed.get("attacker_profit") is None:
        warnings.append("attack_txs is non-empty but attacker_profit is null — consider re-running get_tx_profit")
    if has_txs and proposed.get("block_number") is None:
        warnings.append("attack_txs is non-empty but block_number is null — consider re-running get_tx_block")
    vulnerable_address = str(proposed.get("vulnerable_address") or "").strip()
    if vulnerable_address and proposed.get("fixable") is None:
        warnings.append("vulnerable_address is set but fixable is null — consider re-running get_proxy_context")
    if proposed.get("has_public_source") is True and proposed.get("file") is None:
        warnings.append("has_public_source is true but file is null — consider checking staged source or get_contract_source")

    vuln_type = proposed.get("type")
    allowed_types = {"accounting-error", "price-manipulation", "access-control", "unsafe-external-call", "input-validation", None}
    if vuln_type not in allowed_types:
        warnings.append(f"type '{vuln_type}' is not in the allowed vulnerability-type labels")

    func = str(proposed.get("function") or "").strip()
    if proposed.get("has_public_source") is True:
        if func.startswith("0x") and len(func) == 10:
            warnings.append(
                f"has_public_source is true but function is a 4-byte selector '{func}' "
                "— when verified source is available, use the human-readable function name instead. "
                "Use get_contract_source to find the matching function name."
            )
    elif not proposed.get("has_public_source"):
        if func and not func.startswith("0x"):
            warnings.append(
                f"has_public_source is false but function is '{func}' (a human-readable name) "
                "— the eval agent only has access to bytecode and cannot see this name. "
                "Use get_decompiled_contract or get_tx_trace to find the 4-byte selector "
                "(e.g. 0x6c3c669c) and replace function with that selector."
            )

    return warnings


def _is_fill_mutable_path(path: str) -> bool:
    normalized = str(path).strip()
    if not normalized:
        return False
    blocked_prefixes = (
        "agent",
        "review",
        "annotation_hints",
        "ground_truth_quality",
        "case_path",
        "review_case_path",
        "manual_case_path",
    )
    blocked_exact = {"id", "name", "source", "description", *DEPRECATED_CHAIN_CONTEXT_PATHS}
    if normalized in blocked_exact:
        return False
    return not any(
        normalized == prefix or normalized.startswith(prefix + ".") for prefix in blocked_prefixes
    )


def _task_fill_allowed_paths(task: str) -> frozenset[str] | None:
    return TASK_FILL_ALLOWED_PATHS.get(str(task).strip().lower())


def _is_task_fill_mutable_path(task: str, path: str) -> bool:
    normalized = str(path).strip()
    if not _is_fill_mutable_path(normalized):
        return False
    allowed = _task_fill_allowed_paths(task)
    if allowed is None:
        return True
    return normalized in allowed


def _filter_changed_fields_for_task(task: str, changed_fields: dict[str, Any]) -> dict[str, Any]:
    allowed = _task_fill_allowed_paths(task)
    raw = dict(changed_fields or {})
    if allowed is None:
        return raw
    return {path: deepcopy(value) for path, value in raw.items() if path in allowed}


def _fill_taxonomy_paths_for_task(task: str) -> tuple[str, ...]:
    return TASK_FILL_TAXONOMY_PATHS.get(str(task).strip().lower(), DEFAULT_FILL_TAXONOMY_PATHS)


def _recompute_changed_fields(
    raw_case: dict[str, Any],
    updated_review_case: dict[str, Any],
    candidate_paths: list[str],
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for path in _dedupe_keep_order(candidate_paths):
        if not _is_fill_mutable_path(path):
            continue
        new_value = _get_nested_value(updated_review_case, path)
        original_value = _get_nested_value(raw_case, path)
        if _is_missing(new_value) and _is_missing(original_value):
            continue
        if new_value == original_value:
            continue
        if _is_missing(new_value):
            continue
        out[path] = deepcopy(new_value)
    return out


def _delete_nested_value(data: dict[str, Any], path: str) -> None:
    current = data
    parts = path.split(".")
    for part in parts[:-1]:
        child = current.get(part)
        if not isinstance(child, dict):
            return
        current = child
    current.pop(parts[-1], None)


def _path_matches_issue(changed_path: str, issue_path: str) -> bool:
    changed = str(changed_path).strip()
    issue = str(issue_path).strip()
    for prefix in ("changed_fields.", "suggested_manual_case.", "suggested_review_case."):
        if issue.startswith(prefix):
            issue = issue[len(prefix) :].strip()
            break
    if not changed or not issue:
        return False
    return changed == issue or changed.startswith(issue + ".")


def _normalize_issue_path(path: str) -> str:
    issue = str(path).strip()
    for prefix in ("changed_fields.", "suggested_manual_case.", "suggested_review_case."):
        if issue.startswith(prefix):
            return issue[len(prefix) :].strip()
    return issue


def _issue_paths_for_actions(
    changed_fields: dict[str, Any],
    review_payload: dict[str, Any],
    *,
    actions: set[str],
) -> list[str]:
    issues = review_payload.get("issues", [])
    if not isinstance(issues, list) or not isinstance(changed_fields, dict):
        return []

    matched: list[str] = []
    for item in issues:
        if not isinstance(item, dict):
            continue
        action = str(item.get("action", "")).strip().lower()
        if action not in actions:
            continue
        issue_path = _normalize_issue_path(item.get("path", ""))
        if not issue_path:
            continue
        if any(_path_matches_issue(path, issue_path) for path in changed_fields):
            matched.append(issue_path)
    return _dedupe_keep_order(matched)


def _prunable_issue_paths(
    changed_fields: dict[str, Any], review_payload: dict[str, Any]
) -> list[str]:
    return _issue_paths_for_actions(
        changed_fields,
        review_payload,
        actions={"drop", "revise"},
    )


def _addressed_issue_paths(
    issue_paths: list[str],
    applied_paths: list[str],
) -> list[str]:
    addressed: list[str] = []
    for issue_path in issue_paths:
        if any(_path_matches_issue(applied_path, issue_path) for applied_path in applied_paths):
            addressed.append(issue_path)
    return _dedupe_keep_order(addressed)


def _prune_report_with_review_feedback(
    task: str,
    raw_case: dict[str, Any],
    report: dict[str, Any],
    rejected_paths: list[str],
) -> dict[str, Any]:
    task_name = str(task).strip().lower()
    updated_review_case = deepcopy(report.get("suggested_review_case", raw_case))
    if not isinstance(updated_review_case, dict):
        updated_review_case = deepcopy(raw_case)

    filtered_changes: dict[str, Any] = {}
    for path, value in dict(report.get("changed_fields", {}) or {}).items():
        if any(_path_matches_issue(path, rejected_path) for rejected_path in rejected_paths):
            original_value = _get_nested_value(raw_case, path)
            if _is_missing(original_value):
                _delete_nested_value(updated_review_case, path)
            else:
                _set_nested_value(updated_review_case, path, deepcopy(original_value))
            continue
        filtered_changes[path] = value

    updated_review_case.pop("annotation_hints", None)
    normalized_manual_case = normalize_task_case(task_name, updated_review_case)
    refreshed_review_case = attach_annotation_hints(
        task_name, deepcopy(normalized_manual_case), raw_case=raw_case
    )

    pruned_report = dict(report)
    pruned_report["changed_fields"] = filtered_changes
    pruned_report["suggested_review_case"] = refreshed_review_case
    pruned_report["suggested_manual_case"] = normalized_manual_case
    pruned_report["remaining_annotation_hints"] = _remaining_missing_annotation_hints(
        normalized_manual_case
    )
    return pruned_report


def _path_within_revision_scope(path: str, issue_paths: list[str]) -> bool:
    candidate = str(path).strip()
    if not candidate:
        return False
    for issue_path in issue_paths:
        normalized_issue = _normalize_issue_path(issue_path)
        if not normalized_issue:
            continue
        if _path_matches_issue(candidate, normalized_issue):
            return True
        if "." in normalized_issue:
            parent = normalized_issue.rsplit(".", 1)[0]
            if candidate == parent or candidate.startswith(parent + "."):
                return True
    return False


def _strip_deprecated_block_fields(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text in {"block", "fork_block"}:
                continue
            if key_text in DEPRECATED_CHAIN_CONTEXT_PATHS:
                continue
            cleaned[key_text] = _strip_deprecated_block_fields(item)
        return cleaned
    if isinstance(value, list):
        return [_strip_deprecated_block_fields(item) for item in value]
    return value


def _strip_final_benchmark_only_paths(value: Any) -> Any:
    if not isinstance(value, dict):
        return deepcopy(value)
    cleaned = deepcopy(value)
    for path in FINAL_BENCHMARK_PATHS_TO_DROP:
        _delete_nested_value(cleaned, path)
    return cleaned


def _strip_final_only_changed_fields(value: Any) -> Any:
    if not isinstance(value, dict):
        return {}
    return {
        str(path): deepcopy(item)
        for path, item in value.items()
        if str(path) not in FINAL_BENCHMARK_PATHS_TO_DROP
    }


def _compact_text_preview(raw: str, *, width: int = 240) -> str:
    text = " ".join(str(raw or "").split())
    if len(text) <= width:
        return text
    return text[: width - 3] + "..."


def _remaining_missing_annotation_hints(case_payload: dict[str, Any]) -> dict[str, Any]:
    hints = case_payload.get("annotation_hints", {})
    if not isinstance(hints, dict):
        return {}
    remaining: dict[str, Any] = {}
    for path, payload in hints.items():
        if not isinstance(payload, dict):
            continue
        status = str(payload.get("status", "")).strip()
        if not status or status == "missing":
            remaining[str(path)] = payload
    return remaining


def _enforce_reviewer_missing_hint_gate(
    report: dict[str, Any], review_payload: dict[str, Any]
) -> dict[str, Any]:
    remaining = _strip_deprecated_block_fields(report.get("remaining_annotation_hints", {}))
    if not isinstance(remaining, dict) or not remaining:
        return review_payload
    if str(review_payload.get("verdict", "")).strip().lower() != "accept":
        return review_payload

    blocked_paths = sorted(str(path).strip() for path in remaining if str(path).strip())
    payload = dict(review_payload)
    issues = list(payload.get("issues", []))
    issues.append(
        {
            "path": "annotation_hints",
            "message": "proposal still has missing required fields: " + ", ".join(blocked_paths),
            "action": "needs_human",
        }
    )
    payload["verdict"] = "reject"
    payload["reason"] = (
        str(payload.get("reason", "")).strip() + "; " if str(payload.get("reason", "")).strip() else ""
    ) + "proposal still has missing required fields"
    payload["issues"] = issues
    return payload


def _review_issue_signature(issue: Any) -> tuple[str, str, str]:
    if not isinstance(issue, dict):
        return ("", "", "")
    return (
        str(issue.get("path", "")).strip(),
        str(issue.get("action", "")).strip().lower(),
        str(issue.get("message", "")).strip(),
    )


def _review_disagreement_detected(history: list[dict[str, Any]]) -> bool:
    signatures: list[tuple[tuple[str, str, str], ...]] = []
    for entry in history:
        if not isinstance(entry, dict):
            continue
        issues = entry.get("issues", [])
        if not isinstance(issues, list):
            continue
        signature = tuple(
            sorted(sig for sig in (_review_issue_signature(issue) for issue in issues) if any(sig))
        )
        if signature:
            signatures.append(signature)
    if len(signatures) < 2:
        return False
    first = signatures[0]
    return any(signature != first for signature in signatures[1:])


def _report_status(report: dict[str, Any]) -> str:
    review = report.get("review", {})
    if isinstance(review, dict):
        status = str(review.get("status", "")).strip()
        if status:
            return status
    changed = report.get("changed_fields", {})
    remaining = report.get("remaining_annotation_hints", {})
    changed_count = len(changed) if isinstance(changed, dict) else 0
    remaining_count = len(remaining) if isinstance(remaining, dict) else 0
    if changed_count and remaining_count:
        return "partial_fill"
    if changed_count and not remaining_count:
        return "filled"
    if remaining_count:
        return "unresolved"
    return "no_change"


def _build_report_summary(task: str, report: dict[str, Any]) -> dict[str, Any]:
    changed_fields = _strip_final_only_changed_fields(
        _strip_deprecated_block_fields(report.get("changed_fields", {}))
    )
    remaining = _strip_deprecated_block_fields(report.get("remaining_annotation_hints", {}))
    evidence = _strip_deprecated_block_fields(report.get("evidence", {}))
    review = report.get("review", {})
    summary: dict[str, Any] = {
        "task": str(task).strip().lower(),
        "case_id": str(report.get("case_id", "")).strip(),
        "status": _report_status(report),
        "changed_field_count": len(changed_fields) if isinstance(changed_fields, dict) else 0,
        "changed_fields": sorted(changed_fields) if isinstance(changed_fields, dict) else [],
        "remaining_hint_count": len(remaining) if isinstance(remaining, dict) else 0,
        "remaining_hints": sorted(remaining) if isinstance(remaining, dict) else [],
        "evidence_keys": sorted(evidence) if isinstance(evidence, dict) else [],
    }
    if isinstance(review, dict) and review:
        summary["review_status"] = str(review.get("status", "")).strip()
        summary["review_rounds"] = int(review.get("rounds", 0) or 0)
        if "consensus_failure" in review:
            summary["review_consensus_failure"] = bool(review.get("consensus_failure"))
        if "disagreement_detected" in review:
            summary["review_disagreement_detected"] = bool(review.get("disagreement_detected"))
        history = review.get("history", [])
        if isinstance(history, list) and history:
            last = history[-1] if isinstance(history[-1], dict) else {}
            if isinstance(last, dict):
                summary["review_summary"] = (
                    str(last.get("reason", "")).strip()
                    or str(last.get("summary", "")).strip()
                    or "(no reviewer summary)"
                )
                issues = last.get("issues", [])
                if isinstance(issues, list) and issues:
                    summary["review_unresolved_issue_count"] = len(issues)
    return summary


def _sanitize_review_payload(value: Any, *, depth: int = 0) -> Any:
    if depth > 10:
        return _compact_text_preview(json.dumps(value, ensure_ascii=False, default=str), width=320)

    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            if name == "texts":
                if isinstance(item, list) and item:
                    cleaned[name] = [_compact_text_preview(str(item[0]), width=320)]
                continue
            if name in {
                "text",
                "html",
                "raw_html",
                "content_html",
                "raw_output",
                "_raw_output",
                "session_log_path",
                "_session_log_path",
                "combined_prompt",
                "system_prompt",
                "user_prompt",
            }:
                continue
            cleaned[name] = _sanitize_review_payload(item, depth=depth + 1)
        return cleaned

    if isinstance(value, list):
        items = [_sanitize_review_payload(item, depth=depth + 1) for item in value[:12]]
        if len(value) > 12:
            items.append({"_truncated_items": len(value) - 12})
        return items

    if isinstance(value, str):
        return _compact_text_preview(value, width=320)

    return value


def _maybe_absolutize_prompt_path(
    base_dir: Path, value: Any, *, require_exists: bool = False
) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text or "://" in text or "\n" in text:
        return value
    path = Path(text)
    resolved: Path
    if path.is_absolute():
        resolved = path
    else:
        normalized = text.replace("\\", "/")
        if not any(normalized.startswith(prefix) for prefix in PROMPT_REPO_RELATIVE_PREFIXES):
            return value
        resolved = resolve_repo_path(base_dir, path).resolve()
    if require_exists and not resolved.exists():
        return ""
    return str(resolved)


def _absolutize_prompt_payload(base_dir: Path, value: Any, *, key: str = "") -> Any:
    if isinstance(value, dict):
        return {
            str(k): _absolutize_prompt_payload(base_dir, v, key=str(k)) for k, v in value.items()
        }
    if isinstance(value, list):
        if key in PROMPT_REPO_PATH_LIST_KEYS:
            return [_maybe_absolutize_prompt_path(base_dir, item) for item in value]
        return [_absolutize_prompt_payload(base_dir, item, key=key) for item in value]
    if isinstance(value, str) and key in PROMPT_REPO_PATH_KEYS:
        return _maybe_absolutize_prompt_path(base_dir, value)
    return value


def _compact_prompt_payload(value: Any, *, key: str = "") -> Any:
    if isinstance(value, dict):
        compact: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            child_key = str(raw_key)
            if key == "contracts" and child_key == "vulnerable":
                continue
            if child_key == "source_files":
                count = 0
                if isinstance(raw_value, dict):
                    count = len(raw_value)
                elif isinstance(raw_value, list):
                    count = len(raw_value)
                if count and "source_file_count" not in value:
                    compact["source_file_count"] = count
                continue
            compact[child_key] = _compact_prompt_payload(raw_value, key=child_key)
        return compact
    if isinstance(value, list):
        if key == "vulnerable":
            return []
        return [_compact_prompt_payload(item, key=key) for item in value]
    return value


def _compact_changed_fields_for_prompt(base_dir: Path, changed_fields: Any) -> dict[str, Any]:
    if not isinstance(changed_fields, dict):
        return {}
    compact: dict[str, Any] = {}
    for raw_path, raw_value in changed_fields.items():
        path = str(raw_path).strip()
        if not path or path == "contracts.vulnerable":
            continue
        leaf = path.split(".")[-1]
        compact_value = _compact_prompt_payload(
            _absolutize_prompt_payload(base_dir, raw_value, key=leaf),
            key=leaf,
        )
        if leaf == "vulnerable" and compact_value == []:
            continue
        compact[path] = compact_value
    return compact


def _compact_fill_evidence_for_prompt(base_dir: Path, evidence: Any) -> dict[str, Any]:
    compact = _strip_deprecated_block_fields(
        _compact_prompt_payload(_absolutize_prompt_payload(base_dir, evidence or {}))
    )
    if not isinstance(compact, dict):
        return {}
    reference_material = compact.get("reference_material")
    if isinstance(reference_material, dict):
        trimmed = dict(reference_material)
        trimmed.pop("section_url", None)
        trimmed.pop("tx_hashes", None)
        texts = trimmed.get("texts")
        if isinstance(texts, list) and texts:
            trimmed["texts"] = texts[:1]
        compact["reference_material"] = trimmed
    for noisy_key in (
        "curator_taxonomy_judgment",
        "attack_tx_trace_probe",
        "attack_tx_profit_probe",
        "attack_tx_trace_preview",
        "deterministic_remediation_enforcement",
    ):
        compact.pop(noisy_key, None)
    return compact


def _build_compact_review_payload(
    task: str,
    case: dict[str, Any],
    report: dict[str, Any],
    *,
    base_dir: Path,
) -> dict[str, Any]:
    return {
        "task": str(task).strip().lower(),
        "case_id": str(report.get("case_id") or case.get("id", "")).strip(),
        "current_review_case": _sanitize_review_payload(
            _strip_deprecated_block_fields(_compact_prompt_payload(_absolutize_prompt_payload(base_dir, case)))
        ),
        "report_summary": _build_report_summary(task, report),
        "changed_fields": _sanitize_review_payload(
            _strip_final_only_changed_fields(
                _strip_deprecated_block_fields(
                    _compact_changed_fields_for_prompt(base_dir, report.get("changed_fields", {}))
                )
            )
        ),
        "evidence": _sanitize_review_payload(
            _compact_fill_evidence_for_prompt(base_dir, report.get("evidence", {}))
        ),
        "remaining_annotation_hints": _sanitize_review_payload(
            _strip_deprecated_block_fields(report.get("remaining_annotation_hints", {}))
        ),
        "proposed_final_case": _sanitize_review_payload(
            _strip_final_benchmark_only_paths(
                _strip_deprecated_block_fields(
                    _compact_prompt_payload(_absolutize_prompt_payload(base_dir, report.get("suggested_manual_case", {})))
                )
            )
        ),
    }


def _review_payload_snapshot_path(
    base_dir: Path,
    task: str,
    case_id: str,
    *,
    work_dir: Path | None = None,
) -> Path:
    if work_dir is not None:
        target_dir = work_dir / "inputs"
    else:
        safe_case_id = str(case_id).strip() or "unknown_case"
        target_dir = (
            base_dir
            / "tmp"
            / "runtime"
            / "curator_review_inputs"
            / str(task).strip()
            / safe_case_id
        )
    target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir / f"_{str(task).strip()}_review_report.json"


def _write_review_payload_snapshot(
    base_dir: Path,
    task: str,
    case_id: str,
    review_payload: dict[str, Any],
    *,
    work_dir: Path | None = None,
) -> Path:
    payload_path = _review_payload_snapshot_path(
        base_dir,
        task,
        case_id,
        work_dir=work_dir,
    )
    payload_path.write_text(
        json.dumps(review_payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return payload_path


def _parse_env_assignments(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key] = value
    return values


@lru_cache(maxsize=8)
def _project_llm_api_config(base_dir_str: str) -> tuple[str, str]:
    env_values = _parse_env_assignments(Path(base_dir_str) / ".env")
    base_url = (
        str(os.environ.get("LLM_API_BASE_URL") or env_values.get("LLM_API_BASE_URL", ""))
        .strip()
        .rstrip("/")
    )
    api_key = str(os.environ.get("LLM_API_KEY") or env_values.get("LLM_API_KEY", "")).strip()
    return base_url, api_key


def _uses_project_llm_direct_api(model: str) -> bool:
    return str(model or "").strip().lower() in {"claude-opus-4-5"}


def _extract_chat_completion_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices", [])
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0] if isinstance(choices[0], dict) else {}
    message = first.get("message", {}) if isinstance(first, dict) else {}
    content = message.get("content", "") if isinstance(message, dict) else ""
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if not isinstance(item, dict):
                continue
            piece = str(item.get("text", "")).strip()
            if piece:
                parts.append(piece)
        return "\n".join(parts).strip()
    return str(content or "").strip()


def _run_project_llm_chat_completion(
    base_dir: Path,
    *,
    model: str,
    system_prompt: str,
    user_prompt: str,
    session_log_path: Path,
) -> str:
    base_url, api_key = _project_llm_api_config(str(base_dir.resolve()))
    if not base_url or not api_key:
        raise ValueError("LLM_API_BASE_URL/LLM_API_KEY not configured")

    session_log_path.parent.mkdir(parents=True, exist_ok=True)
    request_payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.0,
    }
    request_log = json.dumps(
        {**request_payload, "api_key": "<redacted>"},
        indent=2,
        ensure_ascii=False,
        sort_keys=True,
    )
    request_body = json.dumps(request_payload, ensure_ascii=False)
    curl_cmd = [
        "curl",
        "-sS",
        f"{base_url}/chat/completions",
        "-H",
        f"Authorization: Bearer {api_key}",
        "-H",
        "Content-Type: application/json",
        "--data-binary",
        "@-",
        "-w",
        "\n__CURL_STATUS__:%{http_code}\n",
    ]
    curl_cmd_preview = json.dumps(
        curl_cmd[:-3] + ["<payload via stdin>", "-w", "\n__CURL_STATUS__:%{http_code}\n"],
        ensure_ascii=False,
    )
    try:
        proc = subprocess.run(
            curl_cmd,
            input=request_body,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
            check=False,
        )
    except Exception as exc:
        session_log_path.write_text(
            f"""[project_llm request]
{request_log}

[project_llm error]
{exc}
""",
            encoding="utf-8",
        )
        raise ValueError(f"project_llm API error: {exc}")

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    marker = "\n__CURL_STATUS__:"
    body = stdout
    status = ""
    if marker in stdout:
        body, status = stdout.rsplit(marker, 1)
        status = status.strip()
    session_log_path.write_text(
        f"""[project_llm request]
{request_log}

[project_llm curl_cmd]
{curl_cmd_preview}

[project_llm stderr]
{stderr}

[project_llm response]
{body}

[project_llm status]
{status or '<unknown>'}
""",
        encoding="utf-8",
    )
    if proc.returncode != 0:
        raise ValueError(f"project_llm API error: curl exit {proc.returncode} {stderr[:400]}")
    if status and status != "200":
        raise ValueError(f"project_llm API error: HTTP {status} {body[:400]}")
    payload = json.loads(body)
    content = _extract_chat_completion_text(payload)
    if not content:
        raise ValueError("empty reviewer output")
    return content


class Curator:
    """Shared curator shell with task dispatch and common prompt/reason rendering."""

    def __init__(
        self,
        base_dir: Path,
        *,
        max_attack_txs: int = 3,
        curator_agent: BaseAgent | None = None,
        reviewer_agent: BaseAgent | None = None,
        review_max_rounds: int = 5,
    ):
        self.base_dir = base_dir.resolve()
        self.max_attack_txs = max(int(max_attack_txs), 1)
        self.curator_agent = curator_agent
        self.reviewer_agent = reviewer_agent
        self.review_max_rounds = max(int(review_max_rounds), 1)

    @staticmethod
    def _auto_fix_function_selector(report: dict[str, Any]) -> dict[str, Any]:  # noqa: C901
        """Post-fill: convert human-readable function names to 4-byte selectors
        when has_public_source is false.

        Strategy: compute candidate selectors from the function name with
        various arg-type guesses, then validate against the actual PUSH4
        selectors in the contract's on-chain runtime bytecode.
        """
        suggested = report.get("suggested_manual_case", {})
        if not isinstance(suggested, dict):
            return report
        if suggested.get("has_public_source"):
            return report
        func = str(suggested.get("function") or "").strip()
        if not func or func.startswith("0x"):
            return report

        chain = str(suggested.get("chain") or "").strip()
        address = str(suggested.get("vulnerable_address") or "").strip()
        proxy = str(suggested.get("proxy_address") or "").strip()
        block = suggested.get("block_number")

        on_chain_selectors: set[str] | None = None
        if chain:
            for addr in (address, proxy):
                if not addr:
                    continue
                try:
                    bytecode = lookup_runtime_code(chain, addr, block)
                    if bytecode:
                        sels = _extract_selectors_from_bytecode(bytecode)
                        if on_chain_selectors is None:
                            on_chain_selectors = sels
                        else:
                            on_chain_selectors |= sels
                except Exception:
                    pass

        selector = _compute_selector_via_cast(func, on_chain_selectors)
        if selector:
            suggested["function"] = selector
        return report

    def build_report(
        self, task: str, case: dict[str, Any], *, case_path: Path | None = None
    ) -> dict[str, Any]:
        task_name = str(task).strip().lower()
        base_report = build_manual_fill_report(self.base_dir, task_name, case, case_path=case_path)
        if self.curator_agent is not None:
            base_report, _ = self._apply_initial_fill_feedback(
                task_name,
                case,
                case_path=case_path,
                report=base_report,
            )
            base_report = self._auto_fix_function_selector(base_report)
        if self.reviewer_agent is not None and base_report.get("changed_fields"):
            base_report = self._review_report_until_consensus(
                task_name,
                case,
                case_path=case_path,
                base_report=base_report,
            )
        suggested_manual_case = deepcopy(base_report.get("suggested_manual_case", {}))
        manual_output_path = ""
        if isinstance(suggested_manual_case, dict) and suggested_manual_case.get("id"):
            manual_output_path = str(
                (self.base_dir / manual_case_path(task_name, suggested_manual_case)).resolve()
            )

        if task_name == "benchmark_case":
            base_report = _sync_benchmark_case_determinations(
                base_report,
                fallback_source="final_case_sync",
            )
        report = {
            **base_report,
            "summary": _build_report_summary(task_name, base_report),
            "agent": {
                "name": "curator",
                "strategy": [
                    "benchmark_input_case",
                    "deterministic_manual_fill",
                    "manual_case_normalization",
                ],
            },
            "review_case_path": (
                str(case_path) if case_path is not None and Path(case_path).exists() else ""
            ),
            "manual_case_path": manual_output_path,
        }
        if self.curator_agent is not None:
            report["agent"]["strategy"].append("agent_taxonomy_fill")
        if self.reviewer_agent is not None:
            report["agent"]["strategy"].append("reviewer_consensus_gate")
        if self.curator_agent is not None and self.reviewer_agent is not None:
            report["agent"]["strategy"].append("reviewer_guided_fill_revision")
        return report

    def build_review_prompt_bundle(
        self,
        task: str,
        case: dict[str, Any],
        *,
        case_path: Path | None = None,
        report: dict[str, Any],
        fill_report_path: str = "",
        work_dir: Path | None = None,
        inline_payload: bool = False,
    ) -> dict[str, str]:
        case_id = str(report.get("case_id") or case.get("id", "")).strip()
        review_payload = _build_compact_review_payload(
            task,
            case,
            report,
            base_dir=self.base_dir,
        )
        review_payload_path = ""
        if not inline_payload:
            review_payload_path = str(
                _write_review_payload_snapshot(
                    self.base_dir,
                    task,
                    case_id,
                    review_payload,
                    work_dir=work_dir,
                ).resolve()
            )
        user_prompt = _render_verify_curator_prompt(
            task=task,
            case_id=case_id,
            review_payload=review_payload,
            review_payload_path=review_payload_path,
        )
        system_prompt = ""
        combined_prompt = f"{system_prompt.strip()}\n\n{user_prompt.strip()}\n"
        return {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "combined_prompt": combined_prompt,
            "review_payload_path": review_payload_path,
        }

    def _run_fill_prompt(
        self,
        task: str,
        case: dict[str, Any],
        *,
        case_path: Path | None,
        report: dict[str, Any],
    ) -> dict[str, Any]:
        if self.curator_agent is None:
            return {}

        prompt_bundle = self._build_curator_prompt_bundle_core(
            task,
            case,
            case_path=case_path,
            report=_strip_deprecated_block_fields(report),
        )
        curator_model = str(getattr(self.curator_agent, "model", "")).strip()
        direct_project_api = _uses_project_llm_direct_api(curator_model)
        session_log_path = ""
        try:
            task_type = _task_type_for_name(task)
            case_id = str(report.get("case_id") or case.get("id", "")).strip()
            can_stage_fill_workspace = hasattr(self.curator_agent, "_root_dir") and hasattr(
                self.curator_agent, "get_case_workspace"
            )
            work_dir = None
            if can_stage_fill_workspace:
                work_dir = prepare_workspace(
                    self.curator_agent,
                    task_type,
                    case_id=case_id,
                    case_input_text="",
                )
                # _build_curator_prompt_bundle_core writes CASE_INPUT.txt when work_dir is set
                prompt_bundle = self._build_curator_prompt_bundle_core(
                    task,
                    case,
                    case_path=case_path,
                    report=_strip_deprecated_block_fields(report),
                    work_dir=work_dir,
                )
            else:
                prompt_bundle = self._build_curator_prompt_bundle_core(
                    task,
                    case,
                    case_path=case_path,
                    report=_strip_deprecated_block_fields(report),
                    work_dir=None,
                )
            if direct_project_api:
                if work_dir is None:
                    raise ValueError("direct API requires workspace-capable curator agent")
                session_log = work_dir / f"_{task_type.value}_fill_api_session.log"
                raw_output = _run_project_llm_chat_completion(
                    self.base_dir,
                    model=curator_model,
                    system_prompt=prompt_bundle["system_prompt"],
                    user_prompt=prompt_bundle["user_prompt"],
                    session_log_path=session_log,
                )
                session_log_path = str(session_log)
            elif work_dir is not None:
                raw_output, session_log_path = run_prompt(
                    self.curator_agent,
                    prompt_bundle["combined_prompt"],
                    task_type=task_type,
                    schema_text=CURATOR_SCHEMA,
                    work_dir=work_dir,
                    exec_cwd=work_dir,
                )
            else:
                raw_output, session_log_path = run_prompt(
                    self.curator_agent,
                    prompt_bundle["combined_prompt"],
                    task_type=task_type,
                    schema_text=CURATOR_SCHEMA,
                )
        except Exception as exc:
            failure = {
                "summary": f"fill execution failed: {exc}",
                "proposed_case": deepcopy(report.get("suggested_manual_case", case)),
                "recommended_changes": [],
                "summary": [],
                "remaining_unknowns": [f"fill execution failed: {exc}"],
                "_session_log_path": session_log_path,
                "_raw_output": "",
            }
            if direct_project_api:
                failure["_curator_family"] = "project_api"
                failure["_curator_model"] = curator_model
            return failure

        try:
            payload = _normalize_fill_payload(task, _parse_json_object(raw_output), current_case=report.get("suggested_review_case", case))
        except Exception as exc:
            failure = {
                "summary": f"fill execution failed: {exc}",
                "proposed_case": deepcopy(report.get("suggested_manual_case", case)),
                "recommended_changes": [],
                "summary": [],
                "remaining_unknowns": [f"fill execution failed: {exc}"],
                "_session_log_path": session_log_path,
                "_raw_output": raw_output,
            }
            if direct_project_api:
                failure["_curator_family"] = "project_api"
                failure["_curator_model"] = curator_model
            return failure

        payload["_session_log_path"] = session_log_path
        payload["_raw_output"] = raw_output
        if direct_project_api:
            payload["_curator_family"] = "project_api"
            payload["_curator_model"] = curator_model
        return payload

    def _apply_initial_fill_feedback(
        self,
        task: str,
        case: dict[str, Any],
        *,
        case_path: Path | None,
        report: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if self.curator_agent is None:
            return report, {}

        fill_payload = self._run_fill_prompt(
            task,
            case,
            case_path=case_path,
            report=report,
        )
        current_report = deepcopy(report)
        task_name = str(task).strip().lower()
        updated_review_case = deepcopy(current_report.get("suggested_review_case", case))
        if not isinstance(updated_review_case, dict):
            updated_review_case = deepcopy(case)

        allowed_taxonomy_paths = set(_fill_taxonomy_paths_for_task(task_name))
        applied_paths: list[str] = []
        for item in fill_payload.get("recommended_changes", []):
            if not isinstance(item, dict):
                continue
            path = str(item.get("path", "")).strip()
            if not path or not _is_task_fill_mutable_path(task_name, path):
                continue
            parsed_value = _parse_json_literal_text(item.get("value", ""))
            if path in allowed_taxonomy_paths:
                value = _canonical_detect_taxonomy_label(parsed_value)
                if not value:
                    continue
            else:
                value = parsed_value
                if _is_missing(value):
                    continue
            _set_nested_value(updated_review_case, path, deepcopy(value))
            applied_paths.append(path)

        taxonomy_changes: dict[str, Any] = {}
        if task_name == "benchmark_case":
            original_type = str(updated_review_case.get("type", "")).strip()
            normalized_type = _canonical_detect_taxonomy_label(original_type)
            if normalized_type and normalized_type != original_type:
                updated_review_case["type"] = normalized_type
                taxonomy_changes["type"] = normalized_type
        else:
            _normalize_detect_taxonomy_fields(updated_review_case, taxonomy_changes)
        applied_paths.extend(taxonomy_changes.keys())
        applied_paths = _dedupe_keep_order(applied_paths)

        updated_review_case.pop("annotation_hints", None)
        normalized_manual_case = normalize_task_case(task_name, updated_review_case)
        refreshed_review_case = attach_annotation_hints(
            task_name,
            deepcopy(normalized_manual_case),
            raw_case=case,
        )
        recomputed_changed_fields = _filter_changed_fields_for_task(
            task_name,
            _recompute_changed_fields(
                case,
                normalized_manual_case,
                list(dict(report.get("changed_fields", {}) or {})) + applied_paths,
            ),
        )

        revised_report = dict(current_report)
        revised_report["changed_fields"] = recomputed_changed_fields
        revised_report["suggested_review_case"] = refreshed_review_case
        revised_report["suggested_manual_case"] = normalized_manual_case
        revised_report["remaining_annotation_hints"] = _remaining_missing_annotation_hints(
            normalized_manual_case
        )
        evidence = dict(revised_report.get("evidence", {}) or {})
        status = "applied" if applied_paths else "no_change"
        summary = str(fill_payload.get("summary", "")).strip()
        if not applied_paths and summary.startswith("fill execution failed:"):
            status = "failed"
        evidence["curator_taxonomy_judgment"] = {
            "status": status,
            "summary": summary,
            "applied_paths": applied_paths,
            "summary": fill_payload.get("summary", []),
            "remaining_unknowns": fill_payload.get("remaining_unknowns", []),
            "session_log_path": str(fill_payload.get("_session_log_path", "")).strip(),
            "raw_output_preview": _compact_text_preview(
                str(fill_payload.get("_raw_output", "")).strip()
            ),
            "curator_agent": {
                "model": str(fill_payload.get("_curator_model", "")).strip()
                or str(getattr(self.curator_agent, "model", "")).strip(),
                "family": str(fill_payload.get("_curator_family", "")).strip()
                or str(getattr(self.curator_agent, "cli_family", "")).strip()
                or str(type(self.curator_agent).__name__),
            },
        }
        revised_report["evidence"] = evidence
        if task_name == "benchmark_case":
            revised_report = _sync_benchmark_case_determinations(
                revised_report,
                fallback_source="curator_analysis",
            )
        return revised_report, evidence["curator_taxonomy_judgment"]

    def build_curator_revision_prompt_bundle(
        self,
        task: str,
        case: dict[str, Any],
        *,
        case_path: Path | None = None,
        report: dict[str, Any],
        review_payload: dict[str, Any],
    ) -> dict[str, str]:
        case_id = str(report.get("case_id") or case.get("id", "")).strip()
        reviewer_feedback = {
            "reason": str(review_payload.get("reason", "")).strip(),
            "issues": review_payload.get("issues", []),
        }
        prompt_review_case = _strip_deprecated_block_fields(
            _compact_prompt_payload(_absolutize_prompt_payload(self.base_dir, case))
        )
        prompt_manual_case = _strip_deprecated_block_fields(
            _compact_prompt_payload(
                _absolutize_prompt_payload(self.base_dir, report.get("suggested_manual_case", {}))
            )
        )
        prompt_case_path = _maybe_absolutize_prompt_path(
            self.base_dir,
            (
                str(case_path)
                if case_path is not None and Path(case_path).exists()
                else str(report.get("review_case_path", "")).strip()
            ),
            require_exists=True,
        )
        prompt_manual_case_path = _maybe_absolutize_prompt_path(
            self.base_dir,
            str(report.get("manual_case_path", "")).strip(),
        )
        prompt_report = dict(report)
        prompt_report["changed_fields"] = _compact_changed_fields_for_prompt(
            self.base_dir,
            report.get("changed_fields", {}),
        )
        prompt_report["suggested_manual_case"] = prompt_manual_case

        # Build dynamic tool guide with actual case values
        from agents.task_agent.cli_workspace import render_fill_tool_guide
        tool_context = _extract_fill_tool_context(case, report)
        tool_guide = render_fill_tool_guide(**tool_context)

        user_prompt = _render_curator_revision_prompt(
            task=task,
            case_id=case_id,
            review_case_payload=prompt_review_case,
            manual_case_payload=prompt_manual_case,
            report=prompt_report,
            reviewer_feedback=reviewer_feedback,
            case_path=str(prompt_case_path).strip(),
            manual_case_path=str(prompt_manual_case_path).strip(),
            tool_guide=tool_guide,
        )
        system_prompt = ""
        combined_prompt = f"{system_prompt.strip()}\n\n{user_prompt.strip()}\n"
        return {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "combined_prompt": combined_prompt,
        }

    def _run_fill_revision_prompt(
        self,
        task: str,
        case: dict[str, Any],
        *,
        case_path: Path | None,
        report: dict[str, Any],
        review_payload: dict[str, Any],
    ) -> dict[str, Any]:
        if self.curator_agent is None:
            return {}

        prompt_bundle = self.build_curator_revision_prompt_bundle(
            task,
            case,
            case_path=case_path,
            report=report,
            review_payload=review_payload,
        )
        curator_model = str(getattr(self.curator_agent, "model", "")).strip()
        direct_project_api = _uses_project_llm_direct_api(curator_model)
        session_log_path = ""
        try:
            if direct_project_api:
                task_type = _task_type_for_name(task)
                case_id = str(report.get("case_id") or case.get("id", "")).strip()
                work_dir = prepare_workspace(
                    self.curator_agent,
                    task_type,
                    case_id=case_id,
                    case_input_text=prompt_bundle["user_prompt"],
                )
                session_log = work_dir / f"_{task_type.value}_fill_revision_api_session.log"
                raw_output = _run_project_llm_chat_completion(
                    self.base_dir,
                    model=curator_model,
                    system_prompt=prompt_bundle["system_prompt"],
                    user_prompt=prompt_bundle["user_prompt"],
                    session_log_path=session_log,
                )
                session_log_path = str(session_log)
            else:
                raw_output, session_log_path = run_prompt(
                    self.curator_agent,
                    prompt_bundle["combined_prompt"],
                    task_type=_task_type_for_name(task),
                    schema_text=CURATOR_SCHEMA,
                )
        except Exception as exc:
            failure = {
                "summary": f"fill revision execution failed: {exc}",
                "proposed_case": deepcopy(report.get("suggested_manual_case", case)),
                "recommended_changes": [],
                "summary": [],
                "remaining_unknowns": [f"fill revision execution failed: {exc}"],
                "_session_log_path": session_log_path,
                "_raw_output": "",
            }
            if direct_project_api:
                failure["_curator_family"] = "project_api"
                failure["_curator_model"] = curator_model
            return failure

        try:
            payload = _normalize_fill_payload(task, _parse_json_object(raw_output), current_case=report.get("suggested_review_case", case))
        except Exception as exc:
            failure = {
                "summary": f"fill revision execution failed: {exc}",
                "proposed_case": deepcopy(report.get("suggested_manual_case", case)),
                "recommended_changes": [],
                "summary": [],
                "remaining_unknowns": [f"fill revision execution failed: {exc}"],
                "_session_log_path": session_log_path,
                "_raw_output": raw_output,
            }
            if direct_project_api:
                failure["_curator_family"] = "project_api"
                failure["_curator_model"] = curator_model
            return failure

        payload["_session_log_path"] = session_log_path
        payload["_raw_output"] = raw_output
        if direct_project_api:
            payload["_curator_family"] = "project_api"
            payload["_curator_model"] = curator_model
        return payload

    def _apply_fill_revision_feedback(
        self,
        task: str,
        case: dict[str, Any],
        *,
        case_path: Path | None,
        report: dict[str, Any],
        review_payload: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        revise_issue_paths = _issue_paths_for_actions(
            dict(report.get("changed_fields", {}) or {}),
            review_payload,
            actions={"revise"},
        )
        if not revise_issue_paths or self.curator_agent is None:
            return report, {}

        revision_payload = self._run_fill_revision_prompt(
            task,
            case,
            case_path=case_path,
            report=report,
            review_payload=review_payload,
        )
        current_report = deepcopy(report)
        updated_review_case = deepcopy(current_report.get("suggested_review_case", case))
        if not isinstance(updated_review_case, dict):
            updated_review_case = deepcopy(case)

        task_name = str(task).strip().lower()
        allowed_taxonomy_paths = set(_fill_taxonomy_paths_for_task(task_name))
        applied_paths: list[str] = []
        for item in revision_payload.get("recommended_changes", []):
            if not isinstance(item, dict):
                continue
            path = str(item.get("path", "")).strip()
            if (
                not path
                or not _path_within_revision_scope(path, revise_issue_paths)
                or not _is_task_fill_mutable_path(task, path)
            ):
                continue
            raw_value = item.get("value")
            if path in allowed_taxonomy_paths:
                value = _canonical_detect_taxonomy_label(raw_value)
                if not value:
                    continue
            else:
                value = raw_value
                if _is_missing(value):
                    continue
            _set_nested_value(updated_review_case, path, deepcopy(value))
            applied_paths.append(path)

        revision_meta = {
            "status": "applied" if applied_paths else "no_change",
            "summary": str(revision_payload.get("summary", "")).strip(),
            "applied_paths": _dedupe_keep_order(applied_paths),
            "addressed_issue_paths": _addressed_issue_paths(revise_issue_paths, applied_paths),
            "summary": revision_payload.get("summary", []),
            "remaining_unknowns": revision_payload.get("remaining_unknowns", []),
            "session_log_path": str(revision_payload.get("_session_log_path", "")).strip(),
            "raw_output_preview": _compact_text_preview(
                str(revision_payload.get("_raw_output", "")).strip()
            ),
            "curator_agent": {
                "model": str(revision_payload.get("_curator_model", "")).strip()
                or str(getattr(self.curator_agent, "model", "")).strip(),
                "family": str(revision_payload.get("_curator_family", "")).strip()
                or str(getattr(self.curator_agent, "cli_family", "")).strip()
                or str(type(self.curator_agent).__name__),
            },
        }
        if not applied_paths:
            return report, revision_meta

        task_name = str(task).strip().lower()
        updated_review_case.pop("annotation_hints", None)
        normalized_manual_case = normalize_task_case(task_name, updated_review_case)
        refreshed_review_case = attach_annotation_hints(
            task_name,
            deepcopy(normalized_manual_case),
            raw_case=case,
        )
        recomputed_changed_fields = _filter_changed_fields_for_task(
            task_name,
            _recompute_changed_fields(
                case,
                normalized_manual_case,
                list(dict(report.get("changed_fields", {}) or {})) + applied_paths,
            ),
        )

        revised_report = dict(current_report)
        revised_report["changed_fields"] = recomputed_changed_fields
        revised_report["suggested_review_case"] = refreshed_review_case
        revised_report["suggested_manual_case"] = normalized_manual_case
        revised_report["remaining_annotation_hints"] = _remaining_missing_annotation_hints(
            normalized_manual_case
        )
        evidence = dict(revised_report.get("evidence", {}) or {})
        evidence["fill_revision_feedback"] = {
            "review_reason": str(review_payload.get("reason", "")).strip(),
            "issue_paths": revise_issue_paths,
            "applied_paths": _dedupe_keep_order(applied_paths),
            "summary": revision_meta["summary"],
            "summary": revision_meta["summary"],
            "remaining_unknowns": revision_meta["remaining_unknowns"],
        }
        revised_report["evidence"] = evidence
        return revised_report, revision_meta

    def _run_review_prompt(
        self,
        task: str,
        case: dict[str, Any],
        *,
        case_path: Path | None,
        report: dict[str, Any],
    ) -> dict[str, Any]:
        if self.reviewer_agent is None:
            return {}

        task_type = _task_type_for_name(task)
        case_id = str(report.get("case_id") or case.get("id", "")).strip()
        reviewer_model = str(getattr(self.reviewer_agent, "model", "")).strip()
        direct_project_api = _uses_project_llm_direct_api(reviewer_model)
        can_stage_review_file = (
            not direct_project_api
            and hasattr(self.reviewer_agent, "_root_dir")
            and hasattr(self.reviewer_agent, "get_case_workspace")
        )
        work_dir = None
        if direct_project_api or can_stage_review_file:
            work_dir = prepare_workspace(
                self.reviewer_agent,
                task_type,
                case_id=case_id,
                case_input_text="",
            )
        prompt_bundle = self.build_review_prompt_bundle(
            task,
            case,
            case_path=case_path,
            report=report,
            work_dir=work_dir,
            inline_payload=direct_project_api or not can_stage_review_file,
        )
        if direct_project_api and work_dir is not None:
            (work_dir / "CASE_INPUT.txt").write_text(
                prompt_bundle["user_prompt"].strip() + "\n",
            )
        session_log_path = ""
        try:
            if direct_project_api and work_dir is not None:
                session_log = work_dir / f"_{task_type.value}_api_session.log"
                raw_output = _run_project_llm_chat_completion(
                    self.base_dir,
                    model=reviewer_model,
                    system_prompt=prompt_bundle["system_prompt"],
                    user_prompt=prompt_bundle["user_prompt"],
                    session_log_path=session_log,
                )
                session_log_path = str(session_log)
            elif can_stage_review_file and work_dir is not None:
                raw_output, session_log_path = run_prompt(
                    self.reviewer_agent,
                    prompt_bundle["combined_prompt"],
                    task_type=task_type,
                    schema_text=FILL_REVIEWER_SCHEMA,
                    work_dir=work_dir,
                    exec_cwd=work_dir,
                )
            else:
                raw_output, session_log_path = run_prompt(
                    self.reviewer_agent,
                    prompt_bundle["combined_prompt"],
                    task_type=task_type,
                    schema_text=FILL_REVIEWER_SCHEMA,
                )
        except Exception as exc:
            failure = {
                "reason": f"review execution failed: {exc}",
                "verdict": "reject",
                "issues": [
                    {
                        "path": "review",
                        "message": f"review execution failed: {exc}",
                        "action": "needs_human",
                    }
                ],
                "_session_log_path": session_log_path,
                "_raw_output": "",
            }
            if direct_project_api:
                failure["_reviewer_family"] = "project_api"
                failure["_reviewer_model"] = reviewer_model
            return failure
        try:
            payload = _normalize_review_payload(_parse_json_object(raw_output))
        except Exception as exc:
            failure = {
                "reason": f"review execution failed: {exc}",
                "verdict": "reject",
                "issues": [
                    {
                        "path": "review",
                        "message": f"review execution failed: {exc}",
                        "action": "needs_human",
                    }
                ],
                "_session_log_path": session_log_path,
                "_raw_output": raw_output,
            }
            if direct_project_api:
                failure["_reviewer_family"] = "project_api"
                failure["_reviewer_model"] = reviewer_model
            return failure
        payload["_session_log_path"] = session_log_path
        payload["_raw_output"] = raw_output
        if direct_project_api:
            payload["_reviewer_family"] = "project_api"
            payload["_reviewer_model"] = reviewer_model
        return payload

    def _review_report_until_consensus(
        self,
        task: str,
        case: dict[str, Any],
        *,
        case_path: Path | None,
        base_report: dict[str, Any],
    ) -> dict[str, Any]:
        current_report = deepcopy(base_report)
        history: list[dict[str, Any]] = []

        for round_index in range(1, self.review_max_rounds + 1):
            try:
                review_payload = self._run_review_prompt(
                    task,
                    case,
                    case_path=case_path,
                    report=_strip_deprecated_block_fields(current_report),
                )
            except Exception as exc:
                review_payload = {
                    "reason": f"review execution failed: {exc}",
                    "verdict": "reject",
                    "issues": [
                        {
                            "path": "review",
                            "message": f"review execution failed: {exc}",
                            "action": "needs_human",
                        }
                    ],
                    "_session_log_path": "",
                    "_raw_output": "",
                }

            review_payload = _enforce_reviewer_missing_hint_gate(current_report, review_payload)
            review_payload = _filter_review_payload_scope(task, review_payload)

            round_entry = {
                "round": round_index,
                "reason": str(
                    review_payload.get("reason", review_payload.get("summary", ""))
                ).strip(),
                "verdict": str(review_payload.get("verdict", "")).strip(),
                "issues": review_payload.get("issues", []),
                "session_log_path": str(review_payload.get("_session_log_path", "")).strip(),
                "raw_output_preview": _compact_text_preview(
                    str(review_payload.get("_raw_output", "")).strip()
                ),
            }
            history.append(round_entry)

            if str(review_payload.get("verdict", "")).strip().lower() == "accept":
                reviewed_report = dict(current_report)
                reviewed_report["review"] = {
                    "enabled": True,
                    "status": "accepted",
                    "rounds": round_index,
                    "reviewer_agent": {
                        "model": str(review_payload.get("_reviewer_model", "")).strip()
                        or str(getattr(self.reviewer_agent, "model", "")).strip(),
                        "family": str(review_payload.get("_reviewer_family", "")).strip()
                        or str(getattr(self.reviewer_agent, "cli_family", "")).strip()
                        or str(type(self.reviewer_agent).__name__),
                    },
                    "history": history,
                }
                return reviewed_report

            issue_actions = {
                str(item.get("action", "")).strip().lower()
                for item in review_payload.get("issues", [])
                if isinstance(item, dict)
            }
            if issue_actions and issue_actions <= {"needs_human"}:
                break

            revise_issue_paths = _issue_paths_for_actions(
                dict(current_report.get("changed_fields", {}) or {}),
                review_payload,
                actions={"revise"},
            )
            addressed_issue_paths: list[str] = []
            if revise_issue_paths and self.curator_agent is not None:
                current_report, revision_meta = self._apply_fill_revision_feedback(
                    task,
                    case,
                    case_path=case_path,
                    report=current_report,
                    review_payload=review_payload,
                )
                round_entry["revision"] = revision_meta
                if isinstance(revision_meta, dict):
                    addressed_issue_paths = _dedupe_keep_order(
                        list(revision_meta.get("addressed_issue_paths", []) or [])
                    )

            rejected_paths = _prunable_issue_paths(
                dict(current_report.get("changed_fields", {}) or {}),
                review_payload,
            )
            if addressed_issue_paths:
                rejected_paths = [
                    issue_path
                    for issue_path in rejected_paths
                    if issue_path not in set(addressed_issue_paths)
                ]
            if rejected_paths:
                current_report = _prune_report_with_review_feedback(
                    task,
                    case,
                    current_report,
                    rejected_paths,
                )

            if round_index >= self.review_max_rounds:
                break

            # Reviewer feedback either triggered a curator-side revision or pruned unsupported fields.
            # The revised proposal is reviewed again on the next round.
            continue

        reviewed_report = dict(current_report)
        last_round = history[-1] if history and isinstance(history[-1], dict) else {}
        unresolved_issues = (
            last_round.get("issues", [])
            if isinstance(last_round, dict) and isinstance(last_round.get("issues", []), list)
            else []
        )
        reviewed_report["review"] = {
            "enabled": True,
            "status": "needs_review",
            "rounds": len(history),
            "consensus_failure": True,
            "disagreement_detected": _review_disagreement_detected(history),
            "unresolved_issues": unresolved_issues,
            "reviewer_agent": {
                "model": str(getattr(self.reviewer_agent, "model", "")).strip(),
                "family": str(getattr(self.reviewer_agent, "cli_family", "")).strip()
                or str(type(self.reviewer_agent).__name__),
            },
            "history": history,
        }
        return reviewed_report

    def build_prompt_bundle(
        self,
        task: str,
        case: dict[str, Any],
        *,
        case_path: Path | None = None,
        report: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        return self._build_curator_prompt_bundle_core(
            task,
            case,
            case_path=case_path,
            report=report,
            work_dir=None,
        )

    def _build_curator_prompt_bundle_core(
        self,
        task: str,
        case: dict[str, Any],
        *,
        case_path: Path | None = None,
        report: dict[str, Any] | None = None,
        work_dir: Path | None = None,
    ) -> dict[str, str]:
        from agents.task_agent.cli_workspace import render_fill_tool_guide

        current_report = (
            report if report is not None else self.build_report(task, case, case_path=case_path)
        )
        case_id = str(current_report.get("case_id") or case.get("id", "")).strip()
        staged_case = _stage_fill_workspace_inputs(self.base_dir, case, work_dir)
        prompt_review_case = _strip_deprecated_block_fields(
            _compact_prompt_payload(staged_case)
        )
        prompt_manual_case = _strip_deprecated_block_fields(
            _compact_prompt_payload(
                _absolutize_prompt_payload(
                    self.base_dir, current_report.get("suggested_manual_case", {})
                )
            )
        )
        prompt_report = dict(current_report)
        prompt_report["changed_fields"] = _compact_changed_fields_for_prompt(
            self.base_dir,
            current_report.get("changed_fields", {}),
        )
        prompt_report["evidence"] = _compact_fill_evidence_for_prompt(
            self.base_dir,
            current_report.get("evidence", {}),
        )
        prompt_report["suggested_manual_case"] = prompt_manual_case

        # Build dynamic tool guide with actual case values
        tool_context = _extract_fill_tool_context(staged_case, current_report)
        tool_guide = render_fill_tool_guide(**tool_context)

        # Build CASE_INPUT.txt content with structured case data
        compact_materials = _compact_fill_evidence_for_prompt(
            self.base_dir, current_report.get("evidence", {})
        )
        case_input_text = _render_fill_case_input_text(
            case_id=case_id,
            review_case_payload=prompt_review_case,
            manual_case_payload=prompt_manual_case,
            case_materials=compact_materials,
        )

        # Write CASE_INPUT.txt to workspace if available
        if work_dir is not None:
            (work_dir / "CASE_INPUT.txt").write_text(
                case_input_text.strip() + "\n", encoding="utf-8"
            )

        user_prompt = _render_curator_prompt(
            task=task,
            case_id=case_id,
            review_case_payload=prompt_review_case,
            manual_case_payload=prompt_manual_case,
            report=prompt_report,
            tool_guide=tool_guide,
        )
        system_prompt = ""
        combined_prompt = f"{system_prompt.strip()}\n\n{user_prompt.strip()}\n"
        return {
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "combined_prompt": combined_prompt,
            "case_input_text": case_input_text,
        }

    def build_reason_text(
        self,
        task: str,
        case: dict[str, Any],
        *,
        case_path: Path | None = None,
        report: dict[str, Any] | None = None,
    ) -> str:
        current_report = (
            report if report is not None else self.build_report(task, case, case_path=case_path)
        )
        case_id = str(current_report.get("case_id") or case.get("id", "")).strip() or "(unknown)"
        manual_case_path = (
            str(current_report.get("manual_case_path", "")).strip() or "(manual case not found)"
        )
        review_case_path = (
            str(current_report.get("review_case_path", "")).strip() or "(not provided)"
        )
        changed_fields = current_report.get("changed_fields", {})
        evidence = current_report.get("evidence", {})
        remaining = current_report.get("remaining_annotation_hints", {})

        lines = [
            f"# Fill rationale for {case_id}",
            "",
            "## Summary",
            "",
            f"- Task: {task}",
            f"- Status: {_report_status(current_report)}",
            f"- Changed fields: {len(changed_fields) if isinstance(changed_fields, dict) else 0}",
            f"- Remaining hints: {len(remaining) if isinstance(remaining, dict) else 0}",
            "",
        ]

        review_meta = current_report.get("review", {})
        if isinstance(review_meta, dict) and review_meta:
            lines.append(
                f"- Review verdict: {str(review_meta.get('status', '')).strip() or '(unknown)'}"
            )
            lines.append(f"- Review rounds: {int(review_meta.get('rounds', 0) or 0)}")
            lines.append("")

        if isinstance(changed_fields, dict) and changed_fields:
            lines.append("## Applied changes")
            lines.append("")
            for path in sorted(changed_fields):
                value = changed_fields[path]
                reason = self._summarize_field_reason(path, evidence)
                lines.append(f"- `{path}` -> `{self._compact_value(value)}`")
                lines.append(f"  Reason: {reason}")
            lines.append("")
        else:
            lines.extend(
                [
                    "## Applied changes",
                    "",
                    "- No missing field could be improved confidently from the deterministic evidence that was available.",
                    "",
                ]
            )

        if isinstance(evidence, dict) and evidence:
            lines.append("## Evidence used")
            lines.append("")
            for key in sorted(evidence):
                lines.append(f"- `{key}`: {self._compact_value(evidence[key], width=180)}")
            lines.append("")

        if isinstance(remaining, dict) and remaining:
            lines.append("## Still unresolved")
            lines.append("")
            for key in sorted(remaining):
                lines.append(f"- `{key}`: {self._compact_value(remaining[key], width=180)}")
            lines.append("")

        if isinstance(review_meta, dict) and review_meta:
            lines.append("## Reviewer verdict")
            lines.append("")
            reviewer_agent = review_meta.get("reviewer_agent", {})
            if isinstance(reviewer_agent, dict):
                reviewer_model = str(reviewer_agent.get("model", "")).strip()
                reviewer_family = str(reviewer_agent.get("family", "")).strip()
                lines.append(
                    f"- Reviewer: {reviewer_family or '(unknown)'} {reviewer_model or ''}".rstrip()
                )
            history = review_meta.get("history", [])
            if bool(review_meta.get("consensus_failure")):
                disagreement = bool(review_meta.get("disagreement_detected"))
                lines.append(
                    "- Consensus failure: yes"
                    + (" (review rounds disagreed)" if disagreement else "")
                )
            if isinstance(history, list) and history:
                last_round = history[-1] if isinstance(history[-1], dict) else {}
                if isinstance(last_round, dict):
                    lines.append(
                        "- Last decision: "
                        + (
                            str(last_round.get("reason", "")).strip()
                            or str(last_round.get("summary", "")).strip()
                            or "(no reviewer summary)"
                        )
                    )
                    issues = last_round.get("issues", [])
                    if isinstance(issues, list) and issues:
                        lines.append("")
                        lines.append("### Reviewer issues")
                        lines.append("")
                        for issue in issues:
                            if not isinstance(issue, dict):
                                continue
                            severity = str(issue.get("severity", "")).strip() or "issue"
                            path = str(issue.get("path", "")).strip() or "(unspecified)"
                            message = str(issue.get("message", "")).strip() or "(no message)"
                            lines.append(f"- [{severity}] `{path}`: {message}")
                        lines.append("")
                    else:
                        lines.append("")
        lines.extend(
            [
                "## Output paths",
                "",
                f"- Review case: {review_case_path}",
                f"- Manual output: {manual_case_path}",
                "",
            ]
        )

        return "\n".join(lines)

    @staticmethod
    def _compact_value(value: Any, *, width: int = 120) -> str:
        text = (
            json.dumps(value, ensure_ascii=False, sort_keys=True)
            if isinstance(value, (dict, list))
            else str(value)
        )
        compact = " ".join(text.split())
        if len(compact) <= width:
            return compact
        return compact[: width - 3] + "..."

    @staticmethod
    def _summarize_field_reason(path: str, evidence: Any) -> str:
        if not isinstance(evidence, dict):
            return "filled from deterministic local review evidence"
        remediation_reasoning = evidence.get("remediation_reasoning")
        if path.startswith("remediation.") and isinstance(remediation_reasoning, dict):
            agent_model = str(remediation_reasoning.get("agent_model", "")).strip()
            proxy_info = remediation_reasoning.get("proxy_info")
            proxy_note = ""
            if isinstance(proxy_info, dict) and proxy_info.get("proxy_detected"):
                proxy_note = " after proxy/implementation inspection"
            if agent_model:
                return f"inferred by the fix reasoning agent ({agent_model}){proxy_note}"
            return f"inferred by the fix reasoning agent{proxy_note}"
        if path.startswith("chain_context.") and "attack_tx_context" in evidence:
            return "derived from historical attack-transaction context"
        if path.startswith("ground_truth.line"):
            return "recovered by mapping the known function name to a local source file"
        if path.startswith("ground_truth.vulnerable") or path.startswith("contracts.vulnerable"):
            if "clara_snapshot" in evidence:
                return "recovered from Clara incident metadata and victim-address evidence"
            return "recovered from case-local vulnerable-address evidence"
        if path.startswith("profit_token.") and "profit_token_candidates" in evidence:
            return "recovered from profit-token candidates inferred from local incident evidence"
        if path.startswith("remediation.") and "attack_tx_context" in evidence:
            return "filled from available remediation lane and attack replay context"
        if "clara_snapshot" in evidence:
            return "recovered from Clara snapshot metadata"
        return "filled from deterministic local review evidence"

    @staticmethod
    def _is_missing(value: Any) -> bool:
        if value is None:
            return True
        if isinstance(value, str):
            return not value.strip()
        if isinstance(value, (list, dict)):
            return len(value) == 0
        return False
