"""Helpers for optional on-chain metadata enrichment and caching."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from csv import DictReader
from html import unescape
from io import StringIO
from pathlib import Path
from typing import Iterable

from project_layout import canonicalize_repo_relative, resolve_repo_path
from project_root import PROJECT_ROOT
from .metadata_constants import (
    CHAIN_RPC_ALIASES,
    CHAIN_RPC_ENV_VARS,
    CHAIN_TRACE_RPC_ENV_VARS,
    DEFAULT_CONTEXT_CACHE,
    DFHL_RECOVERED_SOURCE_ASSET_ROOT,
    DFHL_RECOVERED_SOURCE_ROOT,
    DFHL_VERIFIED_SOURCE_ASSET_ROOT,
    DFHL_VERIFIED_SOURCE_ROOT,
    DUNE_API_BASE,
    DUNE_SCHEMA_BY_CHAIN,
    ERC1967_ADMIN_SLOT,
    ERC1967_BEACON_SLOT,
    ERC1967_IMPLEMENTATION_SLOT,
    ETHERSCAN_V2_BASE,
    EXPLORER_ADDRESS_HOSTS,
    EXPLORER_CHAIN_IDS,
    IMPLEMENTATION_SELECTOR,
)
from .metadata_utils import (
    _clean_optional_text,
    _dedupe_keep_order,
    _extract_minimal_proxy_target,
    _load_metadata,
    _normalize_block_tag,
    _normalize_chain_name,
    _normalize_logs_block_param,
    _normalize_paths,
    _normalize_storage_slot,
    _rpc_error_message,
    _word_to_address,
)

_RPC_ENV_MTIME: float | None = None
_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
_PRAGMA_SOLIDITY_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
_CONTRACT_DECL_RE = re.compile(
    r"^\s*(?:abstract\s+)?(?:contract|library)\s+(\w+)\b",
    flags=re.MULTILINE,
)
_IMPORT_PATH_RE = re.compile(r'import\s+(?:[^"\']+\s+from\s+)?["\']([^"\']+)["\']')


def _infer_compiler_version_from_source_text(source_text: str) -> str:
    match = _PRAGMA_SOLIDITY_RE.search(str(source_text or ""))
    if not match:
        return ""
    return str(match.group(1)).strip()


def _parse_primary_contract_name(source_text: str) -> str:
    match = _CONTRACT_DECL_RE.search(str(source_text or ""))
    if not match:
        return ""
    return str(match.group(1)).strip()


def _match_flat_verified_source_file(root: Path, *, file_hint: str = "", contract_name_hint: str = "") -> Path | None:
    if not root.exists():
        return None
    candidates = sorted(path for path in root.glob("*.sol") if path.is_file())
    if not candidates:
        return None

    file_name = Path(str(file_hint or "")).name
    file_stem = Path(file_name).stem.lower()
    contract_stem = str(contract_name_hint or "").strip().lower()

    scored: list[tuple[int, int, Path]] = []
    for path in candidates:
        name = path.name
        stem = path.stem.lower()
        score = 0
        if file_name and name == file_name:
            score += 100
        if file_name and name.endswith(f"_{file_name}"):
            score += 80
        if file_stem and stem == file_stem:
            score += 60
        if file_stem and stem.endswith(f"_{file_stem}"):
            score += 50
        if contract_stem and (stem == contract_stem or stem.endswith(f"_{contract_stem}")):
            score += 40
        if file_stem and file_stem in stem:
            score += 20
        if contract_stem and contract_stem in stem:
            score += 10
        if score > 0:
            scored.append((score, -len(name), path))

    if scored:
        scored.sort(reverse=True)
        return scored[0][2]
    return None


def _resolve_flat_bundle_local_name(root: Path, import_path: str) -> str:
    file_name = Path(str(import_path or "")).name
    if not file_name:
        return ""
    candidates = [path.name for path in root.glob("*.sol") if path.is_file()]
    exact = [name for name in candidates if name.lower() == file_name.lower()]
    if exact:
        return sorted(exact, key=len)[0]
    suffix = [name for name in candidates if name.lower().endswith(f"_{file_name.lower()}")]
    if suffix:
        return sorted(suffix, key=len)[0]
    stem = Path(file_name).stem.lower()
    stem_matches = [name for name in candidates if Path(name).stem.lower().endswith(f"_{stem}") or Path(name).stem.lower() == stem]
    if stem_matches:
        return sorted(stem_matches, key=len)[0]
    return ""


def _collect_flat_bundle_dependency_files(root: Path, entry: Path) -> list[str]:
    pending = [entry.name]
    seen: set[str] = set()
    ordered: list[str] = []
    while pending:
        local_name = pending.pop()
        lowered = local_name.lower()
        if lowered in seen:
            continue
        source_path = root / local_name
        if not source_path.exists():
            continue
        seen.add(lowered)
        ordered.append(local_name)
        source_text = source_path.read_text(errors="replace")
        for import_path in _IMPORT_PATH_RE.findall(source_text):
            resolved = _resolve_flat_bundle_local_name(root, import_path)
            if resolved and resolved.lower() not in seen:
                pending.append(resolved)
    return sorted(ordered)


def _infer_flat_bundle_source_metadata(
    base_dir: Path,
    *,
    file_hint: str = "",
    contract_name_hint: str = "",
) -> dict:
    root = resolve_repo_path(base_dir.resolve(), DFHL_VERIFIED_SOURCE_ASSET_ROOT)
    target = _match_flat_verified_source_file(
        root,
        file_hint=file_hint,
        contract_name_hint=contract_name_hint,
    )
    if target is None:
        return {}

    source_text = target.read_text(errors="replace")
    compiler_version = _infer_compiler_version_from_source_text(source_text)
    contract_name = _parse_primary_contract_name(source_text) or str(contract_name_hint or "").strip()
    files = _collect_flat_bundle_dependency_files(root, target)
    return {
        "source_origin": "verified_flat_bundle",
        "source_dir": canonicalize_repo_relative(root.relative_to(base_dir.resolve())),
        "files": files,
        "compiler_version": compiler_version,
        "contract_name": contract_name,
        "target_contract_name": contract_name,
    }


def resolve_case_source_metadata(
    case_id: str,
    base_dir: Path,
    *,
    chain: str = "",
    address: str = "",
    file_hint: str = "",
    contract_name_hint: str = "",
    explicit_metadata: dict | None = None,
) -> dict:
    result = dict(explicit_metadata or {})
    result.setdefault("source_origin", str(result.get("source_origin", "")).strip())
    result.setdefault("source_dir", str(result.get("source_dir", "")).strip())
    result.setdefault("compiler_version", str(result.get("compiler_version", "")).strip())
    if not isinstance(result.get("files"), list):
        result["files"] = []
    target_contract_name = str(
        result.get("target_contract_name") or result.get("contract_name") or contract_name_hint or ""
    ).strip()
    if target_contract_name:
        result["target_contract_name"] = target_contract_name
        result.setdefault("contract_name", target_contract_name)

    address_metadata = load_dfhl_source_metadata(
        case_id,
        base_dir,
        chain=chain,
        address=address,
    )
    for key in ("source_origin", "source_dir", "compiler_version", "files"):
        if not result.get(key):
            result[key] = address_metadata.get(key, result.get(key))
    if not result.get("target_contract_name"):
        candidate = str(address_metadata.get("target_contract_name") or address_metadata.get("contract_name") or "").strip()
        if candidate:
            result["target_contract_name"] = candidate
            result["contract_name"] = candidate

    if not result.get("source_dir") or not result.get("compiler_version") or not result.get("files"):
        flat_metadata = _infer_flat_bundle_source_metadata(
            base_dir,
            file_hint=file_hint,
            contract_name_hint=str(result.get("target_contract_name", "")) or contract_name_hint,
        )
        for key in ("source_origin", "source_dir", "compiler_version", "files"):
            if not result.get(key):
                result[key] = flat_metadata.get(key, result.get(key))
        if not result.get("target_contract_name"):
            candidate = str(flat_metadata.get("target_contract_name") or flat_metadata.get("contract_name") or "").strip()
            if candidate:
                result["target_contract_name"] = candidate
                result["contract_name"] = candidate

    return {
        "source_origin": str(result.get("source_origin", "")).strip(),
        "source_dir": str(result.get("source_dir", "")).strip(),
        "compiler_version": str(result.get("compiler_version", "")).strip(),
        "files": [str(item).strip() for item in (result.get("files") or []) if str(item).strip()],
        "contract_name": str(result.get("contract_name", "")).strip() or str(result.get("target_contract_name", "")).strip(),
        "target_contract_name": str(result.get("target_contract_name", "")).strip() or str(result.get("contract_name", "")).strip(),
    }


def _iter_dfhl_source_dir_candidates(
    case_id: str,
    base_dir: Path,
    *,
    chain: str = "",
    address: str = "",
) -> list[tuple[Path, str]]:
    resolved_base = base_dir.resolve()
    normalized_chain = _normalize_chain_name(chain)
    normalized_address = str(address or "").strip().lower()
    candidates: list[tuple[Path, str]] = []
    seen: set[Path] = set()

    if normalized_chain and normalized_address:
        for root, origin in (
            (Path("data/sources/DeFiHackLabs/verified_source_by_address"), "verified_by_address"),
            (DFHL_VERIFIED_SOURCE_ASSET_ROOT, "verified"),
            (DFHL_RECOVERED_SOURCE_ASSET_ROOT, "recovered"),
        ):
            source_dir = resolve_repo_path(
                resolved_base, root / normalized_chain / normalized_address
            )
            if source_dir not in seen:
                seen.add(source_dir)
                candidates.append((source_dir, origin))

    normalized_case_id = str(case_id or "").strip()
    if normalized_case_id:
        for root, origin in (
            (DFHL_VERIFIED_SOURCE_ROOT, "verified"),
            (DFHL_RECOVERED_SOURCE_ROOT, "recovered"),
        ):
            source_dir = resolve_repo_path(resolved_base, root / normalized_case_id)
            if source_dir not in seen:
                seen.add(source_dir)
                candidates.append((source_dir, origin))

    return candidates


def _load_env_file(path: Path, *, override: bool = False) -> bool:
    if not path.exists():
        return False
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if override:
            os.environ[key] = value
        else:
            os.environ.setdefault(key, value)
    return True


def _load_local_rpc_defaults() -> None:
    global _RPC_ENV_MTIME
    root = PROJECT_ROOT
    env_path = root / ".env"

    # Re-read when .env is modified on disk (or on first call).
    try:
        current_mtime = env_path.stat().st_mtime if env_path.exists() else 0.0
    except OSError:
        current_mtime = 0.0
    if _RPC_ENV_MTIME is not None and current_mtime == _RPC_ENV_MTIME:
        return
    _RPC_ENV_MTIME = current_mtime

    # .env is authoritative — override existing env vars so edits take effect.
    _load_env_file(env_path, override=True)
    # .env.rpc / public fallback only fills in gaps.
    _load_env_file(root / ".env.rpc") or _load_env_file(
        root / "configs" / "rpc_endpoints.public.env"
    )


def _load_etherscan_api_keys() -> list[str]:
    _load_env_file(PROJECT_ROOT / ".env")
    multi = os.environ.get("ETHERSCAN_API_KEYS", "").strip()
    if multi:
        return [item.strip() for item in multi.split(",") if item.strip()]
    single = os.environ.get("ETHERSCAN_API_KEY", "").strip()
    return [single] if single else []


def _load_dune_api_key() -> str:
    _load_env_file(PROJECT_ROOT / ".env")
    return os.environ.get("DUNE_API_KEY", "").strip()


def _dune_headers(
    api_key: str,
    *,
    content_type: str | None = "application/json",
) -> dict[str, str]:
    headers = {
        "User-Agent": "Web3Bug-Benchmark/0.1",
        "X-DUNE-API-KEY": api_key,
    }
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def _dune_post_json(
    url: str,
    payload: dict[str, object],
    headers: dict[str, str],
    *,
    timeout: int = 60,
) -> dict[str, object]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8", errors="replace")
    data = json.loads(raw)
    return data if isinstance(data, dict) else {}


def _dune_get_json(
    url: str,
    headers: dict[str, str],
    *,
    timeout: int = 60,
) -> dict[str, object]:
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8", errors="replace")
    data = json.loads(raw)
    return data if isinstance(data, dict) else {}


def _dune_get_text(
    url: str,
    headers: dict[str, str],
    *,
    timeout: int = 120,
) -> str:
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def _dune_wait_for_execution(
    api_key: str,
    execution_id: str,
    *,
    timeout_s: int = 180,
    poll_interval_s: float = 4.0,
) -> dict[str, object]:
    deadline = time.time() + max(1, int(timeout_s))
    status_url = f"{DUNE_API_BASE}/execution/{execution_id}/status"
    last_status: dict[str, object] = {}
    while time.time() < deadline:
        try:
            status = _dune_get_json(
                status_url,
                _dune_headers(api_key, content_type=None),
            )
        except urllib.error.HTTPError as exc:
            if int(getattr(exc, "code", 0)) == 429:
                time.sleep(max(5.0, float(poll_interval_s) * 2.0))
                continue
            raise
        last_status = status if isinstance(status, dict) else {}
        if bool(last_status.get("is_execution_finished")):
            state = str(last_status.get("state", "")).strip()
            if state not in {"QUERY_STATE_COMPLETED", "QUERY_STATE_COMPLETED_PARTIAL"}:
                raise RuntimeError(f"Dune execution failed: {last_status}")
            return last_status
        time.sleep(max(0.5, float(poll_interval_s)))
    raise RuntimeError(f"Dune execution timed out: {last_status}")


def _parse_csv_rows(csv_text: str) -> list[dict[str, str]]:
    return [
        {str(key): str(value) for key, value in row.items()}
        for row in DictReader(StringIO(csv_text))
    ]


def _dune_varbinary_literal(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized.startswith("0x"):
        normalized = normalized[2:]
    return f"from_hex('{normalized}')"


def _render_dune_transaction_trace_sql(chain: str, tx_hash: str) -> str:
    schema = DUNE_SCHEMA_BY_CHAIN[chain]
    return f"""
SELECT
    concat('0x', lower(to_hex(tx_hash))) AS tx_hash,
    lower(cast(call_type AS varchar)) AS call_type,
    concat('0x', lower(to_hex(\"from\"))) AS \"from\",
    CASE
        WHEN \"to\" IS NULL THEN ''
        ELSE concat('0x', lower(to_hex(\"to\")))
    END AS \"to\",
    coalesce(cast(error AS varchar), '') AS error
FROM {schema}.traces
WHERE tx_hash = {_dune_varbinary_literal(tx_hash)}
LIMIT 20
""".strip()


def _lookup_transaction_trace_via_dune(chain: str, tx_hash: str) -> dict[str, object]:
    api_key = _load_dune_api_key()
    result: dict[str, object] = {
        "ok": False,
        "chain": chain,
        "tx_hash": str(tx_hash).strip(),
        "trace_method": "",
        "trace": None,
    }
    if not api_key:
        result["error"] = "DUNE_API_KEY is not configured"
        return result
    if chain not in DUNE_SCHEMA_BY_CHAIN:
        result["error"] = f"unsupported Dune chain: {chain}"
        return result

    sql = _render_dune_transaction_trace_sql(chain, tx_hash)
    try:
        execution = _dune_post_json(
            f"{DUNE_API_BASE}/sql/execute",
            {"sql": sql, "performance": "medium"},
            _dune_headers(api_key),
        )
        execution_id = str(execution.get("execution_id", "")).strip()
        if not execution_id:
            raise RuntimeError(f"Dune execute SQL failed: {execution}")
        _dune_wait_for_execution(api_key, execution_id, timeout_s=180, poll_interval_s=2.0)
        csv_text = _dune_get_text(
            f"{DUNE_API_BASE}/execution/{execution_id}/results/csv?allow_partial_results=true",
            _dune_headers(api_key, content_type=None),
        )
        rows = _parse_csv_rows(csv_text)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
        result["error"] = str(exc)
        return result
    except RuntimeError as exc:
        result["error"] = str(exc)
        return result

    result.update(
        {
            "ok": True,
            "trace_method": "dune_traces",
            "trace": rows,
            "count": len(rows),
            "source": "dune",
        }
    )
    return result


def _render_dune_address_transactions_sql(
    chain: str,
    address: str,
    *,
    startblock: int,
    endblock: int,
    page: int,
    offset: int,
    sort: str,
) -> str:
    schema = DUNE_SCHEMA_BY_CHAIN[chain]
    row_start = ((page - 1) * offset) + 1
    row_end = row_start + offset - 1
    order = "ASC" if sort == "asc" else "DESC"
    return f"""
WITH params AS (
    SELECT
        from_hex(substr('{address.lower()}', 3)) AS target_address,
        CAST({int(startblock)} AS bigint) AS start_block,
        CAST({int(endblock)} AS bigint) AS end_block,
        CAST({int(row_start)} AS bigint) AS row_start,
        CAST({int(row_end)} AS bigint) AS row_end
),
ranked AS (
    SELECT
        concat('0x', lower(to_hex(t.hash))) AS hash,
        CAST(t.block_number AS varchar) AS blockNumber,
        concat('0x', lower(to_hex(t."from"))) AS "from",
        CASE
            WHEN t."to" IS NULL THEN ''
            ELSE concat('0x', lower(to_hex(t."to")))
        END AS "to",
        '0x' AS input,
        CAST(t.value AS varchar) AS value,
        row_number() OVER (
            ORDER BY
                t.block_number {order},
                t.block_time {order},
                t.hash {order}
        ) AS row_num
    FROM {schema}.transactions t
    CROSS JOIN params p
    WHERE
        (t."from" = p.target_address OR t."to" = p.target_address)
        AND t.block_number BETWEEN p.start_block AND p.end_block
)
SELECT hash, blockNumber, "from", "to", input, value
FROM ranked
CROSS JOIN params
WHERE row_num BETWEEN row_start AND row_end
ORDER BY row_num
""".strip()


def _lookup_address_transactions_via_dune(
    chain: str,
    address: str,
    *,
    startblock: int,
    endblock: int,
    page: int,
    offset: int,
    sort: str,
) -> dict[str, object]:
    api_key = _load_dune_api_key()
    result: dict[str, object] = {
        "ok": False,
        "transactions": [],
    }
    if not api_key:
        result["error"] = "DUNE_API_KEY is not configured"
        return result

    schema = DUNE_SCHEMA_BY_CHAIN.get(chain)
    if not schema:
        result["error"] = f"unsupported Dune chain: {chain}"
        return result

    sql = _render_dune_address_transactions_sql(
        chain,
        address,
        startblock=startblock,
        endblock=endblock,
        page=page,
        offset=offset,
        sort=sort,
    )
    try:
        execution = _dune_post_json(
            f"{DUNE_API_BASE}/sql/execute",
            {"sql": sql, "performance": "medium"},
            _dune_headers(api_key),
        )
        execution_id = str(execution.get("execution_id", "")).strip()
        if not execution_id:
            raise RuntimeError(f"Dune execute SQL failed: {execution}")
        status = _dune_wait_for_execution(api_key, execution_id)
        csv_text = _dune_get_text(
            f"{DUNE_API_BASE}/execution/{execution_id}/results/csv?allow_partial_results=true",
            _dune_headers(api_key, content_type=None),
        )
        rows = _parse_csv_rows(csv_text)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
        result["error"] = str(exc)
        return result
    except RuntimeError as exc:
        result["error"] = str(exc)
        return result

    result.update(
        {
            "ok": True,
            "transactions": rows,
            "count": len(rows),
            "source": "dune",
            "dune_execution_status": status,
        }
    )
    return result


def _etherscan_v2_request(params: dict[str, object]) -> tuple[dict | None, str]:
    api_keys = _load_etherscan_api_keys()
    requests = api_keys or [""]
    last_error = "etherscan request failed"

    for api_key in requests:
        query = urllib.parse.urlencode(
            {
                key: value
                for key, value in {
                    **params,
                    "apikey": api_key,
                }.items()
                if value not in (None, "")
            }
        )
        request = urllib.request.Request(
            f"{ETHERSCAN_V2_BASE}?{query}",
            headers={"User-Agent": "Web3Bug-Benchmark/0.1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            last_error = str(exc)
            continue

        if isinstance(data, dict):
            result = data.get("result")
            if isinstance(result, str) and result.strip():
                last_error = result.strip()
            elif isinstance(data.get("message"), str) and data.get("message", "").strip():
                last_error = str(data.get("message", "")).strip()
            return data, last_error

    if not api_keys:
        last_error = "ETHERSCAN_API_KEY or ETHERSCAN_API_KEYS is not configured"
    return None, last_error


def _fetch_explorer_address_code_page(chain: str, address: str) -> str:
    normalized_chain = _normalize_chain_name(chain)
    host = EXPLORER_ADDRESS_HOSTS.get(normalized_chain, "")
    target = str(address).strip()
    if not host or not target:
        return ""

    request = urllib.request.Request(
        f"https://{host}/address/{target}#code",
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": f"https://{host}/",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8", "replace")
    except (OSError, urllib.error.URLError):
        return ""


def _extract_explorer_page_bytecodes(page_html: str) -> dict[str, str]:
    html_text = str(page_html or "")
    if not html_text:
        return {}

    patterns: dict[str, tuple[str, ...]] = {
        "runtime_bytecode": (
            r"Deployed Bytecode[\s\S]{0,4000}?<pre[^>]*>\s*(?:<div[^>]*>)?\s*(0x[0-9a-fA-F]+)",
            r"id=['\"]verifiedbytecode['\"][^>]*>\s*(0x[0-9a-fA-F]+)",
            r"id=['\"]dividcode['\"][\s\S]{0,2000}?<pre[^>]*>\s*(0x[0-9a-fA-F]+)",
        ),
        "creation_bytecode": (
            r"Contract Creation Code[\s\S]{0,4000}?id=['\"]verifiedbytecode2['\"][^>]*>\s*(0x[0-9a-fA-F]+)",
            r"Contract Creation Code[\s\S]{0,4000}?<pre[^>]*>\s*(?:<div[^>]*>)?\s*(0x[0-9a-fA-F]+)",
        ),
    }
    extracted: dict[str, str] = {}
    for key, candidates in patterns.items():
        for pattern in candidates:
            match = re.search(pattern, html_text, re.IGNORECASE)
            if not match:
                continue
            bytecode = unescape(match.group(1)).strip()
            if bytecode.startswith("0x") and len(bytecode) > 2:
                extracted[key] = bytecode
                break
    return extracted


def _lookup_explorer_page_bytecodes(chain: str, address: str) -> dict[str, str]:
    return _extract_explorer_page_bytecodes(_fetch_explorer_address_code_page(chain, address))


def _parse_verified_source_files(
    source_code: str, contract_name: str
) -> tuple[dict[str, str], list[str]]:
    if not source_code:
        return {}, []

    parsed: dict[str, str] = {}
    remappings: list[str] = []
    if source_code.startswith("{{"):
        try:
            json_input = json.loads(source_code[1:-1])
        except json.JSONDecodeError:
            json_input = {}
        sources = json_input.get("sources", {}) if isinstance(json_input, dict) else {}
        if isinstance(sources, dict):
            for filepath, file_data in sources.items():
                if not isinstance(file_data, dict):
                    continue
                content = str(file_data.get("content", ""))
                if content:
                    parsed[str(filepath)] = content
        settings = json_input.get("settings", {}) if isinstance(json_input, dict) else {}
        raw_remappings = settings.get("remappings", []) if isinstance(settings, dict) else []
        if isinstance(raw_remappings, list):
            remappings = [str(r) for r in raw_remappings if str(r).strip()]
    elif source_code.startswith("{"):
        try:
            files = json.loads(source_code)
        except json.JSONDecodeError:
            files = {}
        if isinstance(files, dict):
            for filepath, file_data in files.items():
                if isinstance(file_data, dict):
                    content = str(file_data.get("content", ""))
                else:
                    content = str(file_data)
                if content:
                    parsed[str(filepath)] = content

    if parsed:
        return parsed, remappings

    fallback_name = f"{contract_name or 'Contract'}.sol"
    return {fallback_name: source_code}, remappings


def lookup_verified_source(chain: str, address: str) -> dict[str, object]:
    normalized_chain = _normalize_chain_name(chain)
    target = str(address).strip()
    result: dict[str, object] = {
        "ok": False,
        "chain": normalized_chain,
        "address": target,
        "contract_name": "",
        "compiler_version": "",
        "proxy_implementation": "",
        "source_files": {},
    }
    if not target:
        result["error"] = "address is required"
        return result

    chain_id = EXPLORER_CHAIN_IDS.get(normalized_chain)
    if chain_id is None:
        result["error"] = f"unsupported explorer chain: {normalized_chain}"
        return result

    last_error = "verified source lookup failed"

    while True:
        data, request_error = _etherscan_v2_request(
            {
                "chainid": chain_id,
                "module": "contract",
                "action": "getsourcecode",
                "address": target,
            }
        )
        if not isinstance(data, dict):
            last_error = request_error or last_error
            break
        items = data.get("result") if isinstance(data, dict) else None
        if not isinstance(items, list) or not items:
            last_error = (
                str(data.get("result", last_error)) if isinstance(data, dict) else last_error
            )
            break

        item = items[0] if isinstance(items[0], dict) else {}
        source_code = str(item.get("SourceCode", ""))
        if not source_code:
            last_error = str(item.get("ABI", "") or "contract source code not verified")
            break

        contract_name = str(item.get("ContractName", "")).strip()
        source_files, remappings = _parse_verified_source_files(source_code, contract_name)
        if not source_files:
            last_error = "verified source payload did not contain Solidity files"
            break

        result.update(
            {
                "ok": True,
                "contract_name": contract_name,
                "compiler_version": str(item.get("CompilerVersion", "")).strip(),
                "optimization_used": bool(int(item.get("OptimizationUsed", "0") or "0")),
                "optimization_runs": int(item.get("Runs", "200") or "200"),
                "evm_version": str(item.get("EVMVersion", "")).strip() or "default",
                "proxy_implementation": str(item.get("Implementation", "")).strip(),
                "source_files": source_files,
                "remappings": remappings,
            }
        )
        return result
    result["error"] = last_error
    return result


def _lookup_explorer_transaction(chain: str, tx_hash: str) -> dict[str, object]:
    normalized_chain = _normalize_chain_name(chain)
    target = str(tx_hash).strip()
    if not target:
        return {}

    chain_id = EXPLORER_CHAIN_IDS.get(normalized_chain)
    if chain_id is None:
        return {}

    data, _ = _etherscan_v2_request(
        {
            "chainid": chain_id,
            "module": "proxy",
            "action": "eth_getTransactionByHash",
            "txhash": target,
        }
    )
    result = data.get("result") if isinstance(data, dict) else None
    return result if isinstance(result, dict) else {}


def lookup_contract_creation(chain: str, address: str) -> dict[str, object]:
    normalized_chain = _normalize_chain_name(chain)
    target = str(address).strip()
    result: dict[str, object] = {
        "ok": False,
        "chain": normalized_chain,
        "address": target,
        "tx_hash": "",
        "contract_creator": "",
        "block_number": None,
        "creation_bytecode": "",
    }
    if not target:
        result["error"] = "address is required"
        return result

    chain_id = EXPLORER_CHAIN_IDS.get(normalized_chain)
    if chain_id is None:
        result["error"] = f"unsupported explorer chain: {normalized_chain}"
        return result

    data, last_error = _etherscan_v2_request(
        {
            "chainid": chain_id,
            "module": "contract",
            "action": "getcontractcreation",
            "contractaddresses": target,
        }
    )
    items = data.get("result") if isinstance(data, dict) else None
    if not isinstance(items, list) or not items or not isinstance(items[0], dict):
        scraped = _lookup_explorer_page_bytecodes(normalized_chain, target)
        creation_bytecode = str(scraped.get("creation_bytecode", "")).strip()
        if creation_bytecode.startswith("0x") and len(creation_bytecode) > 2:
            result.update(
                {
                    "ok": True,
                    "creation_bytecode": creation_bytecode,
                }
            )
            return result
        result["error"] = last_error or "contract creation lookup failed"
        return result

    item = items[0]
    tx_hash = str(item.get("txHash", "")).strip()
    creator = str(item.get("contractCreator", "")).strip()
    raw_block = item.get("blockNumber")
    creation_bytecode = str(item.get("creationBytecode", "")).strip()

    block_number: int | None = None
    if isinstance(raw_block, int):
        block_number = raw_block
    else:
        raw_block_text = str(raw_block or "").strip()
        if raw_block_text.isdigit():
            block_number = int(raw_block_text)
        elif raw_block_text.startswith("0x"):
            try:
                block_number = int(raw_block_text, 16)
            except ValueError:
                block_number = None

    if not creation_bytecode and tx_hash:
        tx = _lookup_explorer_transaction(normalized_chain, tx_hash)
        creation_bytecode = str(tx.get("input", "")).strip()

    if not creation_bytecode:
        scraped = _lookup_explorer_page_bytecodes(normalized_chain, target)
        creation_bytecode = str(scraped.get("creation_bytecode", "")).strip()

    result.update(
        {
            "ok": bool(tx_hash or creation_bytecode),
            "tx_hash": tx_hash,
            "contract_creator": creator,
            "block_number": block_number,
            "creation_bytecode": creation_bytecode if creation_bytecode.startswith("0x") else "",
        }
    )
    if not result["ok"]:
        result["error"] = last_error or "contract creation lookup failed"
    return result


def lookup_address_transactions(
    chain: str,
    address: str,
    *,
    startblock: int = 0,
    endblock: int = 99999999,
    page: int = 1,
    offset: int = 10,
    sort: str = "desc",
) -> dict[str, object]:
    normalized_chain = _normalize_chain_name(chain)
    target = str(address).strip()
    result: dict[str, object] = {
        "ok": False,
        "chain": normalized_chain,
        "address": target,
        "startblock": startblock,
        "endblock": endblock,
        "page": page,
        "offset": offset,
        "sort": sort,
        "transactions": [],
        "source": "",
    }
    if not target:
        result["error"] = "address is required"
        return result

    chain_id = EXPLORER_CHAIN_IDS.get(normalized_chain)
    if chain_id is None:
        result["error"] = f"unsupported explorer chain: {normalized_chain}"
        return result

    startblock = max(int(startblock), 0)
    endblock = max(int(endblock), startblock)
    page = max(int(page), 1)
    offset = max(int(offset), 1)
    sort = str(sort).strip().lower()
    if sort not in {"asc", "desc"}:
        result["error"] = f"unsupported sort order: {sort}"
        return result

    api_keys = _load_etherscan_api_keys()
    requests = api_keys or [""]
    last_error = "address transaction lookup failed"

    for api_key in requests:
        params = (
            f"chainid={chain_id}&module=account&action=txlist"
            f"&address={target}&startblock={startblock}&endblock={endblock}"
            f"&page={page}&offset={offset}&sort={sort}&apikey={api_key}"
        )
        request = urllib.request.Request(
            f"{ETHERSCAN_V2_BASE}?{params}",
            headers={"User-Agent": "Web3Bug-Benchmark/0.1"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            continue

        if not isinstance(data, dict):
            continue

        payload = data.get("result")
        if isinstance(payload, list):
            result["ok"] = True
            result["transactions"] = payload
            result["count"] = len(payload)
            result["source"] = "etherscan"
            return result

        message = str(payload or data.get("message", "") or last_error)
        if "no transactions found" in message.lower():
            result["ok"] = True
            result["transactions"] = []
            result["count"] = 0
            result["source"] = "etherscan"
            return result
        last_error = message

    dune_result = _lookup_address_transactions_via_dune(
        normalized_chain,
        target,
        startblock=startblock,
        endblock=endblock,
        page=page,
        offset=offset,
        sort=sort,
    )
    if dune_result.get("ok"):
        result["ok"] = True
        result["transactions"] = dune_result.get("transactions", [])
        result["count"] = int(dune_result.get("count", 0) or 0)
        result["source"] = "dune"
        return result

    if not api_keys:
        last_error = "ETHERSCAN_API_KEY or ETHERSCAN_API_KEYS is not configured"
    dune_error = str(dune_result.get("error", "")).strip()
    result["error"] = (
        f"{last_error}; dune fallback failed: {dune_error}" if dune_error else last_error
    )
    return result


def lookup_address_logs(
    chain: str,
    address: str,
    *,
    fromblock: str | int = 0,
    toblock: str | int = "latest",
    page: int = 1,
    offset: int = 100,
    topic0: str = "",
    topic1: str = "",
    topic2: str = "",
    topic3: str = "",
    topic0_1_opr: str = "",
    topic1_2_opr: str = "",
    topic2_3_opr: str = "",
    topic0_2_opr: str = "",
    topic0_3_opr: str = "",
    topic1_3_opr: str = "",
) -> dict[str, object]:
    normalized_chain = _normalize_chain_name(chain)
    target = str(address).strip()
    result: dict[str, object] = {
        "ok": False,
        "chain": normalized_chain,
        "address": target,
        "fromblock": fromblock,
        "toblock": toblock,
        "page": page,
        "offset": offset,
        "logs": [],
    }
    if not target:
        result["error"] = "address is required"
        return result

    chain_id = EXPLORER_CHAIN_IDS.get(normalized_chain)
    if chain_id is None:
        result["error"] = f"unsupported explorer chain: {normalized_chain}"
        return result

    try:
        fromblock_text = _normalize_logs_block_param(fromblock, "0")
        toblock_text = _normalize_logs_block_param(toblock, "latest")
    except ValueError as exc:
        result["error"] = str(exc)
        return result

    page = max(int(page), 1)
    offset = max(int(offset), 1)

    topic_params = {
        "topic0": str(topic0).strip(),
        "topic1": str(topic1).strip(),
        "topic2": str(topic2).strip(),
        "topic3": str(topic3).strip(),
        "topic0_1_opr": str(topic0_1_opr).strip().lower(),
        "topic1_2_opr": str(topic1_2_opr).strip().lower(),
        "topic2_3_opr": str(topic2_3_opr).strip().lower(),
        "topic0_2_opr": str(topic0_2_opr).strip().lower(),
        "topic0_3_opr": str(topic0_3_opr).strip().lower(),
        "topic1_3_opr": str(topic1_3_opr).strip().lower(),
    }
    for key, value in list(topic_params.items()):
        if key.endswith("_opr") and value and value not in {"and", "or"}:
            result["error"] = f"unsupported topic operator: {value}"
            return result

    data, last_error = _etherscan_v2_request(
        {
            "chainid": chain_id,
            "module": "logs",
            "action": "getLogs",
            "address": target,
            "fromBlock": fromblock_text,
            "toBlock": toblock_text,
            "page": page,
            "offset": offset,
            **{key: value for key, value in topic_params.items() if value},
        }
    )

    payload = data.get("result") if isinstance(data, dict) else None
    if isinstance(payload, list):
        result["ok"] = True
        result["fromblock"] = fromblock_text
        result["toblock"] = toblock_text
        result["logs"] = payload
        result["count"] = len(payload)
        return result

    message = str(payload or (data or {}).get("message", "") or last_error).strip()
    if any(token in message.lower() for token in ("no records found", "no logs found")):
        result["ok"] = True
        result["fromblock"] = fromblock_text
        result["toblock"] = toblock_text
        result["logs"] = []
        result["count"] = 0
        return result

    result["error"] = message or "address logs lookup failed"
    return result


def load_dfhl_source_metadata(
    case_id: str,
    base_dir: Path,
    *,
    chain: str = "",
    address: str = "",
) -> dict:
    resolved_base = base_dir.resolve()
    normalized_chain = _normalize_chain_name(chain)
    normalized_address = str(address or "").strip().lower()
    for source_dir, origin in _iter_dfhl_source_dir_candidates(
        case_id,
        resolved_base,
        chain=normalized_chain,
        address=normalized_address,
    ):
        metadata = _load_metadata(source_dir / "_metadata.json")
        if not metadata:
            continue
        metadata["source_origin"] = str(metadata.get("source_origin", origin or "verified"))
        metadata["source_dir"] = canonicalize_repo_relative(source_dir.relative_to(resolved_base))
        if normalized_chain and not str(metadata.get("chain", "")).strip():
            metadata["chain"] = normalized_chain
        if normalized_address and not str(metadata.get("address", "")).strip():
            metadata["address"] = normalized_address
        return metadata
    return {}


def resolve_dfhl_vulnerable_sources(
    case_id: str,
    base_dir: Path,
    fallback_paths: Iterable[str] = (),
    *,
    chain: str = "",
    address: str = "",
) -> list[str]:
    """Return real contract source paths for a DeFiHackLabs case when available.

    DeFiHackLabs raw cases historically used the exploit test as ``contracts.vulnerable``.
    That leaks the reference exploit into detect/exploit/fix prompts. Prefer the
    verified-source cache when present and only fall back to the raw paths otherwise.
    """
    resolved_base = base_dir.resolve()
    for source_dir, _origin in _iter_dfhl_source_dir_candidates(
        case_id,
        resolved_base,
        chain=chain,
        address=address,
    ):
        if not source_dir.exists():
            continue

        metadata = _load_metadata(source_dir / "_metadata.json")
        files: list[str] = []
        listed = metadata.get("files", []) if isinstance(metadata, dict) else []
        if isinstance(listed, list):
            for item in listed:
                text = str(item).strip()
                if text.endswith(".sol"):
                    files.append(text)

        if not files:
            files = [
                path.name for path in source_dir.glob("*.sol") if path.name != "_metadata.json"
            ]

        resolved = [
            str((source_dir / file_name).relative_to(resolved_base))
            for file_name in files
            if (source_dir / file_name).exists()
        ]
        if resolved:
            return _normalize_paths(resolved_base, resolved)

    return _normalize_paths(resolved_base, fallback_paths)


def resolve_trace_rpc_url(chain: str) -> str:
    _load_local_rpc_defaults()
    normalized = str(chain).strip().lower().replace(" ", "-")
    normalized = CHAIN_RPC_ALIASES.get(normalized, normalized)
    for env_name in CHAIN_TRACE_RPC_ENV_VARS.get(normalized, ()):
        value = os.environ.get(env_name, "").strip()
        if value:
            return value
    # No silent fallback to the regular RPC — most public/free nodes reject
    # debug_traceTransaction, so returning a non-trace endpoint here leads to
    # confusing third-party errors (e.g. "Tokenview unsupported method").
    return ""


def resolve_rpc_url(chain: str) -> str:
    _load_local_rpc_defaults()
    normalized = str(chain).strip().lower().replace(" ", "-")
    normalized = CHAIN_RPC_ALIASES.get(normalized, normalized)
    for env_name in CHAIN_RPC_ENV_VARS.get(normalized, ()):
        value = os.environ.get(env_name, "").strip()
        if value:
            return value
    return ""


def _json_rpc(rpc_url: str, method: str, params: list[object]) -> dict | None:
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }
    ).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Web3Bug-Benchmark/infra.cli",
    }
    max_retries = 4
    for attempt in range(max_retries):
        request = urllib.request.Request(rpc_url, data=payload, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt < max_retries - 1:
                import time
                time.sleep(2 ** attempt)
                continue
            try:
                body = exc.read().decode("utf-8", errors="replace")
                parsed = json.loads(body)
                if isinstance(parsed, dict):
                    return parsed
                return {"error": {"code": exc.code, "message": body}}
            except Exception:
                return {"error": {"code": exc.code, "message": str(exc)}}
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            if attempt < max_retries - 1:
                import time
                time.sleep(1)
                continue
            return None
    return None


def lookup_tx_block(chain: str, tx_hash: str) -> int | None:
    rpc_url = resolve_trace_rpc_url(chain)
    if not rpc_url:
        return None

    response = _json_rpc(rpc_url, "eth_getTransactionByHash", [tx_hash])
    if not response or not isinstance(response.get("result"), dict):
        return None

    block_number = str(response["result"].get("blockNumber", "")).strip()
    if not block_number:
        return None
    try:
        return int(block_number, 16)
    except ValueError:
        return None


def fill_missing_fork_block(chain_context: dict, *, fallback_chain: str = "") -> dict:
    current = dict(chain_context or {})
    if current.get("fork_block") not in (None, ""):
        return current

    chain = _normalize_chain_name(
        str(current.get("fork_chain", "") or current.get("chain", "") or fallback_chain).strip()
    )
    if not chain:
        return current

    attack_txs = [str(item).strip() for item in current.get("attack_txs", []) if str(item).strip()]
    if not attack_txs:
        return current

    tx_block = lookup_tx_block(chain, attack_txs[0])
    if tx_block is None:
        return current

    current["fork_chain"] = chain
    current["fork_block"] = tx_block
    if not str(current.get("source_hint", "")).strip():
        current["source_hint"] = "attack_tx_rpc"
    return current


def lookup_transaction(chain: str, tx_hash: str) -> dict[str, object]:
    rpc_url = resolve_rpc_url(chain)
    target = str(tx_hash).strip()
    if not target:
        return {}

    if rpc_url:
        response = _json_rpc(rpc_url, "eth_getTransactionByHash", [target])
        result = response.get("result") if isinstance(response, dict) else None
        if isinstance(result, dict):
            return result

    return _lookup_explorer_transaction(chain, target)


def lookup_transaction_receipt(chain: str, tx_hash: str) -> dict[str, object]:
    rpc_url = resolve_rpc_url(chain)
    if not rpc_url or not str(tx_hash).strip():
        return {}

    response = _json_rpc(rpc_url, "eth_getTransactionReceipt", [str(tx_hash).strip()])
    result = response.get("result") if isinstance(response, dict) else None
    return result if isinstance(result, dict) else {}


def lookup_transaction_trace(
    chain: str,
    tx_hash: str,
    *,
    trace_timeout: str = "20s",
) -> dict[str, object]:
    rpc_url = resolve_trace_rpc_url(chain)
    normalized_chain = _normalize_chain_name(chain)
    target = str(tx_hash).strip()
    result: dict[str, object] = {
        "ok": False,
        "chain": normalized_chain,
        "tx_hash": target,
        "trace_method": "",
        "trace": None,
    }
    if not target:
        result["error"] = "tx_hash is required"
        return result
    if not rpc_url:
        result["error"] = f"trace rpc url not configured for chain: {normalized_chain or chain}"
        return result

    params = [
        target,
        {
            "tracer": "callTracer",
            "timeout": str(trace_timeout).strip() or "20s",
        },
    ]
    response = _json_rpc(rpc_url, "debug_traceTransaction", params)
    if not isinstance(response, dict):
        result["error"] = "debug_traceTransaction: empty rpc response"
        return result
    payload = response.get("result") if isinstance(response, dict) else None
    if isinstance(payload, (dict, list)):
        result["ok"] = True
        result["trace_method"] = "debug_traceTransaction"
        result["trace"] = payload
        return result
    if isinstance(payload, str) and payload.strip():
        result["error"] = f"debug_traceTransaction: {payload.strip()}"
        return result

    message = _rpc_error_message(response) or "no trace result"
    result["error"] = f"debug_traceTransaction: {message}"
    return result


def lookup_address_transaction_traces(
    chain: str,
    address: str,
    *,
    startblock: int = 0,
    endblock: int = 99999999,
    page: int = 1,
    offset: int = 10,
    sort: str = "desc",
    include_transaction: bool = False,
    include_receipt: bool = False,
    trace_timeout: str = "20s",
) -> dict[str, object]:
    history = lookup_address_transactions(
        chain,
        address,
        startblock=startblock,
        endblock=endblock,
        page=page,
        offset=offset,
        sort=sort,
    )
    result: dict[str, object] = {
        "ok": bool(history.get("ok")),
        "chain": history.get("chain", _normalize_chain_name(chain)),
        "address": str(address).strip(),
        "startblock": history.get("startblock", startblock),
        "endblock": history.get("endblock", endblock),
        "page": history.get("page", page),
        "offset": history.get("offset", offset),
        "sort": history.get("sort", sort),
        "count": 0,
        "traced_count": 0,
        "tx_hashes": [],
        "items": [],
    }
    if not history.get("ok"):
        result["error"] = str(history.get("error", "failed to fetch address transactions"))
        return result

    transactions = history.get("transactions", [])
    if not isinstance(transactions, list):
        result["error"] = "transactions payload was not a list"
        result["ok"] = False
        return result

    items: list[dict[str, object]] = []
    traced_count = 0
    tx_hashes: list[str] = []
    normalized_chain = str(result["chain"]).strip()
    for tx_item in transactions:
        explorer_tx = tx_item if isinstance(tx_item, dict) else {"raw": tx_item}
        tx_hash = str(explorer_tx.get("hash") or explorer_tx.get("transactionHash") or "").strip()
        if tx_hash:
            tx_hashes.append(tx_hash)
        entry: dict[str, object] = {
            "tx_hash": tx_hash,
            "explorer_transaction": explorer_tx,
        }
        if include_transaction and tx_hash:
            entry["transaction"] = lookup_transaction(normalized_chain, tx_hash)
        if include_receipt and tx_hash:
            entry["receipt"] = lookup_transaction_receipt(normalized_chain, tx_hash)

        if tx_hash:
            trace_payload = lookup_transaction_trace(
                normalized_chain,
                tx_hash,
                trace_timeout=trace_timeout,
            )
        else:
            trace_payload = {
                "ok": False,
                "chain": normalized_chain,
                "tx_hash": "",
                "trace_method": "",
                "trace": None,
                "error": "missing tx hash",
            }

        entry["trace_ok"] = bool(trace_payload.get("ok"))
        entry["trace_method"] = str(trace_payload.get("trace_method", "")).strip()
        entry["trace"] = trace_payload.get("trace")
        if trace_payload.get("warnings"):
            entry["trace_warnings"] = trace_payload.get("warnings")
        if not entry["trace_ok"]:
            entry["trace_error"] = str(trace_payload.get("error", "trace lookup failed")).strip()
        else:
            traced_count += 1
        items.append(entry)

    result["count"] = len(items)
    result["traced_count"] = traced_count
    result["tx_hashes"] = tx_hashes
    result["items"] = items
    return result


def _iter_call_trace_nodes(node: object) -> list[dict[str, object]]:
    if isinstance(node, list):
        return [item for item in node if isinstance(item, dict)]
    if not isinstance(node, dict):
        return []
    nodes = [node]
    for child in node.get("calls", []) or []:
        nodes.extend(_iter_call_trace_nodes(child))
    return nodes


def _trace_delegatecall_proxy_matches(
    trace: object,
    tracked_address: str,
    *,
    tx_hash: str,
    source_hint: str,
    trace_method: str,
) -> list[dict[str, object]]:
    tracked = str(tracked_address).strip().lower()
    if not tracked:
        return []

    matches: list[dict[str, object]] = []
    for node in _iter_call_trace_nodes(trace):
        call_type = str(node.get("type") or node.get("callType") or node.get("call_type") or "").strip().lower()
        from_addr = str(node.get("from") or "").strip()
        to_addr = str(node.get("to") or "").strip()
        if call_type != "delegatecall":
            continue
        if not from_addr or not to_addr:
            continue
        if not _ADDRESS_RE.fullmatch(from_addr) or not _ADDRESS_RE.fullmatch(to_addr):
            continue
        from_lower = from_addr.lower()
        to_lower = to_addr.lower()
        proxy_address = ""
        implementation_address = ""
        if to_lower == tracked and from_lower != tracked:
            proxy_address = from_addr
            implementation_address = tracked_address
        elif from_lower == tracked and to_lower != tracked:
            proxy_address = tracked_address
            implementation_address = to_addr
        else:
            continue
        matches.append(
            {
                "proxy_address": proxy_address,
                "implementation_address": implementation_address,
                "tx_hash": tx_hash,
                "source_hint": source_hint,
                "trace_method": trace_method,
                "call_type": call_type,
            }
        )
    return matches


def lookup_delegatecall_proxy(
    chain: str,
    implementation_address: str,
    *,
    tx_hashes: Iterable[str] = (),
    block_number: int | None = None,
    recent_offset: int = 5,
    trace_timeout: str = "10s",
) -> dict[str, object]:
    normalized_chain = _normalize_chain_name(chain)
    implementation = str(implementation_address).strip()
    result: dict[str, object] = {
        "ok": False,
        "chain": normalized_chain,
        "implementation_address": implementation,
        "checked_tx_hashes": [],
        "checked_trace_count": 0,
        "proxy_address": "",
        "matches": [],
    }
    if not normalized_chain or not _ADDRESS_RE.fullmatch(implementation):
        result["error"] = "missing or invalid chain / implementation address"
        return result

    tx_candidates = _dedupe_keep_order(
        [str(item).strip() for item in tx_hashes if str(item).strip()]
    )
    all_matches: list[dict[str, object]] = []
    seen_hashes: set[str] = set()

    for tx_hash in tx_candidates[:3]:
        payload = lookup_transaction_trace(
            normalized_chain,
            tx_hash,
            trace_timeout=trace_timeout,
        )
        seen_hashes.add(tx_hash)
        result["checked_tx_hashes"].append(tx_hash)
        if not payload.get("ok"):
            continue
        result["checked_trace_count"] += 1
        all_matches.extend(
            _trace_delegatecall_proxy_matches(
                payload.get("trace"),
                implementation,
                tx_hash=tx_hash,
                source_hint="attack_tx_trace",
                trace_method=str(payload.get("trace_method", "")).strip(),
            )
        )

    if all_matches:
        best = all_matches[0]
        result["proxy_address"] = str(best.get("proxy_address", "")).strip()
        result["tx_hash"] = str(best.get("tx_hash", "")).strip()
        result["source_hint"] = str(best.get("source_hint", "")).strip()
        result["trace_method"] = str(best.get("trace_method", "")).strip()
        result["matches"] = all_matches[:5]
    result["ok"] = True
    return result


def extract_case_attack_txs(raw_case: dict) -> list[str]:
    """Collect attack transaction hashes from normalized/raw benchmark inputs."""
    if not isinstance(raw_case, dict):
        return []

    chain_context = (
        raw_case.get("chain_context", {}) if isinstance(raw_case.get("chain_context"), dict) else {}
    )
    clara = raw_case.get("clara", {}) if isinstance(raw_case.get("clara"), dict) else {}

    txs: list[str] = []
    for source in (
        chain_context.get("attack_txs", []),
        raw_case.get("tx_hashes", []),
        clara.get("tx_hashes", []),
    ):
        if isinstance(source, list):
            txs.extend(str(item).strip() for item in source if str(item).strip())
    return _dedupe_keep_order(txs)


def infer_attack_tx_context(
    chain: str,
    tx_hashes: Iterable[str],
    *,
    vulnerable_addresses: Iterable[str] = (),
    block_number: int | None = None,
) -> dict[str, object]:
    """Infer coarse attack entrypoint metadata from historical transaction hashes.

    This is intentionally heuristic. Plain transaction + receipt lookup cannot
    reveal full internal call traces, but it can still surface the most useful
    externally visible addresses for agent prompting and tx-replay candidates.
    """
    hashes = _dedupe_keep_order([str(item).strip() for item in tx_hashes if str(item).strip()])
    if not hashes:
        return {}

    vulnerable = {str(item).strip().lower() for item in vulnerable_addresses if str(item).strip()}
    attack_senders: list[str] = []
    attack_targets: list[str] = []
    attack_created_contracts: list[str] = []
    contract_candidates: list[str] = []

    normalized_chain = str(chain).strip()
    for tx_hash in hashes[:3]:
        tx = lookup_transaction(normalized_chain, tx_hash) if normalized_chain else {}
        receipt = lookup_transaction_receipt(normalized_chain, tx_hash) if normalized_chain else {}

        sender = _clean_optional_text(tx.get("from", ""))
        target = _clean_optional_text(tx.get("to", ""))
        created_contract = _clean_optional_text(receipt.get("contractAddress", ""))

        if sender:
            attack_senders.append(sender)
        if target:
            attack_targets.append(target)
        if created_contract:
            attack_created_contracts.append(created_contract)

        # Prefer a created contract, then a non-vulnerable tx target, then a
        # contract sender when RPC code lookup is available.
        if created_contract and created_contract.lower() not in vulnerable:
            contract_candidates.append(created_contract)
        if target and target.lower() not in vulnerable:
            contract_candidates.append(target)

        if sender and sender.lower() not in vulnerable and normalized_chain:
            runtime_code = lookup_runtime_code(normalized_chain, sender, block_number)
            if runtime_code:
                contract_candidates.append(sender)

    attack_senders = _dedupe_keep_order(attack_senders)
    attack_targets = _dedupe_keep_order(attack_targets)
    attack_created_contracts = _dedupe_keep_order(attack_created_contracts)
    contract_candidates = _dedupe_keep_order(contract_candidates)

    attack_entrypoint = ""
    if contract_candidates:
        attack_entrypoint = contract_candidates[0]
    elif attack_targets:
        attack_entrypoint = attack_targets[0]
    elif attack_senders:
        attack_entrypoint = attack_senders[0]

    result: dict[str, object] = {
        "attack_txs": hashes,
    }
    if attack_senders:
        result["attack_senders"] = attack_senders
    if attack_targets:
        result["attack_targets"] = attack_targets
    if attack_created_contracts:
        result["attack_created_contracts"] = attack_created_contracts
    if attack_entrypoint:
        result["attack_entrypoint"] = attack_entrypoint
    if normalized_chain and (attack_senders or attack_targets or attack_created_contracts):
        result["source_hint"] = "attack_tx_rpc"
    return result


def lookup_block_timestamp(chain: str, block_number: int) -> int | None:
    rpc_url = resolve_rpc_url(chain)
    if not rpc_url or block_number < 0:
        return None

    response = _json_rpc(rpc_url, "eth_getBlockByNumber", [hex(block_number), False])
    if not response or not isinstance(response.get("result"), dict):
        return None

    timestamp_hex = str(response["result"].get("timestamp", "")).strip()
    if not timestamp_hex:
        return None
    try:
        return int(timestamp_hex, 16)
    except ValueError:
        return None


def lookup_runtime_code(chain: str, address: str, block_number: str | int | None = None) -> str:
    rpc_url = resolve_rpc_url(chain)
    normalized_address = str(address).strip()
    if not normalized_address:
        return ""
    try:
        tag = _normalize_block_tag(block_number)
    except ValueError:
        return ""

    if rpc_url:
        response = _json_rpc(rpc_url, "eth_getCode", [normalized_address, tag])
        if response and isinstance(response.get("result"), str):
            code = response["result"].strip()
            if code.startswith("0x") and len(code) > 2:
                return code

    normalized_chain = _normalize_chain_name(chain)
    chain_id = EXPLORER_CHAIN_IDS.get(normalized_chain)
    if chain_id is None:
        return ""

    data, _ = _etherscan_v2_request(
        {
            "chainid": chain_id,
            "module": "proxy",
            "action": "eth_getCode",
            "address": normalized_address,
            "tag": tag,
        }
    )
    result = data.get("result") if isinstance(data, dict) else None
    if not isinstance(result, str):
        result = ""
    code = str(result).strip()
    if code.startswith("0x") and len(code) > 2:
        return code

    scraped = _lookup_explorer_page_bytecodes(normalized_chain, normalized_address)
    code = str(scraped.get("runtime_bytecode", "")).strip()
    return code if code.startswith("0x") and len(code) > 2 else ""


def lookup_storage_slot(
    chain: str,
    address: str,
    slot: str | int,
    block: str | int | None = None,
) -> str:
    rpc_url = resolve_rpc_url(chain)
    normalized_address = str(address).strip()
    if not rpc_url or not normalized_address:
        return ""

    try:
        normalized_slot = _normalize_storage_slot(slot)
        block_tag = _normalize_block_tag(block)
    except ValueError:
        return ""

    response = _json_rpc(
        rpc_url, "eth_getStorageAt", [normalized_address, normalized_slot, block_tag]
    )
    if not response or not isinstance(response.get("result"), str):
        return ""

    value = response["result"].strip()
    return value if value.startswith("0x") else ""


def eth_call(
    chain: str,
    to: str,
    data: str = "0x",
    block: str | int | None = None,
    *,
    from_address: str = "",
) -> str:
    rpc_url = resolve_rpc_url(chain)
    target = str(to).strip()
    if not rpc_url or not target:
        return ""

    try:
        block_tag = _normalize_block_tag(block)
    except ValueError:
        return ""

    calldata = str(data).strip() or "0x"
    if not calldata.startswith("0x"):
        calldata = "0x" + calldata

    tx_obj: dict[str, str] = {
        "to": target,
        "data": calldata,
    }
    sender = str(from_address).strip()
    if sender:
        tx_obj["from"] = sender

    response = _json_rpc(rpc_url, "eth_call", [tx_obj, block_tag])
    if not response or not isinstance(response.get("result"), str):
        return ""

    result = response["result"].strip()
    return result if result.startswith("0x") else ""


def lookup_proxy_info(
    chain: str,
    address: str,
    block: str | int | None = None,
) -> dict[str, object]:
    target = str(address).strip()
    block_tag = block if block not in (None, "") else "latest"
    bytecode = lookup_runtime_code(chain, target, block)
    code_size = (len(bytecode) - 2) // 2 if bytecode.startswith("0x") else 0
    minimal_proxy_target = _extract_minimal_proxy_target(bytecode)

    implementation_slot = lookup_storage_slot(chain, target, ERC1967_IMPLEMENTATION_SLOT, block)
    admin_slot = lookup_storage_slot(chain, target, ERC1967_ADMIN_SLOT, block)
    beacon_slot = lookup_storage_slot(chain, target, ERC1967_BEACON_SLOT, block)

    implementation = _word_to_address(implementation_slot)
    admin = _word_to_address(admin_slot)
    beacon = _word_to_address(beacon_slot)
    beacon_implementation = ""
    if beacon:
        beacon_implementation = _word_to_address(
            eth_call(chain, beacon, IMPLEMENTATION_SELECTOR, block)
        )

    proxy_kind = "direct"
    proxy_detected = False
    notes: list[str] = []
    if minimal_proxy_target:
        proxy_kind = "eip1167"
        proxy_detected = True
        notes.append("standard EIP-1167 minimal proxy pattern detected")
    elif beacon:
        proxy_kind = "erc1967-beacon"
        proxy_detected = True
        notes.append("ERC-1967 beacon slot is populated")
    elif implementation:
        proxy_kind = "erc1967"
        proxy_detected = True
        notes.append("ERC-1967 implementation slot is populated")

    if admin:
        notes.append("ERC-1967 admin slot is populated")

    return {
        "ok": bool(bytecode),
        "chain": chain,
        "address": target,
        "block": block_tag,
        "code_size": code_size,
        "proxy_detected": proxy_detected,
        "proxy_kind": proxy_kind,
        "implementation": implementation,
        "beacon": beacon,
        "beacon_implementation": beacon_implementation,
        "admin": admin,
        "minimal_proxy_target": minimal_proxy_target,
        "implementation_slot": implementation_slot,
        "admin_slot": admin_slot,
        "beacon_slot": beacon_slot,
        "notes": notes,
    }


def disassemble_runtime_code(bytecode: str, timeout: int = 120) -> str:
    if not str(bytecode).strip():
        return ""
    try:
        proc = subprocess.run(
            ["cast", "disassemble", bytecode],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""

    output = (proc.stdout + proc.stderr).strip()
    return output





def _decompile_bytecode_with_panoramix(bytecode: str, timeout: int = 180) -> str:
    """Decompile bytecode using Panoramix (better quality, slower)."""
    code = str(bytecode).strip()
    if not code:
        return ""


    script = r"""
import logging
import re
import sys

logging.disable(logging.CRITICAL)

try:
    import panoramix.utils.signatures as signatures
    import panoramix.loader as loader
    from panoramix.decompiler import decompile_bytecode
except Exception:
    raise SystemExit(2)

signatures.fetch_sig = lambda selector: None
loader.Loader.find_sig = staticmethod(lambda sig, add_color=False: None)

result = decompile_bytecode(sys.stdin.read().strip())
text = re.sub(r"\x1b\[[0-9;]*m", "", str(result.text or "")).strip()
if text:
    sys.stdout.write(text)
"""
    candidates: list[list[str]] = []
    uv = shutil.which("uv")
    if uv:
        candidates.append([
            uv, "run", "--no-project", "--quiet",
            "--with", "panoramix-decompiler",
            "python", "-c", script,
        ])
    for executable in (sys.executable, "python3"):
        value = str(executable).strip()
        if value:
            candidates.append([value, "-c", script])

    for command in candidates:
        try:
            proc = subprocess.run(
                command,
                input=code,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    return ""


def decompile_bytecode(bytecode: str, timeout: int = 180) -> str:
    code = str(bytecode).strip()
    if not code:
        return ""

    return _decompile_bytecode_with_panoramix(code, timeout=timeout)


def lookup_runtime_artifacts(
    chain: str,
    address: str,
    block_number: int | None = None,
) -> dict[str, str]:
    bytecode = lookup_runtime_code(chain, address, block_number)
    if bytecode:
        artifacts = {
            "runtime_bytecode.hex": bytecode,
        }
        disassembly = disassemble_runtime_code(bytecode)
        if disassembly:
            artifacts["runtime_disassembly.txt"] = disassembly
        decompiled = decompile_bytecode(bytecode)
        if decompiled:
            artifacts["runtime_decompiled.txt"] = decompiled
        return artifacts

    creation = lookup_contract_creation(chain, address)
    creation_bytecode = str(creation.get("creation_bytecode", "")).strip()
    if not creation_bytecode.startswith("0x") or len(creation_bytecode) <= 2:
        return {}

    artifacts = {
        "creation_bytecode.hex": creation_bytecode,
    }
    disassembly = disassemble_runtime_code(creation_bytecode)
    if disassembly:
        artifacts["creation_disassembly.txt"] = disassembly
    decompiled = decompile_bytecode(creation_bytecode)
    if decompiled:
        artifacts["creation_decompiled.txt"] = decompiled
    return artifacts


def load_runtime_artifacts(
    base_dir: Path,
    *,
    runtime_bytecode_path: str = "",
    disassembly_path: str = "",
) -> dict[str, str]:
    artifacts: dict[str, str] = {}

    for rel_path in (runtime_bytecode_path, disassembly_path):
        text = str(rel_path).strip()
        if not text:
            continue
        full_path = resolve_repo_path(base_dir, text)
        if not full_path.exists():
            continue
        artifacts[full_path.name] = full_path.read_text(errors="replace")

    return artifacts


def load_context_cache(
    base_dir: Path, relative_path: Path = DEFAULT_CONTEXT_CACHE
) -> dict[str, dict]:
    cache_path = (
        relative_path if relative_path.is_absolute() else resolve_repo_path(base_dir, relative_path)
    )
    if not cache_path.exists():
        return {}
    try:
        data = json.loads(cache_path.read_text())
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(key): value for key, value in data.items() if isinstance(value, dict)}


def write_context_cache(cache_path: Path, cache: dict[str, dict]) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(cache, indent=2, ensure_ascii=False) + "\n")


def merge_cached_chain_context(case_id: str, chain_context: dict, cache: dict[str, dict]) -> dict:
    current = dict(chain_context or {})
    cached = cache.get(case_id, {})
    if not isinstance(cached, dict):
        cached = {}
    cached_lookup_miss = bool(cached.get("_fork_block_lookup_miss"))

    if current.get("fork_block") in (None, "") and cached.get("fork_block") not in (None, ""):
        current["fork_block"] = cached.get("fork_block")
    for key in (
        "attack_txs",
        "explorer_urls",
        "debug_urls",
        "vulnerable_addresses",
        "related_addresses",
    ):
        current[key] = _dedupe_keep_order(
            [str(item).strip() for item in current.get(key, []) if str(item).strip()]
            + [str(item).strip() for item in cached.get(key, []) if str(item).strip()]
        )
    if not str(current.get("fork_rpc_alias", "")).strip():
        current["fork_rpc_alias"] = str(cached.get("fork_rpc_alias", "")).strip()
    if not str(current.get("fork_chain", "")).strip():
        current["fork_chain"] = str(cached.get("fork_chain", "")).strip()
    if not str(current.get("source_hint", "")).strip():
        current["source_hint"] = str(cached.get("source_hint", "")).strip()

    if not (
        cached_lookup_miss and current.get("fork_block") in (None, "") and current.get("attack_txs")
    ):
        current = fill_missing_fork_block(current)

    if current != cached:
        merged_cache_entry = dict(cached)
        merged_cache_entry.update(
            {
                key: value
                for key, value in current.items()
                if key
                in {
                    "fork_block",
                    "fork_rpc_alias",
                    "fork_chain",
                    "attack_txs",
                    "explorer_urls",
                    "debug_urls",
                    "vulnerable_addresses",
                    "related_addresses",
                    "source_hint",
                }
            }
        )
        if current.get("fork_block") in (None, "") and current.get("attack_txs"):
            merged_cache_entry["_fork_block_lookup_miss"] = True
        else:
            merged_cache_entry.pop("_fork_block_lookup_miss", None)
        cache[case_id] = merged_cache_entry

    return current
