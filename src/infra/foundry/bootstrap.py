"""Helpers for injecting historical fork/bootstrap setup into on-chain tests."""

from __future__ import annotations

import re

_SETUP_RE = re.compile(r"function\s+setUp\s*\([^)]*\)\s*[^{]*\{")
_TEST_RE = re.compile(r"^(\s*)function\s+testExploit\s*\(", re.MULTILINE)


def _coerce_int(value: object) -> int | None:
    if value in (None, "") or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).replace("_", "").strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _normalize_statement(statement: str) -> str:
    return re.sub(r"\s+", "", statement).replace("_", "").strip().rstrip(";")


def _build_base_fork_line(state_context: dict, chain_context: dict) -> str:
    base_fork = (
        state_context.get("base_fork", {})
        if isinstance(state_context.get("base_fork"), dict)
        else {}
    )
    rpc_alias = (
        str(base_fork.get("rpc_alias", "")).strip()
        or str(chain_context.get("fork_rpc_alias", "")).strip()
    )
    chain = (
        str(base_fork.get("chain", "")).strip() or str(chain_context.get("fork_chain", "")).strip()
    )
    fork_target = rpc_alias or chain
    block = _coerce_int(base_fork.get("block"))
    if block is None:
        block = _coerce_int(chain_context.get("block"))
    if block is None:
        block = _coerce_int(chain_context.get("fork_block"))
    if not fork_target:
        return ""
    if block is None:
        return f'vm.createSelectFork("{fork_target}");'
    return f'vm.createSelectFork("{fork_target}", {block});'


def normalize_create_select_fork(
    solidity_code: str,
    *,
    state_context: dict | None = None,
    chain_context: dict | None = None,
) -> tuple[str, bool, str]:
    """Rewrite existing ``createSelectFork`` calls to the benchmark-configured target.

    Agent-generated PoCs frequently hardcode public RPC URLs such as Cloudflare,
    Ankr, or demo Alchemy endpoints inside ``vm.createSelectFork(...)``. That
    makes provider selection part of the PoC, which is the wrong boundary for
    evaluation. The benchmark already knows the canonical fork chain/block from
    case metadata, so normalize all existing fork calls back to that canonical
    target before execution.
    """

    state_context = state_context if isinstance(state_context, dict) else {}
    chain_context = chain_context if isinstance(chain_context, dict) else {}
    canonical_line = _build_base_fork_line(state_context, chain_context)
    if not canonical_line or "createSelectFork" not in solidity_code:
        return solidity_code, False, canonical_line

    canonical_expr = canonical_line.rstrip(";")
    changed = False
    normalized_lines: list[str] = []
    for line in solidity_code.splitlines(keepends=True):
        if "createSelectFork" not in line:
            normalized_lines.append(line)
            continue

        call_start = max(line.find("vm.createSelectFork"), line.find("cheats.createSelectFork"))
        call_end = line.rfind(";")
        if call_start == -1 or call_end == -1 or call_end < call_start:
            normalized_lines.append(line)
            continue

        replacement = line[:call_start] + canonical_expr + line[call_end:]
        if replacement != line:
            changed = True
        normalized_lines.append(replacement)

    return "".join(normalized_lines), changed, canonical_line


def bootstrap_lines_from_context(
    state_context: dict | None, chain_context: dict | None
) -> list[str]:
    state_context = state_context if isinstance(state_context, dict) else {}
    chain_context = chain_context if isinstance(chain_context, dict) else {}

    lines: list[str] = []
    base_line = _build_base_fork_line(state_context, chain_context)
    if base_line:
        lines.append(base_line)

    for action in state_context.get("bootstrap", []):
        if not isinstance(action, dict):
            continue
        snippet = str(action.get("snippet", "")).strip()
        if not snippet or "createSelectFork" in snippet:
            continue
        lines.append(snippet if snippet.endswith(";") else f"{snippet};")

    deduped: list[str] = []
    seen: set[str] = set()
    for line in lines:
        key = _normalize_statement(line)
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(line)
    return deduped


def _find_function_bounds(code: str, function_name: str) -> tuple[int, int, int] | None:
    pattern = re.compile(r"function\s+" + re.escape(function_name) + r"\s*\([^)]*\)\s*[^{]*\{")
    match = pattern.search(code)
    if not match:
        return None

    body_start = match.end()
    depth = 1
    idx = body_start
    while idx < len(code):
        char = code[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return match.start(), body_start, idx
        idx += 1
    return None


def _inject_into_existing_setup(code: str, lines: list[str]) -> str:
    bounds = _find_function_bounds(code, "setUp")
    if bounds is None:
        return code

    _, body_start, body_end = bounds
    body = code[body_start:body_end]
    body_lines = body.splitlines(keepends=True)
    indent = "        "
    for line in body_lines:
        if line.strip():
            indent = re.match(r"\s*", line).group(0) or indent
            break

    insert_idx = 0
    for index, line in enumerate(body_lines):
        if "createSelectFork" in line:
            insert_idx = index + 1
            break

    injected = "".join(f"{indent}{line}\n" for line in lines)
    if body_lines:
        body_lines.insert(insert_idx, injected)
        new_body = "".join(body_lines)
    else:
        new_body = "\n" + injected
    return code[:body_start] + new_body + code[body_end:]


def _inject_new_setup(code: str, lines: list[str]) -> str:
    match = _TEST_RE.search(code)
    if not match:
        return code
    indent = match.group(1)
    body_indent = indent + "    "
    function_block = (
        f"{indent}function setUp() public {{\n"
        + "".join(f"{body_indent}{line}\n" for line in lines)
        + f"{indent}}}\n\n"
    )
    return code[: match.start()] + function_block + code[match.start() :]


def inject_state_bootstrap(
    solidity_code: str,
    *,
    state_context: dict | None = None,
    chain_context: dict | None = None,
) -> tuple[str, bool, list[str]]:
    """Inject historical fork/bootstrap lines into a Foundry exploit if missing."""
    lines = bootstrap_lines_from_context(state_context, chain_context)
    if not lines:
        return solidity_code, False, []

    if "createSelectFork" in solidity_code:
        lines = [line for line in lines if "createSelectFork" not in line]
        if not lines:
            return solidity_code, False, []

    existing = {
        _normalize_statement(match.group(0))
        for match in re.finditer(r"[A-Za-z_][^;\n{}]*\([^;\n{}]*\)\s*;", solidity_code)
    }
    missing = [line for line in lines if _normalize_statement(line) not in existing]
    if not missing:
        return solidity_code, False, []

    if _SETUP_RE.search(solidity_code):
        return _inject_into_existing_setup(solidity_code, missing), True, missing
    return _inject_new_setup(solidity_code, missing), True, missing
