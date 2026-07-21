"""
Extract ground-truth location from DeFiHackLabs exploit .sol files.

Strategy:
  1. Collect declared function names from inline definitions and shared
     `interface.sol` (interfaces, abstract contracts, concrete contracts).
  2. Find candidate vulnerable calls in executable contract bodies, including
     direct calls, selector references, and `abi.encodeWithSignature(...)`.
  3. Prefer the earliest non-standard candidate that maps back to a declared
     protocol interface/contract when possible.
  4. Infer filename from the declaration container (e.g. `ISpankChain` ->
     `SpankChain.sol`).
"""

from __future__ import annotations

import re
from pathlib import Path

# Standard functions to ignore when identifying vulnerable functions
_STANDARD_FUNCS = {
    # ERC20
    "balanceOf",
    "approve",
    "transfer",
    "transferFrom",
    "allowance",
    "totalSupply",
    "decimals",
    "name",
    "symbol",
    # Foundry/test
    "setUp",
    "deal",
    "prank",
    "startPrank",
    "stopPrank",
    "label",
    "createSelectFork",
    "rollFork",
    "warp",
    "roll",
    "expectRevert",
    "expectEmit",
    "assertEq",
    "assertTrue",
    # Common utilities
    "log",
    "emit",
    "console",
}

# Standard DeFi operations — lower priority but still valid
_DEFI_STANDARD = {
    "deposit",
    "withdraw",
    "borrow",
    "repay",
    "supply",
    "swap",
    "flashLoan",
    "flashloan",
    "mint",
    "burn",
    "redeem",
    "earn",
    "withdrawAll",
    "add_liquidity",
    "remove_liquidity",
}

_HELPER_PREFIXES = (
    "get",
    "is",
    "has",
    "can",
    "check",
    "owner",
    "under",
    "calc",
    "quote",
    "preview",
)

_DECL_BLOCK_RE = re.compile(r"\b(?:interface|abstract\s+contract|contract|library)\s+(\w+)[^{;]*\{")

_SKIP_CONTAINER_NAMES = {
    "CheatCodes",
    "ContractTest",
    "Test",
    "AttackContract",
    "Attacker",
    "AttackerC",
    "AttackerCC",
    "FakeJar",
    "FakeUnderlying",
}

_HARNESS_CONTAINER_MARKERS = (
    "attack",
    "attacker",
    "exploit",
    "helper",
    "mock",
    "test",
)


def _strip_comments_preserve_length(content: str) -> str:
    """Remove comments while preserving offsets for line-number lookups."""

    def _blank(match: re.Match[str]) -> str:
        return "".join("\n" if ch == "\n" else " " for ch in match.group(0))

    content = re.sub(r"/\*.*?\*/", _blank, content, flags=re.DOTALL)
    content = re.sub(r"//[^\n]*", _blank, content)
    return content


def _extract_brace_block(content: str, start: int) -> tuple[str, int]:
    """Return the body for a declaration whose opening brace is at start - 1."""
    brace_depth = 1
    pos = start
    while pos < len(content) and brace_depth > 0:
        if content[pos] == "{":
            brace_depth += 1
        elif content[pos] == "}":
            brace_depth -= 1
        pos += 1
    return content[start : pos - 1], pos


def _collect_declared_funcs(content: str) -> dict[str, list[str]]:
    """Collect declared function names mapped to the containers that define them."""
    funcs: dict[str, list[str]] = {}
    for match in _DECL_BLOCK_RE.finditer(content):
        container = match.group(1)
        body, _ = _extract_brace_block(content, match.end())
        for fn_match in re.finditer(r"\bfunction\s+(\w+)\s*\(", body):
            name = fn_match.group(1)
            funcs.setdefault(name, []).append(container)
    return funcs


def _collect_function_metadata(
    content: str,
    shared_iface_path: Path | None = None,
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Collect function declarations from the exploit file and shared interfaces."""
    local_funcs = _collect_declared_funcs(content)
    shared_funcs: dict[str, list[str]] = {}
    if shared_iface_path and shared_iface_path.exists() and "interface.sol" in content:
        shared = _strip_comments_preserve_length(shared_iface_path.read_text(errors="replace"))
        shared_funcs = _collect_declared_funcs(shared)
    return local_funcs, shared_funcs


def _extract_contract_bodies(content: str) -> list[str]:
    """Extract all contract/library bodies where executable code may appear."""
    bodies: list[str] = []
    for match in re.finditer(r"\b(?:abstract\s+contract|contract|library)\s+\w+[^{;]*\{", content):
        body, _ = _extract_brace_block(content, match.end())
        bodies.append(body)
    return bodies


def _iter_candidate_calls(search_space: str) -> list[tuple[int, str]]:
    """Collect candidate vulnerable function names in source order."""
    matches: list[tuple[int, str]] = []

    patterns = (
        r"\.(\w+)\s*[\({]",
        r"\.(\w+)\.selector\b",
        r'abi\.encodeWithSignature\(\s*"([A-Za-z_]\w*)\s*\(',
        r"abi\.encodeCall\(\s*[\w\.]+\.(\w+)\s*,",
        r'"([A-Za-z_]\w*)\([^"\n]*\)"',
    )
    for pattern in patterns:
        for match in re.finditer(pattern, search_space):
            matches.append((match.start(), match.group(1)))

    matches.sort(key=lambda item: item[0])
    return matches


def _choose_primary(candidates: list[str]) -> str | None:
    """Pick the most plausible vulnerable function from ordered candidates."""
    for fn in candidates:
        lower = fn.lower()
        if lower not in _DEFI_STANDARD and not lower.startswith(_HELPER_PREFIXES):
            return fn
    for fn in candidates:
        if not fn.lower().startswith(_HELPER_PREFIXES):
            return fn
    for fn in candidates:
        if fn.lower() not in _DEFI_STANDARD:
            return fn
    return candidates[0] if candidates else None


def _is_harness_container(container: str) -> bool:
    lowered = str(container or "").strip().lower()
    if not lowered:
        return False
    normalized = lowered[1:] if lowered.startswith("i") else lowered
    if normalized in {name.lower() for name in _SKIP_CONTAINER_NAMES}:
        return True
    return any(marker in normalized for marker in _HARNESS_CONTAINER_MARKERS)


def _ordered_repeated(candidates: list[str], counts: dict[str, int]) -> list[str]:
    return [candidate for candidate in candidates if counts.get(candidate, 0) > 1]


def _infer_filename(primary: str, func_to_containers: dict[str, list[str]], sol_path: Path) -> str:
    """Best-effort vulnerable source filename."""
    for container in func_to_containers.get(primary, []):
        normalized = container[1:] if container.startswith("I") else container
        if container in _SKIP_CONTAINER_NAMES or normalized in _SKIP_CONTAINER_NAMES:
            continue
        if (
            normalized.endswith("Test")
            or normalized.startswith("Fake")
            or normalized.startswith("Attack")
        ):
            continue
        if len(normalized) > 2:
            return f"{normalized}.sol"
    return sol_path.name


def extract_location(sol_path: Path) -> dict | None:
    """Extract vulnerable function from a DeFiHackLabs exploit .sol file.

    Returns dict with keys: function, file? (or None if extraction fails).
    """
    if not sol_path.exists():
        return None

    content = sol_path.read_text(errors="replace")
    cleaned = _strip_comments_preserve_length(content)

    # Shared interface.sol (one directory up from the exploit file)
    shared_iface = sol_path.parent.parent / "interface.sol"

    local_funcs, shared_funcs = _collect_function_metadata(cleaned, shared_iface)
    local_declared = set(local_funcs) - _STANDARD_FUNCS
    local_protocol_declared = {
        name
        for name in local_declared
        if any(not _is_harness_container(container) for container in local_funcs.get(name, []))
    }
    local_harness_declared = local_declared - local_protocol_declared
    shared_declared = set(shared_funcs) - _STANDARD_FUNCS
    all_declared = local_protocol_declared | local_harness_declared | shared_declared

    # Extract all contract bodies
    all_bodies = _extract_contract_bodies(cleaned)
    search_space = "\n".join(all_bodies) if all_bodies else cleaned

    # Find candidate calls in source order.
    local_called: list[str] = []
    shared_called: list[str] = []
    fallback_called: list[str] = []
    harness_called: list[str] = []
    local_seen: set[str] = set()
    shared_seen: set[str] = set()
    fallback_seen: set[str] = set()
    harness_seen: set[str] = set()
    local_counts: dict[str, int] = {}
    shared_counts: dict[str, int] = {}
    fallback_counts: dict[str, int] = {}
    harness_counts: dict[str, int] = {}
    for _, fname in _iter_candidate_calls(search_space):
        if fname in _STANDARD_FUNCS:
            continue
        if fname in shared_declared:
            shared_counts[fname] = shared_counts.get(fname, 0) + 1
            if fname not in shared_seen:
                shared_called.append(fname)
                shared_seen.add(fname)
            continue
        if fname in local_protocol_declared:
            local_counts[fname] = local_counts.get(fname, 0) + 1
            if fname not in local_seen:
                local_called.append(fname)
                local_seen.add(fname)
            continue
        if fname in local_harness_declared:
            harness_counts[fname] = harness_counts.get(fname, 0) + 1
            if fname not in harness_seen:
                harness_called.append(fname)
                harness_seen.add(fname)
            continue
        if (
            fname not in all_declared
            and not re.match(r"^(get|is|has|_)", fname)
            and fname not in fallback_seen
        ):
            fallback_called.append(fname)
            fallback_seen.add(fname)
            fallback_counts[fname] = fallback_counts.get(fname, 0) + 1

    if shared_called:
        called_funcs = _ordered_repeated(shared_called, shared_counts) or shared_called
    elif local_called:
        called_funcs = _ordered_repeated(local_called, local_counts) or local_called
    elif fallback_called:
        called_funcs = _ordered_repeated(fallback_called, fallback_counts) or fallback_called
    else:
        called_funcs = _ordered_repeated(harness_called, harness_counts) or harness_called

    if not called_funcs:
        return None

    # Pick the most likely vulnerable function:
    # prefer non-standard-DeFi functions
    primary = _choose_primary(called_funcs)
    if primary is None:
        return None

    location: dict = {"function": primary}

    # Best-effort line number from exploit file (call site of primary function).
    # This is a heuristic anchor for localization when on-chain source line is
    # unavailable in the local dataset.
    call_match = re.search(rf"\.{re.escape(primary)}\s*(?:\(|\{{)", content)
    if call_match:
        location["line"] = content[: call_match.start()].count("\n") + 1

    preferred_containers = (
        local_funcs if primary in local_funcs else {**shared_funcs, **local_funcs}
    )
    location["file"] = _infer_filename(primary, preferred_containers, sol_path)

    return location


def find_function_in_source(
    source_files: dict[str, str],
    function_name: str,
    contract_name: str | None = None,
) -> dict | None:
    """Find a function declaration in source files."""
    if not function_name:
        return None

    pattern = re.compile(rf"function\s+{re.escape(function_name)}\s*\(", re.MULTILINE)

    best_match: dict | None = None

    def _line_num(content: str, offset: int) -> int:
        return content[:offset].count("\n") + 1

    def _find_block_end(content: str, decl_start: int, search_start: int) -> int:
        brace_depth = 0
        pos = search_start
        while pos < len(content):
            ch = content[pos]
            if ch == "{":
                brace_depth += 1
                pos += 1
                break
            if ch == ";":
                return pos
            pos += 1

        while pos < len(content):
            ch = content[pos]
            if ch == "{":
                brace_depth += 1
            elif ch == "}":
                brace_depth -= 1
                if brace_depth == 0:
                    return pos
            pos += 1
        return len(content) - 1 if content else decl_start

    for fname, content in source_files.items():
        for match in pattern.finditer(content):
            line_num = _line_num(content, match.start())
            end_offset = _find_block_end(content, match.start(), match.end())
            end_line = _line_num(content, end_offset)

            is_main = False
            if contract_name:
                is_main = (
                    contract_name.lower() in fname.lower()
                    or fname.replace(".sol", "") == contract_name
                )

            result = {
                "file": fname,
                "function": function_name,
                "line": line_num,
                "line_range": [line_num, end_line],
            }

            if is_main:
                return result
            if best_match is None:
                best_match = result

    return best_match
