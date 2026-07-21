#!/usr/bin/env python3
"""Local stdio MCP server exposing workspace tools for AI agent CLIs.

Usage:
    python -m web3mcp.server \
        --workspace /path/to/case/workspace \
        --repo-root /path/to/web3-swe-agent \
        [--task detect|exploit|patch|fix]
"""

from __future__ import annotations

import argparse
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from web3mcp.runtime import (
    TASK_EXPLOIT,
    TASK_TOOL_ALLOWLIST,
    ToolContext,
    execute_tool,
    load_exploit_case_chain,
)

# ---------------------------------------------------------------------------
# Server instance — tools are registered below
# ---------------------------------------------------------------------------

server = FastMCP("web3bug-tools")

# Global context, populated in main() before the server starts.
_ctx: ToolContext | None = None


def _get_ctx() -> ToolContext:
    assert _ctx is not None, "ToolContext not initialised; server must be launched via main()"
    return _ctx


MAX_TOOL_OUTPUT_CHARS = 30_000
_TAIL_CHARS = 2_000


def _run_tool(tool_name: str, args: list[str]) -> str:
    """Common helper: execute a tool and return formatted output."""
    result = execute_tool(tool_name, args, context=_get_ctx())
    if result.returncode != 0:
        parts: list[str] = []
        if result.stderr:
            parts.append(result.stderr.rstrip())
        if result.stdout:
            parts.append(result.stdout.rstrip())
        msg = "\n".join(parts) if parts else f"tool exited with code {result.returncode}"
        raise RuntimeError(msg)
    output = result.stdout.rstrip() if result.stdout else "(no output)"
    if len(output) > MAX_TOOL_OUTPUT_CHARS:
        head = output[: MAX_TOOL_OUTPUT_CHARS - _TAIL_CHARS]
        tail = output[-_TAIL_CHARS:]
        output = (
            head
            + f"\n\n... ({len(result.stdout)} chars total, middle truncated — "
            "use Read on the saved file for full content) ...\n\n"
            + tail
        )
    return output


# ---------------------------------------------------------------------------
# Read tools (Phase 1)
# ---------------------------------------------------------------------------

@server.tool()
async def get_contract_source(
    chain: str,
    address: str,
    output_dir: str = "",
) -> str:
    """Fetch verified source files for a contract from an Etherscan-family explorer.

    Args:
        chain: Normalized chain name, e.g. ethereum or bsc
        address: Target contract address
        output_dir: Optional output directory (relative to workspace)
    """
    args = ["--chain", chain, "--address", address]
    if output_dir:
        args.extend(["--output-dir", output_dir])
    return _run_tool("get_contract_source", args)


@server.tool()
async def get_decompiled_contract(
    chain: str,
    address: str,
    output_dir: str = "",
) -> str:
    """Fetch creation bytecode and decompiled source for a contract.

    Args:
        chain: Normalized chain name, e.g. ethereum or bsc
        address: Target contract address
        output_dir: Output directory for bytecode and decompiled text (relative to workspace)
    """
    args = ["--chain", chain, "--address", address]
    if output_dir:
        args.extend(["--output-dir", output_dir])
    return _run_tool("get_decompiled_contract", args)


@server.tool()
async def get_tx_block(
    chain: str,
    tx_hash: str,
) -> str:
    """Read the block number for a historical transaction.

    Args:
        chain: Normalized chain name, e.g. ethereum or bsc
        tx_hash: Transaction hash
    """
    return _run_tool("get_tx_block", ["--chain", chain, "--tx-hash", tx_hash])


@server.tool()
async def get_tx_trace(
    chain: str,
    tx_hash: str,
    trace_timeout: str = "20s",
) -> str:
    """Trace a historical transaction using debug_traceTransaction.

    Args:
        chain: Normalized chain name, e.g. ethereum or bsc
        tx_hash: Transaction hash
        trace_timeout: RPC trace timeout hint (default: 20s)
    """
    args = ["--chain", chain, "--tx-hash", tx_hash]
    if trace_timeout != "20s":
        args.extend(["--trace-timeout", trace_timeout])
    return _run_tool("get_tx_trace", args)


@server.tool()
async def get_tx_profit(
    chain: str,
    tx_hash: str,
    attacker_address: str = "",
) -> str:
    """Compute the attacker's profit from a historical exploit transaction.

    Args:
        chain: Normalized chain name, e.g. ethereum or bsc
        tx_hash: Transaction hash
        attacker_address: Optional attacker address override (defaults to tx.from)
    """
    args = ["--chain", chain, "--tx-hash", tx_hash]
    if attacker_address:
        args.extend(["--attacker-address", attacker_address])
    return _run_tool("get_tx_profit", args)


@server.tool()
async def get_proxy_context(
    chain: str,
    address: str,
    tx_hash: str,
    trace_timeout: str = "10s",
) -> str:
    """Resolve proxy implementation context for a contract.

    Args:
        chain: Normalized chain name
        address: Target contract address
        tx_hash: Transaction hash for context
        trace_timeout: RPC trace timeout hint (default: 10s)
    """
    args = ["--chain", chain, "--address", address, "--tx-hash", tx_hash]
    if trace_timeout != "10s":
        args.extend(["--trace-timeout", trace_timeout])
    return _run_tool("get_proxy_context", args)


@server.tool()
async def get_storage_slot(
    chain: str,
    address: str,
    slot: str,
    block: int | None = None,
) -> str:
    """Read a raw storage slot from a contract at an optional historical block.

    Args:
        chain: Normalized chain name, e.g. ethereum or bsc
        address: Target contract address
        slot: Storage slot index as hex or decimal
        block: Optional historical block number
    """
    args = ["--chain", chain, "--address", address, "--slot", slot]
    if block is not None:
        args.extend(["--block", str(block)])
    return _run_tool("get_storage_slot", args)


@server.tool()
async def eth_call(
    chain: str,
    to: str,
    data: str,
    block: str = "latest",
) -> str:
    """Execute a read-only eth_call against a contract (view/pure functions).

    Args:
        chain: Normalized chain name, e.g. ethereum or bsc
        to: Contract address
        data: Calldata hex (e.g. 0x70a08231000...)
        block: Block number or 'latest' (default: latest)
    """
    args = ["--chain", chain, "--to", to, "--data", data]
    if block != "latest":
        args.extend(["--block", block])
    return _run_tool("eth_call", args)


@server.tool()
async def write_report(
    task: str,
    output_path: str = "",
    summary: str = "",
    blocker: str = "",
    vulnerable: bool | None = None,
    type: str = "",
    file: str = "",
    function: str = "",
    description: str = "",
    poc_written: bool | None = None,
    validation_passed: bool | None = None,
    exploit_path: str = "",
    fixable: bool | None = None,
    proxy_address: str = "",
    rationale: str = "",
    fixed_contract_path: str = "",
) -> str:
    """Write a validated task report JSON to disk.

    Args:
        task: Task type (detect, exploit, or fix)
        output_path: Output file path (relative to workspace)
        summary: Optional summary text
        blocker: Optional blocker text
        vulnerable: (detect) Whether a vulnerability was found
        type: (detect) Vulnerability type
        file: (detect) Affected file
        function: (detect) Affected function
        description: (detect) Vulnerability description
        poc_written: (exploit) Whether a PoC was written
        validation_passed: (exploit) Whether validation passed
        exploit_path: (exploit) Path to exploit file
        fixable: (fix) Whether the vulnerability is fixable
        proxy_address: (fix) Proxy contract address
        rationale: (fix) Fix rationale
        fixed_contract_path: (fix) Path to the fixed contract
    """
    args = ["--task", task]
    if output_path:
        args.extend(["--output-path", output_path])
    if summary:
        args.extend(["--summary", summary])
    if blocker:
        args.extend(["--blocker", blocker])
    # detect fields
    if vulnerable is not None:
        args.extend(["--vulnerable", str(vulnerable).lower()])
    if type:
        args.extend(["--type", type])
    if file:
        args.extend(["--file", file])
    if function:
        args.extend(["--function", function])
    if description:
        args.extend(["--description", description])
    # exploit fields
    if poc_written is not None:
        args.extend(["--poc-written", str(poc_written).lower()])
    if validation_passed is not None:
        args.extend(["--validation-passed", str(validation_passed).lower()])
    if exploit_path:
        args.extend(["--exploit-path", exploit_path])
    # fix fields
    if fixable is not None:
        args.extend(["--fixable", str(fixable).lower()])
    if proxy_address:
        args.extend(["--proxy-address", proxy_address])
    if rationale:
        args.extend(["--rationale", rationale])
    if fixed_contract_path:
        args.extend(["--fixed-contract-path", fixed_contract_path])
    return _run_tool("write_report", args)


# ---------------------------------------------------------------------------
# Validation tools (Phase 2)
# ---------------------------------------------------------------------------

@server.tool()
async def run_exploit_test(
    case_id: str,
    exploit_path: str,
    artifact_dir: str = "",
    json_output: str = "",
    execution_project: str = "",
) -> str:
    """Run a Foundry exploit test against a benchmark case.

    Args:
        case_id: Exploit benchmark case id
        exploit_path: Path to the exploit .sol file (relative to workspace)
        artifact_dir: Optional artifact output directory (relative to workspace)
        json_output: Optional JSON output path (relative to workspace)
        execution_project: Optional execution project override (empty or source_project)
    """
    args = ["--case-id", case_id, "--exploit-path", exploit_path]
    if artifact_dir:
        args.extend(["--artifact-dir", artifact_dir])
    if json_output:
        args.extend(["--json-output", json_output])
    if execution_project:
        args.extend(["--execution-project", execution_project])
    return _run_tool("run_exploit_test", args)


@server.tool()
async def validate_exploit(
    case_id: str,
    exploit_path: str,
    artifact_dir: str = "",
) -> str:
    """Validate an exploit file against a benchmark exploit case.

    Args:
        case_id: Exploit benchmark case id
        exploit_path: Path to the exploit .sol file (relative to workspace)
        artifact_dir: Optional artifact output directory (relative to workspace)
    """
    args = ["--case-id", case_id, "--exploit-path", exploit_path]
    if artifact_dir:
        args.extend(["--artifact-dir", artifact_dir])
    return _run_tool("validate_exploit", args)


@server.tool()
async def validate_patch(
    case_id: str,
    fixed_path: str,
    artifact_dir: str = "",
    fix_possible: bool | None = None,
    required_authority: str = "",
    confidence: str = "",
    rationale: str = "",
    target_contracts: list[str] | None = None,
    skip_attack_tx_replay: bool = False,
    attack_tx_hashes: list[str] | None = None,
    attack_tx_limit: int = 3,
    attack_tx_timeout: int = 300,
    skip_normal_tx_replay: bool = False,
    normal_tx_hashes: list[str] | None = None,
    normal_tx_limit: int = 3,
    normal_tx_search_offset: int = 25,
    normal_tx_timeout: int = 300,
) -> str:
    """Validate a patched contract against the original attack and benign transactions.

    Args:
        case_id: Patch benchmark case id
        fixed_path: Path to the patched .sol file (relative to workspace)
        artifact_dir: Optional artifact output directory (relative to workspace)
        fix_possible: Optional boolean remediation flag
        required_authority: Optional remediation authority hint
        confidence: Optional remediation confidence
        rationale: Optional remediation rationale
        target_contracts: Optional target contract or address hints
        skip_attack_tx_replay: Skip replaying historical attack transactions
        attack_tx_hashes: Specific historical attack transaction hashes to replay
        attack_tx_limit: Max attack transactions to replay (default: 3)
        attack_tx_timeout: Per-transaction forge timeout for attack tx replay (default: 300)
        skip_normal_tx_replay: Skip replaying recent benign historical transactions
        normal_tx_hashes: Specific benign historical transaction hashes to replay
        normal_tx_limit: Max normal transactions to replay (default: 3)
        normal_tx_search_offset: How many recent transactions to scan (default: 25)
        normal_tx_timeout: Per-transaction forge timeout for normal tx replay (default: 300)
    """
    args = ["--case-id", case_id, "--fixed-path", fixed_path]
    if artifact_dir:
        args.extend(["--artifact-dir", artifact_dir])
    if fix_possible is not None:
        args.extend(["--patch-possible", str(fix_possible).lower()])
    if required_authority:
        args.extend(["--required-authority", required_authority])
    if confidence:
        args.extend(["--confidence", confidence])
    if rationale:
        args.extend(["--rationale", rationale])
    for tc in target_contracts or []:
        args.extend(["--target-contract", tc])
    if skip_attack_tx_replay:
        args.append("--skip-attack-tx-replay")
    for txh in attack_tx_hashes or []:
        args.extend(["--attack-tx-hash", txh])
    if attack_tx_limit != 3:
        args.extend(["--attack-tx-limit", str(attack_tx_limit)])
    if attack_tx_timeout != 300:
        args.extend(["--attack-tx-timeout", str(attack_tx_timeout)])
    if skip_normal_tx_replay:
        args.append("--skip-normal-tx-replay")
    for txh in normal_tx_hashes or []:
        args.extend(["--normal-tx-hash", txh])
    if normal_tx_limit != 3:
        args.extend(["--normal-tx-limit", str(normal_tx_limit)])
    if normal_tx_search_offset != 25:
        args.extend(["--normal-tx-search-offset", str(normal_tx_search_offset)])
    if normal_tx_timeout != 300:
        args.extend(["--normal-tx-timeout", str(normal_tx_timeout)])
    return _run_tool("validate_patch", args)


# Backwards-compatible alias: validate_fix still works for old agents
validate_fix = validate_patch


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Web3Bug MCP tool server")
    parser.add_argument(
        "--workspace", type=Path, required=True,
        help="Case workspace root (all agent path args are resolved relative to this)",
    )
    parser.add_argument(
        "--repo-root", type=Path, required=True,
        help="Project repository root (contains src/)",
    )
    parser.add_argument(
        "--task", choices=["detect", "exploit", "patch", "fix", "fill"], default=None,
        help="Task type for task-specific restrictions",
    )
    args = parser.parse_args()

    workspace = args.workspace.resolve()
    repo_root = args.repo_root.resolve()
    task_type = args.task  # plain string or None

    allowed_chain = ""
    if task_type == TASK_EXPLOIT:
        allowed_chain = load_exploit_case_chain(workspace)

    global _ctx
    _ctx = ToolContext(
        repo_root=repo_root,
        workspace_root=workspace,
        task_type=task_type,
        allowed_exploit_chain=allowed_chain,
    )

    if task_type and task_type in TASK_TOOL_ALLOWLIST:
        allowed = TASK_TOOL_ALLOWLIST[task_type]
        for name in list(server._tool_manager._tools):
            if name not in allowed:
                server.remove_tool(name)

    server.run(transport="stdio")


if __name__ == "__main__":
    main()
