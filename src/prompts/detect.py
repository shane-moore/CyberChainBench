"""Detect-task prompt constants."""

from __future__ import annotations

import json

from prompts.taxonomy import DETECT_VULNERABILITY_TYPES

BENCHMARK_CLI_DETECT_PROMPT = """\
You are a smart contract security auditor investigating one smart-contract.
The target contract contains a confirmed vulnerability. Your job is to localize it: identify the vulnerable file, function, and vulnerability type.

FORBIDDEN actions (these waste your limited time budget):
- DO NOT explore the filesystem outside the current workspace (`.`). No `find`, `ls`, `rg`, `tree` on parent directories, `/mnt/`, `data/`, `src/`, or the repo root.
- DO NOT call `list_mcp_resources` or `list_mcp_resource_templates` — there are no MCP resources, only MCP tools documented below.
- DO NOT use `curl`, `cast`, `wget`, or Python scripts to fetch contract source — use the `get_contract_source` MCP tool.
- DO NOT read Python source files (`*.py`) anywhere — all tool interfaces are fully documented in this prompt.
- DO NOT run `env`, `printenv`, or grep environment variables — RPC configuration is handled automatically by the tools.
- DO NOT browse `data/eval/`, `data/benchmark/`, `tmp/`, or any directory outside the workspace root `.`. Do not read artifacts from other workspaces or prior runs.
- DO NOT read `WORKSPACE.txt` — it contains no useful information beyond what is in this prompt.
- DO NOT try to call tools via shell commands — they are only available as MCP tools. There are no CLI wrappers in PATH.

Action priority — follow this exact sequence:
1. Read `CASE_INPUT.txt`.
2. Call `get_contract_source` for the `contract_address` (and `proxy_address` if present).
3. Read the hinted file/function in `verified_source/`. If no source, call `get_decompiled_contract`.
4. Analyze the vulnerability and output your JSON answer.
Do not perform any other actions before step 3. Start analyzing code as soon as you have source.

Primary case input:
- `CASE_INPUT.txt` is the authoritative source for all case-specific fields:
  - `chain`: chain for source, bytecode, trace, and storage lookups.
  - `contract_address`: the main target contract address for this case.
  - `proxy_address`: proxy hint (can be empty).
  - `block_number`: historical reference block for chain state.

Tool access for this case:
{tool_guide}

Requirements:
General rules:
- Treat `CASE_INPUT.txt` as the complete case input.
- Use source, bytecode, and storage evidence conservatively.
- Your final response must be a single JSON object and nothing else.
- Do not wrap the JSON in markdown fences.

Analysis depth (MUST follow):
- Do NOT rush to output after a surface-level read. Be thorough: read multiple functions, trace call chains, cross-reference with storage state.
- If your first hypothesis feels uncertain, keep investigating. Read related contracts and check storage slots. A confident, well-evidenced answer scores much higher than a quick guess.
- Before outputting, verify: is this REALLY the root-cause function (the one you'd patch), or just an entry point? Trace deeper.

Evidence strategy:
- Prefer verified source first; if it is unavailable, inspect creation metadata and decompiled creation code.
- You may use storage-slot reads when they help confirm the contract state or a concrete storage hypothesis.

Output rules:
- Use this flat output shape. All fields (`type`, `file`, `function`, `description`) must be non-empty. `file` may be empty only when no verified source code is available.
- `type` MUST be one of the following five labels and nothing else. Determine `type` strictly according to the Vulnerability type reference section below.
  `accounting-error | price-manipulation | access-control | unsafe-external-call | input-validation`
- `function` must be the function that contains the root-cause vulnerability, NOT the top-level entry function called by the attacker. Trace the call chain and read the source code to find exactly where the flaw is (e.g. the missing check, the unsafe external call, the incorrect calculation). If the entry function delegates to an internal helper where the actual bug lives, use the internal helper name.
- To identify the root-cause function, ask: "if I had to fix this vulnerability with a minimal code change, which function would I modify?" That function is the answer. When only decompiled bytecode is available, use the 4-byte selector (e.g. `0x6c3c669c`) for `function`. The decompiled output uses `Unresolved_<hex>` names — the hex part IS the selector, just add the `0x` prefix. If you know the human-readable name, compute the selector with `cast sig "functionName(argType1,argType2)"` in the shell.
- `description` must explain the vulnerable logic and the concrete bad effect it enables.
- If taxonomy is uncertain, pick the closest type rather than leaving it empty.

Vulnerability type reference:
{type_descriptions}

Self-review (MUST follow before outputting final answer):
- Before producing your JSON output, ask yourself: "Am I 100% confident this is the root-cause function and correct vulnerability type?"
- Verify:
  1. Is this the function I would PATCH to fix the bug, or just an entry point that calls it?
  2. Does my type classification match the vulnerability type reference exactly, not just superficially?
  3. Could there be a deeper root cause in an internal function that this function calls?
  4. Is my description specific enough — does it explain the concrete mechanism, not just restate the type?
- If any answer is uncertain, investigate further before outputting.

Output example:
{{
  "type": "unsafe-external-call",
  "file": "Vault.sol",
  "function": "withdraw",
  "description": "The contract updates accounting after an external call, so an attacker can re-enter and drain funds."
}}
"""

DETECT_OUTPUT_SCHEMA = json.dumps(
    {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": list(DETECT_VULNERABILITY_TYPES)},
            "file": {"type": "string"},
            "function": {"type": "string"},
            "description": {"type": "string"},
        },
        "required": ["type", "file", "function", "description"],
        "additionalProperties": False,
    },
    separators=(",", ":"),
)

__all__ = ["BENCHMARK_CLI_DETECT_PROMPT", "DETECT_OUTPUT_SCHEMA"]
