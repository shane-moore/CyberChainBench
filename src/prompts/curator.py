"""Curator prompt constants."""

from __future__ import annotations

from prompts.taxonomy import VULNERABILITY_TYPE_DESCRIPTIONS


def render_type_descriptions() -> str:
    """Render vulnerability type descriptions for prompt injection."""
    lines = ["- Vulnerability type definitions (use these to decide the `type` field):"]
    for label, desc in VULNERABILITY_TYPE_DESCRIPTIONS.items():
        first_line = desc.split("\n")[0]
        lines.append(f"  - `{label}`: {first_line}")
    return "\n".join(lines)


CURATOR_PROMPT = """\
You are curating one canonical incident record for a smart-contract security incident.
Your job is to read the input case, use the supplied evidence conservatively, and propose field-level updates for the canonical output.

Primary case input:
- Read `CASE_INPUT.txt` first.
- Treat `CASE_INPUT.txt` as the authoritative source for the input case, canonical output snapshot, and case materials.
- If any other prompt text conflicts with `CASE_INPUT.txt`, follow `CASE_INPUT.txt`.
- Interpret the common fields in `CASE_INPUT.txt` as follows:
  - `chain`: the chain to use for source, trace, profit, and proxy lookups.
  - `vulnerable_address`: the main target contract address for this case.
  - `attack_txs`: historical incident transactions to inspect with transaction tools.
  - `block_number`: the historical reference block for on-chain lookups.

Tool access for this case:
{tool_guide}
- Read local staged source under `verified_source/local_input/` first when it exists.
- Use `verified_source/` for fetched source, `runtime_artifacts/` for decompilation output, and `validation_artifacts/` for validation artifacts.
- To fetch a URL, use WebFetch if available, otherwise use `curl` in the shell. To search the web, use the built-in web search if available, or try `curl 'https://html.duckduckgo.com/html/?q=<query>'`.

Requirements:
General rules:
- Use the input case plus case materials to propose the canonical output.
- Try to fill as many canonical fields as possible.
- Focus first on fields that are missing, weakly specified, or strongly contradicted by the materials.
- Do not invent facts that are absent from the case and attached evidence.
- Prefer exact field-level updates over vague summaries.
- Do not restate a value that is already present in the current canonical output unless you are replacing it with a stronger value.
- If no field can be improved confidently, return the current canonical output unchanged in `proposed_case` and say so explicitly in `summary`.
- Do not modify `description`.

Canonical schema:
- The `type` field MUST be one of the following five labels and nothing else:
  `accounting-error | price-manipulation | access-control | unsafe-external-call | input-validation`
- Produce one flat canonical case using these top-level fields only:
  `case_link`, `attack_txs`, `chain`, `block_number`, `vulnerable_address`, `has_public_source`, `fixable`, `proxy_address`, `file`, `function`, `type`, `attacker_profit`.
- `has_public_source` and `fixable` are boolean fields.

Evidence and transaction selection:
- Leave a field null only after you have tried the relevant tools and still cannot justify a value.
- If the case materials contain `reference_urls`, fetch each URL before deciding `type`, `file`, and `function`. Twitter/X links always fail — when that happens, search the web for this case's attack analysis (e.g. audit reports, post-mortems, blog posts) and read at least 2 external results before proceeding.
- You MUST find and read at least one external article, audit report, or post-mortem about this incident before deciding `type`, `file`, and `function`. Do not rely solely on source code and traces — external analysis often identifies the root cause more precisely. Search for the protocol name + "audit report", "exploit analysis", or "post-mortem". Also try searching for the contract name + "vulnerability".
- Determine `attack_txs` yourself by reading the case link, case materials, and any staged files. Do not assume the pipeline has already selected the correct attack transaction.
- Choose one concrete attack transaction first before using transaction tools.
- When an exploit path or staged reference text is present, read it before concluding that fields are unknown.
- If `has_public_source` is `false`, `file` may remain null. For `function`, you MUST write a 4-byte selector (e.g. `0x6c3c669c`) as the `function` value — human-readable names are NOT accepted when `has_public_source` is `false`.
  - The decompiled output uses `Unresolved_<hex>` names — the hex part IS the selector, just add the `0x` prefix (e.g. `Unresolved_6c3c669c` → `0x6c3c669c`).
  - If you know the human-readable function name (e.g. from articles or traces), compute its selector with `cast sig "functionName(argType1,argType2)"` in the shell, which returns the 4-byte selector. Use that selector as the `function` value.
  - Do NOT use human-readable function names from the reference exploit interface — the eval agent cannot see that interface and will only have access to the raw bytecode.

Tool workflow:
- FIRST: If `reference_urls` is non-empty, fetch each URL. Twitter/X links always fail — when that happens, search the web (use DuckDuckGo lite) for attack analysis, audit reports, or post-mortems about this case. You must read external material before deciding `type`, `file`, and `function`.
- Use `get_tx_block` on the **first (earliest)** attack transaction to fill `block_number`. The eval harness forks at this block, so it must be the block of the first attack tx to ensure a clean pre-attack state.
- Then use `get_tx_trace` to identify the vulnerable contract address in the attack path. The trace shows the attacker's entry point and call chain — use it to narrow down which contract and function to investigate, but do not stop there.
- Then use `get_tx_profit` to fill `attacker_profit`. IMPORTANT: use the `attacker_profit` field from the response — this is the profit in USD. Do NOT use `token_amounts` (raw token quantity) or `attacker_profit_native` (native coin before USD conversion).
- If `get_tx_profit` returns `attacker_profit = 0`, write `0` in `proposed_case`. Use `null` only when the lookup itself did not resolve.
- NEVER estimate or calculate `attacker_profit` yourself from articles, exploit code, or any other source. The ONLY acceptable source for `attacker_profit` is the `get_tx_profit` tool response. If the tool returns 0 or null, use that value as-is.
- Then use `get_proxy_context` to fill `fixable` and `proxy_address`.
- If `get_proxy_context` shows the vulnerable contract is actually the proxy, swap `vulnerable_address` to the implementation and put the proxy in `proxy_address`.
- After those fields are grounded, localize `file`, `function`, and `type` from trace evidence and materials. Determine `type` strictly according to the Vulnerability type reference section below.
- IMPORTANT: `function` must be the function that contains the root-cause vulnerability, NOT the top-level entry function called by the attacker. Trace the call chain from the attack transaction and read the source code to find exactly where the flaw is (e.g. the missing check, the unsafe external call, the incorrect calculation). If the entry function delegates to an internal helper where the actual bug lives, use the internal helper name.
- To identify the root-cause function, ask yourself: "if I had to fix this vulnerability with a minimal code change, which function would I modify?" The function you would patch is the one that contains the vulnerability.
- Do not use `get_tx_trace` to decide `fixable` or `proxy_address`; use `get_proxy_context`.
- Use `get_storage_slot` only when storage inspection is actually needed.

Reporting:
- Before you finish, write `report.json` with `write_report` and keep it consistent with your final answer.
- If you cannot justify an attack transaction from the materials, leave `attack_txs` and `attacker_profit` empty rather than guessing.
- Keep `summary` factual. Do not claim you derived evidence unless the corresponding field is actually populated.

Vulnerability type reference:
{type_descriptions}

Self-check before returning:
- If `attack_txs` is non-empty but `attacker_profit` is null, re-run `get_tx_profit`.
- If `attack_txs` is non-empty but `block_number` is null, re-run `get_tx_block`.
- If `vulnerable_address` is non-empty but `fixable` is null, re-run `get_proxy_context`.
- If `has_public_source` is true but `file` is null, attempt `get_contract_source` or re-check staged source.

Return exactly one JSON object matching this schema:
{output_schema}

Output example:
{{
  "summary": "Added the canonical attack transaction and recorded attacker_profit from that tx.",
  "proposed_case": {{
    "case_link": "https://github.com/...",
    "attack_txs": ["0xabc..."],
    "chain": "ethereum",
    "block_number": 12345678,
    "vulnerable_address": "0x123...",
    "has_public_source": true,
    "fixable": false,
    "proxy_address": null,
    "file": "Vault.sol",
    "function": "withdraw",
    "type": "accounting-error",
    "attacker_profit": 12.34
  }}
}}
"""

CURATOR_SCHEMA = """{
  "type": "object",
  "properties": {
    "summary": {"type": "string"},
    "proposed_case": {
      "type": "object",
      "properties": {
        "case_link": {"type": ["string", "null"]},
        "attack_txs": {"type": ["array", "null"], "items": {"type": "string"}},
        "chain": {"type": ["string", "null"]},
        "block_number": {"type": ["integer", "null"]},
        "vulnerable_address": {"type": ["string", "null"]},
        "has_public_source": {"type": ["boolean", "null"]},
        "fixable": {"type": ["boolean", "null"]},
        "proxy_address": {"type": ["string", "null"]},
        "file": {"type": ["string", "null"]},
        "function": {"type": ["string", "null"]},
        "type": {"type": ["string", "null"], "enum": ["accounting-error", "price-manipulation", "access-control", "unsafe-external-call", "input-validation", null]},
        "attacker_profit": {"type": ["number", "integer", "null"]}
      },
      "required": ["case_link", "attack_txs", "chain", "block_number", "vulnerable_address", "has_public_source", "fixable", "proxy_address", "file", "function", "type", "attacker_profit"],
      "additionalProperties": false
    }
  },
  "required": ["summary", "proposed_case"],
  "additionalProperties": false
}
"""

__all__ = ["CURATOR_PROMPT", "CURATOR_SCHEMA"]
