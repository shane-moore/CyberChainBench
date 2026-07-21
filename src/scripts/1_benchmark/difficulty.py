"""Step 5: Label benchmark cases with difficulty (easy/medium/hard) using LLM.

Reads DeFiHackLabs PoC files and asks an LLM to assess difficulty based on:
- Code complexity (lines, interfaces, steps)
- Whether flash loans are needed
- Number of contracts involved
- Complexity of the vulnerability mechanism

Usage:
    python 1_benchmark/difficulty.py                          # label all unlabeled cases
    python 1_benchmark/difficulty.py --limit 10               # label first 10
    python 1_benchmark/difficulty.py --case bench-234         # label specific case
    python 1_benchmark/difficulty.py --dry-run                # show prompt without calling LLM
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

import click
from openai import OpenAI


CASES_DIR = Path("data/benchmark/cases")
POC_DIR = Path("data/sources/DeFiHackLabs/src/test")

DIFFICULTY_PROMPT = """\
You are a smart contract security expert. Given a Foundry PoC (proof-of-concept) exploit test file, assess the overall difficulty of this vulnerability case.

Rate as: easy, medium, or hard using the following calibration:

**easy** (a competent auditor could write the exploit in <30 minutes):
- Single-step or two-step exploit
- Obvious vulnerability pattern (missing access control, straightforward reentrancy, simple input validation bypass)
- Minimal DeFi protocol knowledge needed
- PoC typically <100 lines, 1-2 external calls

**medium** (requires 30 min to 2 hours for an experienced auditor):
- Multi-step exploit (3-5 steps) requiring understanding of specific DeFi primitives
- Flash loan + price manipulation, or multi-contract interaction
- Requires reading and understanding protocol-specific logic
- PoC typically 100-250 lines, uses flash loans or complex swap routing

**hard** (would take an experienced auditor >2 hours):
- Complex multi-contract attack chain (5+ steps)
- Requires deep understanding of protocol internals (governance, cross-pool accounting, proxy storage layout)
- Non-obvious vulnerability that requires reasoning about state across multiple transactions or complex math
- Sophisticated setup (multiple flash loans, cross-protocol interactions, timing dependencies)
- PoC typically >250 lines or involves highly protocol-specific logic

PoC file:
```solidity
{poc_code}
```

Respond with ONLY a JSON object (no markdown fences):
{{"difficulty": "easy|medium|hard", "reasoning": "1-2 sentence explanation"}}
"""


def find_poc_file(case: dict) -> Path | None:
    """Find the DeFiHackLabs PoC file for a benchmark case."""
    name = case.get("name", "")
    source_id = case.get("source_case_id", "")

    # Try to find by name pattern in PoC directory
    all_pocs = list(POC_DIR.rglob("*_exp.sol")) + list(POC_DIR.rglob("*_exp2.sol"))

    # Normalize name for matching
    name_lower = name.lower().replace(" ", "").replace("-", "").replace("_", "")

    for poc in all_pocs:
        poc_stem = poc.stem.lower().replace("_exp", "").replace("_exp2", "").replace("-", "").replace("_", "")
        if poc_stem and (poc_stem in name_lower or name_lower in poc_stem):
            return poc

    # Fallback: try partial match on first word of name
    first_word = name.split()[0].lower() if name else ""
    if len(first_word) >= 4:
        for poc in all_pocs:
            if first_word in poc.stem.lower():
                return poc

    return None


def label_difficulty(client: OpenAI, poc_code: str, model: str = "gpt-5.4") -> dict:
    """Call LLM to label difficulty."""
    prompt = DIFFICULTY_PROMPT.format(poc_code=poc_code[:15000])  # Truncate very long PoCs

    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=1.0,
        max_tokens=200,
    )

    text = response.choices[0].message.content.strip()
    # Parse JSON from response
    try:
        # Remove markdown fences if present
        text = re.sub(r"^```(?:json)?\s*\n?", "", text)
        text = re.sub(r"\n?```\s*$", "", text)
        return json.loads(text)
    except json.JSONDecodeError:
        return {"error": f"Failed to parse: {text[:100]}"}


@click.command()
@click.option("--limit", "-l", type=int, default=None, help="Max cases to label")
@click.option("--case", "-c", type=str, default=None, help="Specific case id")
@click.option("--model", "-m", type=str, default="gpt-5.4", help="LLM model to use")
@click.option("--dry-run", is_flag=True, help="Show prompt without calling LLM")
@click.option("--force", is_flag=True, help="Re-label already labeled cases")
def main(limit, case, model, dry_run, force):
    """Label benchmark cases with difficulty using LLM."""
    # Load API config
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("LLM_API_KEY", "")
    base_url = os.environ.get("OPENAI_BASE_URL") or os.environ.get("LLM_API_BASE_URL", "http://api.example.com/v1")

    if not api_key and not dry_run:
        print("ERROR: No API key found. Set OPENAI_API_KEY or LLM_API_KEY.")
        return

    client = OpenAI(api_key=api_key, base_url=base_url) if not dry_run else None

    # Load cases
    if case:
        case_files = [CASES_DIR / f"{case}.json"]
    else:
        case_files = sorted(CASES_DIR.glob("bench-*.json"))

    if limit:
        case_files = case_files[:limit]

    labeled = 0
    skipped = 0
    failed = 0

    for cf in case_files:
        if not cf.exists():
            print(f"[SKIP] {cf} not found")
            continue

        data = json.loads(cf.read_text())
        case_id = data.get("id", cf.stem)

        # Skip already labeled unless --force
        if not force and data.get("difficulty") and isinstance(data["difficulty"], str):
            skipped += 1
            continue

        # Find PoC file
        poc_path = find_poc_file(data)
        if not poc_path:
            print(f"[SKIP] {case_id}: no PoC file found for '{data.get('name', '')}'")
            failed += 1
            continue

        poc_code = poc_path.read_text()

        if dry_run:
            print(f"\n{'='*60}")
            print(f"Case: {case_id} ({data.get('name', '')})")
            print(f"PoC: {poc_path} ({len(poc_code)} chars)")
            print("Prompt preview:")
            print(DIFFICULTY_PROMPT.format(poc_code=poc_code[:500] + "\n... [truncated]"))
            labeled += 1
            continue

        # Call LLM
        print(f"  [{case_id}] {data.get('name', ''):<30} ({poc_path.name})...", end=" ", flush=True)
        try:
            result = label_difficulty(client, poc_code, model=model)
        except Exception as e:
            print(f"ERROR: {e}")
            failed += 1
            continue

        if "error" in result:
            print(f"PARSE ERROR: {result['error']}")
            failed += 1
            continue

        # Save to case file
        data["difficulty"] = result.get("difficulty", "unknown")
        data["difficulty_reasoning"] = result.get("reasoning", "")
        cf.write_text(json.dumps(data, indent=2) + "\n")
        labeled += 1
        print(f"{result.get('difficulty', '?')}")

        # Rate limit
        time.sleep(0.5)

    print(f"\nDone: {labeled} labeled, {skipped} skipped, {failed} failed")


if __name__ == "__main__":
    main()
