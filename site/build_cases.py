#!/usr/bin/env python3
"""Build site/assets/cases.json from data/benchmark/cases/*.json.

Extracts only the fields the Case Explorer UI needs, keeping the payload small.
Run from the repo root:  python3 site/build_cases.py
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = ROOT / "data" / "benchmark" / "cases"
OUT = ROOT / "site" / "assets" / "cases.json"

KEEP = [
    "id", "name", "chain", "type", "difficulty", "attacker_profit",
    "attack_date", "fixable", "has_public_source", "vulnerable_address",
    "function", "file", "case_link", "fix_description", "difficulty_reasoning",
]

# Cases excluded from evaluation (and therefore from the site), keeping the
# count aligned with the paper's 541. bench-211 could not be run.
EXCLUDE = {"bench-211"}


def main() -> None:
    cases = []
    for path in sorted(CASES_DIR.glob("*.json")):
        with path.open() as fh:
            raw = json.load(fh)
        if raw.get("id") in EXCLUDE:
            continue
        row = {k: raw.get(k) for k in KEEP}
        # Cases without an auto-assigned difficulty (no PoC to label from) default to easy.
        if (row.get("difficulty") or "unknown") == "unknown":
            row["difficulty"] = "easy"
        cases.append(row)

    # Sort by attacker profit descending so the table opens on the biggest hacks.
    cases.sort(key=lambda c: c.get("attacker_profit") or 0, reverse=True)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w") as fh:
        json.dump(cases, fh, separators=(",", ":"), ensure_ascii=False)
    print(f"wrote {len(cases)} cases -> {OUT.relative_to(ROOT)} ({OUT.stat().st_size//1024} KB)")


if __name__ == "__main__":
    main()
