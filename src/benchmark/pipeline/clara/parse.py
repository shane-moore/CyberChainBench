"""
Extract detect-oriented benchmark cases from the local Clara snapshot.

Input:
  data/sources/Clara/incidents.jsonl
  data/sources/Clara/raw/incidents/*.html

Optional output:
  data/sources/preprocessed/clara/<category>/<case_id>.json
  data/sources/preprocessed/clara/case_links.json

This parser is intentionally conservative. A Clara incident is included only if:
  - the page is public
  - the incident is classified as ATTACK
  - Clara marked it as manually validated
  - a main Solidity code-analysis block can be extracted
  - a likely target function can be inferred from the root-cause text

The resulting Clara cases are currently suitable for the detect task only.
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

from project_layout import CLARA_DIR, PARSER_PREPROCESSED_DIR, UPSTREAM_DIR

CHAIN_MAP: dict[str, str] = {
    "ethereum": "ethereum",
    "bsc": "bsc",
    "bnb chain": "bsc",
    "base": "base",
    "arbitrum": "arbitrum",
    "polygon": "polygon",
    "optimism": "optimism",
    "avalanche": "avalanche",
    "fantom": "fantom",
}


def _load_rows(dataset_root: Path) -> list[dict]:
    manifest = dataset_root / "incidents.jsonl"
    if not manifest.exists():
        raise FileNotFoundError(f"Clara snapshot not found: {manifest}")
    return [
        json.loads(line)
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _extract_code_analysis_html(raw_html: str) -> str | None:
    needle = 'dangerouslySetInnerHTML\\":{\\"__html\\":\\"$'
    start = raw_html.find(needle)
    if start == -1:
        return None
    token_start = start + len(needle)
    token_end = raw_html.find('\\"', token_start)
    if token_end == -1:
        return None
    token = raw_html[token_start:token_end]
    token_idx = raw_html.find(f"{token}:T")
    if token_idx == -1:
        return None

    marker = 'self.__next_f.push([1,"'
    payload_start = raw_html.find(marker, token_idx)
    if payload_start == -1:
        return None
    payload_end = raw_html.find('"]) </script>', payload_start)
    if payload_end == -1:
        payload_end = raw_html.find('"])</script>', payload_start)
    if payload_end == -1:
        return None

    encoded = raw_html[payload_start + len(marker) : payload_end]
    try:
        decoded = json.loads(f'"{encoded}"')
    except json.JSONDecodeError:
        return None
    return html.unescape(decoded)


def _highlighted_html_to_code(highlighted_html: str | None) -> str | None:
    if not highlighted_html:
        return None

    code = re.sub(r"<[^>]+>", "", highlighted_html)
    code = html.unescape(code)
    lines = [line.rstrip() for line in code.splitlines()]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    text = "\n".join(lines).strip()
    return text or None


def _extract_target_function(root_cause_text: str, code_text: str | None) -> str | None:
    if not root_cause_text and not code_text:
        return None

    title_zone = root_cause_text.splitlines()[0] if root_cause_text else ""
    zone = root_cause_text or ""
    root_cause_match = re.search(
        r"Root cause:(.{0,1400})", root_cause_text, re.IGNORECASE | re.DOTALL
    )
    if root_cause_match:
        zone = root_cause_match.group(1)

    generic_names = {
        "allowance",
        "approve",
        "balanceOf",
        "borrow",
        "execute",
        "getContractBalance",
        "getReserves",
        "getSignaturesWeight",
        "owner",
        "setUp",
        "swap",
        "sync",
        "testExploit",
        "token0",
        "token1",
        "transfer",
        "transferFrom",
    }
    generic_lower = {entry.lower() for entry in generic_names}

    declared: set[str] = set()
    if code_text:
        declared.update(re.findall(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", code_text))
        if re.search(r"\bconstructor\s*\(", code_text):
            declared.add("constructor")
        if re.search(r"\bfallback\s*\(", code_text):
            declared.add("fallback")
        if re.search(r"\breceive\s*\(", code_text):
            declared.add("receive")

    if re.search(r"\bconstructor\b", title_zone, re.IGNORECASE):
        return "constructor"
    if re.search(r"\bfallback\b", title_zone, re.IGNORECASE):
        return "fallback"
    if re.search(r"\breceive\b", title_zone, re.IGNORECASE):
        return "receive"

    backticked = re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)\s*\([^`]*\)`", zone)
    for name in backticked:
        if name.lower() not in generic_lower or re.search(
            rf"\b{re.escape(name)}\b", title_zone, re.IGNORECASE
        ):
            return name

    if declared:
        title_matches = []
        for name in declared:
            if re.search(rf"\b{re.escape(name)}\b", title_zone, re.IGNORECASE):
                penalty = 1 if name.lower() in generic_lower else 0
                title_matches.append((penalty, title_zone.lower().find(name.lower()), name))
        if title_matches:
            title_matches.sort()
            return title_matches[0][2]

    return None


def _extract_function_line(code_text: str | None, function_name: str | None) -> int | None:
    if not code_text or not function_name:
        return None
    if function_name in {"constructor", "fallback", "receive"}:
        match = re.search(rf"\b{re.escape(function_name)}\s*\(", code_text)
    else:
        match = re.search(rf"\bfunction\s+{re.escape(function_name)}\s*\(", code_text)
    if not match:
        return None
    return code_text[: match.start()].count("\n") + 1


def _infer_category(title: str, description: str, root_cause_text: str) -> str:
    root_cause_excerpt = root_cause_text
    match = re.search(r"Root cause:(.{0,1000})", root_cause_text, re.IGNORECASE | re.DOTALL)
    if match:
        root_cause_excerpt = match.group(1)
    text = " ".join(filter(None, [title, root_cause_excerpt])).lower()

    if "reentr" in text:
        return "reentrancy"
    if "flash-loan" in text or "flash loan" in text or "flash-swap" in text or "flash swap" in text:
        return "flash-loan"
    if "oracle" in text:
        return "oracle-manipulation"
    if "overflow" in text or "underflow" in text:
        return "integer-overflow"
    if "unchecked call" in text or ("unchecked" in text and "call" in text):
        return "unchecked-call"
    if any(
        phrase in text
        for phrase in [
            "access control",
            "access-control",
            "admin role",
            "authentication bypass",
            "auth bypass",
            "authorization bypass",
            "defaultadminrole",
            "improper authorization",
            "initialization race",
            "initialize race",
            "missing authorization",
            "onlyowner",
            "owner-only",
            "role check",
            "tx.origin",
            "uups takeover",
            "unauthorized",
        ]
    ):
        return "access-control"
    return "logic-error"


def _infer_chain(row: dict) -> str:
    for candidate in row.get("blockchains") or []:
        key = str(candidate).strip().lower()
        if key in CHAIN_MAP:
            return CHAIN_MAP[key]

    text = " ".join(
        filter(
            None,
            [
                row.get("title", ""),
                row.get("page_description", ""),
                row.get("root_cause_text", ""),
            ],
        )
    ).lower()
    for key, value in CHAIN_MAP.items():
        if key in text:
            return value
    return "ethereum"


def _build_description(row: dict) -> str:
    source = row.get("root_cause_text") or row.get("page_description") or row.get("title") or ""
    text = re.sub(r"\s+", " ", source).strip()
    title = (row.get("title") or "").strip()
    if title and text.lower().startswith(title.lower()):
        text = text[len(title) :].lstrip(" :-")
    return text[:900]


def _select_rows(rows: list[dict]) -> list[dict]:
    selected: list[dict] = []
    for row in rows:
        if row.get("page_locked"):
            continue
        if row.get("incident_classification") != "ATTACK":
            continue
        if not row.get("manual_validated"):
            continue
        selected.append(row)
    return selected


def _write_output(output_dir: Path, cases: list[dict]) -> None:
    if output_dir.exists():
        for stale_json in output_dir.rglob("*.json"):
            stale_json.unlink()
    output_dir.mkdir(parents=True, exist_ok=True)
    by_category: dict[str, list[dict]] = {}
    for case in cases:
        by_category.setdefault(case["category"], []).append(case)

    for category, cat_cases in by_category.items():
        cat_dir = output_dir / category
        cat_dir.mkdir(parents=True, exist_ok=True)
        for case in cat_cases:
            (cat_dir / f"{case['id']}.json").write_text(
                json.dumps(case, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

    (output_dir / "case_links.json").write_text(
        json.dumps(sorted(cases, key=lambda item: item["id"]), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def extract_all(dataset_root: Path, output_dir: Path | None = None) -> list[dict]:
    rows = _load_rows(dataset_root)
    candidate_rows = _select_rows(rows)
    code_dir = dataset_root / "code_analysis"
    code_dir.mkdir(parents=True, exist_ok=True)
    for stale_code in code_dir.glob("clr-*.sol"):
        stale_code.unlink()

    cases: list[dict] = []
    skipped_no_code = 0
    skipped_no_function = 0
    blocked_ground_truth = {
        "allowance",
        "assert",
        "balanceOf",
        "getContractBalance",
        "getReserves",
        "getSignaturesWeight",
        "isContract",
        "owner",
        "require",
        "setUp",
        "testExploit",
        "token0",
        "token1",
        "transfer",
    }

    for row in candidate_rows:
        raw_html_path = row.get("raw_html_path")
        if not raw_html_path:
            skipped_no_code += 1
            continue

        raw_html_file = Path(raw_html_path)
        if not raw_html_file.exists():
            fallback = dataset_root / "raw" / "incidents" / raw_html_file.name
            if fallback.exists():
                raw_html_file = fallback
        if not raw_html_file.exists():
            skipped_no_code += 1
            continue

        raw_html = raw_html_file.read_text(encoding="utf-8")
        highlighted_html = _extract_code_analysis_html(raw_html)
        code_text = _highlighted_html_to_code(highlighted_html)
        if not code_text:
            skipped_no_code += 1
            continue

        function_name = _extract_target_function(row.get("root_cause_text", ""), code_text)
        if not function_name:
            skipped_no_function += 1
            continue
        if function_name.startswith("Unresolved_") or re.fullmatch(
            r"[0-9a-fA-F]{8,}", function_name
        ):
            skipped_no_function += 1
            continue
        if function_name.lower() in {name.lower() for name in blocked_ground_truth}:
            skipped_no_function += 1
            continue

        incident_id = row["public_incident_id"]
        case_id = f"clr-{incident_id[:8]}"
        code_rel_path = UPSTREAM_DIR / "Clara" / "code_analysis" / f"{case_id}.sol"
        code_abs_path = dataset_root / "code_analysis" / f"{case_id}.sol"
        code_abs_path.write_text(code_text.rstrip() + "\n", encoding="utf-8")

        line_num = _extract_function_line(code_text, function_name)
        title = row.get("title") or incident_id
        description = _build_description(row)
        category = _infer_category(
            title, row.get("page_description", ""), row.get("root_cause_text", "")
        )
        chain = _infer_chain(row)
        report_date = row.get("incident_time") or row.get("page_published_time") or ""
        date_only = report_date.split("T", 1)[0] if report_date else ""

        case = {
            "id": case_id,
            "name": title,
            "source": "Clara",
            "category": category,
            "severity": "high",
            "chain": chain,
            "date": date_only,
            "report_date": report_date,
            "loss": row.get("loss_badge") or "",
            "contracts": {
                "vulnerable": [str(code_rel_path)],
                "vulnerable_address": (row.get("victim_addresses") or [""])[0],
            },
            "description": description,
            "report_section": row.get("root_cause_text", ""),
            "reference": row.get("page_url", ""),
            "vulnerability_detail": {
                "root_cause": row.get("root_cause_text", ""),
                "impact": row.get("loss_badge", ""),
            },
            "tasks": {
                "detect": {
                    "expected_type": category,
                    "expected_location": {
                        "file": str(code_rel_path),
                        "function": function_name,
                        "line": line_num,
                    },
                },
                "patch": {
                    "fix_description": row.get("root_cause_text", "")[:1200],
                },
            },
            "clara": {
                "incident_id": incident_id,
                "page_url": row.get("page_url", ""),
                "page_description": row.get("page_description", ""),
                "window_label": row.get("window_label", ""),
                "tx_hashes": row.get("tx_hashes", []),
                "victim_addresses": row.get("victim_addresses", []),
                "manual_validated": row.get("manual_validated", False),
            },
        }
        cases.append(case)

    if output_dir is not None:
        _write_output(output_dir, cases)

    print(f"[Clara] Candidate rows: {len(candidate_rows)}")
    print(f"[Clara] Extracted cases: {len(cases)}")
    print(f"[Clara] Skipped (no code block): {skipped_no_code}")
    print(f"[Clara] Skipped (no target function): {skipped_no_function}")
    by_category: dict[str, int] = {}
    for case in cases:
        by_category[case["category"]] = by_category.get(case["category"], 0) + 1
    print(
        "[Clara] Categories: "
        + ", ".join(f"{cat}({count})" for cat, count in sorted(by_category.items()))
    )
    return sorted(cases, key=lambda item: item["id"])


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract detect benchmark cases from Clara snapshot"
    )
    parser.add_argument("--dataset-root", type=Path, default=CLARA_DIR)
    parser.add_argument("--output", type=Path, default=PARSER_PREPROCESSED_DIR / "clara")
    args = parser.parse_args()

    extract_all(args.dataset_root, args.output)


if __name__ == "__main__":
    main()
