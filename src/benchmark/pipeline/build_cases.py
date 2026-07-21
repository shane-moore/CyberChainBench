"""
Build benchmark case files from upstream source data.

Generation strategy:
  1) Parse upstream Clara / DeFiHackLabs data in memory.
  2) Normalize + merge raw cases.
  3) Route each raw case through the unified BenchmarkCurator.
  4) Write review/manual benchmark workspaces.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from agents.curator import build_curator
from benchmark.pipeline.merge_cases import collect_raw_cases
from benchmark.pipeline.task_cases import write_manual_task_index
from benchmark.pipeline.paths import (
    manual_case_path,
    manual_cases_path,
    manual_root,
    review_case_path,
    review_cases_path,
    review_root,
)
from benchmark.schema_utils import validate_task_cases_or_raise


def _write_cases(path: Path, cases: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cases, indent=2, ensure_ascii=False) + "\n")


def _dedupe_cases_by_id(cases: list[dict]) -> list[dict]:
    deduped: dict[str, dict] = {}
    for case in cases:
        case_id = str(case.get("id", "")).strip()
        if not case_id:
            raise ValueError("Task case missing id during benchmark build")
        existing = deduped.get(case_id)
        if existing is None:
            deduped[case_id] = case
            continue
        if existing != case:
            raise ValueError(f"Conflicting duplicate task case for {case_id}")
    return sorted(deduped.values(), key=lambda case: case["id"])


def _write_review_workspace(base_dir: Path, cases: list[dict]) -> None:
    task = "benchmark_case"
    root = base_dir / review_root(task)
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)

    for case in cases:
        out_path = base_dir / review_case_path(task, case)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(case, indent=2, ensure_ascii=False) + "\n")

    _write_cases(base_dir / review_cases_path(task), cases)


def _write_manual_workspace(base_dir: Path, cases: list[dict]) -> None:
    task = "benchmark_case"
    root = base_dir / manual_root(task)
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)

    for case in cases:
        out_path = base_dir / manual_case_path(task, case)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(case, indent=2, ensure_ascii=False) + "\n")

    _write_cases(base_dir / manual_cases_path(task), cases)


def _resolve_build_source(source: str, *, include_clara: bool) -> str:
    normalized = str(source).strip().lower() or "all"
    if normalized == "all" and not include_clara:
        return "defihacklabs"
    return normalized


def _build_cases(
    *,
    raw_cases: list[dict],
    curator,
) -> tuple[list[dict], list[dict]]:
    review_cases: list[dict] = []
    manual_cases: list[dict] = []

    for raw in raw_cases:
        report = curator.build_report(raw)
        suggested_review = report.get("suggested_review_case")
        suggested_manual = report.get("suggested_manual_case")
        if isinstance(suggested_review, dict) and str(suggested_review.get("id", "")).strip():
            review_cases.append(suggested_review)
        if isinstance(suggested_manual, dict) and str(suggested_manual.get("id", "")).strip():
            manual_cases.append(suggested_manual)

    return _dedupe_cases_by_id(review_cases), _dedupe_cases_by_id(manual_cases)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Build benchmark case files")
    parser.add_argument(
        "--source",
        choices=["all", "defihacklabs", "clara"],
        default="all",
    )
    parser.add_argument(
        "--include-clara",
        action="store_true",
        help="Include Clara cases when --source=all. Default build only uses DeFiHackLabs.",
    )
    parser.add_argument("--base-dir", type=Path, default=Path("."))
    parser.add_argument(
        "--emit-raw-cache",
        action="store_true",
        help="Also write parser_preprocessed raw outputs for debugging.",
    )
    args = parser.parse_args()

    base = args.base_dir
    effective_source = _resolve_build_source(args.source, include_clara=bool(args.include_clara))
    all_raw = collect_raw_cases(base, effective_source, emit_parser_output=args.emit_raw_cache)
    print(
        f"Loaded {len(all_raw)} raw cases from upstream sources"
        f" (requested_source={args.source}, include_clara={bool(args.include_clara)}, effective_source={effective_source})"
    )

    curator = build_curator("benchmark_case", base)
    review_cases, manual_cases = _build_cases(
        raw_cases=all_raw,
        curator=curator,
    )

    _write_review_workspace(base, review_cases)
    _write_manual_workspace(base, manual_cases)

    benchmark_cases = write_manual_task_index(base, "benchmark_case")
    validate_task_cases_or_raise("benchmark_case", benchmark_cases)

    print(f"  [benchmark_case]  {len(benchmark_cases):>4} -> data/benchmark/drafts/benchmark_case")


if __name__ == "__main__":
    main()
