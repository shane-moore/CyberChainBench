"""Shared path helpers for generated benchmark data."""

from __future__ import annotations

from pathlib import Path

from project_layout import BENCHMARK_DRAFT_DIR, PARSER_PREPROCESSED_DIR

RAW_ALL_CASES_PATH = PARSER_PREPROCESSED_DIR / "all_cases.json"
BENCHMARK_CASE_INPUT_DIR = BENCHMARK_DRAFT_DIR / "benchmark_case_inputs"
BENCHMARK_CASE_OUTPUT_DIR = BENCHMARK_DRAFT_DIR / "benchmark_case"


def review_root(task: str = "benchmark_case") -> Path:
    return BENCHMARK_CASE_INPUT_DIR


def review_cases_path(task: str = "benchmark_case") -> Path:
    return review_root() / "cases.json"


def review_case_path(task: str = "benchmark_case", case: dict | None = None) -> Path:
    case_id = str(case["id"]).strip()  # type: ignore[index]
    return review_root() / f"{case_id}.json"


def manual_root(task: str = "benchmark_case") -> Path:
    return BENCHMARK_CASE_OUTPUT_DIR


def manual_cases_path(task: str = "benchmark_case") -> Path:
    return manual_root() / "cases.json"


def manual_case_path(task: str = "benchmark_case", case: dict | None = None) -> Path:
    source = str(case.get("source", "")).strip().lower().replace(" ", "-") or "unknown"  # type: ignore[union-attr]
    case_id = str(case["id"]).strip()  # type: ignore[index]
    return manual_root() / source / f"{case_id}.json"
