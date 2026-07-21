"""Schema helpers for unified benchmark-case validation."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft7Validator

SCHEMA_ROOT = Path(__file__).resolve().parent / "schema"
BENCHMARK_CASE_SCHEMA_PATH = SCHEMA_ROOT / "benchmark_case.schema.json"
TASK_SCHEMAS: dict[str, Path] = {"benchmark_case": BENCHMARK_CASE_SCHEMA_PATH}


@lru_cache(maxsize=None)
def _load_schema(schema_path: str) -> dict:
    return json.loads(Path(schema_path).read_text())


@lru_cache(maxsize=None)
def _get_validator(schema_path: str) -> Draft7Validator:
    schema = _load_schema(schema_path)
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema)


def schema_path_for(task: str = "benchmark_case") -> Path:
    return BENCHMARK_CASE_SCHEMA_PATH


def _format_error(case: dict, index: int, error) -> str:
    case_id = str(case.get("id", f"index:{index}"))
    location = ".".join(str(part) for part in error.absolute_path) or "<root>"
    return f"{case_id}: {location}: {error.message}"


def validate_cases_or_raise(
    cases: list[dict],
    schema_path: Path,
    *,
    label: str,
) -> None:
    validator = _get_validator(str(schema_path.resolve()))
    errors: list[str] = []
    for index, case in enumerate(cases):
        for error in validator.iter_errors(case):
            errors.append(_format_error(case, index, error))

    if not errors:
        return

    preview = "\n".join(errors[:10])
    extra = len(errors) - 10
    if extra > 0:
        preview += f"\n... {extra} more validation errors"
    raise ValueError(
        f"{label} failed schema validation against {schema_path.name}\n{preview}"
    )


def validate_task_cases_or_raise(task: str = "benchmark_case", cases: list[dict] | None = None) -> None:
    validate_cases_or_raise(
        cases or [],
        schema_path_for(),
        label=task,
    )
