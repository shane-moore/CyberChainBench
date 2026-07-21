from __future__ import annotations

from pathlib import Path, PurePosixPath

DATA_DIR = Path("data")
TMP_DIR = Path("tmp")
BENCHMARK_DIR = DATA_DIR / "benchmark"
BENCHMARK_CASES_DIR = BENCHMARK_DIR / "cases"
BENCHMARK_DRAFT_DIR = BENCHMARK_DIR / "trace_draft"
SOURCES_DIR = DATA_DIR / "sources"
UPSTREAM_DIR = SOURCES_DIR  # backwards-compat alias
RUNTIME_DIR = DATA_DIR / "runtime"
TMP_BENCHMARK_DIR = TMP_DIR / "benchmark"
ARCHIVE_DIR = Path("archive")

DEFIHACKLABS_DIR = SOURCES_DIR / "DeFiHackLabs"
CLARA_DIR = SOURCES_DIR / "Clara"
BENCHMARK_CACHE_DIR = TMP_BENCHMARK_DIR / "cache"
PARSER_PREPROCESSED_DIR = SOURCES_DIR / "preprocessed"
RESULTS_DIR = DATA_DIR / "eval_results"
HARBOR_TASKS_DIR = BENCHMARK_DIR / "harbor_tasks"

DETECT_WORKSPACE_DIR = TMP_DIR / "detect"
EXPLOIT_WORKSPACE_DIR = TMP_DIR / "exploit"
PATCH_WORKSPACE_DIR = TMP_DIR / "patch"
FIX_WORKSPACE_DIR = PATCH_WORKSPACE_DIR  # backwards-compat alias
EVAL_DETECT_WORKSPACE_DIR = TMP_DIR / "eval_detect"
EVAL_EXPLOIT_WORKSPACE_DIR = TMP_DIR / "eval_exploit"
EVAL_PATCH_WORKSPACE_DIR = TMP_DIR / "eval_patch"
EVAL_FIX_WORKSPACE_DIR = EVAL_PATCH_WORKSPACE_DIR  # backwards-compat alias
CURATOR_WORKSPACE_DIR = TMP_DIR / "curator"
LIVE_SCRAPE_WORKSPACE_DIR = TMP_DIR / "live_scrape"

CURATOR_OUTPUTS_DIR = BENCHMARK_DRAFT_DIR
CURATOR_REPORTS_DIR = BENCHMARK_DRAFT_DIR / "reports"
CURATOR_PROMPTS_DIR = BENCHMARK_DRAFT_DIR / "prompts"
CURATOR_REASONS_DIR = BENCHMARK_DRAFT_DIR / "reasons"
MANUAL_FILL_REPORTS_DIR = BENCHMARK_DRAFT_DIR

_LEGACY_ROOTS = {
    "benchmark": BENCHMARK_DIR,
    "upstream": SOURCES_DIR,
    "sources": SOURCES_DIR,
    "runtime": RUNTIME_DIR,
    "tmp": TMP_DIR,
}

_TASK_ROOTS = {
    "detect": DETECT_WORKSPACE_DIR,
    "exploit": EXPLOIT_WORKSPACE_DIR,
    "patch": PATCH_WORKSPACE_DIR,
    "fix": PATCH_WORKSPACE_DIR,
}


def _canonicalize_runtime_path(parts: tuple[str, ...]) -> str:
    if len(parts) >= 4 and parts[1] == "eval_workspace" and parts[2] == "agent_cases":
        task_root = _TASK_ROOTS.get(parts[3])
        if task_root is not None:
            return task_root.joinpath(*parts[4:]).as_posix()

    if len(parts) >= 3 and parts[1] == "eval_case_workspaces":
        task_root = _TASK_ROOTS.get(parts[2])
        if task_root is not None:
            return (task_root / "_foundry_cases").joinpath(*parts[3:]).as_posix()

    if len(parts) >= 2 and parts[1] == "eval_workspace":
        return (EXPLOIT_WORKSPACE_DIR / "_foundry_shared").joinpath(*parts[2:]).as_posix()
    if len(parts) >= 2 and parts[1] == "curator_case_workers":
        rel = parts[2:]
        if len(rel) == 1:
            return (CURATOR_WORKSPACE_DIR / rel[0] / "workspace").as_posix()
        return CURATOR_WORKSPACE_DIR.joinpath(*rel).as_posix()
    if len(parts) >= 2 and parts[1] == "curator_review_inputs":
        return (CURATOR_WORKSPACE_DIR / "review_inputs").joinpath(*parts[2:]).as_posix()
    if len(parts) >= 2 and parts[1] == "curator_screen":
        return (CURATOR_WORKSPACE_DIR / "screen").joinpath(*parts[2:]).as_posix()
    if len(parts) >= 2 and parts[1] == "manual_fill_reports":
        return MANUAL_FILL_REPORTS_DIR.joinpath(*parts[2:]).as_posix()
    if len(parts) >= 2 and parts[1] == "results":
        return RESULTS_DIR.joinpath(*parts[2:]).as_posix()
    return RUNTIME_DIR.joinpath(*parts[1:]).as_posix()


def canonicalize_repo_relative(path_value: str | Path) -> str:
    text = str(path_value).strip()
    if not text:
        return ""

    path = Path(text)
    if path.is_absolute():
        return str(path)

    parts = PurePosixPath(path.as_posix()).parts
    if not parts:
        return ""
    if parts[0] == "benchmark" and len(parts) >= 2:
        if parts[1] == "cache":
            return BENCHMARK_CACHE_DIR.joinpath(*parts[2:]).as_posix()
        if parts[1] == "parser_preprocessed":
            return PARSER_PREPROCESSED_DIR.joinpath(*parts[2:]).as_posix()
    if parts[0] == "runtime" and len(parts) >= 2:
        return _canonicalize_runtime_path(parts)
    if parts[0] in _LEGACY_ROOTS:
        return _LEGACY_ROOTS[parts[0]].joinpath(*parts[1:]).as_posix()
    return PurePosixPath(*parts).as_posix()


def repo_relative_variants(path_value: str | Path) -> list[Path]:
    text = str(path_value).strip()
    if not text:
        return []

    path = Path(text)
    if path.is_absolute():
        return [path]

    variants: list[Path] = []

    canonical_text = canonicalize_repo_relative(path)
    if canonical_text:
        variants.append(Path(canonical_text))

    canonical_parts = PurePosixPath(canonical_text).parts
    if (
        len(canonical_parts) >= 2
        and canonical_parts[0] == "data"
        and canonical_parts[1] in _LEGACY_ROOTS
    ):
        variants.append(Path(canonical_parts[1]).joinpath(*canonical_parts[2:]))

    variants.append(Path(PurePosixPath(path.as_posix())))

    deduped: list[Path] = []
    seen: set[str] = set()
    for candidate in variants:
        key = candidate.as_posix()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped


def resolve_repo_path(base_dir: Path, path_value: str | Path) -> Path:
    text = str(path_value).strip()
    if not text:
        return base_dir

    path = Path(text)
    if path.is_absolute():
        return path

    variants = repo_relative_variants(path)
    for relative in variants:
        candidate = base_dir / relative
        if candidate.exists():
            return candidate
    return base_dir / variants[0]
