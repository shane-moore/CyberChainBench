"""CLI for the deterministic curator."""

from __future__ import annotations

import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import json
import re
import traceback
import shutil
from pathlib import Path
from typing import Any

from benchmark.pipeline.task_cases import write_benchmark_case_output_index
from benchmark.pipeline.paths import manual_root, review_root
from eval.runner_registry import AGENT_REGISTRY, CLI_AGENT_KEYS, build_agent_kwargs
from project_layout import CURATOR_PROMPTS_DIR, CURATOR_REASONS_DIR, CURATOR_REPORTS_DIR

from . import build_curator

DEFAULT_REPORT_ROOT = CURATOR_REPORTS_DIR
DEFAULT_PROMPT_ROOT = CURATOR_PROMPTS_DIR
DEFAULT_REASON_ROOT = CURATOR_REASONS_DIR
DEFAULT_DFHL_CASE_LINKS = Path("data/sources/preprocessed/defihacklabs/case_links.json")


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return payload


def _read_json_list(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError(f"Expected JSON array: {path}")
    return [item for item in payload if isinstance(item, dict)]


def _load_single_case(
    base_dir: Path, task: str, case_id: str = "", input_path: Path | None = None
) -> tuple[Path, dict[str, Any]]:
    if input_path is not None:
        path = input_path.resolve()
    else:
        path = (base_dir / review_root(task) / f"{case_id}.json").resolve()
    if not path.exists():
        raise FileNotFoundError(f"Benchmark input case not found: {path}")
    return path, _read_json(path)


def _default_case_links_path(base_dir: Path) -> Path:
    return (base_dir / DEFAULT_DFHL_CASE_LINKS).resolve()


def _iter_case_link_seed_cases(
    base_dir: Path,
    task: str,
    *,
    source: str = "",
    case_id: str = "",
    input_path: Path | None = None,
    only_missing: bool = False,
    manual_case_index: dict[str, Path] | None = None,
) -> list[tuple[Path, dict[str, Any]]]:
    seed_path = (
        input_path.resolve() if input_path is not None else _default_case_links_path(base_dir)
    )
    if not seed_path.exists():
        return []

    payload = _read_json_list(seed_path)
    source_filter = str(source).strip().lower()
    target_id = str(case_id).strip()
    selected: list[tuple[Path, dict[str, Any]]] = []

    for item in payload:
        item_source = str(item.get("source", "")).strip().lower()
        if source_filter and item_source != source_filter:
            continue
        current_id = str(item.get("id", "")).strip()
        if target_id and current_id != target_id:
            continue
        if not current_id:
            continue

        synthetic_case_path = (base_dir / review_root(task) / f"{current_id}.json").resolve()
        if only_missing:
            existing_manual_path = (manual_case_index or {}).get(current_id)
            if existing_manual_path is not None and existing_manual_path.exists():
                existing_manual = _read_json(existing_manual_path)
                if not _has_missing_annotation_hints(existing_manual):
                    continue
            elif synthetic_case_path.exists():
                existing_review = _read_json(synthetic_case_path)
                if not _has_missing_annotation_hints(existing_review):
                    continue

        selected.append((synthetic_case_path, item))

    return selected


def _iter_review_case_paths(base_dir: Path, task: str) -> list[Path]:
    root = (base_dir / review_root(task)).resolve()
    if not root.exists():
        return []
    return [path for path in sorted(root.glob("*.json")) if path.name != "cases.json"]


def _iter_manual_case_paths(base_dir: Path, task: str) -> list[Path]:
    root = (base_dir / manual_root(task)).resolve()
    if not root.exists():
        return []
    return [path for path in sorted(root.rglob("*.json")) if path.name != "cases.json"]


def _has_missing_annotation_hints(case: dict[str, Any]) -> bool:
    hints = case.get("annotation_hints")
    if not isinstance(hints, dict) or not hints:
        return False

    for payload in hints.values():
        if not isinstance(payload, dict):
            return True
        status = str(payload.get("status", "")).strip().lower()
        if not status or status in ("missing", "invalid"):
            return True
    return False


def _build_report_path(
    base_dir: Path, task: str, case_id: str, report_dir: Path | None = None
) -> Path:
    if report_dir is not None:
        root = report_dir.resolve()
    else:
        root = (base_dir / DEFAULT_REPORT_ROOT).resolve()
    return root / f"{case_id}.json"


def _build_prompt_path(
    base_dir: Path, task: str, case_id: str, prompt_dir: Path | None = None
) -> Path:
    if prompt_dir is not None:
        root = prompt_dir.resolve()
    else:
        root = (base_dir / DEFAULT_PROMPT_ROOT).resolve()
    return root / f"{case_id}.txt"


def _build_reason_path(
    base_dir: Path, task: str, case_id: str, reason_dir: Path | None = None
) -> Path:
    if reason_dir is not None:
        root = reason_dir.resolve()
    else:
        root = (base_dir / DEFAULT_REASON_ROOT).resolve()
    return root / f"{case_id}.md"


def _infer_batch_output_root(task: str, output_path: Path) -> Path:
    parent = output_path.parent
    if parent.name == task and parent.parent.name in {"reports", "reasons", "prompts"}:
        return parent.parent.parent if parent.parent.parent.name else parent.parent
    if parent.name in {"reports", "reasons", "prompts"}:
        return parent.parent
    return parent


def _build_batch_benchmark_path(
    batch_root: Path,
    task: str,
    case_id: str,
    source: str,
) -> Path:
    source_slug = re.sub(r"[^a-z0-9]+", "-", str(source or "").strip().lower()).strip("-")
    if not source_slug:
        source_slug = "unknown"
    return (batch_root / "cases" / source_slug / f"{case_id}.json").resolve()


def _reset_case_agent_work_dir(path: Path) -> Path:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _case_agent_work_dir(
    base_dir: Path, task: str, role: str, agent_key: str, case_id: str
) -> Path:
    _ = (task, role, agent_key)
    safe_case_id = str(case_id or "_unknown").strip() or "_unknown"
    return (base_dir / "tmp" / "curator" / safe_case_id / "workspace").resolve()


def _build_case_scoped_agent(
    agent_key: str,
    *,
    model: str,
    base_dir: Path,
    task: str,
    case_id: str,
    role: str,
):
    agent_factory = AGENT_REGISTRY[agent_key]
    agent_kwargs = build_agent_kwargs(agent_key, base_dir, {})
    if agent_key in CLI_AGENT_KEYS:
        agent_kwargs["work_dir"] = _reset_case_agent_work_dir(
            _case_agent_work_dir(base_dir, task, role, agent_key, case_id)
        )
    if model:
        return agent_factory(model=model, **agent_kwargs)
    return agent_factory(**agent_kwargs)


def _default_review_max_rounds_for_task(task: str) -> int:
    _ = task
    return 5


def _build_case_curator(args: argparse.Namespace, base_dir: Path, case_id: str):
    curator_agent = _build_case_scoped_agent(
        args.curator_agent,
        model=str(args.curator_model).strip(),
        base_dir=base_dir,
        task=args.task,
        case_id=case_id,
        role="fill",
    )

    return build_curator(
        args.task,
        base_dir,
        max_attack_txs=args.max_attack_txs,
        curator_agent=curator_agent,
        reviewer_agent=None,
        review_max_rounds=_default_review_max_rounds_for_task(args.task),
    )


def _process_selected_case(
    args: argparse.Namespace,
    base_dir: Path,
    case_path: Path,
    case: dict[str, Any],
    *,
    single_case_mode: bool,
) -> dict[str, Any]:
    case_id = str(case.get("id", "")).strip() or case_path.stem
    agent = _build_case_curator(args, base_dir, case_id)
    report = agent.build_report(case, case_path=case_path)
    allow_final_write = True

    # Per-case output directory: output_root/<case_id>/
    case_out_dir = None
    if args.output_root is not None:
        case_out_dir = args.output_root.resolve() / case_id
        case_out_dir.mkdir(parents=True, exist_ok=True)

    report_path = (
        args.report_out.resolve()
        if args.report_out is not None and single_case_mode
        else (case_out_dir / "report.json" if case_out_dir else
              _build_report_path(base_dir, args.task, str(report["case_id"]), args.report_dir))
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    benchmark_snapshot_path = (
        case_out_dir / "case.json" if case_out_dir else
        _build_batch_benchmark_path(
            _infer_batch_output_root(args.task, report_path),
            args.task,
            str(report["case_id"]),
            str(report.get("source", case.get("source", ""))).strip(),
        )
    )
    benchmark_snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    benchmark_snapshot_path.write_text(
        json.dumps(report.get("suggested_manual_case", {}), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    prompt_path = None
    prompt_text = ""
    prompt_bundle = None
    if args.prompt_out is not None or args.prompt_dir is not None or args.print_prompt or case_out_dir:
        prompt_bundle = agent.build_prompt_bundle(case, case_path=case_path, report=report)
    if prompt_bundle is not None:
        prompt_path = (
            args.prompt_out.resolve()
            if args.prompt_out is not None and single_case_mode
            else (case_out_dir / "prompt.txt" if case_out_dir else
                  _build_prompt_path(base_dir, args.task, str(report["case_id"]), args.prompt_dir))
        )
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        prompt_text = prompt_bundle["combined_prompt"]
        prompt_path.write_text(prompt_text, encoding="utf-8")

    reason_text = agent.build_reason_text(case, case_path=case_path, report=report)
    reason_path = (
        args.reason_out.resolve()
        if args.reason_out is not None and single_case_mode
        else (case_out_dir / "reason.md" if case_out_dir else
              _build_reason_path(base_dir, args.task, str(report["case_id"]), args.reason_dir))
    )
    reason_path.parent.mkdir(parents=True, exist_ok=True)
    reason_path.write_text(reason_text, encoding="utf-8")

    traj_path = None
    evidence = report.get("evidence", {}) or {}
    fill_judgment = evidence.get("curator_taxonomy_judgment", {}) or {}
    session_log_src = str(fill_judgment.get("session_log_path", "")).strip()
    if session_log_src and Path(session_log_src).exists():
        if case_out_dir:
            traj_path = case_out_dir / "traj.jsonl"
        elif args.output_root is not None:
            traj_dir = args.output_root.resolve() / "trajs"
            traj_dir.mkdir(parents=True, exist_ok=True)
            traj_path = traj_dir / f"{case_id}.jsonl"
        if traj_path:
            shutil.copy2(session_log_src, traj_path)

    return {
        "case_id": case_id,
        "case_path": case_path,
        "report": report,
        "report_path": report_path,
        "prompt_path": prompt_path,
        "prompt_text": prompt_text,
        "reason_path": reason_path,
        "traj_path": traj_path,
        "benchmark_snapshot_path": benchmark_snapshot_path,
        "allow_final_write": allow_final_write,
    }


def _emit_case_result(args: argparse.Namespace, result: dict[str, Any]) -> None:
    report = result["report"]
    review_meta = report.get("review", {})
    review_status = (
        str(review_meta.get("status", "")).strip() if isinstance(review_meta, dict) else ""
    )
    if args.print_prompt and result.get("prompt_text"):
        print(f"===== curator prompt: {report['case_id']} =====")
        print(str(result["prompt_text"]).rstrip())
    print(f"[curator] task={args.task} case_id={report['case_id']}")
    print(f"[curator] report={result['report_path']}")
    print(f"[curator] changed_fields={len(report['changed_fields'])}")
    if result.get("prompt_path") is not None:
        print(f"[curator] prompt={result['prompt_path']}")
    print(f"[curator] reason={result['reason_path']}")
    print(f"[curator] benchmark_output={result['benchmark_snapshot_path']}")
    print(f"[curator] manual_case_path={report.get('manual_case_path', '')}")
    print(f"[curator] remaining_hints={len(report.get('remaining_annotation_hints', {}))}")
    if review_status:
        print(f"[curator] review_status={review_status}")
        print(
            f"[curator] review_rounds={int(review_meta.get('rounds', 0) or 0) if isinstance(review_meta, dict) else 0}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fill unified benchmark cases from benchmark inputs"
    )
    parser.add_argument(
        "--task", required=True, choices=["benchmark_case"]
    )
    parser.add_argument("--case-id", default="", help="Single benchmark case id such as clr-5c1a8dd3")
    parser.add_argument(
        "--input", type=Path, default=None, help="Optional explicit benchmark input path"
    )
    parser.add_argument("--base-dir", type=Path, default=Path("."))
    parser.add_argument(
        "--report-out", type=Path, default=None, help="Explicit report path for single-case runs"
    )
    parser.add_argument("--report-dir", type=Path, default=None, help="Directory for batch reports")
    parser.add_argument(
        "--prompt-out",
        type=Path,
        default=None,
        help="Explicit combined-prompt path for single-case runs",
    )
    parser.add_argument(
        "--prompt-dir", type=Path, default=None, help="Directory for batch prompt exports"
    )
    parser.add_argument(
        "--reason-out", type=Path, default=None, help="Explicit rationale path for single-case runs"
    )
    parser.add_argument(
        "--reason-dir", type=Path, default=None, help="Directory for per-case fill rationales"
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=None,
        help="Per-run output root; when set, write per-case reports/prompts/reasons and benchmark snapshots under this directory as each case finishes",
    )
    parser.add_argument(
        "--print-prompt", action="store_true", help="Print the combined prompt to stdout"
    )
    parser.add_argument("--limit", type=int, default=0, help="Batch mode limit; 0 means no limit")
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="Number of parallel case workers; each worker runs a full per-case fill/review pipeline",
    )
    parser.add_argument(
        "--source", default="", help="Only process cases from this source, e.g. Clara"
    )
    parser.add_argument(
        "--seed-from-case-links",
        action="store_true",
        help="Read DeFiHackLabs parser case-link seeds instead of benchmark input files",
    )
    parser.add_argument(
        "--case-links-input",
        type=Path,
        default=None,
        help="Explicit parser case-links JSON path; implies --seed-from-case-links",
    )
    parser.add_argument(
        "--only-missing",
        action="store_true",
        help="Only process cases that still carry annotation_hints",
    )
    parser.add_argument(
        "--max-attack-txs",
        type=int,
        default=3,
        help="Max historical attack transactions to inspect per case",
    )
    parser.add_argument(
        "--curator-agent",
        default="codex_cli",
        choices=sorted(AGENT_REGISTRY),
        help="Agent adapter used for the curator pass",
    )
    parser.add_argument(
        "--curator-model",
        default="gpt-5.4-sf",
        help="Optional model override for the curator agent",
    )
    args = parser.parse_args()
    os.environ.setdefault("TASK_AGENT_USE_MCP", "1")
    base_dir = args.base_dir.resolve()

    if args.output_root is None and all(
        value is None
        for value in (
            args.report_out,
            args.report_dir,
            args.prompt_out,
            args.prompt_dir,
            args.reason_out,
            args.reason_dir,
        )
    ):
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output_root = base_dir / "data" / "benchmark" / "drafts" / f"batch_{stamp}"

    if args.output_root is not None:
        output_root = args.output_root.resolve()
        output_root.mkdir(parents=True, exist_ok=True)

    selected: list[tuple[Path, dict[str, Any]]] = []
    manual_case_index: dict[str, Path] = {}
    if args.only_missing:
        manual_case_index = {
            path.stem: path for path in _iter_manual_case_paths(base_dir, args.task)
        }
    use_case_link_seeds = args.seed_from_case_links or args.case_links_input is not None
    if args.case_id or args.input is not None:
        if use_case_link_seeds and args.input is None:
            selected.extend(
                _iter_case_link_seed_cases(
                    base_dir,
                    args.task,
                    source=args.source,
                    case_id=args.case_id,
                    input_path=args.case_links_input,
                    only_missing=args.only_missing,
                    manual_case_index=manual_case_index,
                )
            )
        else:
            selected.append(_load_single_case(base_dir, args.task, args.case_id, args.input))
    else:
        if use_case_link_seeds:
            selected.extend(
                _iter_case_link_seed_cases(
                    base_dir,
                    args.task,
                    source=args.source,
                    input_path=args.case_links_input,
                    only_missing=args.only_missing,
                    manual_case_index=manual_case_index,
                )
            )
            if args.limit:
                selected = selected[: args.limit]
        else:
            source_filter = str(args.source).strip().lower()
            for path in _iter_review_case_paths(base_dir, args.task):
                case = _read_json(path)
                if source_filter and str(case.get("source", "")).strip().lower() != source_filter:
                    continue
                if args.only_missing:
                    case_id = str(case.get("id", "")).strip() or path.stem
                    existing_manual_path = manual_case_index.get(case_id)
                    if existing_manual_path is not None and existing_manual_path.exists():
                        existing_manual = _read_json(existing_manual_path)
                        if not _has_missing_annotation_hints(existing_manual):
                            continue
                    elif not _has_missing_annotation_hints(case):
                        continue
                selected.append((path, case))
                if args.limit and len(selected) >= args.limit:
                    break

    if not selected:
        if use_case_link_seeds:
            raise SystemExit("no matching case_links seed cases found")
        raise SystemExit("no matching benchmark input cases found")

    jobs = max(int(args.jobs), 1)
    if args.print_prompt and jobs > 1 and len(selected) > 1:
        print(
            "[curator] forcing jobs=1 because --print-prompt would interleave parallel case output"
        )
        jobs = 1

    changed_count = 0
    written_reports: list[Path] = []
    written_prompts: list[Path] = []
    written_reasons: list[Path] = []
    failures: list[tuple[str, str]] = []

    def record_success(result: dict[str, Any]) -> None:
        nonlocal changed_count
        report = result["report"]
        if report["changed_fields"]:
            changed_count += 1
        written_reports.append(result["report_path"])
        if result.get("prompt_path") is not None:
            written_prompts.append(result["prompt_path"])
        written_reasons.append(result["reason_path"])
        _emit_case_result(args, result)

    def record_failure(case_path: Path, case: dict[str, Any], exc: Exception) -> None:
        case_id = str(case.get("id", "")).strip() or case_path.stem
        failures.append((case_id, str(exc)))
        failure_path = _build_report_path(
            base_dir, args.task, case_id, args.report_dir
        ).with_suffix(".error.txt")
        failure_path.parent.mkdir(parents=True, exist_ok=True)
        failure_path.write_text(traceback.format_exc(), encoding="utf-8")
        print(f"[curator] task={args.task} case_id={case_id} failed: {exc}")
        print(f"[curator] failure_report={failure_path}")

    single_case_mode = len(selected) == 1
    if jobs == 1 or single_case_mode:
        for case_path, case in selected:
            try:
                result = _process_selected_case(
                    args,
                    base_dir,
                    case_path,
                    case,
                    single_case_mode=single_case_mode,
                )
            except Exception as exc:
                if single_case_mode:
                    raise
                record_failure(case_path, case, exc)
                continue
            record_success(result)
    else:
        worker_count = min(jobs, len(selected))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(
                    _process_selected_case,
                    args,
                    base_dir,
                    case_path,
                    case,
                    single_case_mode=False,
                ): (case_path, case)
                for case_path, case in selected
            }
            for future in as_completed(futures):
                case_path, case = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    record_failure(case_path, case, exc)
                    continue
                record_success(result)

    print(
        "[curator] "
        f"processed={len(selected)} changed={changed_count} "
        f"failures={len(failures)}"
    )
    if args.output_root is not None:
        print(f"[curator] output_root={args.output_root.resolve()}")
    if len(written_reports) > 1:
        print(f"[curator] report_dir={written_reports[0].parent}")
    if len(written_prompts) > 1:
        print(f"[curator] prompt_dir={written_prompts[0].parent}")
    if len(written_reasons) > 1:
        print(f"[curator] reason_dir={written_reasons[0].parent}")
    write_benchmark_case_output_index(base_dir)
    if failures:
        print("[curator] failed_cases=" + ",".join(case_id for case_id, _ in failures))


if __name__ == "__main__":
    main()
