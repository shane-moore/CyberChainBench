"""
Benchmark evaluation runner.

Each task (detect / exploit / patch) runs independently against the on-chain
benchmark.

Usage:
    python -m eval.runner --task detect  --track on_chain --agent claude_code --limit 5
    python -m eval.runner --task exploit --track on_chain --agent claude_code --category reentrancy
    python -m eval.runner --task patch   --track on_chain --agent codex_cli --model gpt-5.2
    python -m eval.runner --task detect  --track on_chain --dry-run --category flash-loan
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
import json
import os
import threading
import time
import traceback
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from agents.task_agent.base import AgentResponse, BaseAgent, TaskType
from agents.task_agent.mock_agent import MockAgent
from agents.task_agent.output_parser import extract_vuln_type, rewrite_detect_response_as_json
from benchmark.loader import BenchmarkLoader
from benchmark.tasks.detect.case import DetectCase
from benchmark.tasks.exploit.case import ExploitCase
from benchmark.tasks.patch.case import PatchCase
FixCase = PatchCase
from eval.artifacts import copy_session_log_to_artifact, write_raw_response_artifact
from eval.runner_contracts import (
    _expected_fix_targets,
    _get_contract_code as _runner_get_contract_code,
    _get_fix_contract_code as _runner_get_fix_contract_code,
    _lookup_fix_proxy_info as _runner_lookup_fix_proxy_info,
)
from eval.runner_inputs import (
    _detect_input_lines,
    _exploit_input_lines,
    _fix_input_lines,
)
from eval.runner_payloads import (
    _canonical_source,
    _deserialize_agent_response,
    _extract_serialized_agent_response,
    _generated_case_output_payload,
    _make_artifact_dir,
    _write_legacy_case_result_directory,
)
from eval.runner_registry import (
    AGENT_REGISTRY,
    TRACK_LABELS,
    build_agent_kwargs as _build_agent_kwargs,
    normalize_task_track as _normalize_task_track,
)
from eval.tasks.detect import DetectScore, evaluate_detection, write_detect_score_artifact
from eval.tasks.exploit import (
    ExploitScore,
    attach_profit_baselines,
    evaluate_exploit,
    evaluate_reference_exploit,
    load_reference_baseline_cache,
    reference_score_from_cache,
    summarize_exploit_outcome,
    write_exploit_score_artifact,
)
from eval.tasks.patch import PatchScore, evaluate_patch, write_patch_score_artifact
FixScore = PatchScore
evaluate_fix = evaluate_patch
write_fix_score_artifact = write_patch_score_artifact
from eval.result_paths import default_results_dir
from eval.workspace import (
    cleanup_agent_case_workspace,
    cleanup_agent_case_workspaces,
    create_agent_case_workspace,
)
from infra.chain.metadata import lookup_proxy_info, lookup_verified_source
from infra.foundry.workspace import cleanup_foundry_eval_tmp
from project_layout import BENCHMARK_CASES_DIR as BENCHMARK_DIR, resolve_repo_path

console = Console()

# ---- Token cost calculation ----
# Prices in USD per 1M tokens: (input, cached_input, output)
_MODEL_PRICING: dict[str, tuple[float, float, float]] = {
    # OpenAI GPT
    "gpt-5.5":        (5.00,  0.50, 30.00),
    "gpt-5.4":        (2.50,  0.25, 15.00),
    "gpt-5.4-sf":     (2.50,  0.25, 15.00),
    "gpt-5.4-mini":   (0.75,  0.075, 4.50),
    "gpt-5.4-nano":   (0.20,  0.02, 1.25),
    "gpt-5.2":        (1.75,  0.175, 14.00),
    "gpt-5.1":        (1.25,  0.125, 10.00),
    "gpt-5":          (1.25,  0.125, 10.00),
    "gpt-5-mini":     (0.25,  0.025, 2.00),
    "gpt-5-nano":     (0.05,  0.005, 0.40),
    "gpt-4.1":        (2.00,  0.50,  8.00),
    "gpt-4.1-mini":   (0.40,  0.10,  1.60),
    "gpt-4.1-nano":   (0.10,  0.025, 0.40),
    "gpt-4o":         (2.50,  1.25, 10.00),
    "gpt-4o-mini":    (0.15,  0.075, 0.60),
    # Anthropic Claude
    "claude-opus-4-7":       (10.00, 0.50, 25.00),
    "claude-opus-4-6":       (10.00, 0.50, 25.00),
    "claude-opus-4-5":       (10.00, 0.50, 25.00),
    "claude-opus-4-1":       (30.00, 1.50, 75.00),
    "claude-opus-4":         (30.00, 1.50, 75.00),
    "claude-sonnet-4-6":     (6.00,  0.30, 15.00),
    "claude-sonnet-4-5":     (6.00,  0.30, 15.00),
    "claude-sonnet-4":       (6.00,  0.30, 15.00),
    "claude-haiku-4-5":      (2.00,  0.10,  5.00),
    "claude-haiku-3-5":      (1.60,  0.08,  4.00),
    # OpenAI reasoning models
    "o3":                 (2.00,  0.50, 8.00),
    "o3-mini":            (0.55,  0.14, 2.20),
    "o4-mini":            (0.55,  0.14, 2.20),
    # Google Gemini
    "gemini-2.5-pro":     (1.25,  0.315, 10.00),
    "gemini-2.5-flash":   (0.15,  0.0375, 0.60),
    "gemini-3.1-pro":     (1.25,  0.315, 10.00),
    "gemini-3-pro":       (1.25,  0.315, 10.00),
    "gemini-3-flash":     (0.15,  0.0375, 0.60),
    # Qwen
    "qwen-3":             (0.40,  0.10,  1.20),
    "qwen3-coder":        (0.40,  0.10,  1.20),
    # Kimi
    "kimi":               (0.60,  0.15,  2.40),
    # DeepSeek
    "deepseek-r1":        (0.55,  0.14,  2.19),
    "deepseek-v3":        (0.27,  0.07,  1.10),
}


def compute_cost_usd(
    model: str,
    input_tokens: int | None,
    output_tokens: int | None,
    cached_input_tokens: int | None = None,
) -> float | None:
    """Compute API cost in USD given token counts and model name."""
    if input_tokens is None or output_tokens is None:
        return None
    model_key = model.lower().strip()
    pricing = _MODEL_PRICING.get(model_key)
    if not pricing:
        for key, val in _MODEL_PRICING.items():
            if key in model_key or model_key in key:
                pricing = val
                break
    if not pricing:
        return None
    price_input, price_cached, price_output = pricing
    cached = cached_input_tokens or 0
    uncached = max(input_tokens - cached, 0)
    cost = (uncached * price_input + cached * price_cached + output_tokens * price_output) / 1_000_000
    return round(cost, 6)


def _persist_session_log(response: AgentResponse) -> AgentResponse:
    """Read session log file content into response.session_log_text before workspace cleanup."""
    if response.session_log_text:
        return response
    log_path = response.session_log_path
    if log_path:
        p = Path(log_path)
        if p.exists() and p.is_file():
            response = replace(response, session_log_text=p.read_text(errors="replace"))
    return response


def _stage_workspace_input_file(work_dir: Path, relative_path: str, content: str) -> Path:
    destination = work_dir / Path(relative_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content if content.endswith("\n") else content + "\n", encoding="utf-8")
    return destination


def _is_missing_benchmark_value(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) == 0
    return False


def _benchmark_missing_fields(case) -> list[str]:
    raw = dict(getattr(case, "raw", {}) or {})
    required = [
        "case_link",
        "attack_txs",
        "chain",
        "block_number",
        "vulnerable_address",
        "has_public_source",
        "fixable",
        "function",
        "type",
        "attacker_profit",
    ]
    missing = [field for field in required if _is_missing_benchmark_value(raw.get(field))]
    has_public_source = raw.get("has_public_source")
    if has_public_source is True and _is_missing_benchmark_value(raw.get("file")):
        missing.append("file")
    fixable = raw.get("fixable")
    if isinstance(fixable, bool) and fixable and _is_missing_benchmark_value(raw.get("proxy_address")):
        missing.append("proxy_address")
    return missing


def _incomplete_benchmark_score(task: str, missing_fields: list[str]):
    reason = "incomplete benchmark fields: " + ", ".join(missing_fields)
    if task == "detect":
        return DetectScore(
            gate_reason="incomplete_benchmark_case",
            summary=reason,
            diagnostic_notes=[reason],
        )
    if task == "exploit":
        return ExploitScore(
            skipped=True,
            skip_reason=reason,
            outcome_reason=reason,
        )
    return FixScore(
        skipped=True,
        skip_reason=reason,
        summary=reason,
        diagnostic_notes=[reason],
    )


def _is_process_killed(score: object) -> bool:
    """Check if a score object indicates the agent process was killed (SIGKILL/OOM)."""
    elapsed = getattr(score, "agent_elapsed_seconds", None)
    if elapsed is not None and elapsed < 10:
        response_path = str(getattr(score, "response_path", "") or "")
        if response_path:
            try:
                content = Path(response_path).read_text(errors="replace")[:3000]
                if "exit code: -9" in content or "exit code: -6" in content:
                    return True
            except OSError:
                pass
        for attr in ("outcome_reason", "test_output", "compile_error"):
            text = str(getattr(score, attr, "") or "")
            if "exit code: -9" in text or "exit code: -6" in text:
                return True
        if elapsed < 5 and getattr(score, "score", -1) == 0.0:
            return True
    return False


def _is_rate_limited(score: object) -> bool:
    """Check if a score object indicates the agent was killed by API 429."""
    _429_MARKER = "429"
    _429_MSG = "Too many"
    # Check common score text fields
    for attr in ("test_output", "compile_error", "outcome_reason", "summary"):
        text = str(getattr(score, attr, "") or "")
        if _429_MARKER in text and _429_MSG in text:
            return True
    # Check the raw response artifact file
    response_path = str(getattr(score, "response_path", "") or "")
    if response_path:
        try:
            content = Path(response_path).read_text(errors="replace")[:2000]
            if _429_MARKER in content and _429_MSG in content and "exit code" in content:
                return True
        except OSError:
            pass
    return False


def _get_contract_code(case, base_dir: Path) -> dict[str, str]:
    return _runner_get_contract_code(case, base_dir, note=console.print)


def _create_agent_workspace(
    *,
    base_dir: Path,
    task: str,
    case_id: str,
    agent: BaseAgent,
    case_input_text: str,
    output_name: str = "",
) -> Path:
    return create_agent_case_workspace(
        base_dir,
        task=task,
        case_id=case_id,
        model=str(getattr(agent, "model", "unknown")),
        case_input_text=case_input_text,
        output_name=output_name,
    )


def _stage_fix_reference_exploit(workspace_dir: Path, exploit_code: str) -> Path | None:
    text = str(exploit_code or "").strip()
    if not text:
        return None
    path = workspace_dir / "reference_exploit.sol"
    path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    return path


def _lookup_fix_proxy_info(case: FixCase) -> dict[str, object] | None:
    return _runner_lookup_fix_proxy_info(
        case,
        lookup_proxy_info_fn=lookup_proxy_info,
    )


def _get_fix_contract_code(
    case: FixCase,
    base_dir: Path,
    proxy_info: dict[str, object] | None = None,
) -> dict[str, str]:
    return _runner_get_fix_contract_code(
        case,
        base_dir,
        proxy_info=proxy_info,
        lookup_verified_source_fn=lookup_verified_source,
        note=console.print,
    )


def _write_detect_artifacts(
    *,
    artifact_dir: Path,
    raw_response: str,
    score: DetectScore,
    workspace_dir: str = "",
    session_log_path: str = "",
    session_log_text: str = "",
    hint_text: str = "",
) -> DetectScore:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    score.artifact_dir = str(artifact_dir)
    if workspace_dir:
        score.workspace_dir = workspace_dir
    if session_log_path:
        score.session_log_path = copy_session_log_to_artifact(
            artifact_dir,
            session_log_path,
            session_log_text,
        )
    elif session_log_text:
        score.session_log_path = copy_session_log_to_artifact(artifact_dir, "", session_log_text)

    score.agent_elapsed_seconds = getattr(score, "agent_elapsed_seconds", None)
    score.input_tokens_total = getattr(score, "input_tokens_total", None)
    score.output_tokens_total = getattr(score, "output_tokens_total", None)
    score.cache_read_input_tokens_total = getattr(score, "cache_read_input_tokens_total", None)
    score.cache_write_input_tokens_total = getattr(score, "cache_write_input_tokens_total", None)
    score.response_path = write_raw_response_artifact(artifact_dir, raw_response)
    if hint_text:
        hint_path = artifact_dir / "hint.txt"
        hint_path.write_text(hint_text)
        score.hint_path = str(hint_path)
    else:
        score.hint_path = ""
    score.case_input_path = ""
    score.normalized_response_path = ""
    return write_detect_score_artifact(score, artifact_dir)


def generate_detect_output(case: DetectCase, agent: BaseAgent, base_dir: Path) -> dict[str, object]:
    contract_code = _get_contract_code(case, base_dir)
    vulnerable_address = str(case.contracts.get("vulnerable_address", "")).strip()
    tool_capable = bool(getattr(agent, "supports_tools", False))
    if tool_capable and vulnerable_address:
        contract_code = {}
    if not contract_code and not vulnerable_address:
        score = DetectScore(
            gate_reason="no_contract_code_or_vulnerable_address",
            summary="detect input had neither local contract code nor a vulnerable address",
            diagnostic_notes=[
                "no contract code and no vulnerable address were available for detect evaluation"
            ],
        )
        return _generated_case_output_payload(
            task="detect",
            case=case,
            model=str(getattr(agent, "model", "unknown")),
            status="score_stub",
            score_stub=score,
        )
    if not contract_code and not tool_capable:
        score = DetectScore(
            gate_reason="no_local_source_and_agent_has_no_on_chain_tools",
            summary="detect input required address-driven inspection, but the selected agent has no on-chain tools",
            diagnostic_notes=[
                "address-only detect case was rejected because the agent cannot fetch on-chain data"
            ],
        )
        return _generated_case_output_payload(
            task="detect",
            case=case,
            model=str(getattr(agent, "model", "unknown")),
            status="score_stub",
            score_stub=score,
        )
    hint_text = "\n".join(
        _detect_input_lines(case, tool_capable=tool_capable, contract_code=contract_code)
    ).strip()
    workspace_dir = _create_agent_workspace(
        base_dir=base_dir,
        task="detect",
        case_id=case.id,
        agent=agent,
        case_input_text=hint_text,
    )
    try:
        response = agent.detect(
            contract_code,
            context=hint_text,
            case_id=case.id,
            workspace_dir=str(workspace_dir),
        )
        response = _persist_session_log(response)
        payload = _generated_case_output_payload(
            task="detect",
            case=case,
            model=str(getattr(agent, "model", "unknown")),
            status="completed",
            response=response,
        )
        payload["hint_text"] = hint_text
        return payload
    finally:
        cleanup_agent_case_workspace(workspace_dir)


def score_detect_generated_output(
    case: DetectCase,
    generated_output: dict[str, object],
    base_dir: Path,
    *,
    output_dir: Path,
) -> DetectScore:
    if str(generated_output.get("status", "")) == "score_stub":
        raw_stub = generated_output.get("score_stub")
        if isinstance(raw_stub, dict):
            score = DetectScore(**raw_stub)
            return _write_detect_artifacts(
                artifact_dir=_make_artifact_dir(
                    output_dir,
                    case.id,
                    str(generated_output.get("model", "unknown")),
                ),
                raw_response="",
                score=score,
                session_log_path="",
                session_log_text="",
            )
        return DetectScore()

    raw_output = _extract_serialized_agent_response(generated_output)
    if not isinstance(raw_output, dict):
        raise ValueError(f"missing llm_output for detect case {case.id}")

    response = _deserialize_agent_response(raw_output)
    raw_detect_response = response.raw_response
    normalized_detect_response = rewrite_detect_response_as_json(raw_detect_response)
    normalized_response = replace(
        response,
        raw_response=normalized_detect_response,
        vulnerability_description=raw_detect_response,
        vulnerability_type=extract_vuln_type(normalized_detect_response)
        or response.vulnerability_type,
    )
    score = evaluate_detection(case, normalized_response)
    score.agent_elapsed_seconds = response.agent_elapsed_seconds
    score.input_tokens_total = response.input_tokens_total
    score.output_tokens_total = response.output_tokens_total
    score.cache_read_input_tokens_total = response.cache_read_input_tokens_total
    score.cache_write_input_tokens_total = response.cache_write_input_tokens_total
    score.cost_usd = compute_cost_usd(
        str(generated_output.get("model", "")),
        response.input_tokens_total, response.output_tokens_total,
        response.cache_read_input_tokens_total,
    )
    return _write_detect_artifacts(
        artifact_dir=_make_artifact_dir(
            output_dir,
            case.id,
            str(generated_output.get("model", "unknown")),
        ),
        raw_response=raw_detect_response,
        score=score,
        workspace_dir=str(response.workspace_dir or ""),
        session_log_path=str(response.session_log_path or ""),
        session_log_text=str(response.session_log_text or ""),
        hint_text=str(generated_output.get("hint_text", "")),
    )


def run_detect(
    case: DetectCase,
    agent: BaseAgent,
    base_dir: Path,
    *,
    output_dir: Path,
) -> DetectScore:
    generated_output = generate_detect_output(case, agent, base_dir)
    score = score_detect_generated_output(
        case,
        generated_output,
        base_dir,
        output_dir=output_dir,
    )
    gate = "[green]PASS[/green]" if score.vulnerability_detected else "[red]FAIL[/red]"
    console.print(
        f"  {gate} detected={score.vulnerability_detected}  score={score.score:.2f}"
    )
    return score


def _print_exploit_score_summary(score: ExploitScore) -> None:
    if score.succeeds and score.profit_verified:
        profit = f" observed_profit={score.profit_amount}"
        if score.profit_ratio_vs_reference is not None:
            profit += f" vs_reference={score.profit_ratio_vs_reference:.2f}x"
        console.print(f"  [green]PASS[/green]{profit}")
    elif score.succeeds:
        console.print("  [yellow]PASS without verified attacker profit[/yellow]")
    elif score.runs:
        console.print("  [yellow]ran but failed[/yellow]")
    elif score.compiles:
        console.print("  [yellow]compiled but test failed[/yellow]")
    else:
        console.print("  [red]compile error[/red]")
    if score.outcome_reason:
        console.print(f"  [dim]{score.outcome_reason}[/dim]")


def generate_exploit_output(
    case: ExploitCase,
    agent: BaseAgent,
    base_dir: Path,
    reference_baseline_cache: dict[str, dict] | None = None,
    *,
    review_mode: bool = False,
) -> dict[str, object]:
    if case.has_reference_exploit and isinstance(agent, MockAgent):
        reference_score = reference_score_from_cache(case, reference_baseline_cache)
        if reference_score is None:
            reference_score = evaluate_reference_exploit(case, base_dir)
        if reference_score is not None:
            score = ExploitScore(
                compiles=reference_score.compiles,
                runs=reference_score.runs,
                succeeds=reference_score.succeeds,
                profit_verified=reference_score.profit_verified,
                profit_amount=reference_score.profit_amount,
                observed_profit_breakdown=dict(reference_score.observed_profit_breakdown),
                compile_error=reference_score.compile_error,
                test_output=reference_score.test_output,
            )
            score = attach_profit_baselines(score, case, reference_score, base_dir=base_dir)
            score.outcome_reason = summarize_exploit_outcome(
                score, case, reference_score=reference_score
            )
            return _generated_case_output_payload(
                task="exploit",
                case=case,
                model=str(getattr(agent, "model", "unknown")),
                status="score_stub",
                score_stub=score,
            )

    contract_code = _get_contract_code(case, base_dir)
    hint_parts = _exploit_input_lines(case, base_dir, review_mode=review_mode)
    hint_text = "\n".join(hint_parts)
    workspace_dir = _create_agent_workspace(
        base_dir=base_dir,
        task="exploit",
        case_id=case.id,
        agent=agent,
        case_input_text=hint_text,
        output_name="_exploit.sol",
    )
    try:
        response = agent.exploit(
            contract_code,
            vulnerability_hint=hint_text,
            case_id=case.id,
            workspace_dir=str(workspace_dir),
        )
        response = _persist_session_log(response)
        return _generated_case_output_payload(
            task="exploit",
            case=case,
            model=str(getattr(agent, "model", "unknown")),
            status="completed",
            response=response,
        )
    finally:
        cleanup_agent_case_workspace(workspace_dir)


def score_exploit_generated_output(
    case: ExploitCase,
    generated_output: dict[str, object],
    base_dir: Path,
    reference_baseline_cache: dict[str, dict] | None = None,
    *,
    review_mode: bool = False,
    output_dir: Path,
) -> ExploitScore:
    if str(generated_output.get("status", "")) == "score_stub":
        raw_stub = generated_output.get("score_stub")
        if isinstance(raw_stub, dict):
            score = ExploitScore(**raw_stub)
            artifact_dir = _make_artifact_dir(
                output_dir,
                case.id,
                str(generated_output.get("model", "unknown")),
            )
            return write_exploit_score_artifact(score, artifact_dir)
        return ExploitScore()

    raw_output = _extract_serialized_agent_response(generated_output)
    if not isinstance(raw_output, dict):
        raise ValueError(f"missing llm_output for exploit case {case.id}")

    response = _deserialize_agent_response(raw_output)
    artifact_dir = _make_artifact_dir(
        output_dir,
        case.id,
        str(generated_output.get("model", "unknown")),
    )
    artifact_dir.mkdir(parents=True, exist_ok=True)
    hint_text = "\n".join(_exploit_input_lines(case, base_dir, review_mode=review_mode))
    hint_path = artifact_dir / "hint.txt"
    hint_path.write_text(hint_text)

    reference_score = None
    if case.has_reference_exploit:
        reference_score = reference_score_from_cache(case, reference_baseline_cache)
        if reference_score is None:
            reference_score = evaluate_reference_exploit(case, base_dir)

    score = evaluate_exploit(case, response, base_dir, artifact_dir=artifact_dir)
    score.hint_path = str(hint_path)
    score.workspace_dir = str(response.workspace_dir or "")
    if not score.session_log_path:
        score.session_log_path = copy_session_log_to_artifact(
            artifact_dir,
            response.session_log_path,
            str(response.session_log_text or ""),
        )
    score = attach_profit_baselines(score, case, reference_score, base_dir=base_dir)
    score.outcome_reason = summarize_exploit_outcome(
        score, case, response=response, reference_score=reference_score
    )

    # --- Best-of-history: if the workspace has a best snapshot, evaluate it
    # and keep the higher-profit result. ---
    best_sol = Path(response.workspace_dir or "") / "_exploit_best.sol"
    if best_sol.exists():
        best_code = best_sol.read_text(errors="replace")
        if best_code.strip() and best_code != (response.exploit_code or ""):
            best_response = AgentResponse(
                task_type=TaskType.EXPLOIT,
                raw_response=response.raw_response,
                exploit_code=best_code,
                exploit_source_path=str(best_sol),
                workspace_dir=response.workspace_dir,
                session_log_path=response.session_log_path,
                session_log_text=response.session_log_text,
                input_tokens_total=response.input_tokens_total,
                output_tokens_total=response.output_tokens_total,
                cache_read_input_tokens_total=response.cache_read_input_tokens_total,
            )
            best_score = evaluate_exploit(case, best_response, base_dir, artifact_dir=artifact_dir)
            best_score = attach_profit_baselines(best_score, case, reference_score, base_dir=base_dir)
            cur_usd = score.observed_profit_usd if score.profit_verified else None
            best_usd = best_score.observed_profit_usd if best_score.profit_verified else None
            if best_usd is not None and (cur_usd is None or best_usd > cur_usd):
                best_score.hint_path = str(hint_path)
                best_score.workspace_dir = str(response.workspace_dir or "")
                best_score.session_log_path = score.session_log_path
                best_score.outcome_reason = summarize_exploit_outcome(
                    best_score, case, response=best_response, reference_score=reference_score
                ) + " (best-of-history snapshot)"
                score = best_score

    score.cost_usd = compute_cost_usd(
        str(generated_output.get("model", "")),
        score.input_tokens_total, score.output_tokens_total,
        score.cache_read_input_tokens_total,
    )
    return write_exploit_score_artifact(score, artifact_dir)


def run_exploit(
    case: ExploitCase,
    agent: BaseAgent,
    base_dir: Path,
    reference_baseline_cache: dict[str, dict] | None = None,
    *,
    review_mode: bool = False,
    output_dir: Path,
) -> ExploitScore:
    generated_output = generate_exploit_output(
        case,
        agent,
        base_dir,
        reference_baseline_cache=reference_baseline_cache,
        review_mode=review_mode,
    )
    score = score_exploit_generated_output(
        case,
        generated_output,
        base_dir,
        reference_baseline_cache=reference_baseline_cache,
        review_mode=review_mode,
        output_dir=output_dir,
    )
    _print_exploit_score_summary(score)
    return score


def generate_fix_output(
    case: FixCase,
    agent: BaseAgent,
    base_dir: Path,
    *,
    review_mode: bool = False,
) -> dict[str, object]:
    proxy_info = _lookup_fix_proxy_info(case)
    contract_code = _get_fix_contract_code(case, base_dir, proxy_info=proxy_info)

    exploit_code = None
    exploit_path = case.verification.get("exploit_path", "")
    if exploit_path:
        full = resolve_repo_path(base_dir, exploit_path)
        if full.exists():
            exploit_code = full.read_text(errors="replace")

    if not exploit_code and not case.has_attack_replay_verification:
        score = PatchScore(
            skipped=True,
            skip_reason="no exploit or historical attack transaction for verification",
            expected_target_contracts=_expected_fix_targets(case, contract_code, proxy_info),
            summary="patch evaluation was skipped because neither a verification exploit nor a historical attack transaction was available",
            diagnostic_notes=[
                "verification exploit and historical attack transactions were missing for this patch case"
            ],
        )
        return _generated_case_output_payload(
            task="patch",
            case=case,
            model=str(getattr(agent, "model", "unknown")),
            status="score_stub",
            score_stub=score,
        )

    fix_context_parts = _fix_input_lines(
        case,
        base_dir,
        contract_code=contract_code,
        proxy_info=proxy_info,
        review_mode=review_mode,
    )
    fix_context_parts.extend(
        part
        for part in [
            (
                f"vulnerability_summary: {case.vulnerability_description}"
                if str(case.vulnerability_description or "").strip()
                else ""
            ),
        ]
        if part
    )
    fix_context = "\n".join(fix_context_parts)
    workspace_dir = _create_agent_workspace(
        base_dir=base_dir,
        task="patch",
        case_id=case.id,
        agent=agent,
        case_input_text=fix_context,
        output_name="_patched.sol",
    )
    _stage_fix_reference_exploit(workspace_dir, exploit_code or "")
    try:
        response = agent.fix(
            contract_code,
            vulnerability_description=fix_context,
            case_id=case.id,
            workspace_dir=str(workspace_dir),
        )
        response = _persist_session_log(response)
        return _generated_case_output_payload(
            task="patch",
            case=case,
            model=str(getattr(agent, "model", "unknown")),
            status="completed",
            response=response,
        )
    finally:
        cleanup_agent_case_workspace(workspace_dir)


def score_fix_generated_output(
    case: FixCase,
    generated_output: dict[str, object],
    base_dir: Path,
    *,
    review_mode: bool = False,
    output_dir: Path,
) -> FixScore:
    if str(generated_output.get("status", "")) == "score_stub":
        raw_stub = generated_output.get("score_stub")
        if isinstance(raw_stub, dict):
            score = FixScore(**raw_stub)
            artifact_dir = _make_artifact_dir(
                output_dir,
                case.id,
                str(generated_output.get("model", "unknown")),
            )
            return write_fix_score_artifact(score, artifact_dir)
        return FixScore()

    raw_output = _extract_serialized_agent_response(generated_output)
    if not isinstance(raw_output, dict):
        raise ValueError(f"missing llm_output for fix case {case.id}")

    response = _deserialize_agent_response(raw_output)
    artifact_dir = _make_artifact_dir(
        output_dir,
        case.id,
        str(generated_output.get("model", "unknown")),
    )
    proxy_info = _lookup_fix_proxy_info(case)
    contract_code = _get_fix_contract_code(case, base_dir, proxy_info=proxy_info)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    exploit_code = None
    exploit_path = case.verification.get("exploit_path", "")
    if exploit_path:
        full = resolve_repo_path(base_dir, exploit_path)
        if full.exists():
            exploit_code = full.read_text(errors="replace")

    fix_context_parts = _fix_input_lines(
        case,
        base_dir,
        contract_code=contract_code,
        proxy_info=proxy_info,
        review_mode=review_mode,
    )
    fix_context_parts.extend(
        part
        for part in [
            (
                f"vulnerability_summary: {case.vulnerability_description}"
                if str(case.vulnerability_description or "").strip()
                else ""
            ),
        ]
        if part
    )
    fix_context = "\n".join(fix_context_parts)
    hint_path = artifact_dir / "hint.txt"
    hint_path.write_text(fix_context)

    score = evaluate_fix(
        case,
        response,
        exploit_code,
        base_dir,
        artifact_dir=artifact_dir,
        proxy_info=proxy_info,
    )
    score.hint_path = str(hint_path)
    score.workspace_dir = str(response.workspace_dir or "")
    if not score.session_log_path:
        score.session_log_path = copy_session_log_to_artifact(
            artifact_dir,
            response.session_log_path,
            str(response.session_log_text or ""),
        )

    fixed_code = response.fixed_code or ""
    if fixed_code and any(
        _canonical_source(fixed_code) == _canonical_source(source)
        for source in contract_code.values()
    ):
        if score.exploit_blocked:
            score.exploit_blocked = False
            score.normal_ops_pass = False
            note = (
                "No-op patch matched original source; downgraded false-positive exploit blocking."
            )
            score.test_output = f"{note}\n{score.test_output}".strip()

    # --- Best-of-history: if the workspace has a best snapshot, evaluate it
    # and keep the higher-score result. ---
    best_sol = Path(response.workspace_dir or "") / "_patched_best.sol"
    if best_sol.exists():
        best_code = best_sol.read_text(errors="replace")
        if best_code.strip() and best_code != fixed_code:
            best_response = AgentResponse(
                task_type=TaskType.PATCH,
                raw_response=response.raw_response,
                fixed_code=best_code,
                fix_possible=response.fix_possible,
                required_authority=response.required_authority,
                fix_confidence=response.fix_confidence,
                fix_rationale=response.fix_rationale,
                fix_target_contracts=response.fix_target_contracts,
                workspace_dir=response.workspace_dir,
                session_log_path=response.session_log_path,
                session_log_text=response.session_log_text,
                input_tokens_total=response.input_tokens_total,
                output_tokens_total=response.output_tokens_total,
                cache_read_input_tokens_total=response.cache_read_input_tokens_total,
            )
            best_score = evaluate_fix(
                case, best_response, exploit_code, base_dir,
                artifact_dir=artifact_dir, proxy_info=proxy_info,
            )
            if best_score.score > score.score:
                best_score.hint_path = str(hint_path)
                best_score.workspace_dir = str(response.workspace_dir or "")
                best_score.session_log_path = score.session_log_path
                best_score.summary = (best_score.summary or "") + " (best-of-history snapshot)"
                score = best_score

    score.cost_usd = compute_cost_usd(
        str(generated_output.get("model", "")),
        score.input_tokens_total, score.output_tokens_total,
        score.cache_read_input_tokens_total,
    )
    return write_fix_score_artifact(score, artifact_dir)


def run_fix(
    case: FixCase,
    agent: BaseAgent,
    base_dir: Path,
    *,
    review_mode: bool = False,
    output_dir: Path,
) -> FixScore:
    generated_output = generate_fix_output(case, agent, base_dir, review_mode=review_mode)
    score = score_fix_generated_output(
        case,
        generated_output,
        base_dir,
        review_mode=review_mode,
        output_dir=output_dir,
    )

    if score.exploit_blocked and score.normal_ops_pass:
        console.print("  [green]exploit blocked + normal ops ok[/green]")
    elif score.plan_only:
        verdict = "fixable" if score.patch_possible is True else "not_fixable" if score.patch_possible is False else "unclassified"
        console.print(f"  [cyan]plan-only remediation[/cyan] fixable={verdict}")
    elif score.skipped:
        reason = score.skip_reason or "skipped"
        console.print(f"  [yellow]{reason}[/yellow]")
    elif score.exploit_blocked:
        console.print("  [yellow]exploit blocked, regression failed[/yellow]")
    elif score.compiles:
        console.print("  [red]exploit still passes[/red]")
    else:
        console.print("  [red]doesn't compile[/red]")
    return score


@click.command()
@click.option(
    "--task",
    required=True,
    type=click.Choice(["detect", "exploit", "patch", "fix"]),
    help="Which task benchmark to run",
)
@click.option(
    "--track",
    "track",
    type=click.Choice(["on_chain"]),
    default="on_chain",
    help="Benchmark track",
)
@click.option("--agent", type=click.Choice(list(AGENT_REGISTRY.keys())), default=None)
@click.option("--model", default=None, help="Override model name")
@click.option("--category", default=None, help="Filter by category")
@click.option("--source", default=None, help="Filter by source")
@click.option("--case-id", multiple=True, default=(), help="Run specific case(s); repeat for multiple")
@click.option("--skip-existing", is_flag=True, help="Skip cases that already have score.json in output dir")
@click.option("--limit", type=int, default=None, help="Max cases")
@click.option(
    "--output", type=Path, default=None, help="Output result directory or index.json path"
)
@click.option("--jobs", "-j", type=int, default=1, help="Parallel workers (default: 1)")
@click.option("--dry-run", is_flag=True, help="List cases only")
@click.option("--base-dir", type=Path, default=Path("."), help="Project root")
@click.option("--benchmark-dir", type=Path, default=BENCHMARK_DIR, help="Benchmark root directory (contains benchmark_case/cases.json or cases.json)")
@click.option("--fixable-source-only/--all-cases", default=False, help="Only run fixable=true + has_public_source=true cases (default: off)")
def cli(
    task,
    track,
    agent,
    model,
    category,
    source,
    case_id,
    skip_existing,
    limit,
    fixable_source_only,
    output,
    jobs,
    dry_run,
    base_dir,
    benchmark_dir,
):
    """Web3Bug Benchmark Runner — on-chain only."""
    base_dir = base_dir.resolve()
    task, track = _normalize_task_track(task, track)
    track_label = TRACK_LABELS[track]

    removed_workspaces = cleanup_agent_case_workspaces(base_dir)
    if removed_workspaces:
        console.print(f"[dim]Cleaned {removed_workspaces} stale agent case workspace(s).[/dim]")
    removed_foundry_tmp = cleanup_foundry_eval_tmp(base_dir)
    if removed_foundry_tmp:
        console.print(
            f"[dim]Cleaned {removed_foundry_tmp} stale Foundry temp workspace/cache item(s).[/dim]"
        )

    def _post_run_cleanup() -> None:
        removed_after_run = cleanup_agent_case_workspaces(
            base_dir, include_owner_pids={os.getpid()}
        )
        if removed_after_run:
            console.print(
                f"[dim]Post-run cleanup removed {removed_after_run} agent case workspace(s).[/dim]"
            )
        removed_foundry_after_run = cleanup_foundry_eval_tmp(
            base_dir,
            include_owner_pids={os.getpid()},
        )
        if removed_foundry_after_run:
            console.print(
                f"[dim]Post-run cleanup removed {removed_foundry_after_run} Foundry temp workspace/cache item(s).[/dim]"
            )

    console.print(f"[bold]Web3Bug Benchmark — {task} / {track_label}[/bold]\n")

    split = "final"
    review_mode = False
    resolved_benchmark_dir = resolve_repo_path(base_dir, benchmark_dir)
    loader = BenchmarkLoader(resolved_benchmark_dir)
    loader.load(task, track=track, split=split)
    split_label = "benchmark_case"
    console.print(f"Loaded {len(loader)} {task}/{track} cases from {split_label}")
    if len(loader) == 0:
        console.print(
            "[yellow]No benchmark cases found.[/yellow] "
            f"Populate {resolved_benchmark_dir} with benchmark case .json files (or benchmark_case/cases.json or cases.json)."
        )

    cases = loader.filter(category=category, source=source)
    if case_id:
        id_set = set(case_id) if isinstance(case_id, (list, tuple)) else {case_id}
        cases = [c for c in cases if c.id in id_set]
    if fixable_source_only:
        cases = [
            c for c in cases
            if getattr(c, "raw", {}).get("fixable") is True
            and getattr(c, "raw", {}).get("has_public_source") is True
        ]
    if task == "patch":
        cases = [
            c for c in cases
            if (getattr(c, "raw", {}) or {}).get("normal_txs")
        ]
    if limit:
        cases = cases[:limit]

    # --skip-existing: filter out cases that already have score.json in output dir
    if skip_existing and output is not None:
        output_dir_check = output if output.is_dir() else output.parent
        before = len(cases)
        cases = [c for c in cases if not (output_dir_check / c.id / "score.json").exists()]
        skipped = before - len(cases)
        if skipped:
            console.print(f"[dim]Skipped {skipped} cases with existing results[/dim]")

    console.print(f"Selected {len(cases)} cases\n")

    if dry_run:
        table = Table(title=f"{task.capitalize()} — {track_label}")
        table.add_column("ID")
        table.add_column("Name", max_width=40)
        table.add_column("Category")
        table.add_column("Source")
        for c in cases:
            table.add_row(c.id, c.name[:40], c.category, c.source)
        console.print(table)
        _post_run_cleanup()
        return

    if agent is None:
        if "codex_cli" in AGENT_REGISTRY:
            agent = "codex_cli"
        elif "claude_code" in AGENT_REGISTRY:
            agent = "claude_code"
        elif "mock" in AGENT_REGISTRY:
            agent = "mock"
        else:
            agent = next(iter(AGENT_REGISTRY))
    agent_cls = AGENT_REGISTRY[agent]
    init_kwargs = _build_agent_kwargs(agent, base_dir)
    init_kwargs["benchmark_dir"] = resolved_benchmark_dir
    agent_instance = (
        agent_cls(model=model, **init_kwargs) if model else agent_cls(**init_kwargs)
    )

    console.print(f"Agent: {agent} / {agent_instance.model}\n")

    reference_baseline_cache = load_reference_baseline_cache(base_dir) if task == "exploit" else {}

    if output is None:
        output_dir = default_results_dir(base_dir, task, track)
    elif output.suffix == ".json":
        output_dir = output.with_suffix("")
    else:
        output_dir = output
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_batch_id = output_dir.name

    results = []
    t0 = time.time()
    _print_lock = threading.Lock()
    _completed = {"n": 0}

    def _run_one_case(case):
        missing_fields = _benchmark_missing_fields(case)
        if missing_fields:
            with _print_lock:
                console.print(
                    f"  [yellow]Skipped {case.id}:[/yellow] " + ", ".join(missing_fields)
                )
            return {"case": case, "score": _incomplete_benchmark_score(task, missing_fields)}
        score = None
        run_error = None
        for attempt in range(3):
            try:
                if task == "detect":
                    score = run_detect(
                        case, agent_instance, base_dir, output_dir=output_dir
                    )
                elif task == "exploit":
                    score = run_exploit(
                        case,
                        agent_instance,
                        base_dir,
                        reference_baseline_cache=reference_baseline_cache,
                        review_mode=review_mode,
                        output_dir=output_dir,
                    )
                else:
                    score = run_fix(
                        case,
                        agent_instance,
                        base_dir,
                        review_mode=review_mode,
                        output_dir=output_dir,
                    )
            except Exception as exc:
                tb = traceback.format_exc()
                run_error = {
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "traceback": tb,
                }
                with _print_lock:
                    console.print(f"  [red]{case.id} Error: {exc}[/red]")
                # Persist the traceback so infrastructure failures are auditable
                # and not silently conflated with legitimate zero-score cases.
                try:
                    case_tb_path = output_dir / f"{case.id}_error.txt"
                    case_tb_path.write_text(
                        f"{type(exc).__name__}: {exc}\n\n{tb}", encoding="utf-8"
                    )
                    run_error["traceback_path"] = str(case_tb_path)
                except Exception:
                    pass
                score = None
            # Retry on API 429 rate-limit errors
            if score is not None and _is_rate_limited(score) and attempt < 2:
                wait = 30 * (attempt + 1)
                with _print_lock:
                    console.print(f"  [yellow]{case.id}: API 429, retrying in {wait}s (attempt {attempt + 2}/3)[/yellow]")
                time.sleep(wait)
                continue
            # Retry on process killed (SIGKILL / OOM) — likely resource contention
            if score is not None and _is_process_killed(score) and attempt < 2:
                wait = 10 * (attempt + 1)
                with _print_lock:
                    console.print(f"  [yellow]{case.id}: process killed (elapsed {getattr(score, 'agent_elapsed_seconds', '?')}s), retrying in {wait}s (attempt {attempt + 2}/3)[/yellow]")
                time.sleep(wait)
                continue
            break
        _completed["n"] += 1
        with _print_lock:
            s = f"{score.score:.2f}" if score is not None and hasattr(score, "score") else "ERR"
            console.print(f"[{_completed['n']}/{len(cases)}] {case.id}: {case.name}  score={s}")
        return {"case": case, "score": score, "error": run_error}

    effective_jobs = max(1, jobs)
    if effective_jobs == 1:
        for case in cases:
            results.append(_run_one_case(case))
    else:
        console.print(f"Running with {effective_jobs} parallel workers\n")
        futures = {}
        with ThreadPoolExecutor(max_workers=effective_jobs) as pool:
            for case in cases:
                fut = pool.submit(_run_one_case, case)
                futures[fut] = case
            for fut in as_completed(futures):
                results.append(fut.result())

    elapsed = time.time() - t0
    console.print(f"\nDone in {elapsed:.1f}s\n")

    table = Table(title=f"{task.capitalize()} — {track_label} Results", show_lines=True)
    table.add_column("Case ID", style="cyan")
    table.add_column("Name", max_width=30)
    table.add_column("Score", justify="right")
    table.add_column("Time", justify="right")
    table.add_column("In Tok", justify="right")
    table.add_column("Out Tok", justify="right")
    table.add_column("Cache%", justify="right")
    table.add_column("Cost", justify="right")

    def _fmt_tokens(n: int | None) -> str:
        if n is None:
            return "-"
        if n >= 1_000_000:
            return f"{n / 1_000_000:.1f}M"
        if n >= 1_000:
            return f"{n / 1_000:.1f}k"
        return str(n)

    def _fmt_cost(c: float | None) -> str:
        if c is None:
            return "-"
        if c < 0.01:
            return f"${c:.4f}"
        return f"${c:.2f}"

    scores = []
    total_input = 0
    total_output = 0
    total_cached = 0
    total_cost = 0.0
    infra_error_ids = []
    for result in results:
        case = result["case"]
        score = result["score"]
        if score is None:
            err = result.get("error")
            if err:
                infra_error_ids.append(case.id)
                label = f"[red]infra-err[/red] ({err['type']})"
            else:
                label = "[red]error[/red]"
            table.add_row(case.id, case.name[:30], label, "-", "-", "-", "-", "-")
            continue

        if bool(getattr(score, "skipped", False)):
            table.add_row(case.id, case.name[:30], "[yellow]skip[/yellow]", "-", "-", "-", "-", "-")
            continue
        value = score.score
        scores.append(value)
        color = "green" if value >= 0.5 else ("yellow" if value > 0 else "red")
        elapsed_s = getattr(score, "agent_elapsed_seconds", None)
        time_str = f"{elapsed_s:.0f}s" if elapsed_s else "-"
        inp = getattr(score, "input_tokens_total", None)
        out = getattr(score, "output_tokens_total", None)
        cached = getattr(score, "cache_read_input_tokens_total", None)
        cost = getattr(score, "cost_usd", None)
        cache_pct = f"{cached / inp * 100:.0f}%" if inp and cached else "-"
        if inp:
            total_input += inp
        if out:
            total_output += out
        if cached:
            total_cached += cached
        if cost:
            total_cost += cost
        table.add_row(case.id, case.name[:30], f"[{color}]{value:.2f}[/{color}]",
                       time_str, _fmt_tokens(inp), _fmt_tokens(out), cache_pct, _fmt_cost(cost))

    if scores:
        avg = sum(scores) / len(scores)
        avg_cache_pct = f"{total_cached / total_input * 100:.0f}%" if total_input and total_cached else "-"
        table.add_row("AVERAGE", f"({len(scores)} cases)", f"[bold]{avg:.2f}[/bold]",
                       "", _fmt_tokens(total_input), _fmt_tokens(total_output), avg_cache_pct,
                       f"[bold]{_fmt_cost(total_cost)}[/bold]", style="bold")
    console.print(table)

    if infra_error_ids:
        console.print(
            f"\n[bold red]⚠ {len(infra_error_ids)} case(s) failed with internal/infrastructure "
            f"errors (NOT benchmark failures):[/bold red] {', '.join(infra_error_ids)}"
        )
        console.print(
            "[red]  These results are inconclusive — see *_error.txt in the output dir. "
            "Do not treat as valid scores.[/red]"
        )

    output_index = output_dir / "index.json"

    serialized_results = []
    for result in results:
        score = result["score"]
        row = {
            "case_id": result["case"].id,
            "case_name": result["case"].name,
            "annotation_hints": result["case"].annotation_hints,
        }
        if score is None:
            row["score"] = None
            err = result.get("error")
            if err:
                # Distinguish an internal/infrastructure failure (evaluator
                # crash, RPC/setup error) from a legitimate failed benchmark run.
                row["error"] = {
                    "type": err["type"],
                    "message": err["message"],
                    "traceback_path": err.get("traceback_path"),
                }
        elif task == "exploit":
            row.update(
                {
                    "score": score.score,
                    "artifact_dir": score.artifact_dir,
                    "workspace_dir": score.workspace_dir,
                    "session_log_path": score.session_log_path,
                    "hint_path": score.hint_path,
                    "response_path": score.response_path,
                    "score_path": score.score_path,
                    "exploit_code_path": score.exploit_code_path,
                    "prepared_exploit_path": score.prepared_exploit_path,
                    "forge_output_path": score.forge_output_path,
                    "executed_on_fork": score.executed_on_fork,
                    "execution_mode": score.execution_mode,
                    "execution_command": score.execution_command,
                    "execution_project_root": score.execution_project_root,
                    "fork_chain": score.fork_chain,
                    "fork_block": score.fork_block,
                    "compile_error": score.compile_error[-500:] if score.compile_error else "",
                    "test_output": score.test_output[-500:] if score.test_output else "",
                    "economically_successful": score.economically_successful,
                    "profit_verified": score.profit_verified,
                    "observed_profit": score.profit_amount,
                    "observed_profit_breakdown": score.observed_profit_breakdown,
                    "reference_succeeds": score.reference_succeeds,
                    "reference_profit_verified": score.reference_profit_verified,
                    "profit_ratio_vs_reference": score.profit_ratio_vs_reference,
                    "exceeds_reference_profit": score.exceeds_reference_profit,
                    "profit_comparison_basis": score.profit_comparison_basis,
                    "comparison_note": score.comparison_note,
                    "outcome_reason": score.outcome_reason,
                }
            )
        elif task in ("fix", "patch"):
            row.update(
                {
                    "score": score.score,
                    "artifact_dir": score.artifact_dir,
                    "workspace_dir": score.workspace_dir,
                    "session_log_path": score.session_log_path,
                    "hint_path": score.hint_path,
                    "response_path": score.response_path,
                    "score_path": score.score_path,
                    "patched_code_path": score.patched_code_path,
                    "harness_path": score.harness_path,
                    "regression_path": score.regression_path,
                    "forge_output_path": score.forge_output_path,
                    "regression_output_path": score.regression_output_path,
                    "compile_error": score.compile_error[-500:] if score.compile_error else "",
                    "test_output": score.test_output[-500:] if score.test_output else "",
                    "regression_output": (
                        score.regression_output[-500:] if score.regression_output else ""
                    ),
                    "compiles": score.compiles,
                    "exploit_blocked": score.exploit_blocked,
                    "normal_ops_pass": score.normal_ops_pass,
                    "view_oracle_checked": score.view_oracle_checked,
                    "token_tx_oracle_checked": score.token_tx_oracle_checked,
                    "classification_present": score.classification_present,
                    "patch_possible": score.patch_possible,
                    "required_authority": score.required_authority,
                    "fix_confidence": score.fix_confidence,
                    "fix_rationale": score.fix_rationale,
                    "target_contracts": score.target_contracts,
                    "expected_target_contracts": score.expected_target_contracts,
                    "proxy_target_matched": score.proxy_target_matched,
                    "proxy_detected": score.proxy_detected,
                    "proxy_kind": score.proxy_kind,
                    "proxy_implementation": score.proxy_implementation,
                    "proxy_admin": score.proxy_admin,
                    "plan_only": score.plan_only,
                    "summary": score.summary,
                    "diagnostic_notes": score.diagnostic_notes,
                }
            )
        else:
            row.update(
                {
                    "score": score.score,
                    "artifact_dir": score.artifact_dir,
                    "response_path": score.response_path,
                    "workspace_dir": score.workspace_dir,
                    "session_log_path": score.session_log_path,
                    "agent_elapsed_seconds": score.agent_elapsed_seconds,
                    "input_tokens_total": score.input_tokens_total,
                    "output_tokens_total": score.output_tokens_total,
                    "cache_read_input_tokens_total": score.cache_read_input_tokens_total,
                    "cache_write_input_tokens_total": score.cache_write_input_tokens_total,
                    "cost_usd": score.cost_usd,
                    "detection_credit": score.detection_credit,
                    "localization_credit": score.localization_credit,
                    "vulnerability_detected": score.vulnerability_detected,
                    "ground_truth_type": score.ground_truth_type,
                    "ground_truth_file": score.ground_truth_file,
                    "ground_truth_function": score.ground_truth_function,
                    "gate_reason": score.gate_reason,
                    "outcome_label": score.outcome_label,
                    "debug_reason": score.debug_reason,
                    "summary": score.summary,
                    "expected_type": score.expected_type,
                    "expected_file": score.expected_file,
                    "expected_function": score.expected_function,
                    "type_match": score.type_match,
                    "file_match": score.file_match,
                    "function_match": score.function_match,
                    "matched_dimensions": score.matched_dimensions,
                    "missed_dimensions": score.missed_dimensions,
                    "total_reported": score.total_reported,
                    "used_text_fallback": score.used_text_fallback,
                    "top1_reported": score.top1_reported,
                    "diagnostic_notes": score.diagnostic_notes,
                }
            )
        serialized_results.append(row)

    payload = {
        "task": task,
        "track": track,
        "track_label": track_label,
        "agent": agent,
        "model": agent_instance.model,
        "num_cases": len(cases),
        "elapsed_seconds": elapsed,
        "infrastructure_errors": infra_error_ids,
        "results": serialized_results,
        "case_results_dir": str(output_dir),
    }
    flat_results = os.environ.get("W3BB_FLAT_RESULTS", "").strip().lower() in {"1", "true", "yes"}
    if not flat_results:
        output_index.write_text(json.dumps(payload, indent=2))
        _write_legacy_case_result_directory(output_dir, payload)
    console.print(f"Saved: {output_dir}")
    _post_run_cleanup()


if __name__ == "__main__":
    cli()
