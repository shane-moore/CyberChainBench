"""Serialization and artifact helpers for the benchmark runner."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
import json
import re
from pathlib import Path

from agents.task_agent.base import AgentResponse, TaskType

_SERIALIZED_AGENT_RESPONSE_FIELDS = (
    "task_type",
    "raw_response",
    "workspace_dir",
    "session_log_path",
    "session_log_text",
    "agent_elapsed_seconds",
    "input_tokens_total",
    "output_tokens_total",
    "cache_read_input_tokens_total",
    "cache_write_input_tokens_total",
    "vulnerability_type",
    "vulnerability_location",
    "vulnerability_description",
    "exploit_code",
    "exploit_execution_project",
    "fixed_code",
    "file_patches",
    "fix_description",
    "fix_possible",
    "fix_rationale",
    "required_authority",
    "fix_target_contracts",
    "fix_confidence",
)


def _artifact_slug(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    return text.strip("-") or "unknown"


def _canonical_source(text: str) -> str:
    return " ".join((text or "").split())


def _serialize_agent_response(response: AgentResponse) -> dict[str, object]:
    return {
        "task_type": response.task_type.value,
        "raw_response": response.raw_response,
        "workspace_dir": response.workspace_dir,
        "session_log_path": response.session_log_path,
        "session_log_text": response.session_log_text,
        "agent_elapsed_seconds": response.agent_elapsed_seconds,
        "input_tokens_total": response.input_tokens_total,
        "output_tokens_total": response.output_tokens_total,
        "cache_read_input_tokens_total": response.cache_read_input_tokens_total,
        "cache_write_input_tokens_total": response.cache_write_input_tokens_total,
        "vulnerability_type": response.vulnerability_type,
        "vulnerability_location": response.vulnerability_location,
        "vulnerability_description": response.vulnerability_description,
        "exploit_code": response.exploit_code,
        "exploit_execution_project": response.exploit_execution_project,
        "fixed_code": response.fixed_code,
        "file_patches": response.file_patches,
        "fix_description": response.fix_description,
        "fix_possible": response.fix_possible,
        "fix_rationale": response.fix_rationale,
        "required_authority": response.required_authority,
        "fix_target_contracts": list(response.fix_target_contracts),
        "fix_confidence": response.fix_confidence,
    }


def _extract_serialized_agent_response(
    payload: dict[str, object],
) -> dict[str, object] | None:
    nested = payload.get("llm_output")
    if isinstance(nested, dict):
        return nested

    flattened = {
        field: payload[field] for field in _SERIALIZED_AGENT_RESPONSE_FIELDS if field in payload
    }
    if not flattened:
        return None
    if "task_type" not in flattened:
        flattened["task_type"] = str(payload.get("task", "")).strip().lower() or "detect"
    return flattened


def _optional_text(value: object, *, strip: bool = True) -> str | None:
    if value is None:
        return None
    text = str(value)
    if strip:
        text = text.strip()
    return text or None


def _optional_code(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text.strip() else None


def _deserialize_agent_response(payload: dict[str, object]) -> AgentResponse:
    raw_task_type = (
        str(payload.get("task_type", "")).strip().lower()
        or str(payload.get("task", "")).strip().lower()
        or "detect"
    )
    task_type = TaskType(raw_task_type)
    raw_file_patches = payload.get("file_patches")
    file_patches = (
        {
            str(key): text
            for key, value in raw_file_patches.items()
            if (text := _optional_code(value)) is not None
        }
        if isinstance(raw_file_patches, dict)
        else None
    )
    raw_fix_targets = payload.get("fix_target_contracts")
    fix_target_contracts = (
        [text for item in raw_fix_targets if (text := _optional_text(item)) is not None]
        if isinstance(raw_fix_targets, list)
        else []
    )
    return AgentResponse(
        task_type=task_type,
        raw_response=_optional_text(payload.get("raw_response"), strip=False) or "",
        workspace_dir=_optional_text(payload.get("workspace_dir")),
        session_log_path=_optional_text(payload.get("session_log_path")),
        session_log_text=_optional_text(payload.get("session_log_text")),
        agent_elapsed_seconds=(float(payload.get("agent_elapsed_seconds")) if payload.get("agent_elapsed_seconds") is not None else None),
        input_tokens_total=(int(payload.get("input_tokens_total")) if payload.get("input_tokens_total") is not None else None),
        output_tokens_total=(int(payload.get("output_tokens_total")) if payload.get("output_tokens_total") is not None else None),
        cache_read_input_tokens_total=(int(payload.get("cache_read_input_tokens_total")) if payload.get("cache_read_input_tokens_total") is not None else None),
        cache_write_input_tokens_total=(int(payload.get("cache_write_input_tokens_total")) if payload.get("cache_write_input_tokens_total") is not None else None),
        vulnerability_type=_optional_text(payload.get("vulnerability_type")),
        vulnerability_location=_optional_text(payload.get("vulnerability_location")),
        vulnerability_description=_optional_text(payload.get("vulnerability_description")),
        exploit_code=_optional_code(payload.get("exploit_code")),
        exploit_execution_project=_optional_text(payload.get("exploit_execution_project")),
        fixed_code=_optional_code(payload.get("fixed_code")),
        file_patches=file_patches,
        fix_description=_optional_text(payload.get("fix_description")),
        fix_possible=(
            payload.get("fix_possible") if isinstance(payload.get("fix_possible"), bool) else None
        ),
        fix_rationale=_optional_text(payload.get("fix_rationale")),
        required_authority=_optional_text(payload.get("required_authority")),
        fix_target_contracts=fix_target_contracts,
        fix_confidence=_optional_text(payload.get("fix_confidence")),
    )


def _generated_case_output_payload(
    *,
    task: str,
    case,
    model: str,
    status: str,
    response: AgentResponse | None = None,
    score_stub: object | None = None,
    error: str = "",
) -> dict[str, object]:
    payload: dict[str, object] = {
        "task": task,
        "case_id": str(getattr(case, "id", "")),
        "case_name": str(getattr(case, "name", "")),
        "source": str(getattr(case, "source", "")),
        "category": str(getattr(case, "category", "")),
        "severity": str(getattr(case, "severity", "")),
        "chain": str(getattr(case, "chain", "")),
        "model": model,
        "status": status,
    }
    if response is not None:
        payload["llm_output"] = _serialize_agent_response(response)
    if score_stub is not None:
        payload["score_stub"] = asdict(score_stub)
    if error:
        payload["error"] = error
    return payload


def _write_legacy_case_result_directory(output_dir: Path, payload: dict) -> Path:
    """Write one JSON file per case id for legacy single-task result payloads."""
    case_dir = output_dir / "cases"
    case_dir.mkdir(parents=True, exist_ok=True)

    results = [item for item in payload.get("results", []) if isinstance(item, dict)]
    case_index: list[dict[str, object]] = []
    for row in results:
        case_id = str(row.get("case_id", "")).strip()
        if not case_id:
            continue
        filename = f"{_artifact_slug(case_id)}.json"
        case_payload = {
            "task": payload.get("task", ""),
            "track": payload.get("track", ""),
            "track_label": payload.get("track_label", ""),
            "agent": payload.get("agent", ""),
            "model": payload.get("model", ""),
            "case": row,
        }
        (case_dir / filename).write_text(json.dumps(case_payload, indent=2))
        case_index.append(
            {
                "case_id": case_id,
                "path": filename,
                "score": row.get("score"),
                "artifact_dir": row.get("artifact_dir", ""),
            }
        )

    index_payload = {
        "task": payload.get("task", ""),
        "track": payload.get("track", ""),
        "track_label": payload.get("track_label", ""),
        "agent": payload.get("agent", ""),
        "model": payload.get("model", ""),
        "num_cases": len(case_index),
        "cases": case_index,
    }
    (case_dir / "index.json").write_text(json.dumps(index_payload, indent=2))
    return case_dir


def _make_artifact_dir(
    output_dir: Path,
    case_id: str,
    model: str,
) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return output_dir / _artifact_slug(case_id)
