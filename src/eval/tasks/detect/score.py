from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class DetectScore:
    """Score for vulnerability detection."""

    vulnerability_detected: bool = False
    ground_truth_type: str = ""
    ground_truth_file: str = ""
    ground_truth_function: str = ""
    ground_truth_line: int | None = None
    ground_truth_line_range: list[int] = field(default_factory=list)
    expected_type: bool = False
    expected_file: bool = False
    expected_function: bool = False
    expected_line: bool = False
    type_match: bool = False
    file_match: bool = False
    function_match: bool = False
    line_match: bool = False
    line_distance: int | None = None
    total_reported: int = 0
    gate_reason: str = ""
    summary: str = ""
    used_text_fallback: bool = False
    artifact_dir: str = ""
    hint_path: str = ""
    response_path: str = ""
    normalized_response_path: str = ""
    score_path: str = ""
    case_input_path: str = ""
    workspace_dir: str = ""
    session_log_path: str = ""
    agent_elapsed_seconds: float | None = None
    input_tokens_total: int | None = None
    output_tokens_total: int | None = None
    cache_read_input_tokens_total: int | None = None
    cache_write_input_tokens_total: int | None = None
    cost_usd: float | None = None
    top1_reported: dict[str, object] = field(default_factory=dict)
    diagnostic_notes: list[str] = field(default_factory=list)

    @property
    def detection_credit(self) -> float:
        return 1.0 if self.vulnerability_detected else 0.0

    @property
    def localization_credit(self) -> float:
        if not self.vulnerability_detected:
            return 0.0
        type_ok = self.type_match or not self.expected_type
        func_ok = self.function_match or not self.expected_function
        return 1.0 if (type_ok and func_ok) else 0.0

    @property
    def score(self) -> float:
        if not self.vulnerability_detected:
            return 0.0
        return self.localization_credit

    @property
    def matched_dimensions(self) -> list[str]:
        matched: list[str] = []
        if self.type_match:
            matched.append("type")
        if self.function_match:
            matched.append("function")
        return matched

    @property
    def missed_dimensions(self) -> list[str]:
        missed: list[str] = []
        if self.expected_type and not self.type_match:
            missed.append("type")
        if self.expected_function and not self.function_match:
            missed.append("function")
        return missed

    @property
    def outcome_label(self) -> str:
        if not self.vulnerability_detected:
            return "missed_vulnerability"
        if self.score >= 0.999:
            return "localized_vulnerability"
        if self.matched_dimensions:
            return "partial_localization"
        return "detected_but_not_localized"

    @property
    def debug_reason(self) -> str:
        if not self.vulnerability_detected:
            return self.summary or self.gate_reason or "detection gate failed"
        if self.matched_dimensions:
            return self.summary or "partial localization match"
        if self.missed_dimensions:
            return "detection passed gate but localization missed " + ", ".join(
                self.missed_dimensions
            )
        return self.summary or "detection passed gate but localization evidence was incomplete"


def serialize_detect_score(score: DetectScore) -> dict[str, object]:
    payload = asdict(score)
    payload["score"] = score.score
    payload["outcome_label"] = score.outcome_label
    payload["matched_dimensions"] = score.matched_dimensions
    payload["missed_dimensions"] = score.missed_dimensions
    payload["detection_credit"] = score.detection_credit
    payload["localization_credit"] = score.localization_credit
    return payload


def write_detect_score_artifact(
    score: DetectScore,
    artifact_dir: Path | str | None,
) -> DetectScore:
    if artifact_dir is None:
        return score

    artifact_path = Path(artifact_dir)
    artifact_path.mkdir(parents=True, exist_ok=True)
    score.artifact_dir = str(artifact_path)
    score_path = artifact_path / "score.json"
    score.score_path = str(score_path)
    score_path.write_text(json.dumps(serialize_detect_score(score), indent=2, ensure_ascii=False))
    return score
