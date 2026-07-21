"""
Detection evaluator.

Detect is framed as:
  Given a smart contract with a confirmed vulnerability, localize it by
  identifying the vulnerable file, function, and vulnerability type.

Scoring:
  Phase 1 (gate): Did the agent provide localization output (not an explicit
    denial)? All benchmark cases are confirmed vulnerable, so a denial is
    always wrong.
  Phase 2 (classification/localization): Compare the agent's reported
    vulnerability against ground truth on three dimensions:
    - type_match: correct vulnerability type per benchmark taxonomy
    - function_match: correct function (selector)
"""

from __future__ import annotations

from agents.task_agent.base import AgentResponse
from agents.task_agent.output_parser import extract_json_response
from prompts.taxonomy import normalize_detect_type_label
from benchmark.tasks.detect.case import DetectCase
from eval.tasks.detect.score import DetectScore

DETECT_NO_VULN_PHRASES = (
    "no vulnerabilit",
    "no security issue",
    "no issue found",
    "no issues found",
    "no bug",
    "no flaw",
    "appears safe",
    "appears secure",
    "looks safe",
    "looks secure",
    "is safe",
    "is secure",
    "no exploit",
    "not vulnerable",
    "cannot find any vulnerabilit",
    "could not find any vulnerabilit",
    "did not find any vulnerabilit",
    "don't see any vulnerabilit",
    "no significant vulnerabilit",
)


def _normalize_line_range(value: object) -> list[int]:
    if not isinstance(value, list):
        return []
    numbers = sorted({int(item) for item in value if isinstance(item, int) and item > 0})
    if not numbers:
        return []
    if len(numbers) == 1:
        return [numbers[0], numbers[0]]
    return [numbers[0], numbers[-1]]

def _get_vulnerabilities(parsed: dict | None) -> list[dict]:
    """Extract one normalized vulnerability entry from flat or legacy detect JSON."""
    if not isinstance(parsed, dict):
        return []

    if all(key in parsed for key in ("type", "file", "function")):
        return [{
            "type": parsed.get("type", ""),
            "file": parsed.get("file", ""),
            "function": parsed.get("function", ""),
            "description": parsed.get("description", ""),
        }]

    vs = parsed.get("vulnerabilities")
    if isinstance(vs, list):
        return [v for v in vs if isinstance(v, dict)]

    v = parsed.get("vulnerability")
    if isinstance(v, dict):
        return [v]

    return []


def _check_vulnerability_detected(response: AgentResponse, parsed: dict | None) -> tuple[bool, str]:
    """Phase 1 gate: did the agent provide localization (not deny)?

    All benchmark cases are confirmed vulnerable. An explicit denial is always wrong.
    """
    if isinstance(parsed, dict) and "vulnerable" in parsed:
        if not bool(parsed.get("vulnerable")):
            return False, "structured_response_marked_not_vulnerable"

    if response.vulnerability_type:
        return True, "agent_provided_vulnerability_type"

    raw_lower = response.raw_response.lower()
    for phrase in DETECT_NO_VULN_PHRASES:
        if phrase in raw_lower:
            return False, f"explicit_no_vulnerability_phrase:{phrase}"

    return True, "passed"


def _describe_top1(top1: dict) -> dict[str, object]:
    return {
        "type": str(top1.get("type", "")).strip(),
        "file": str(top1.get("file", "")).strip(),
        "function": str(top1.get("function", "")).strip(),
        "severity": str(top1.get("severity", "")).strip(),
    }


def _finalize_summary(score: DetectScore) -> None:
    if not score.vulnerability_detected:
        reason = score.gate_reason or "gate_failed"
        score.summary = f"detection gate failed: {reason}"
        return

    notes = list(score.diagnostic_notes)
    if (
        (not score.expected_type or score.type_match)
        and score.function_match
    ):
        if not notes:
            score.summary = "top-1 vulnerability matched all available localization anchors"
            return

    if (
        score.used_text_fallback
        and "used raw-text fallback because no structured vulnerability list was present"
        not in notes
    ):
        notes.insert(
            0, "used raw-text fallback because no structured vulnerability list was present"
        )

    if not notes:
        score.summary = "detection passed gate but localization evidence was incomplete"
        return

    score.summary = "; ".join(notes[:4])


def evaluate_detection(case: DetectCase, response: AgentResponse) -> DetectScore:
    """Evaluate the agent's detection response against ground truth.

    Phase 1: Gate — did the agent find a vulnerability?
    Phase 2: Classification/localization — compare top-1 vs ground truth
      (type, file, function)
    Phase 3: reserved (no penalty applied)
    """
    score = DetectScore()
    gt = case.ground_truth

    alt = getattr(case, "acceptable_alternatives", {}) or {}
    expected_type = normalize_detect_type_label(gt.get("type"))
    expected_file = gt.get("file", "")
    expected_func = gt.get("function", "")
    expected_line = gt.get("line")
    expected_line_range = _normalize_line_range(gt.get("line_range"))
    score.ground_truth_type = expected_type
    score.ground_truth_file = str(expected_file).strip()
    score.ground_truth_function = str(expected_func).strip()
    score.ground_truth_line = int(expected_line) if isinstance(expected_line, int) else None
    score.ground_truth_line_range = expected_line_range
    score.expected_type = bool(expected_type and expected_type != "other")
    score.expected_file = bool(expected_file)
    score.expected_function = bool(expected_func)
    score.expected_line = False

    parsed = extract_json_response(response.raw_response)

    # --- Phase 1: Gate ---
    score.vulnerability_detected, score.gate_reason = _check_vulnerability_detected(
        response, parsed
    )
    if not score.vulnerability_detected:
        _finalize_summary(score)
        return score

    # --- Phase 2 & 3: Localization + FP count ---
    vulns = _get_vulnerabilities(parsed)
    score.total_reported = len(vulns)

    if vulns:
        # Compare TOP-1 (most critical, first in list) against ground truth
        top1 = vulns[0]
        score.top1_reported = _describe_top1(top1)

        if score.expected_type:
            agent_type = normalize_detect_type_label(top1.get("type"))
            score.type_match = expected_type == agent_type
            if not score.type_match:
                score.diagnostic_notes.append(
                    f"type mismatch: expected {expected_type}, got {str(top1.get('type', '')).strip() or '(missing)'}"
                )

        # Function match
        if expected_func:
            agent_func = str(top1.get("function", "")).lower()
            score.function_match = expected_func.lower() == agent_func
            if not score.function_match:
                alt_funcs = [f.lower() for f in alt.get("function", [])]
                if agent_func in alt_funcs:
                    score.function_match = True
            if not score.function_match:
                score.diagnostic_notes.append(
                    f"function mismatch: expected {expected_func}, got {str(top1.get('function', '')).strip() or '(missing)'}"
                )

        _finalize_summary(score)

        return score

    # Fallback: raw text matching (for non-JSON responses)
    score.used_text_fallback = True
    raw_lower = response.raw_response.lower()

    if score.expected_type:
        agent_type = normalize_detect_type_label(response.vulnerability_type or response.raw_response)
        score.type_match = expected_type == agent_type
        if not score.type_match:
            score.diagnostic_notes.append(
                f"type mismatch in raw-text fallback: expected {expected_type}"
            )

    if expected_func:
        score.function_match = expected_func.lower() in raw_lower
        if not score.function_match:
            if any(f.lower() in raw_lower for f in alt.get("function", [])):
                score.function_match = True
        if not score.function_match:
            score.diagnostic_notes.append(
                f"function mismatch in raw-text fallback: expected {expected_func}"
            )

    if not score.top1_reported:
        score.top1_reported = {
            "type": str(response.vulnerability_type or "").strip(),
            "file": "",
            "function": "",
        }

    _finalize_summary(score)

    return score
