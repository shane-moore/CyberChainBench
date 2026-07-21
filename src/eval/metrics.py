"""Compatibility exports plus aggregate per-case result serialization."""

from __future__ import annotations

from dataclasses import dataclass, field

from eval.tasks import DetectScore, ExploitScore, PatchScore

# Backwards-compatible alias
FixScore = PatchScore


@dataclass
class CaseResult:
    """Complete evaluation result for one benchmark case."""

    case_id: str
    case_name: str
    agent_name: str
    detect: DetectScore = field(default_factory=DetectScore)
    exploit: ExploitScore = field(default_factory=ExploitScore)
    patch: PatchScore = field(default_factory=PatchScore)
    # Store the exploit code so patch step can reuse it
    exploit_code: str | None = None

    @property
    def fix(self) -> PatchScore:
        """Backwards-compatible alias for patch."""
        return self.patch

    @fix.setter
    def fix(self, value: PatchScore) -> None:
        self.patch = value

    @property
    def active_dimensions(self) -> list[str]:
        """Which evaluation dimensions have valid scores (not skipped)."""
        dims = ["detect"]
        if not self.exploit.skipped:
            dims.append("exploit")
        if not self.patch.skipped:
            dims.append("patch")
        return dims

    @property
    def total_score(self) -> float:
        """Average score across active (non-skipped) dimensions."""
        scores = [self.detect.score]
        if not self.exploit.skipped:
            scores.append(self.exploit.score)
        if not self.patch.skipped:
            scores.append(self.patch.score)
        return sum(scores) / len(scores) if scores else 0.0

    def to_dict(self) -> dict:
        exploit_detail: dict = {
            "artifact_dir": self.exploit.artifact_dir,
            "workspace_dir": self.exploit.workspace_dir,
            "session_log_path": self.exploit.session_log_path,
            "hint_path": self.exploit.hint_path,
            "response_path": self.exploit.response_path,
            "score_path": self.exploit.score_path,
            "exploit_code_path": self.exploit.exploit_code_path,
            "prepared_exploit_path": self.exploit.prepared_exploit_path,
            "forge_output_path": self.exploit.forge_output_path,
            "executed_on_fork": self.exploit.executed_on_fork,
            "execution_mode": self.exploit.execution_mode,
            "execution_command": self.exploit.execution_command,
            "execution_project_root": self.exploit.execution_project_root,
            "fork_chain": self.exploit.fork_chain,
            "fork_block": self.exploit.fork_block,
            "compiles": self.exploit.compiles,
            "runs": self.exploit.runs,
            "succeeds": self.exploit.succeeds,
            "economically_successful": self.exploit.economically_successful,
            "profit_verified": self.exploit.profit_verified,
            "profit_amount": self.exploit.profit_amount,
            "observed_profit_breakdown": self.exploit.observed_profit_breakdown,
            "reference_succeeds": self.exploit.reference_succeeds,
            "reference_profit_verified": self.exploit.reference_profit_verified,
            "profit_ratio_vs_reference": self.exploit.profit_ratio_vs_reference,
            "exceeds_reference_profit": self.exploit.exceeds_reference_profit,
            "profit_comparison_basis": self.exploit.profit_comparison_basis,
            "comparison_note": self.exploit.comparison_note,
            "outcome_reason": self.exploit.outcome_reason,
            "output": self.exploit.test_output[-200:] if self.exploit.test_output else "",
        }
        if self.exploit.skipped:
            exploit_detail = {"skipped": True, "reason": self.exploit.skip_reason}

        patch_detail: dict = {
            "compiles": self.patch.compiles,
            "exploit_blocked": self.patch.exploit_blocked,
            "normal_ops_pass": self.patch.normal_ops_pass,
            "view_oracle_checked": self.patch.view_oracle_checked,
            "token_tx_oracle_checked": self.patch.token_tx_oracle_checked,
            "classification_present": self.patch.classification_present,
            "patch_possible": self.patch.patch_possible,
            "required_authority": self.patch.required_authority,
            "fix_confidence": self.patch.fix_confidence,
            "fix_rationale": self.patch.fix_rationale,
            "target_contracts": self.patch.target_contracts,
            "expected_target_contracts": self.patch.expected_target_contracts,
            "proxy_target_matched": self.patch.proxy_target_matched,
            "proxy_detected": self.patch.proxy_detected,
            "proxy_kind": self.patch.proxy_kind,
            "proxy_implementation": self.patch.proxy_implementation,
            "proxy_admin": self.patch.proxy_admin,
            "plan_only": self.patch.plan_only,
            "summary": self.patch.summary,
            "diagnostic_notes": self.patch.diagnostic_notes,
            "artifact_dir": self.patch.artifact_dir,
            "workspace_dir": self.patch.workspace_dir,
            "session_log_path": self.patch.session_log_path,
            "hint_path": self.patch.hint_path,
            "response_path": self.patch.response_path,
            "score_path": self.patch.score_path,
            "patched_code_path": self.patch.patched_code_path,
            "harness_path": self.patch.harness_path,
            "regression_path": self.patch.regression_path,
            "forge_output_path": self.patch.forge_output_path,
            "regression_output_path": self.patch.regression_output_path,
            "output": self.patch.test_output[-200:] if self.patch.test_output else "",
            "regression_output": (
                self.patch.regression_output[-200:] if self.patch.regression_output else ""
            ),
        }
        if self.patch.skipped:
            patch_detail = {"skipped": True, "reason": self.patch.skip_reason}

        return {
            "case_id": self.case_id,
            "case_name": self.case_name,
            "agent": self.agent_name,
            "scores": {
                "detect": self.detect.score,
                "exploit": self.exploit.score if not self.exploit.skipped else None,
                "patch": self.patch.score if not self.patch.skipped else None,
                "total": self.total_score,
                "dimensions": self.active_dimensions,
            },
            "details": {
                "detect": {
                    "artifact_dir": self.detect.artifact_dir,
                    "hint_path": self.detect.hint_path,
                    "response_path": self.detect.response_path,
                    "normalized_response_path": self.detect.normalized_response_path,
                    "score_path": self.detect.score_path,
                    "case_input_path": self.detect.case_input_path,
                    "workspace_dir": self.detect.workspace_dir,
                    "session_log_path": self.detect.session_log_path,
                    "detection_credit": self.detect.detection_credit,
                    "localization_credit": self.detect.localization_credit,
                    "vulnerability_detected": self.detect.vulnerability_detected,
                    "ground_truth_type": self.detect.ground_truth_type,
                    "ground_truth_file": self.detect.ground_truth_file,
                    "ground_truth_function": self.detect.ground_truth_function,
                    "gate_reason": self.detect.gate_reason,
                    "outcome_label": self.detect.outcome_label,
                    "debug_reason": self.detect.debug_reason,
                    "summary": self.detect.summary,
                    "expected_type": self.detect.expected_type,
                    "expected_file": self.detect.expected_file,
                    "expected_function": self.detect.expected_function,
                    "type_match": self.detect.type_match,
                    "file_match": self.detect.file_match,
                    "function_match": self.detect.function_match,
                    "matched_dimensions": self.detect.matched_dimensions,
                    "missed_dimensions": self.detect.missed_dimensions,
                    "total_reported": self.detect.total_reported,
                    "used_text_fallback": self.detect.used_text_fallback,
                    "top1_reported": self.detect.top1_reported,
                    "diagnostic_notes": self.detect.diagnostic_notes,
                },
                "exploit": exploit_detail,
                "patch": patch_detail,
            },
        }
