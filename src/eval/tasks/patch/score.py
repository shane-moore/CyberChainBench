from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path


@dataclass
class PatchScore:
    """Score for vulnerability patch."""

    compiles: bool = False
    baseline_checked: bool = False
    baseline_passed: bool = False
    exploit_blocked: bool = False
    normal_ops_pass: bool = False
    view_oracle_checked: bool = False
    token_tx_oracle_checked: bool = False
    classification_present: bool = False
    patch_possible: bool | None = None
    case_fixable: bool | None = None
    required_authority: str = ""
    fix_confidence: str = ""
    fix_rationale: str = ""
    target_contracts: list[str] = field(default_factory=list)
    expected_target_contracts: list[str] = field(default_factory=list)
    proxy_target_matched: bool = False
    proxy_detected: bool = False
    proxy_kind: str = ""
    proxy_implementation: str = ""
    proxy_admin: str = ""
    plan_only: bool = False
    summary: str = ""
    diagnostic_notes: list[str] = field(default_factory=list)
    compile_error: str = ""
    test_output: str = ""
    regression_output: str = ""
    artifact_dir: str = ""
    workspace_dir: str = ""
    session_log_path: str = ""
    agent_elapsed_seconds: float | None = None
    input_tokens_total: int | None = None
    output_tokens_total: int | None = None
    cache_read_input_tokens_total: int | None = None
    cache_write_input_tokens_total: int | None = None
    cost_usd: float | None = None
    hint_path: str = ""
    response_path: str = ""
    score_path: str = ""
    patched_code_path: str = ""
    harness_path: str = ""
    regression_path: str = ""
    forge_output_path: str = ""
    regression_output_path: str = ""
    normal_tx_replay_path: str = ""
    historical_normal_txs_checked: int = 0
    historical_normal_txs_preserved: int = 0
    historical_normal_txs_all_preserved: bool = False
    skipped: bool = False
    skip_reason: str = ""

    @property
    def score(self) -> float:
        if self.skipped:
            return 0.0
        # An "exploit blocked" verdict is only trustworthy if the unpatched
        # baseline exploit actually reproduced in this harness/RPC context.
        # Without that, a compile/setup/RPC failure looks like a successful block.
        if self.baseline_checked and not self.baseline_passed:
            return 0.0
        if not self.exploit_blocked:
            return 0.0
        if self.historical_normal_txs_checked <= 0:
            return 0.0
        return 1.0 if self.normal_ops_pass else 0.0


def serialize_patch_score(score: PatchScore) -> dict[str, object]:
    payload = asdict(score)
    payload["score"] = score.score
    return payload


def write_patch_score_artifact(
    score: PatchScore,
    artifact_dir: Path | str | None,
) -> PatchScore:
    if artifact_dir is None:
        return score

    artifact_path = Path(artifact_dir)
    artifact_path.mkdir(parents=True, exist_ok=True)
    score.artifact_dir = str(artifact_path)
    score_path = artifact_path / "score.json"
    score.score_path = str(score_path)
    score_path.write_text(json.dumps(serialize_patch_score(score), indent=2, ensure_ascii=False))
    return score


# Backwards-compatible aliases
FixScore = PatchScore
serialize_fix_score = serialize_patch_score
write_fix_score_artifact = write_patch_score_artifact
