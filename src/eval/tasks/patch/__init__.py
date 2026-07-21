from .evaluator import evaluate_patch
from .score import PatchScore, write_patch_score_artifact

# Backwards-compatible aliases
FixScore = PatchScore
evaluate_fix = evaluate_patch
write_fix_score_artifact = write_patch_score_artifact

__all__ = ["PatchScore", "evaluate_patch", "write_patch_score_artifact",
           "FixScore", "evaluate_fix", "write_fix_score_artifact"]
