"""Task-specific evaluation logic for detect, exploit, and patch."""

from .detect import DetectScore, evaluate_detection
from .exploit import (
    ExploitScore,
    attach_profit_baselines,
    evaluate_exploit,
    evaluate_reference_exploit,
    load_reference_baseline_cache,
    reference_score_from_cache,
    summarize_exploit_outcome,
)
from .patch import PatchScore, evaluate_patch

# Backwards-compatible aliases
FixScore = PatchScore
evaluate_fix = evaluate_patch

__all__ = [
    "DetectScore",
    "ExploitScore",
    "PatchScore",
    "FixScore",
    "attach_profit_baselines",
    "evaluate_detection",
    "evaluate_exploit",
    "evaluate_patch",
    "evaluate_fix",
    "evaluate_reference_exploit",
    "load_reference_baseline_cache",
    "reference_score_from_cache",
    "summarize_exploit_outcome",
]
