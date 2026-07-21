from benchmark.tasks.patch.builder import build_patch_case
from benchmark.tasks.patch.case import PatchCase

# Backwards-compatible aliases
FixCase = PatchCase
build_fix_case = build_patch_case

__all__ = [
    "PatchCase",
    "build_patch_case",
    "FixCase",
    "build_fix_case",
]
