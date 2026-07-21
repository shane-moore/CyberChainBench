"""Re-validate patch trials to recover Block% (exploit_blocked) for new models.

For each patch trial that produced a patch (_patched.sol), re-run the patch
verifier on a mainnet fork and record exploit_blocked. Trials with no patch
(agent timed out before producing one) count as blocked=False.

Writes a JSON summary per model to tmp/revalidate_block/<model>.json and prints
Block% / Pass%.

Run: PYTHONPATH=src python src/scripts/2_eval/revalidate_block.py
"""

from __future__ import annotations

import glob
import json
import os
import re
import subprocess
import sys
from pathlib import Path

MODELS = ["GLM-5.1", "Kimi-K2.6", "MiniMax-M2.7"]
PATCH_ROOT = "data/eval/k8s/patch/opencode"
OUT_DIR = Path("tmp/revalidate_block")
OUT_DIR.mkdir(parents=True, exist_ok=True)


def case_of(trial_dir: str) -> str:
    m = re.search(r"(bench-\d+)", os.path.basename(trial_dir))
    return m.group(1) if m else ""


def revalidate_one(case_id: str, patched: str, artifact_dir: str) -> dict | None:
    cmd = [
        sys.executable, "src/infra/cli/validate_patch.py",
        "--case-id", case_id,
        "--fixed-path", patched,
        "--artifact-dir", artifact_dir,
    ]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=900,
                       env={**os.environ, "PYTHONPATH": "src"})
    except subprocess.TimeoutExpired:
        return {"error": "verifier_timeout"}
    sp = os.path.join(artifact_dir, "score.json")
    if os.path.exists(sp):
        try:
            return json.load(open(sp))
        except Exception:
            return None
    return None


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    for model in MODELS:
        if only and model != only:
            continue
        root = f"{PATCH_ROOT}/{model}/first-trial"
        trials = sorted(glob.glob(f"{root}/patch_*"))
        results = {}
        n_total = len(trials)
        for i, td in enumerate(trials):
            cid = case_of(td)
            patched = os.path.join(td, "artifacts", "workspace", "_patched.sol")
            if not os.path.exists(patched):
                results[cid] = {"exploit_blocked": False, "normal_ops_pass": False,
                                "score": 0.0, "no_patch": True}
                continue
            adir = str(OUT_DIR / model / cid)
            os.makedirs(adir, exist_ok=True)
            r = revalidate_one(cid, patched, adir)
            if r is None or "error" in (r or {}):
                results[cid] = {"exploit_blocked": False, "normal_ops_pass": False,
                                "score": 0.0, "verifier_failed": (r or {}).get("error", "no_score")}
            else:
                results[cid] = {
                    "exploit_blocked": bool(r.get("exploit_blocked")),
                    "normal_ops_pass": bool(r.get("normal_ops_pass")),
                    "score": float(r.get("score", 0.0) or 0.0),
                }
            blk = sum(1 for v in results.values() if v["exploit_blocked"])
            print(f"[{model}] {i+1}/{n_total} {cid}: blocked={results[cid]['exploit_blocked']} "
                  f"score={results[cid]['score']} | running Block={blk}", flush=True)

        out = OUT_DIR / f"{model}.json"
        out.write_text(json.dumps(results, indent=1))
        block = sum(1 for v in results.values() if v["exploit_blocked"])
        passed = sum(1 for v in results.values() if v["score"] >= 0.99)
        print(f"\n=== {model}: n={n_total} Block%={100*block/n_total:.1f} "
              f"Pass%={100*passed/n_total:.1f} -> {out}\n", flush=True)


if __name__ == "__main__":
    main()
