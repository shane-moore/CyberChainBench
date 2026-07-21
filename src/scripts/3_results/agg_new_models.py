"""Ad-hoc aggregator for the k8s eval tree (data/eval/k8s).

Computes the paper-table columns for each (task, agent, model) from the
per-case verifier/details.json plus benchmark difficulty labels.

Columns produced:
  detect : Func% (function_match), Type% (type_match), overall mean, by difficulty
  exploit: Ratio (mean clamped profit ratio), $M (sum best_profit_usd), by difficulty
  patch  : Pass% (best_score==1 mean; block-only not separable here), by difficulty

Difficulty buckets come from data/benchmark/cases/<case_id>.json["difficulty"].
Errored trials (timeout / crash) count as reward 0, matching how the
published rows (DeepSeek/Opus/Gemini) were scored.
"""

from __future__ import annotations

import glob
import json
import os
import re
from collections import defaultdict

BASE = "data/eval/k8s"
CASES = "data/benchmark/cases"


def _load_cases():
    diff, ref = {}, {}
    for f in glob.glob(f"{CASES}/bench-*.json"):
        d = json.load(open(f))
        cid = d.get("id", os.path.basename(f)[:-5])
        diff[cid] = d.get("difficulty", "unknown")
        ref[cid] = float(d.get("attacker_profit", 0) or 0)
    return diff, ref


DIFF, REF = _load_cases()


def case_id_of(trial_dir: str) -> str:
    # trial dir name like detect_bench-263__LCxC8GJ -> bench-263
    name = os.path.basename(trial_dir)
    m = re.search(r"(bench-\d+)", name)
    return m.group(1) if m else ""


def iter_trials(task: str, agent: str, model: str):
    root = f"{BASE}/{task}/{agent}/{model}/first-trial"
    if not os.path.isdir(root):
        return
    for td in glob.glob(f"{root}/{task}_*"):
        dp = os.path.join(td, "verifier", "details.json")
        details = None
        if os.path.exists(dp):
            try:
                details = json.load(open(dp)).get("details", {})
            except Exception:
                details = None
        yield td, details


def pct(num, den):
    return 100.0 * num / den if den else 0.0


def agg(task: str, agent: str, model: str):
    rows = list(iter_trials(task, agent, model))
    if not rows:
        return None
    n = len(rows)
    by_diff = defaultdict(list)  # difficulty -> list of reward
    func_hit = type_hit = 0
    ratios = []
    profit_sum = 0.0

    for td, det in rows:
        cid = case_id_of(td)
        diff = DIFF.get(cid, "unknown")
        if task == "detect":
            tm = bool(det and det.get("type_match"))
            fm = bool(det and det.get("function_match"))
            type_hit += tm
            func_hit += fm
            reward = 1.0 if (tm and fm) else 0.0  # joint exact match = verifier reward
        elif task == "exploit":
            r = float(det.get("ratio", 0.0)) if det else 0.0
            ratios.append(r)
            profit_sum += r * REF.get(cid, 0.0)  # realized = ratio * reference profit
            reward = r
        else:  # patch
            reward = float(det.get("best_score", 0.0)) if det else 0.0
        by_diff[diff].append(reward)

    overall = sum(sum(v) for v in by_diff.values()) / n

    def dmean(d):
        v = by_diff.get(d, [])
        return pct(sum(v), len(v)) if v else None

    out = {
        "n": n,
        "all": overall * 100,
        "easy": dmean("easy"),
        "med": dmean("medium"),
        "hard": dmean("hard"),
    }
    if task == "detect":
        out["func_pct"] = pct(func_hit, n)
        out["type_pct"] = pct(type_hit, n)
    elif task == "exploit":
        out["ratio"] = (sum(ratios) / n) if n else 0.0
        out["profit_musd"] = profit_sum / 1e6
    return out


MODELS = [
    ("claude-code", "anthropic.claude-opus-4-7", "Opus 4.7 (paper-check)"),
    ("opencode", "deepseek-v4-pro", "DeepSeek V4 (paper-check)"),
    ("gemini-cli", "gemini-3.1-pro-preview", "Gemini 3.1 Pro (paper-check)"),
    ("opencode", "GLM-5.1", "GLM-5.1 (NEW)"),
    ("opencode", "Kimi-K2.6", "Kimi-K2.6 (NEW)"),
    ("opencode", "MiniMax-M2.7", "MiniMax-M2.7 (NEW)"),
]


def fmt(x):
    return "  -  " if x is None else f"{x:5.1f}"


for task in ["detect", "exploit", "patch"]:
    print(f"\n{'='*78}\n{task.upper()}\n{'='*78}")
    hdr = f"{'model':28s} {'n':>4} {'All':>6} {'Easy':>6} {'Med':>6} {'Hard':>6}"
    if task == "detect":
        hdr += f" {'Func%':>6} {'Type%':>6}"
    elif task == "exploit":
        hdr += f" {'Ratio':>6} {'$M':>8}"
    print(hdr)
    print("-" * len(hdr))
    for agent, model, label in MODELS:
        a = agg(task, agent, model)
        if not a:
            print(f"{label:28s}  (no data)")
            continue
        line = (f"{label:28s} {a['n']:>4} {fmt(a['all'])} {fmt(a['easy'])} "
                f"{fmt(a['med'])} {fmt(a['hard'])}")
        if task == "detect":
            line += f" {fmt(a['func_pct'])} {fmt(a['type_pct'])}"
        elif task == "exploit":
            line += f" {a['ratio']:6.2f} {a['profit_musd']:8.1f}"
        print(line)
