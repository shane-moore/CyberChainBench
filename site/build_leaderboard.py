"""Regenerate site/assets/leaderboard.json covering all evaluated configs.

Sources:
- k8s tree (data/eval/k8s) for the opencode/claude/gemini runs, including the
  three new open-weight models (Kimi-K2.6, GLM-5.1, MiniMax-M2.7). Scores are
  computed with the same method validated against the paper tables.
- existing leaderboard.json for the codex/GPT runs (not stored under k8s here).

Schema per row matches what index.html consumes:
  task, agent, model, n, mean, pass_pct, cost_usd, avg_dur_sec,
  input_tokens, output_tokens
"""

from __future__ import annotations

import glob
import json
import os
import re
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
K8S = os.path.join(ROOT, "data/eval/k8s")
CASES = os.path.join(ROOT, "data/benchmark/cases")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets/leaderboard.json")
REVAL = os.path.join(ROOT, "tmp/revalidate_block")

# Display agent + model names per k8s dir (agent, model_dir) -> (agent_label, model_label)
NAME = {
    ("claude-code", "anthropic.claude-opus-4-7"): ("claude-code", "claude-opus-4-7"),
    ("claude-code", "anthropic.claude-opus-4-6-v1"): ("claude-code", "claude-opus-4-6"),
    ("opencode", "deepseek-v4-pro"): ("opencode", "deepseek-v4-pro"),
    ("gemini-cli", "gemini-3.1-pro-preview"): ("gemini-cli", "gemini-3.1-pro"),
    ("opencode", "GLM-5.1"): ("opencode", "GLM-5.1"),
    ("opencode", "Kimi-K2.6"): ("opencode", "Kimi-K2.6"),
    ("opencode", "MiniMax-M2.7"): ("opencode", "MiniMax-M2.7"),
}


def load_ref_diff():
    ref = {}
    for f in glob.glob(f"{CASES}/bench-*.json"):
        d = json.load(open(f))
        ref[d.get("id")] = float(d.get("attacker_profit", 0) or 0)
    return ref


REF = load_ref_diff()


def cid(path):
    m = re.search(r"(bench-\d+)", os.path.basename(path))
    return m.group(1) if m else ""


def reval_patch(model):
    """Return {case_id: score} from re-validated patch artifacts, if present."""
    p = os.path.join(REVAL, f"{model}.json")
    if not os.path.exists(p):
        return None
    return json.load(open(p))


def agg(task, agent, model):
    root = f"{K8S}/{task}/{agent}/{model}/first-trial"
    if not os.path.isdir(root):
        return None
    trials = glob.glob(f"{root}/{task}_*")
    if not trials:
        return None
    n = len(trials)
    rewards = []
    n_pass = 0
    in_tok = out_tok = 0
    durs = []
    reval = reval_patch(model) if task == "patch" else None
    for td in trials:
        c = cid(td)
        dp = os.path.join(td, "verifier", "details.json")
        det = {}
        if os.path.exists(dp):
            try:
                det = json.load(open(dp)).get("details", {})
            except Exception:
                det = {}
        if task == "detect":
            r = 1.0 if (det.get("type_match") and det.get("function_match")) else 0.0
        elif task == "exploit":
            r = float(det.get("ratio", 0.0) or 0.0)
        else:  # patch
            if reval and c in reval:
                r = float(reval[c].get("score", 0.0) or 0.0)
            else:
                r = float(det.get("best_score", 0.0) or 0.0)
        rewards.append(r)
        if r >= 0.99:
            n_pass += 1
        # tokens / duration
        rp = os.path.join(td, "result.json")
        if os.path.exists(rp):
            try:
                rr = json.load(open(rp))
                ar = rr.get("agent_result") or {}
                in_tok += ar.get("n_input_tokens", 0) or 0
                out_tok += ar.get("n_output_tokens", 0) or 0
                s, f = rr.get("started_at"), rr.get("finished_at")
                if s and f:
                    durs.append((datetime.fromisoformat(f.replace("Z", "+00:00"))
                                 - datetime.fromisoformat(s.replace("Z", "+00:00"))).total_seconds())
            except Exception:
                pass
    mean = sum(rewards) / n
    return {
        "task": task,
        "agent": NAME[(agent, model)][0],
        "model": NAME[(agent, model)][1],
        "n": n,
        "mean": round(mean, 4),
        "pass_pct": round(100 * n_pass / n, 1),
        "cost_usd": 0.0,
        "avg_dur_sec": round(sum(durs) / len(durs), 1) if durs else 0,
        "input_tokens": in_tok,
        "output_tokens": out_tok,
    }


def main():
    rows = []
    # k8s-derived rows
    for (agent, model) in NAME:
        for task in ["detect", "exploit", "patch"]:
            r = agg(task, agent, model)
            if r and r["n"] >= 50:
                rows.append(r)
    # keep existing codex/GPT rows from current leaderboard.json
    existing = json.load(open(OUT))
    for e in existing:
        if e["agent"] == "codex" and e["n"] >= 50:
            rows.append(e)

    json.dump(rows, open(OUT, "w"), indent=1)
    print(f"wrote {len(rows)} rows -> {OUT}")
    for task in ["detect", "exploit", "patch"]:
        print(f"\n{task}:")
        for r in sorted([x for x in rows if x["task"] == task], key=lambda x: -x["mean"]):
            print(f"  {r['agent']:12s} {r['model']:18s} n={r['n']:4d} mean={r['mean']:.3f} pass={r['pass_pct']}%")


if __name__ == "__main__":
    main()
