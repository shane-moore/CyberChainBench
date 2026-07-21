#!/usr/bin/env python3
"""Generate cost-vs-performance scatter figures (one per task: detect/exploit/patch).

X axis = mean API cost per case (USD, log scale).
Y axis = mean reward (0..1) on that task.
One marker per model.

Outputs PDF + PNG into paper/arxiv/latex/figures/:
  fig_cost_vs_perf_detect.{pdf,png}
  fig_cost_vs_perf_exploit.{pdf,png}
  fig_cost_vs_perf_patch.{pdf,png}

Cost is computed from per-trial token counts in result.json
(agent_result.n_input_tokens / n_cache_tokens / n_output_tokens) times the
model's API price. gemini-cli does not record tokens, so Gemini cost is
estimated from the cross-model mean token usage (flagged in the legend).
"""
from __future__ import annotations

import glob
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = "data/eval/k8s"
OUT = "paper/arxiv/latex/figures"
TASKS = ("detect", "exploit", "patch")

# Mint palette (matches the paper's cyberchain-colors.sty)
ACCENT = "#0E9F6E"
LINK = "#0F766E"
ACCENT2 = "#0891B2"

# Pricing per 1M tokens: (input, cached_input, output). USD.
# Anthropic / Gemini are official. The open-weight / newer models marked
# APPROX should be confirmed against vendor pricing before camera-ready.
PRICING = {
    "anthropic.claude-opus-4-7": (10.00, 0.50, 25.00),
    "anthropic.claude-opus-4-6-v1": (10.00, 0.50, 25.00),
    "anthropic.claude-sonnet-4-6": (6.00, 0.30, 15.00),
    "gemini-3.1-pro-preview": (1.25, 0.315, 10.00),
    # APPROX — confirm before camera-ready:
    "deepseek-v4-pro": (0.27, 0.07, 1.10),
    "GLM-5.1": (0.60, 0.11, 2.20),
    "Kimi-K2.6": (0.60, 0.15, 2.40),
    "MiniMax-M2.7": (0.30, 0.075, 1.20),
}

# Display label, marker color, marker shape per model dir name.
STYLE = {
    "anthropic.claude-opus-4-7": ("Opus 4.7", "#0E9F6E", "o"),
    "anthropic.claude-opus-4-6-v1": ("Opus 4.6", "#34D399", "o"),
    "anthropic.claude-sonnet-4-6": ("Sonnet 4.6", "#A7F3D0", "o"),
    "gemini-3.1-pro-preview": ("Gemini 3.1 Pro", "#0891B2", "D"),
    "deepseek-v4-pro": ("DeepSeek V4", "#6366F1", "s"),
    "GLM-5.1": ("GLM-5.1", "#B45309", "^"),
    "Kimi-K2.6": ("Kimi K2.6", "#9333EA", "v"),
    "MiniMax-M2.7": ("MiniMax M2.7", "#DB2777", "P"),
}

# Models with no recorded tokens; cost is estimated from cross-model mean usage.
ESTIMATED = {"gemini-3.1-pro-preview"}

# Draw order on the legend / figure.
# Sonnet 4.6 is excluded: it only ran on 6 cases (detect has none), too small
# a sample to plot fairly next to the full-benchmark runs.
ORDER = [
    "anthropic.claude-opus-4-7",
    "anthropic.claude-opus-4-6-v1",
    "gemini-3.1-pro-preview",
    "deepseek-v4-pro",
    "GLM-5.1",
    "Kimi-K2.6",
    "MiniMax-M2.7",
]


def model_dirs(task: str):
    out = []
    troot = f"{BASE}/{task}"
    if not os.path.isdir(troot):
        return out
    for agent in os.listdir(troot):
        ap = f"{troot}/{agent}"
        if not os.path.isdir(ap):
            continue
        for m in os.listdir(ap):
            if os.path.isdir(f"{ap}/{m}"):
                out.append((agent, m))
    return out


def trial_dirs(task: str, agent: str, model: str):
    root = f"{BASE}/{task}/{agent}/{model}/first-trial"
    if not os.path.isdir(root):
        root = f"{BASE}/{task}/{agent}/{model}"
    tds = glob.glob(f"{root}/{task}_*")
    if not tds:
        tds = [d for d in glob.glob(f"{root}/*/*") if os.path.isdir(d)]
    return tds


def read_reward(td: str):
    dp = os.path.join(td, "verifier", "details.json")
    if not os.path.exists(dp):
        return None
    try:
        d = json.load(open(dp))
    except Exception:
        return None
    r = d.get("reward")
    if r is None:
        r = d.get("best_score")
    return None if r is None else float(r)


def read_tokens(td: str):
    rp = os.path.join(td, "result.json")
    if not os.path.exists(rp):
        return None
    try:
        ar = json.load(open(rp)).get("agent_result") or {}
    except Exception:
        return None
    it, ct, ot = ar.get("n_input_tokens"), ar.get("n_cache_tokens") or 0, ar.get("n_output_tokens")
    if it is None or ot is None:
        return None
    return it, ct, ot


def cost_of(model: str, toks):
    pr = PRICING.get(model)
    if not pr or toks is None:
        return None
    it, ct, ot = toks
    unc = max(it - ct, 0)
    return (unc * pr[0] + ct * pr[1] + ot * pr[2]) / 1e6


def aggregate(task: str):
    """Return {model: {score, cost, n, mean_tokens}}."""
    rows = {}
    for agent, m in model_dirs(task):
        tds = trial_dirs(task, agent, m)
        n = 0
        rsum = 0.0
        csum = 0.0
        cn = 0
        itsum = ctsum = otsum = 0
        for td in tds:
            r = read_reward(td)
            if r is None:
                continue
            n += 1
            rsum += r
            toks = read_tokens(td)
            c = cost_of(m, toks)
            if c is not None:
                csum += c
                cn += 1
                itsum += toks[0]
                ctsum += toks[1]
                otsum += toks[2]
        if not n:
            continue
        rows[m] = {
            "score": rsum / n,
            "cost": (csum / cn) if cn else None,
            "n": n,
            "cost_n": cn,
            "mean_tokens": ((itsum / cn, ctsum / cn, otsum / cn) if cn else None),
        }
    return rows


def fill_estimated(rows):
    """For models with no token data, estimate cost from cross-model mean usage."""
    have = [v["mean_tokens"] for v in rows.values() if v["mean_tokens"]]
    if not have:
        return
    mit = sum(t[0] for t in have) / len(have)
    mct = sum(t[1] for t in have) / len(have)
    mot = sum(t[2] for t in have) / len(have)
    for m, v in rows.items():
        if v["cost"] is None and m in PRICING:
            v["cost"] = cost_of(m, (mit, mct, mot))
            v["estimated"] = True


def plot_task(task: str, rows, ax):
    fill_estimated(rows)
    for m in ORDER:
        if m not in rows:
            continue
        v = rows[m]
        if v["cost"] is None or v["cost"] <= 0:
            continue
        label, color, marker = STYLE.get(m, (m, "#666666", "o"))
        est = v.get("estimated") or m in ESTIMATED
        ax.scatter(
            v["cost"], v["score"],
            s=130, c=color, marker=marker,
            edgecolors="white", linewidths=1.2, zorder=3,
            alpha=0.95,
        )
        txt = label + ("*" if est else "")
        ax.annotate(
            txt, (v["cost"], v["score"]),
            textcoords="offset points", xytext=(7, 4),
            fontsize=7.5, color="#1f2937",
        )
    ax.set_xscale("log")
    ax.set_xlabel("Cost per case (USD)", fontsize=9)
    ax.set_ylabel("Mean reward", fontsize=9)
    ax.set_title(task.capitalize(), fontsize=11, color=LINK, fontweight="bold")
    ax.grid(True, which="both", ls=":", lw=0.5, color="#cbd5e1", alpha=0.7)
    ax.tick_params(labelsize=8)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)


def main():
    os.makedirs(OUT, exist_ok=True)
    for task in TASKS:
        rows = aggregate(task)
        fig, ax = plt.subplots(figsize=(4.0, 3.2))
        plot_task(task, rows, ax)
        fig.tight_layout()
        for ext in ("pdf", "png"):
            fig.savefig(
                f"{OUT}/fig_cost_vs_perf_{task}.{ext}",
                dpi=200, bbox_inches="tight",
            )
        plt.close(fig)
        # report
        print(f"[{task}]")
        for m in ORDER:
            if m in rows:
                v = rows[m]
                tag = " (est)" if v.get("estimated") else ""
                cs = f"${v['cost']:.3f}{tag}" if v["cost"] else "n/a"
                print(f"   {STYLE.get(m,(m,))[0]:16s} score={v['score']:.3f} cost={cs} n={v['n']}")
        print(f"   -> fig_cost_vs_perf_{task}.pdf/.png")
    print("\n* = cost estimated from cross-model mean token usage (no per-trial tokens recorded).")


if __name__ == "__main__":
    main()
