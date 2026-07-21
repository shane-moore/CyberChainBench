"""Step 4: Generate benchmark and evaluation figures.

Usage:
    python 4_figures/figures.py                    # all figures
    python 4_figures/figures.py --only benchmark   # only benchmark distribution figures
    python 4_figures/figures.py --only eval        # only evaluation result figures
    python 4_figures/figures.py -o figures/        # custom output directory
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import click
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np


CASES_DIR = Path("data/benchmark/cases")
EVAL_DIR = Path("data/eval")
DEFAULT_OUTPUT = Path("figures")

COLORS = {
    "accounting-error": "#e74c3c",
    "price-manipulation": "#3498db",
    "access-control": "#2ecc71",
    "input-validation": "#f39c12",
    "reentrancy": "#9b59b6",
}
TYPE_ORDER = ["accounting-error", "price-manipulation", "access-control", "input-validation", "reentrancy"]


def _load_cases() -> list[dict]:
    files = sorted(CASES_DIR.glob("bench-*.json"))
    return [json.loads(f.read_text()) for f in files]


def _to_quarter(date_str: str) -> str:
    d = datetime.strptime(date_str, "%Y-%m-%d")
    q = (d.month - 1) // 3 + 1
    return f"{d.year}Q{q}"


def fig_type_bar(cases: list[dict], output: Path):
    """Bar chart of vulnerability types."""
    types = Counter(c.get("type", "unknown") for c in cases)
    labels = [t for t in TYPE_ORDER if t in types]
    values = [types[t] for t in labels]
    colors = [COLORS.get(t, "#95a5a6") for t in labels]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, values, color=colors, edgecolor="white", linewidth=0.5)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 2, str(val),
                ha="center", va="bottom", fontsize=11, fontweight="bold")

    ax.set_ylabel("Number of Cases")
    ax.set_title(f"Benchmark Cases by Vulnerability Type (N={len(cases)})")
    ax.set_ylim(0, max(values) * 1.15)
    ax.grid(axis="y", alpha=0.3)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout()
    plt.savefig(output / "type_distribution.png", dpi=150)
    plt.close()
    print("  type_distribution.png")


def fig_quarter_stacked(cases: list[dict], output: Path):
    """Stacked bar chart of cases by quarter and type."""
    type_quarter: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    quarter_total: dict[str, int] = defaultdict(int)

    for c in cases:
        date = c.get("attack_date", "")
        typ = c.get("type", "unknown")
        if date:
            q = _to_quarter(date)
            type_quarter[typ][q] += 1
            quarter_total[q] += 1

    all_quarters = sorted(quarter_total.keys())
    types = [t for t in TYPE_ORDER if t in type_quarter]

    fig, ax = plt.subplots(figsize=(14, 6))
    x = np.arange(len(all_quarters))
    width = 0.8

    bottoms = np.zeros(len(all_quarters))
    for typ in types:
        values = [type_quarter[typ].get(q, 0) for q in all_quarters]
        ax.bar(x, values, width, bottom=bottoms, label=typ, color=COLORS.get(typ, "#95a5a6"))
        bottoms += np.array(values)

    ax.set_xlabel("Quarter")
    ax.set_ylabel("Number of Cases")
    ax.set_title("Benchmark Cases by Vulnerability Type and Quarter")
    ax.set_xticks(x)
    ax.set_xticklabels(all_quarters, rotation=45, ha="right", fontsize=8)
    ax.legend(loc="upper left")
    ax.grid(axis="y", alpha=0.3)

    plt.tight_layout()
    plt.savefig(output / "quarter_distribution.png", dpi=150)
    plt.close()
    print("  quarter_distribution.png")


def fig_chain_bar(cases: list[dict], output: Path):
    """Bar chart of cases by chain."""
    chains = Counter(c.get("chain", "unknown") for c in cases)
    labels = [c for c, _ in chains.most_common()]
    values = [v for _, v in chains.most_common()]

    fig, ax = plt.subplots(figsize=(10, 5))
    bars = ax.barh(labels[::-1], values[::-1], color="#3498db", edgecolor="white")

    for bar, val in zip(bars, values[::-1]):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height() / 2, str(val),
                ha="left", va="center", fontsize=9)

    ax.set_xlabel("Number of Cases")
    ax.set_title(f"Benchmark Cases by Chain (N={len(cases)})")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout()
    plt.savefig(output / "chain_distribution.png", dpi=150)
    plt.close()
    print("  chain_distribution.png")


def fig_pie_charts(cases: list[dict], output: Path):
    """Four-ring donut: outer→inner = type, chain, source, fixable."""
    import matplotlib.patheffects as pe
    stroke = [pe.withStroke(linewidth=2.5, foreground="black")]

    fig, ax = plt.subplots(figsize=(4, 4))

    # Ring 1 (outermost): vulnerability type
    type_counts = Counter(c.get("type", "unknown") for c in cases)
    type_labels = [t for t in TYPE_ORDER if t in type_counts]
    type_values = [type_counts[t] for t in type_labels]
    type_colors = [COLORS[t] for t in type_labels]
    type_display = {
        "accounting-error": "Acct.",
        "access-control": "Access\nCtrl",
        "price-manipulation": "Price\nManip.",
        "input-validation": "Input\nValid.",
        "reentrancy": "Reent.",
    }

    ring_width = 0.22
    gap = 0.01

    # Ring 1: type (radius 0.80 - 1.00)
    r1_outer = 1.0
    r1_inner = r1_outer - ring_width
    wedges1, _ = ax.pie(
        type_values, radius=r1_outer, colors=type_colors,
        wedgeprops=dict(width=ring_width, edgecolor="white", linewidth=1.5),
        startangle=90, counterclock=False,
    )
    for i, wedge in enumerate(wedges1):
        ang = (wedge.theta2 + wedge.theta1) / 2
        r = (r1_outer + r1_inner) / 2
        x = r * np.cos(np.radians(ang))
        y = r * np.sin(np.radians(ang))
        pct = 100 * type_values[i] / sum(type_values)
        ax.text(x, y, f"{type_display[type_labels[i]]}\n{pct:.0f}%",
                ha="center", va="center", fontsize=12, fontweight="bold", color="white",
                path_effects=stroke)

    # Ring 2: chain (top 2 + Other)
    r2_outer = r1_inner - gap
    r2_inner = r2_outer - ring_width
    chain_counts = Counter(c.get("chain", "unknown") for c in cases)
    top_chains = [c for c, _ in chain_counts.most_common(2)]
    chain_labels = top_chains + ["Other"]
    chain_values = [chain_counts[c] for c in top_chains] + [
        sum(v for c, v in chain_counts.items() if c not in top_chains)
    ]
    chain_colors = ["#2c3e50", "#e67e22", "#7f8c8d"]
    chain_display = {"bsc": "BSC", "ethereum": "ETH"}

    wedges2, _ = ax.pie(
        chain_values, radius=r2_outer, colors=chain_colors,
        wedgeprops=dict(width=ring_width, edgecolor="white", linewidth=1.5),
        startangle=90, counterclock=False,
    )
    for i, wedge in enumerate(wedges2):
        ang = (wedge.theta2 + wedge.theta1) / 2
        r = (r2_outer + r2_inner) / 2
        x = r * np.cos(np.radians(ang))
        y = r * np.sin(np.radians(ang))
        pct = 100 * chain_values[i] / sum(chain_values)
        label = chain_display.get(chain_labels[i], chain_labels[i].capitalize())
        ax.text(x, y, f"{label}\n{pct:.0f}%",
                ha="center", va="center", fontsize=12, fontweight="bold", color="white",
                path_effects=stroke)

    # Ring 3: has_public_source
    r3_outer = r2_inner - gap
    r3_inner = r3_outer - ring_width
    has_source = sum(1 for c in cases if c.get("has_public_source"))
    no_source = len(cases) - has_source
    source_values = [has_source, no_source]
    source_colors = ["#27ae60", "#bdc3c7"]

    wedges3, _ = ax.pie(
        source_values, radius=r3_outer, colors=source_colors,
        wedgeprops=dict(width=ring_width, edgecolor="white", linewidth=1.5),
        startangle=90, counterclock=False,
    )
    for i, wedge in enumerate(wedges3):
        ang = (wedge.theta2 + wedge.theta1) / 2
        r = (r3_outer + r3_inner) / 2
        x = r * np.cos(np.radians(ang))
        y = r * np.sin(np.radians(ang))
        pct = 100 * source_values[i] / sum(source_values)
        label = ["Src", "No\nSrc"][i]
        ax.text(x, y, f"{label}\n{pct:.0f}%",
                ha="center", va="center", fontsize=12, fontweight="bold",
                color="white", path_effects=stroke)

    # Ring 4 (innermost): fixable
    r4_outer = r3_inner - gap
    r4_inner = r4_outer - ring_width
    fixable = sum(1 for c in cases if c.get("fixable"))
    not_fixable = len(cases) - fixable
    fix_values = [fixable, not_fixable]
    fix_colors = ["#2980b9", "#bdc3c7"]

    wedges4, _ = ax.pie(
        fix_values, radius=r4_outer, colors=fix_colors,
        wedgeprops=dict(width=ring_width, edgecolor="white", linewidth=1.5),
        startangle=90, counterclock=False,
    )
    for i, wedge in enumerate(wedges4):
        ang = (wedge.theta2 + wedge.theta1) / 2
        r = (r4_outer + r4_inner) / 2
        x = r * np.cos(np.radians(ang))
        y = r * np.sin(np.radians(ang))
        pct = 100 * fix_values[i] / sum(fix_values)
        label = ["Fix", "No\nFix"][i]
        ax.text(x, y, f"{label}\n{pct:.0f}%",
                ha="center", va="center", fontsize=12, fontweight="bold",
                color="white", path_effects=stroke)

    ax.set_aspect("equal")
    plt.subplots_adjust(left=0, right=1, top=1, bottom=0)
    plt.savefig(output / "fig_pie_charts.pdf", bbox_inches="tight", pad_inches=0.05)
    plt.savefig(output / "fig_pie_charts.png", dpi=150, bbox_inches="tight", pad_inches=0.05)
    plt.close()
    print("  fig_pie_charts.pdf / .png")


def fig_pie_source_fixable(cases: list[dict], output: Path):
    """Two simple donuts: source code availability and fixability."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(5, 2.5))

    # Source code pie
    has_source = sum(1 for c in cases if c.get("has_public_source"))
    no_source = len(cases) - has_source
    colors1 = ["#27ae60", "#bdc3c7"]
    wedges1, _ = ax1.pie(
        [has_source, no_source], radius=1.0, colors=colors1,
        wedgeprops=dict(width=0.4, edgecolor="white", linewidth=1.5),
        startangle=90, counterclock=False,
    )
    ax1.text(0, 0, f"{has_source}", ha="center", va="center", fontsize=14, fontweight="bold")
    ax1.set_title("Verified\nSource", fontsize=10, fontweight="bold", pad=2)
    ax1.legend([f"Yes ({has_source})", f"No ({no_source})"], loc="lower center",
               fontsize=8, frameon=False, bbox_to_anchor=(0.5, -0.15))
    ax1.set_aspect("equal")

    # Fixable pie
    fixable = sum(1 for c in cases if c.get("fixable"))
    not_fixable = len(cases) - fixable
    colors2 = ["#2980b9", "#bdc3c7"]
    wedges2, _ = ax2.pie(
        [fixable, not_fixable], radius=1.0, colors=colors2,
        wedgeprops=dict(width=0.4, edgecolor="white", linewidth=1.5),
        startangle=90, counterclock=False,
    )
    ax2.text(0, 0, f"{fixable}", ha="center", va="center", fontsize=14, fontweight="bold")
    ax2.set_title("Patchable", fontsize=10, fontweight="bold", pad=2)
    ax2.legend([f"Yes ({fixable})", f"No ({not_fixable})"], loc="lower center",
               fontsize=8, frameon=False, bbox_to_anchor=(0.5, -0.15))
    ax2.set_aspect("equal")

    plt.tight_layout()
    plt.savefig(output / "fig_source_fixable.pdf", bbox_inches="tight")
    plt.savefig(output / "fig_source_fixable.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("  fig_source_fixable.pdf / .png")


def fig_profit_distribution(cases: list[dict], output: Path):
    """Histogram of attacker profit (log scale)."""
    profits = [c["attacker_profit"] for c in cases if c.get("attacker_profit") and c["attacker_profit"] > 0]

    fig, ax = plt.subplots(figsize=(8, 5))
    log_profits = np.log10(profits)
    ax.hist(log_profits, bins=30, color="#e74c3c", edgecolor="white", alpha=0.8)

    ax.set_xlabel("Attacker Profit (USD, log₁₀)")
    ax.set_ylabel("Number of Cases")
    ax.set_title(f"Distribution of Attacker Profit (N={len(profits)})")
    ax.axvline(np.median(log_profits), color="black", linestyle="--", alpha=0.7, label=f"Median: ${10**np.median(log_profits):,.0f}")
    ax.legend()
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    plt.tight_layout()
    plt.savefig(output / "profit_distribution.png", dpi=150)
    plt.close()
    print("  profit_distribution.png")


@click.command()
@click.option("--only", type=click.Choice(["benchmark", "eval"]), default=None,
              help="Only generate a subset of figures")
@click.option("--output", "-o", type=click.Path(), default=str(DEFAULT_OUTPUT),
              help="Output directory for figures")
def main(only, output):
    """Generate benchmark and evaluation figures."""
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)

    if only is None or only == "benchmark":
        print("=== Benchmark Figures ===")
        cases = _load_cases()
        print(f"  Loaded {len(cases)} cases")
        fig_type_bar(cases, output_path)
        fig_quarter_stacked(cases, output_path)
        fig_chain_bar(cases, output_path)
        fig_profit_distribution(cases, output_path)
        fig_pie_charts(cases, output_path)
        fig_pie_source_fixable(cases, output_path)

    if only is None or only == "eval":
        print("\n=== Evaluation Figures ===")
        if not EVAL_DIR.exists():
            print("  No eval results found. Run 2_eval.py first.")
        else:
            print("  Eval results found; per-benchmark figures are generated by the fig_*.py scripts in this directory.")

    print(f"\nAll figures saved to {output_path}/")


if __name__ == "__main__":
    main()
