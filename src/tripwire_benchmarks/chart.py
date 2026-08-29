"""Publication figures for external benchmark summaries.

Matplotlib is imported inside the drawing function so the benchmark adapter
still imports in a publication-only environment without the optional gym
plotting dependency.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

DIRECT = "#4c78a8"
TRIPWIRE = "#f58518"
INK = "#222222"
FAINT = "#666666"


def heldout_tradeoff(summary_path: str | Path, output_path: str | Path) -> Path:
    """Plot the held-out security/utility move from direct to Tripwire."""
    summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))
    rows = {row["condition"]: row for row in summary["overall"]}
    direct = rows["direct"]
    defended = rows["tripwire-deny"]

    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.ticker import PercentFormatter

    fig, ax = plt.subplots(figsize=(8.4, 5.6))
    plotted: dict[str, tuple[float, float]] = {}
    for condition, row, colour, marker, label in (
        ("direct", direct, DIRECT, "o", "Direct"),
        ("tripwire-deny", defended, TRIPWIRE, "s", "Strict Tripwire"),
    ):
        benign = row["benign_utility"]
        attack = row["attack_success"]
        x = 100 * benign["rate"]
        y = 100 * attack["rate"]
        plotted[condition] = (x, y)
        ax.errorbar(
            x,
            y,
            xerr=[[x - 100 * benign["ci_low"]], [100 * benign["ci_high"] - x]],
            yerr=[[y - 100 * attack["ci_low"]], [100 * attack["ci_high"] - y]],
            fmt=marker,
            markersize=11,
            markeredgecolor="white",
            markeredgewidth=1.2,
            color=colour,
            ecolor=colour,
            elinewidth=1.3,
            capsize=4,
            zorder=3,
        )
        ax.annotate(
            f"{label}\n{x:.1f}% utility · {y:.1f}% ASR",
            (x, y),
            xytext=(10, 10),
            textcoords="offset points",
            fontsize=10.5,
            fontweight="semibold",
            color=colour,
            linespacing=1.25,
            zorder=4,
        )

    direct_x, direct_y = plotted["direct"]
    tripwire_x, tripwire_y = plotted["tripwire-deny"]
    ax.annotate(
        "",
        xy=(tripwire_x, tripwire_y),
        xytext=(direct_x, direct_y),
        arrowprops={
            "arrowstyle": "-|>",
            "color": "#8a8a8a",
            "linewidth": 1.5,
            "mutation_scale": 12,
            "shrinkA": 10,
            "shrinkB": 10,
        },
        zorder=2,
    )
    ax.text(
        0.04,
        0.91,
        f"paired change: {tripwire_y - direct_y:+.1f} pp ASR  ·  "
        f"{tripwire_x - direct_x:+.1f} pp benign utility",
        transform=ax.transAxes,
        fontsize=10,
        fontweight="semibold",
        color=INK,
        bbox={"boxstyle": "round,pad=0.35", "facecolor": "white", "edgecolor": "#d0d0d0"},
    )

    ax.set_xlim(0, 100)
    ax.set_ylim(0, 45)
    ax.xaxis.set_major_formatter(PercentFormatter(100))
    ax.yaxis.set_major_formatter(PercentFormatter(100))
    ax.set_xlabel("benign task utility  →  more useful", fontsize=11, color=INK)
    ax.set_ylabel("attack success  →  less safe", fontsize=11, color=INK)
    ax.set_title(
        "Tripwire cuts attack success—and benign utility",
        loc="left",
        fontsize=15,
        fontweight="bold",
        color=INK,
        pad=27,
    )
    ax.text(
        0,
        1.025,
        "AgentDojo held-out · 844 attacks and 85 benign tasks per condition",
        transform=ax.transAxes,
        fontsize=9.5,
        color=FAINT,
    )
    ax.grid(True, linestyle=":", linewidth=0.7, color="#c9c9c9")
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    fig.text(
        0.01,
        0.005,
        "whiskers: descriptive Wilson 95% intervals · one model, one repetition · "
        "strict unattended denies every gate",
        fontsize=8.5,
        color=FAINT,
    )

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return path


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="plot an external benchmark summary")
    parser.add_argument("summary")
    parser.add_argument("output")
    args = parser.parse_args(argv)
    heldout_tradeoff(args.summary, args.output)


if __name__ == "__main__":
    main()
