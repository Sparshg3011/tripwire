"""The picture the rest of the project has to argue with.

Two numbers per condition: how many attacks got through, and how much of
the ordinary work still got done. Either one on its own is marketing — a
firewall that refuses every call scores a perfect 0% attack success and
a useless 0% completion, and only plotting both puts that where a reader
can see it without reading the prose.

matplotlib lives under the [gym] extra and is imported inside the
drawing functions on purpose: `import tripwire_gym.chart` has to work in
an install that never asked for a plotting library.
"""

from __future__ import annotations

import statistics
from dataclasses import asdict, dataclass, field
from pathlib import Path

from tripwire_gym.runner import CONDITIONS, RunResult
from tripwire_gym.scenario import FAMILIES
from tripwire_gym.scoring import Outcome, Summary, summarize

CONDITION_COLOUR = {
    "undefended": "#b2182b",
    "shadow": "#e08214",
    "loose": "#b8a02e",
    "standard": "#2166ac",
    "strict": "#1a7f52",
}
UNKNOWN_COLOUR = "#6b6b6b"
INK = "#222222"
FAINT = "#666666"
LABEL_MIN_GAP = 6.0


@dataclass
class SeededSummary(Summary):
    # the per-seed rates behind the means, carried so the chart can draw
    # the spread. Empty when the cell only ever ran once.
    attack_rates: list[float] = field(default_factory=list)
    benign_rates: list[float] = field(default_factory=list)


def summaries_from_results(results: list[RunResult]) -> list[Summary]:
    by_condition: dict[str, list[RunResult]] = {}
    for r in results:
        by_condition.setdefault(r.condition, []).append(r)

    summaries: list[Summary] = []
    for condition in sorted(by_condition, key=_condition_order):
        rows = by_condition[condition]
        summary = SeededSummary(**asdict(summarize(condition, [r.outcome for r in rows])))

        by_seed: dict[int, list[Outcome]] = {}
        for r in rows:
            by_seed.setdefault(r.seed, []).append(r.outcome)
        # one seed has nothing to vary; a zero-length error bar would
        # claim a precision nobody measured, so it gets no bar at all
        if len(by_seed) > 1:
            per_seed = [summarize(condition, outcomes) for outcomes in by_seed.values()]
            summary.attack_rates = [s.attack_success_rate for s in per_seed]
            summary.benign_rates = [s.benign_completion_rate for s in per_seed]
        summaries.append(summary)
    return summaries


def _condition_order(condition: str) -> tuple[int, str]:
    # undefended -> strict, the order the story is told in; anything the
    # runner doesn't know about sorts after, alphabetically
    return (CONDITIONS.index(condition) if condition in CONDITIONS else len(CONDITIONS), condition)


# The bar is the standard deviation, across seeds, of the rate each seed
# scored on its own — not a binomial interval over the pooled runs. The
# pooled interval answers "how confident are we in this coin's bias",
# which assumes every run is an independent draw; they aren't, because
# all of a seed's runs share one model, one corpus and one policy. The
# seed spread answers the question a reader actually has: if I run the
# whole benchmark again, how far does this point move? Sample s.d. (n-1)
# rather than population, because five seeds are a sample of the reruns
# we could have done, and it errs wide rather than reassuringly narrow.
def _sd(rates: list[float]) -> float:
    return statistics.stdev(rates) if len(rates) > 1 else 0.0


def _whiskers(value: float, sd: float) -> list[list[float]] | None:
    # a rate can't be -8% or 112%, and a whisker drawn out there reads as
    # a real possibility, so it stops at the axis instead
    if sd <= 0:
        return None
    return [[min(sd, value)], [min(sd, 100.0 - value)]]


def _spread_label_y(values: list[float]) -> list[float]:
    """Place label centres far enough apart to stay legible at README size."""
    if not values:
        return []

    # Reverse the input order for exact ties. The first condition in the
    # published story (undefended) then sits above its control (shadow),
    # matching the reader's top-to-bottom scan.
    ordered = sorted(enumerate(values), key=lambda item: (item[1], -item[0]))
    placed: list[tuple[int, float]] = []
    for index, desired in ordered:
        y = max(3.0, desired)
        if placed:
            y = max(y, float(placed[-1][1]) + LABEL_MIN_GAP)
        placed.append((index, y))

    # Keep the final label inside the axes while preserving every gap.
    overflow = float(placed[-1][1]) - 101.0
    if overflow > 0:
        placed = [(index, y - overflow) for index, y in placed]

    result = [0.0] * len(values)
    for index, y in placed:
        result[int(index)] = float(y)
    return result


def _label_layout(points: list[tuple[float, float]]) -> list[tuple[float, float, str]]:
    """Return direct-label anchors without relying on fragile text offsets."""
    layout: list[tuple[float, float, str] | None] = [None] * len(points)
    for outside in (False, True):
        indices = [i for i, (x, _) in enumerate(points) if (x > 82) == outside]
        label_y = _spread_label_y([points[i][1] for i in indices])
        if outside:
            # Align crowded right-edge labels into one readable column.
            label_x = min(points[i][0] for i in indices) - 3.0 if indices else 0.0
        for index, y in zip(indices, label_y, strict=True):
            x = label_x if outside else points[index][0] + 2.8
            layout[index] = (x, y, "right" if outside else "left")
    return [item for item in layout if item is not None]


def frontier(summaries: list[Summary], path: str | Path, error_bars: bool = True) -> Path:
    plt = _pyplot()
    fig, ax = plt.subplots(figsize=(7.6, 6.4))

    seeds = 0
    drew_bars = False
    points: list[tuple[float, float]] = []
    point_labels: list[tuple[str, str]] = []
    for s in summaries:
        x = 100 * s.benign_completion_rate
        y = 100 * s.attack_success_rate
        colour = CONDITION_COLOUR.get(s.condition, UNKNOWN_COLOUR)
        # getattr, so a plain Summary with no seeds behind it still plots
        attack_rates = getattr(s, "attack_rates", []) if error_bars else []
        benign_rates = getattr(s, "benign_rates", []) if error_bars else []
        seeds = max(seeds, len(attack_rates), len(benign_rates))
        xerr = _whiskers(x, 100 * _sd(benign_rates))
        yerr = _whiskers(y, 100 * _sd(attack_rates))
        drew_bars = drew_bars or xerr is not None or yerr is not None

        ax.errorbar(
            x,
            y,
            xerr=xerr,
            yerr=yerr,
            fmt="o",
            markersize=10,
            markeredgecolor="white",
            markeredgewidth=1.2,
            color=colour,
            ecolor=colour,
            elinewidth=1.3,
            capsize=4,
            zorder=3,
        )
        points.append((x, y))
        point_labels.append((s.condition, colour))

    for (x, y), (label_x, label_y, align), (condition, colour) in zip(
        points, _label_layout(points), point_labels, strict=True
    ):
        ax.annotate(
            condition,
            (x, y),
            xytext=(label_x, label_y),
            textcoords="data",
            ha=align,
            va="center",
            fontsize=10.5,
            fontweight="semibold",
            color=colour,
            zorder=4,
            arrowprops={
                "arrowstyle": "-",
                "color": colour,
                "linewidth": 0.8,
                "alpha": 0.65,
                "shrinkA": 5,
                "shrinkB": 7,
            },
        )

    if len(points) > 1:
        points.sort()
        ax.plot(
            [p[0] for p in points],
            [p[1] for p in points],
            linestyle="--",
            linewidth=1.1,
            color="#9a9a9a",
            zorder=1,
        )

    ax.set_xlabel("benign task completion  →  more useful", fontsize=11, color=INK)
    ax.set_ylabel("attack success  →  less safe", fontsize=11, color=INK)
    ax.set_title(
        "Security / utility frontier",
        fontsize=15,
        fontweight="bold",
        color=INK,
        loc="left",
        pad=26,
    )
    ax.text(
        0,
        1.025,
        "bottom right is best: attacks stopped while benign work still completes",
        transform=ax.transAxes,
        fontsize=9.5,
        color=FAINT,
    )

    ticks = range(0, 101, 20)
    labels = [f"{t}%" for t in ticks]
    ax.set_xticks(list(ticks), labels=labels)
    ax.set_yticks(list(ticks), labels=labels)
    # a hair past 0 and 100 so a point sitting on either bound is whole
    ax.set_xlim(-4, 104)
    ax.set_ylim(-4, 104)
    ax.grid(True, linestyle=":", linewidth=0.7, color="#c9c9c9")
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)

    notes = ["dashed line joins the conditions by utility — a guide for the eye, not a fit"]
    if drew_bars:
        notes.insert(0, f"bars: ±1 s.d. of the per-seed rate across {seeds} seeds")
    fig.text(0.01, 0.005, "  ·  ".join(notes), fontsize=8.5, color=FAINT)

    return _save(plt, fig, path)


def family_breakdown(summaries: list[Summary], path: str | Path) -> Path:
    plt = _pyplot()
    # a family nobody attacked is an absence, not a zero, so it stays off
    # the chart rather than showing an empty bar that reads as a win
    families = [f for f in FAMILIES if any(f in s.by_family for s in summaries)]

    fig, ax = plt.subplots(figsize=(max(8.0, 1.7 * len(families) + 2.5), 5.4))
    if not families:
        ax.text(
            0.5,
            0.5,
            "no attack runs to break down",
            ha="center",
            va="center",
            fontsize=12,
            color=FAINT,
        )
        ax.set_axis_off()
        return _save(plt, fig, path)

    width = 0.78 / len(summaries)
    flat = False
    for i, s in enumerate(summaries):
        offset = (i - (len(summaries) - 1) / 2) * width
        heights = [100 * _family_rate(s.by_family.get(f)) for f in families]
        flat = flat or any(h == 0 for h in heights)
        ax.bar(
            [j + offset for j in range(len(families))],
            heights,
            width=width * 0.9,
            color=CONDITION_COLOUR.get(s.condition, UNKNOWN_COLOUR),
            label=s.condition,
            zorder=2,
        )

    attacked = {f: max(s.by_family.get(f, (0, 0))[1] for s in summaries) for f in families}
    ax.set_xticks(
        range(len(families)),
        labels=[f"{f.replace('_', ' ')}\nn={attacked[f]}" for f in families],
        fontsize=9.5,
    )
    ticks = range(0, 101, 20)
    ax.set_yticks(list(ticks), labels=[f"{t}%" for t in ticks])
    ax.set_ylim(0, 104)
    ax.set_ylabel("attack success rate", fontsize=11, color=INK)
    ax.set_title(
        "Where each tier actually fails",
        fontsize=15,
        fontweight="bold",
        color=INK,
        loc="left",
        pad=26,
    )
    ax.text(
        0,
        1.025,
        "share of that family's attack runs that got through, per condition",
        transform=ax.transAxes,
        fontsize=9.5,
        color=FAINT,
    )
    ax.grid(True, axis="y", linestyle=":", linewidth=0.7, color="#c9c9c9")
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.legend(frameon=False, fontsize=9.5, ncols=min(len(summaries), 5), loc="upper right")
    if flat:
        fig.text(
            0.01,
            0.005,
            "flat on the axis: nothing in that family landed",
            fontsize=8.5,
            color=FAINT,
        )

    return _save(plt, fig, path)


def _family_rate(tally: tuple[int, int] | None) -> float:
    succeeded, total = tally or (0, 0)
    return succeeded / total if total else 0.0


def _pyplot():
    import matplotlib

    matplotlib.use("Agg")  # nothing here ever wants a window
    import matplotlib.pyplot as plt

    return plt


def _save(plt, fig, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return path
