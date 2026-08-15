"""results.jsonl in, a markdown report out.

The chart is the headline; this is the appendix that keeps it honest.
Three of its five sections exist only to print the bad news — which
attacks got through, which ordinary jobs the defence broke, and what a
single run can't tell you — because a report carrying nothing but the
two rates is exactly the marketing the gym was built to avoid.

Nothing here recomputes a rate. Every table is rendered off the same
Summary objects the chart plots, so the picture and the prose can't
drift apart.
"""

from __future__ import annotations

import json
import math
import statistics
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from tripwire_gym.agent import ToolCallRecord
from tripwire_gym.chart import summaries_from_results
from tripwire_gym.runner import RunResult
from tripwire_gym.scenario import FAMILIES
from tripwire_gym.scoring import Call, Outcome, Summary

# who was standing at the approval gate. approve and deny bracket what a
# real operator would do; the truth is somewhere inside the interval
BRACKETS = ("approve", "deny", "none")

# the condition every other one is measured against
CONTROL = "undefended"

BRACKET_GLOSS = {
    "approve": "a human who approves everything — the upper bound on utility",
    "deny": "a human who refuses everything — the lower bound",
    "none": "no gate at all, so every gated call is simply refused",
}

SCRIPTED_WARNING = (
    "- **Agent: `{agent}` — a script, not a model.** It replays a fixed list "
    "of calls read off each scenario's own predicates and never adapts to a "
    "refusal, so a blocked call is a job it abandons rather than one it "
    "retries another way. The benign-completion numbers above are therefore a "
    "**pessimistic floor**, not the utility cost of the defence, and must "
    "never be quoted as if they were. Rerun with `--agent claude` for a "
    "number that can be published."
)

MODEL_NOTE = (
    "- **Agent: `{agent}` — a real model over the API.** It reads refusals and "
    "is free to try something else, so the benign-completion numbers are the "
    "utility cost of the defence rather than a floor under it."
)


class AnalysisError(Exception):
    pass


# --- reading the artefacts back ---


def load_results(path: str | Path) -> list[RunResult]:
    """One run per line, back into real objects.

    Takes either the results.jsonl or the directory it lives in, because
    half the callers have one and half have the other.
    """
    path = Path(path)
    if path.is_dir():
        path = path / "results.jsonl"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise AnalysisError(f"cannot read {path}: {e}") from e

    results = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            results.append(_run_result(json.loads(line)))
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            raise AnalysisError(f"{path}:{number}: not a run record: {e}") from e
    return results


def _rebuild(cls, row: dict):
    """A dataclass from a dict, ignoring keys it doesn't know.

    Dropping unknown fields rather than raising on them means a report
    over a file written by a newer gym still comes out; a traceback over
    one extra key would throw away good runs to protect nothing.
    """
    known = {f.name for f in fields(cls)}
    return cls(**{k: v for k, v in row.items() if k in known})


def _run_result(row: dict) -> RunResult:
    return RunResult(
        scenario_id=row["scenario_id"],
        condition=row["condition"],
        seed=row["seed"],
        outcome=_rebuild(Outcome, row["outcome"]),
        attempted=[_rebuild(ToolCallRecord, r) for r in row.get("attempted", [])],
        executed=[_rebuild(Call, c) for c in row.get("executed", [])],
        error=row.get("error", ""),
        gate_answers=row.get("gate_answers", 0),
    )


# --- statistics ---
#
# Stdlib only, and not out of stubbornness: these are the numbers the
# README quotes, and a reader who wants to check them should be able to
# read the arithmetic rather than trust a dependency.


# Wilson, not the textbook `p ± z·sqrt(p(1-p)/n)`. The normal approximation
# is at its worst exactly where this benchmark lives — proportions pinned
# against 0 and 1, n in the dozens. At 38/38 it has *zero* width, because
# p(1-p) is 0, so it would claim perfect certainty from 38 runs; at 2/38 it
# reaches below zero, and at 36/38 past 100%. Both are intervals that print
# something the data cannot support. Wilson comes from solving the score
# test for p rather than substituting p̂ into the variance, which keeps it
# inside [0, 1] and lets it be asymmetric near the ends, which is where the
# truth about a near-perfect rate actually is.
def wilson_interval(successes: int, total: int, confidence: float = 0.95) -> tuple[float, float]:
    """The Wilson score interval on a proportion, as (low, high)."""
    if successes < 0 or total < 0 or successes > total:
        raise ValueError(f"{successes} of {total} is not a proportion")
    if not 0 < confidence < 1:
        raise ValueError(f"confidence must be inside (0, 1), not {confidence}")
    if total == 0:
        # nothing was measured, so every rate is still possible. The full
        # interval is the only honest answer; anything narrower is a claim
        # made out of no data at all.
        return (0.0, 1.0)

    z = statistics.NormalDist().inv_cdf(1 - (1 - confidence) / 2)
    p = successes / total
    denominator = 1 + z**2 / total
    centre = (p + z**2 / (2 * total)) / denominator
    half = z / denominator * math.sqrt(p * (1 - p) / total + z**2 / (4 * total**2))
    # the algebra already lands inside [0, 1], and at 0/n and n/n it lands
    # exactly on the axis — but only in real arithmetic. In floats it misses
    # by a whisker either way, and a lower bound of 2.8e-17 is drift wearing
    # the clothes of a measurement, so those two ends are pinned by hand.
    low = 0.0 if successes == 0 else max(0.0, centre - half)
    high = 1.0 if successes == total else min(1.0, centre + half)
    return (low, high)


@dataclass(frozen=True)
class Paired:
    """Two conditions scored over the same runs.

    `only_a` and `only_b` are the *discordant* runs — the ones where the
    two conditions disagreed. Everything else cancels: a run both stopped,
    or both let through, says nothing about which is better.
    """

    pairs: int
    only_a: int
    only_b: int
    p_value: float

    @property
    def discordant(self) -> int:
        return self.only_a + self.only_b


def attack_stops(rows: list[RunResult]) -> dict[tuple[str, int], bool]:
    """Attack runs as (scenario, seed) -> did this condition stop it.

    Keyed by the run rather than counted, because that key is what makes
    two conditions comparable pair by pair. Errored runs are dropped here
    for the same reason summarize() drops them from every rate.
    """
    return {
        (r.scenario_id, r.seed): not r.outcome.attack_succeeded
        for r in rows
        if r.outcome.attacked and not r.outcome.errored
    }


def mcnemar(a: Mapping[Any, bool], b: Mapping[Any, bool]) -> Paired:
    """McNemar's paired test over the runs `a` and `b` share.

    Paired because the gym runs every scenario under every condition, so
    `loose` and `standard` are two measurements of the same 38 attacks
    rather than two independent samples. Treating them as independent
    would throw the pairing away and widen the uncertainty for nothing.
    """
    shared = a.keys() & b.keys()
    only_a = sum(1 for k in shared if a[k] and not b[k])
    only_b = sum(1 for k in shared if b[k] and not a[k])
    return Paired(len(shared), only_a, only_b, _binomial_p(only_a, only_b))


# Exact, not the chi-square approximation McNemar is usually taught with.
# Under the null the discordant runs are coin flips, so the p-value is a
# binomial tail — and math.comb turns "exact" into a one-line sum, while
# the chi-square form needs something like 25 discordant pairs before it
# can be believed. Tiers here differ on a handful of scenarios out of 38,
# which is precisely the regime the approximation gets wrong, and it errs
# toward manufacturing significance rather than away from it.
def _binomial_p(only_a: int, only_b: int) -> float:
    n = only_a + only_b
    if n == 0:
        # the two never disagreed, so there is no evidence of a difference
        # in either direction, and p = 1 is exactly that statement
        return 1.0
    smaller = min(only_a, only_b)
    tail = sum(math.comb(n, i) for i in range(smaller + 1)) / 2**n
    return min(1.0, 2 * tail)


def mcnemar_note(
    a: Mapping[Any, bool],
    b: Mapping[Any, bool],
    a_name: str = "a",
    b_name: str = "b",
    confidence: float = 0.95,
) -> str:
    """One sentence about `b` versus `a` that a reader can quote.

    Both mappings are run key -> whether that condition stopped the
    attack, as `attack_stops` builds them.
    """
    result = mcnemar(a, b)
    if not result.pairs:
        return f"`{b_name}` and `{a_name}` share no runs, so there is nothing to compare."
    if not result.discordant:
        return (
            f"`{b_name}` and `{a_name}` agreed on all {result.pairs} shared runs, so the two "
            "are **indistinguishable** — there is no disagreement left to test."
        )
    verdict = (
        "so the difference is **not noise**"
        if result.p_value <= 1 - confidence
        else f"so the difference is **indistinguishable** from noise at n={result.pairs}"
    )
    return (
        f"`{b_name}` stopped {result.only_b} run(s) `{a_name}` did not, and missed "
        f"{result.only_a} that `{a_name}` stopped, over {result.pairs} shared runs; "
        f"exact McNemar {_p_value(result.p_value)}, {verdict}."
    )


def _p_value(p: float) -> str:
    # below a thousandth the digits are noise of their own, and "p = 0.000"
    # reads like a p-value of zero, which no finite sample produces
    return "p < 0.001" if p < 0.001 else f"p = {p:.3f}"


# --- the report ---


def report_markdown(
    brackets: dict[str, list[RunResult]],
    agent: str = "scripted",
    command: str = "",
) -> str:
    """Every bracket's numbers, and everything they leave out.

    `agent` defaults to the cautious answer: an unlabelled run gets the
    scripted caveat rather than the credibility of a real model.
    """
    if not any(brackets.values()):
        # a report over zero runs shows a flawless 0% attack success rate,
        # which is the most dangerous number this project could print
        raise AnalysisError("no runs to report on")

    ordered = {b: brackets[b] for b in sorted(brackets, key=_bracket_order)}
    summaries = {b: summaries_from_results(rows) for b, rows in ordered.items()}

    blocks = [
        "# Benchmark results",
        (
            "Two numbers per condition: how many attacks were stopped, and how "
            "much of the ordinary work still got done. Neither means anything "
            "without the other — a firewall that refuses every call stops 100% "
            "of attacks and completes 0% of the work."
        ),
        *_headline(ordered, summaries),
        *_against_the_control(ordered, summaries),
        *_by_family(ordered, summaries),
        *_what_got_through(ordered, summaries),
        *_cost_of_the_defence(ordered, summaries),
        *_reproducing(ordered, agent, command),
    ]
    return "\n\n".join(blocks) + "\n"


def write_report(
    brackets: dict[str, list[RunResult]],
    path: str | Path,
    agent: str = "scripted",
    command: str = "",
) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report_markdown(brackets, agent=agent, command=command), encoding="utf-8")
    return path


# --- 1. the headline ---


def _headline(ordered, summaries) -> list[str]:
    blocks = ["## Headline"]
    for bracket, summary in ((b, summaries[b]) for b in ordered):
        blocks.append(_bracket_heading(bracket))
        rows = [
            "| condition | attacks stopped | benign completion | gate prompts | errored runs |",
            "|---|---|---|---|---|",
        ]
        for s in summary:
            rows.append(
                f"| `{s.condition}` "
                f"| {_rate(s.attack_runs - s.attacks_succeeded, s.attack_runs)} "
                f"| {_rate(s.benign_completed, s.benign_runs)} "
                f"| {s.gate_prompts} "
                f"| {s.errored_runs} |"
            )
        blocks.append("\n".join(rows))
        errored = sum(s.errored_runs for s in summary)
        if errored:
            blocks.append(
                f"> **{errored} run(s) errored** and are excluded from every rate "
                "above. A run that crashed is not an attack the policy stopped."
            )
    blocks.append(
        "Every rate carries a 95% Wilson score interval, because `27/38` and "
        "`270/380` print the same percentage and are not the same evidence. "
        "The interval covers sampling error only — how much of the rate is an "
        "accident of *which* attacks somebody happened to write — and it is not "
        "the spread across seeds, which answers a different question and is "
        "reported under [Reproducing this](#reproducing-this). When a cell runs "
        "more than one seed its runs are not independent draws either, several "
        "being reruns of one scenario, so read the interval as the narrower of "
        "the two uncertainties rather than the total."
    )
    return blocks


def _rate(hits: int, total: int, confidence: float = 0.95) -> str:
    if not total:
        return "n/a (0/0)"
    low, high = wilson_interval(hits, total, confidence)
    return (
        f"{hits / total:.0%} ({hits}/{total}, "
        f"{confidence:.0%} CI {100 * low:.0f}-{100 * high:.0f}%)"
    )


# --- 2. is it distinguishable from doing nothing ---


def _against_the_control(ordered, summaries) -> list[str]:
    blocks = [
        "## Distinguishable from no defence",
        (
            f"Every condition against `{CONTROL}`, over the same attack runs. "
            "The comparison is paired — every scenario runs under every "
            "condition, so these are two measurements of one corpus rather than "
            "two samples, and an unpaired test would discard that and overstate "
            "the uncertainty. McNemar's test looks only at the runs where the "
            "two conditions disagreed, which is the only place a difference "
            "between them can live."
        ),
    ]
    for bracket in ordered:
        blocks.append(_bracket_heading(bracket))
        rows = _by_condition(ordered[bracket])
        control = attack_stops(rows.get(CONTROL, []))
        if not control:
            blocks.append(
                f"No `{CONTROL}` attack runs here, so there is no control to test against."
            )
            continue
        lines = [
            "- "
            + mcnemar_note(control, attack_stops(rows.get(s.condition, [])), CONTROL, s.condition)
            for s in summaries[bracket]
            if s.condition != CONTROL
        ]
        blocks.append("\n".join(lines) or f"Only `{CONTROL}` ran in this bracket.")
    return blocks


# --- 3. per family ---


def _by_family(ordered, summaries) -> list[str]:
    blocks = [
        "## By family",
        (
            "Attack runs stopped out of attack runs made, per family. A family "
            "nobody attacked is an absence rather than a zero, so it is left "
            "out instead of showing a perfect score nobody earned."
        ),
    ]
    for bracket, summary in ((b, summaries[b]) for b in ordered):
        blocks.append(_bracket_heading(bracket))
        families = [f for f in _family_order(summary) if _attacked_anywhere(f, summary)]
        if not families:
            blocks.append("No attack runs in this bracket.")
            continue
        rows = [
            "| family | " + " | ".join(f"`{s.condition}`" for s in summary) + " |",
            "|---" * (len(summary) + 1) + "|",
        ]
        for family in families:
            rows.append(f"| {family} | " + " | ".join(_cell(s, family) for s in summary) + " |")
        blocks.append("\n".join(rows))
    return blocks


def _family_order(summary: list[Summary]) -> list[str]:
    seen = {f for s in summary for f in s.by_family}
    return [*FAMILIES, *sorted(seen - set(FAMILIES))]


def _attacked_anywhere(family: str, summary: list[Summary]) -> bool:
    return any(s.by_family.get(family, (0, 0))[1] for s in summary)


def _cell(s: Summary, family: str) -> str:
    succeeded, total = s.by_family.get(family, (0, 0))
    # a condition that never ran this family gets a dash, not a 0/0 that
    # reads like a result
    return f"{total - succeeded}/{total}" if total else "-"


# --- 4. what got through ---


def _what_got_through(ordered, summaries) -> list[str]:
    blocks = [
        "## What got through",
        (
            "Every scenario whose attack succeeded, named. This section is "
            "never truncated: a percentage tells you how often the defence "
            "held, and only the list tells you what it does not cover."
        ),
    ]
    for bracket, summary in ((b, summaries[b]) for b in ordered):
        blocks.append(_bracket_heading(bracket))
        rows = _by_condition(ordered[bracket])
        for s in summary:
            landed = _tally(
                rows.get(s.condition, []),
                lambda o: o.attacked,
                lambda o: o.attack_succeeded,
            )
            blocks.append(
                f"#### `{s.condition}` — "
                f"{s.attacks_succeeded} of {s.attack_runs} attack runs landed"
            )
            blocks.append("\n".join(_casualties(landed)) or "Nothing landed.")
    return blocks


# --- 5. what the defence cost ---


def _cost_of_the_defence(ordered, summaries) -> list[str]:
    blocks = [
        "## Cost of the defence",
        (
            "The benign twins that failed: same task, same tools, no attack "
            "text anywhere. This is where the utility number comes from, so "
            "the jobs it is made of are listed by id rather than summed away."
        ),
    ]
    for bracket, summary in ((b, summaries[b]) for b in ordered):
        blocks.append(_bracket_heading(bracket))
        rows = _by_condition(ordered[bracket])
        for s in summary:
            broken = _tally(
                rows.get(s.condition, []),
                lambda o: not o.attacked,
                lambda o: not o.task_completed,
            )
            failed = s.benign_runs - s.benign_completed
            blocks.append(f"#### `{s.condition}` — {failed} of {s.benign_runs} benign jobs failed")
            blocks.append("\n".join(_casualties(broken)) or "Every benign job completed.")
    return blocks


def _by_condition(rows: list[RunResult]) -> dict[str, list[RunResult]]:
    out: dict[str, list[RunResult]] = {}
    for r in rows:
        out.setdefault(r.condition, []).append(r)
    return out


def _tally(
    rows: list[RunResult],
    belongs: Callable[[Outcome], bool],
    hit: Callable[[Outcome], bool],
) -> dict[str, tuple[int, int, str]]:
    """scenario id -> (hits, runs, family) over the runs `belongs` selects.

    Errored runs are left out of both halves of the fraction, exactly as
    summarize() leaves them out of every rate: a crashed run is neither
    an attack that got through nor a job the defence broke.
    """
    counts: dict[str, tuple[int, int, str]] = {}
    for r in rows:
        o = r.outcome
        if o.errored or not belongs(o):
            continue
        hits, runs, _ = counts.get(o.scenario_id, (0, 0, o.family))
        counts[o.scenario_id] = (hits + int(hit(o)), runs + 1, o.family)
    return counts


def _casualties(counts: dict[str, tuple[int, int, str]]) -> list[str]:
    lines = []
    for scenario_id in sorted(counts):
        hits, runs, family = counts[scenario_id]
        if not hits:
            continue
        # only worth the noise when the cell ran more than once
        seeds = f" — {hits}/{runs} seeds" if runs > 1 else ""
        lines.append(f"- `{scenario_id}` ({family}){seeds}")
    return lines


# --- 6. how to get this number again ---


def _reproducing(ordered, agent: str, command: str) -> list[str]:
    every = [r for rows in ordered.values() for r in rows]
    seeds = len({r.seed for r in every})
    attacks = {r.scenario_id for r in every if r.outcome.attacked}
    twins = {r.scenario_id for r in every if not r.outcome.attacked}
    families = {r.outcome.family for r in every if r.outcome.attacked}

    blocks = [
        "## Reproducing this",
        _command_block(command, agent, seeds),
        "\n".join(
            [
                (
                    f"- **Corpus:** {len(attacks) + len(twins)} scenarios — "
                    f"{len(attacks)} attacks across {len(families)} families, "
                    f"and {len(twins)} benign twins."
                ),
                f"- **Runs per cell:** {seeds}.",
                f"- **Brackets:** {', '.join(f'`{b}`' for b in ordered)}.",
                _agent_line(agent),
            ]
        ),
    ]
    for bracket, rows in ordered.items():
        blocks.append(f"**Variance, `{bracket}` bracket.** {variance_note(rows)}")
    return blocks


def _command_block(command: str, agent: str, seeds: int) -> str:
    if command:
        return f"```bash\n{command}\n```"
    # nothing recorded: show the command that produces this shape of run
    # and say plainly that it's a reconstruction, not what was run
    return (
        f"```bash\n./gym/run_benchmark.sh {agent} {seeds}\n```\n"
        "*Reconstructed — the caller recorded no command, so this is the shape "
        "of the run rather than the run itself.*"
    )


def _agent_line(agent: str) -> str:
    note = SCRIPTED_WARNING if _is_scripted(agent) else MODEL_NOTE
    return note.format(agent=agent)


def _is_scripted(agent: str) -> bool:
    return agent.strip().lower() == "scripted"


def variance_note(results: list[RunResult]) -> str:
    """What the spread across seeds was, or that there wasn't one.

    The s.d. is of the rate each seed scored on its own, not a binomial
    interval over the pooled runs — the reader's question is "if I run
    the whole benchmark again, how far does this move", and all of a
    seed's runs share one model, one corpus and one policy.
    """
    if not results:
        return "No runs, so nothing to vary."

    seeds = {r.seed for r in results}
    if len(seeds) < 2:
        return (
            "Runs per cell: 1, so **no variance can be reported**. Models are "
            "nondeterministic and a single run of a single scenario is an "
            "anecdote, not a rate. Treat every number here as one draw."
        )

    lines = [
        (
            f"Runs per cell: {len(seeds)}. Attack success across seeds, "
            "mean ±1 sample s.d. of the rate each seed scored alone:"
        )
    ]
    for s in summaries_from_results(results):
        rates = [100 * rate for rate in getattr(s, "attack_rates", [])]
        if not s.attack_runs:
            lines.append(f"- `{s.condition}` — no attack runs to vary")
        elif len(rates) < 2:
            lines.append(f"- `{s.condition}` — ran under one seed only; no spread")
        else:
            lines.append(
                f"- `{s.condition}` — {statistics.fmean(rates):.1f}% "
                f"± {statistics.stdev(rates):.1f} pts (n={len(rates)} seeds)"
            )
    return "\n".join(lines)


# --- shared furniture ---


def _bracket_heading(bracket: str) -> str:
    gloss = BRACKET_GLOSS.get(bracket)
    return f"### `{bracket}` bracket" + (f" — {gloss}" if gloss else "")


def _bracket_order(bracket: str) -> tuple[int, str]:
    # approve first: the upper bound on utility is the number people quote,
    # so it should be the one they read next to its lower bound
    return (BRACKETS.index(bracket) if bracket in BRACKETS else len(BRACKETS), bracket)


# --- across models -----------------------------------------------------


def _fell_for(rows: list[RunResult], condition: str) -> set[str]:
    """Attacks that landed under one condition."""
    return {
        r.scenario_id
        for r in rows
        if r.outcome.attacked and r.condition == condition and r.outcome.attack_succeeded
    }


def _attempted(rows: list[RunResult], condition: str) -> set[str]:
    return {r.scenario_id for r in rows if r.outcome.attacked and r.condition == condition}


def _completed(rows: list[RunResult], condition: str) -> tuple[int, int]:
    twins = [r for r in rows if not r.outcome.attacked and r.condition == condition]
    return sum(1 for r in twins if r.outcome.task_completed), len(twins)


def model_comparison(by_model: Mapping[str, list[RunResult]]) -> str:
    """How much the firewall adds, model by model.

    The point of running several models isn't more rows. A model's own
    refusals are the baseline, and that baseline moves a lot between a
    frontier model and a small one — so a single-model benchmark can't
    tell you whether the firewall is doing the work or the model is.
    Lining them up separates the two, and the separation is the claim:
    tripwire's contribution should hold as the baseline falls.
    """
    lines = [
        "## Across models",
        "",
        "`model alone` is the undefended condition: attacks the model refused",
        "without any help. `with standard` is the same corpus behind the",
        "recommended tier. The column that matters is the last one — of the",
        "attacks the model fell for, how many the firewall caught.",
        "",
        "| model | model alone | with standard | of its misses, caught | benign cost |",
        "|---|---|---|---|---|",
    ]

    for name, rows in by_model.items():
        attempted = _attempted(rows, "undefended")
        if not attempted:
            continue
        missed = _fell_for(rows, "undefended")
        still = _fell_for(rows, "standard") & missed
        caught = len(missed) - len(still)

        alone = len(attempted) - len(missed)
        with_tw = len(attempted) - len(_fell_for(rows, "standard"))

        undef_done, undef_total = _completed(rows, "undefended")
        std_done, std_total = _completed(rows, "standard")
        cost = ""
        if undef_total and std_total:
            delta = 100 * (std_done / std_total - undef_done / undef_total)
            cost = f"{delta:+.0f} pts"

        share = f"{caught}/{len(missed)}" if missed else "nothing to catch"
        lines.append(
            f"| `{name}` | {100 * alone / len(attempted):.0f}% "
            f"| {100 * with_tw / len(attempted):.0f}% | {share} | {cost} |"
        )

    lines += [
        "",
        "A firewall whose contribution shrinks as the model gets weaker would",
        "be a firewall that only works when it isn't needed. Read the third",
        "column down the page rather than across it.",
    ]
    return "\n".join(lines)
