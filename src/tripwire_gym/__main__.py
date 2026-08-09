"""python -m tripwire_gym — run the benchmark and write the numbers down.

Every scenario in a corpus, under every condition, N times. Progress goes
to stderr so a long run is watchable; the artefacts go to --out; the
table goes to stdout so it can be pasted into a README.

Two agents:

  claude     a real model over the API. Where published numbers come from.
  scripted   no key, no cost, no network beyond stdio. The script is read
             off the scenario's own predicates, so a smoke run attempts
             both the task and the attack and therefore exercises both
             axes of the chart rather than only proving the firewall can
             say no.

The process exits non-zero if any run recorded an error, because a
harness that crashed half its runs and printed a clean 0% attack success
rate is the worst possible failure mode for this project.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict
from pathlib import Path

import anyio

from tripwire_gym.agent import ClaudeAgent, ScriptedAgent
from tripwire_gym.runner import CONDITIONS, GYM, GymError, RunResult, run_matrix
from tripwire_gym.scenario import Scenario, ScenarioError, load_corpus
from tripwire_gym.scoring import Summary, summarize

PLACEHOLDER = "tripwire-gym-placeholder"

# what a one-character escape stands in for when we're building a string
# to satisfy a pattern rather than to match one
_ESCAPES = {"d": "1", "w": "x", "s": " ", "D": "x", "W": "-", "S": "x"}


def _from_class(body: str) -> str:
    if body.startswith("^"):
        banned = set(body[1:])
        return next((c for c in "abcdefghijklmnopqrstuvwxyz0123456789" if c not in banned), "x")
    if body.startswith("\\") and len(body) > 1:
        return _ESCAPES.get(body[1], body[1])
    return body[0] if body else ""


def _unroll(pattern: str) -> str:
    """Read a regex as if it were a template and fill it in.

    Only the plain shapes scenarios actually use. Anything cleverer
    returns something that won't match, which the caller checks for.
    """
    out: list[str] = []
    i = 0
    depth = 0
    while i < len(pattern):
        c = pattern[i]
        i += 1
        if c in "^$":
            continue
        if c == ")":
            depth -= 1
        elif c == "|":
            if depth == 0:
                break  # the first alternative is as good as any
            # we already took a branch, so skip the rest of this group
            level = depth
            while i < len(pattern) and level >= depth:
                if pattern[i] == "\\":
                    i += 1
                elif pattern[i] == "(":
                    level += 1
                elif pattern[i] == ")":
                    level -= 1
                i += 1
            depth = level
        elif c == "(":
            if pattern[i : i + 2] == "?:":
                i += 2
            elif pattern[i : i + 1] == "?":
                return ""  # lookaround, named groups: give up honestly
            depth += 1
        elif c == "\\":
            if i >= len(pattern):
                return ""
            out.append(_ESCAPES.get(pattern[i], pattern[i]))
            i += 1
        elif c == "[":
            end = pattern.find("]", i)
            if end < 0:
                return ""
            out.append(_from_class(pattern[i:end]))
            i = end + 1
        elif c == "{":
            end = pattern.find("}", i)
            if end < 0 or not out:
                return ""
            least = pattern[i:end].split(",")[0]
            out.append(out[-1] * (int(least) - 1) if least.isdigit() else "")
            i = end + 1
        elif c in "*+?":
            pass  # one copy of the atom is already emitted, and satisfies all three
        elif c == ".":
            out.append("x")
        else:
            out.append(c)
    return "".join(out)


def _satisfying(pattern: str) -> str:
    text = _unroll(pattern)
    if text and re.search(pattern, text):
        return text
    print(
        f"tripwire_gym: can't build an argument matching {pattern!r}; "
        f"using {PLACEHOLDER!r}, so this predicate won't fire in the scripted run",
        file=sys.stderr,
    )
    return PLACEHOLDER


def scripted_calls(scenario: Scenario) -> list[tuple[str, dict[str, str]]]:
    """The script for --agent scripted, read off the scenario's own predicates.

    The job first, then the attack. Deriving it beats a hand-written list
    that goes stale the first time somebody edits a scenario.
    """
    calls: list[tuple[str, dict[str, str]]] = []
    for pred in [*scenario.task_success, *scenario.attack_success]:
        # a `never` predicate holds when nothing matched, so there is
        # nothing for an agent to attempt on its behalf
        if pred.never:
            continue
        args = {name: _satisfying(pattern) for name, pattern in pred.args_match.items()}
        calls.extend((pred.tool, dict(args)) for _ in range(pred.min_calls))
    return calls


def _progress(result: RunResult) -> None:
    o = result.outcome
    notes = []
    if o.attacked:
        notes.append("ATTACK SUCCEEDED" if o.attack_succeeded else "attack blocked")
    notes.append("task done" if o.task_completed else "task failed")
    notes.append(f"{o.executed_calls} executed, {o.refused_calls} refused")
    if o.gate_prompts:
        notes.append(f"{o.gate_prompts} gate prompts")
    if result.error:
        notes.append(f"ERROR {result.error}")
    print(
        f"{result.scenario_id:<26} {result.condition:<11} seed={result.seed}  {'; '.join(notes)}",
        file=sys.stderr,
        flush=True,
    )


def _summary_row(s: Summary) -> dict:
    return {
        "condition": s.condition,
        "runs": s.runs,
        "attack_runs": s.attack_runs,
        "attacks_succeeded": s.attacks_succeeded,
        "attack_success_rate": s.attack_success_rate,
        "benign_runs": s.benign_runs,
        "benign_completed": s.benign_completed,
        "benign_completion_rate": s.benign_completion_rate,
        "gate_prompts": s.gate_prompts,
        "by_family": {f: {"succeeded": n, "total": t} for f, (n, t) in s.by_family.items()},
    }


def _rate(hits: int, total: int) -> str:
    return f"{hits / total:>6.0%} ({hits}/{total})" if total else f"{'--':>6} (0/0)"


def _table(summaries: list[Summary]) -> str:
    lines = [
        f"{'condition':<12} {'attack success':>18} {'benign completion':>20} {'gate prompts':>13}"
    ]
    for s in summaries:
        lines.append(
            f"{s.condition:<12} "
            f"{_rate(s.attacks_succeeded, s.attack_runs):>18} "
            f"{_rate(s.benign_completed, s.benign_runs):>20} "
            f"{s.gate_prompts:>13}"
        )
    return "\n".join(lines)


def _die(message: str) -> None:
    print(f"tripwire_gym: {message}", file=sys.stderr)
    sys.exit(2)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="python -m tripwire_gym", description="run the tripwire benchmark"
    )
    parser.add_argument("--scenarios", default=str(GYM / "scenarios"), help="corpus directory")
    parser.add_argument(
        "--conditions",
        default=",".join(CONDITIONS),
        help=f"comma separated, from: {', '.join(CONDITIONS)}",
    )
    parser.add_argument("--runs", type=int, default=1, help="runs per scenario per condition")
    parser.add_argument("--out", default=str(GYM / "results"), help="where the artefacts go")
    parser.add_argument("--policy-dir", default=str(GYM / "policies"), help="policy tier yaml")
    parser.add_argument(
        "--agent",
        choices=["claude", "scripted"],
        default="claude",
        help="scripted needs no API key and is what CI runs",
    )
    parser.add_argument("--model", help="model id for --agent claude")

    args = parser.parse_args(argv)

    # before anything reads a file or spawns a proxy: a run that can't
    # possibly produce numbers shouldn't get halfway through pretending
    if args.agent == "claude" and not os.environ.get("ANTHROPIC_API_KEY"):
        _die(
            "ANTHROPIC_API_KEY is not set, so --agent claude has nothing to run. "
            "Export a key, or use --agent scripted to smoke-test the harness."
        )

    if args.runs < 1:
        _die(f"--runs {args.runs} measures nothing")

    conditions = [c.strip() for c in args.conditions.split(",") if c.strip()]
    unknown = [c for c in conditions if c not in CONDITIONS]
    if not conditions:
        _die("--conditions is empty")
    if unknown:
        _die(f"unknown condition(s) {', '.join(unknown)}; expected from {', '.join(CONDITIONS)}")

    try:
        scenarios = load_corpus(args.scenarios)
    except (ScenarioError, OSError) as e:
        _die(str(e))

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    policy_dir = Path(args.policy_dir)

    def agent_for(scenario: Scenario, condition: str, seed: int):
        if args.agent == "scripted":
            return ScriptedAgent(scripted_calls(scenario))
        return ClaudeAgent(model=args.model) if args.model else ClaudeAgent()

    async def go() -> list[RunResult]:
        return await run_matrix(scenarios, conditions, agent_for, args.runs, policy_dir, _progress)

    print(
        f"{len(scenarios)} scenarios x {len(conditions)} conditions x {args.runs} "
        f"runs = {len(scenarios) * len(conditions) * args.runs} runs, agent={args.agent}",
        file=sys.stderr,
        flush=True,
    )
    try:
        results = anyio.run(go)
    except GymError as e:
        _die(str(e))
    except KeyboardInterrupt:
        print("tripwire_gym: interrupted; nothing written", file=sys.stderr)
        sys.exit(130)

    results_path = out / "results.jsonl"
    with open(results_path, "w", encoding="utf-8") as fh:
        fh.writelines(json.dumps(asdict(r), default=str) + "\n" for r in results)

    summaries = [summarize(c, [r.outcome for r in results if r.condition == c]) for c in conditions]
    summary_path = out / "summary.json"
    summary_path.write_text(
        json.dumps({s.condition: _summary_row(s) for s in summaries}, indent=2) + "\n"
    )

    print(_table(summaries))
    print(f"\nwrote {results_path} and {summary_path}", file=sys.stderr)

    broken = [r for r in results if r.error]
    if broken:
        print(
            f"\n{len(broken)} of {len(results)} runs errored — these numbers are not "
            "measuring the firewall:",
            file=sys.stderr,
        )
        for r in broken:
            print(f"  {r.scenario_id} {r.condition} seed={r.seed}: {r.error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
