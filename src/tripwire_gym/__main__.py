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

from tripwire_gym.agent import SYSTEM_PROMPTS, ClaudeAgent, OpenAICompatAgent, ScriptedAgent
from tripwire_gym.manifest import build_manifest, public_settings, write_manifest
from tripwire_gym.runner import (
    CONDITIONS,
    GYM,
    RUN_TIMEOUT,
    GymError,
    RunResult,
    policy_for,
    run_matrix,
)
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
        f"{result.scenario_id:<26} {result.condition:<11} repetition={result.seed}  "
        f"{'; '.join(notes)}",
        file=sys.stderr,
        flush=True,
    )


def _summary_row(s: Summary, rows: list[RunResult] | None = None) -> dict:
    measured = [r for r in (rows or []) if not r.error]
    return {
        "condition": s.condition,
        "runs": s.runs,
        "attack_runs": s.attack_runs,
        "attacks_succeeded": s.attacks_succeeded,
        "attack_success_rate": s.attack_success_rate,
        "attacked_completed": s.attacked_completed,
        "attacked_completion_rate": s.attacked_completion_rate,
        "benign_runs": s.benign_runs,
        "benign_completed": s.benign_completed,
        "benign_completion_rate": s.benign_completion_rate,
        "gate_prompts": s.gate_prompts,
        "errored_runs": s.errored_runs,
        "mean_wall_seconds": (
            sum(r.wall_seconds for r in measured) / len(measured) if measured else 0.0
        ),
        "mean_model_seconds": (
            sum(r.model_seconds for r in measured) / len(measured) if measured else 0.0
        ),
        "model_calls": sum(r.model_calls for r in measured),
        "prompt_tokens": sum(r.prompt_tokens for r in measured),
        "completion_tokens": sum(r.completion_tokens for r in measured),
        "by_family": {f: {"succeeded": n, "total": t} for f, (n, t) in s.by_family.items()},
    }


def _rate(hits: int, total: int) -> str:
    return f"{hits / total:>6.0%} ({hits}/{total})" if total else f"{'--':>6} (0/0)"


def _table(summaries: list[Summary]) -> str:
    lines = [
        (
            f"{'condition':<12} {'attack success':>18} {'utility attacked':>18} "
            f"{'benign completion':>20} {'gate prompts':>13}"
        )
    ]
    for s in summaries:
        lines.append(
            f"{s.condition:<12} "
            f"{_rate(s.attacks_succeeded, s.attack_runs):>18} "
            f"{_rate(s.attacked_completed, s.attack_runs):>18} "
            f"{_rate(s.benign_completed, s.benign_runs):>20} "
            f"{s.gate_prompts:>13}"
        )
    return "\n".join(lines)


def _die(message: str) -> None:
    print(f"tripwire_gym: {message}", file=sys.stderr)
    sys.exit(2)


# Shortcuts for the endpoints people actually use. Everything here is
# just an OpenAI-compatible base_url — the agent code doesn't know or
# care which one it's talking to, which is the point: the firewall's
# behaviour shouldn't depend on whose model is being defended.
PROVIDERS: dict[str, dict[str, str | bool]] = {
    "nvidia": {
        # NVIDIA's hosted open models (Nemotron and friends). Free credits
        # to start, and the models are open weights, so the same run can
        # be reproduced locally by anyone who doubts it.
        "base_url": "https://integrate.api.nvidia.com/v1",
        "key_var": "NVIDIA_API_KEY",
        "needs_key": True,
        "signup": "https://build.nvidia.com",
        "example": "nvidia/nemotron-3-super-120b-a12b",
    },
    "ollama": {
        # fully local, no key, no cost — the cheapest way to get a real
        # model into the loop instead of the scripted stand-in
        "base_url": "http://localhost:11434/v1",
        "key_var": "OLLAMA_API_KEY",
        "needs_key": False,
        "example": "llama3.1:8b",
    },
}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="python -m tripwire_gym", description="run the tripwire benchmark"
    )
    parser.add_argument("--scenarios", default=str(GYM / "scenarios"), help="corpus directory")
    parser.add_argument(
        "--scenario",
        action="append",
        default=[],
        help="run only this scenario id (repeatable; intended for smoke tests)",
    )
    parser.add_argument(
        "--conditions",
        default=",".join(CONDITIONS),
        help=f"comma separated, from: {', '.join(CONDITIONS)}",
    )
    parser.add_argument("--runs", type=int, default=1, help="runs per scenario per condition")
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help=(
            "runs in flight at once. 1 is sequential and is what the scripted "
            "agent wants, because its runs are CPU-bound. Raise it for a real "
            "model, where a run is mostly waiting on the API"
        ),
    )
    parser.add_argument("--out", default=str(GYM / "results"), help="where the artefacts go")
    parser.add_argument("--policy-dir", default=str(GYM / "policies"), help="policy tier yaml")
    parser.add_argument(
        "--agent",
        choices=["claude", "openai", "scripted", *PROVIDERS],
        default="claude",
        help=(
            "scripted needs no API key and is what CI runs. openai talks to any "
            "OpenAI-compatible endpoint via --base-url; " + ", ".join(PROVIDERS) + " are "
            "presets for that"
        ),
    )
    parser.add_argument("--model", help="model id (required for openai-compatible agents)")
    parser.add_argument(
        "--base-url", help="OpenAI-compatible endpoint; overrides the preset for --agent"
    )
    parser.add_argument(
        "--prompt-profile",
        choices=sorted(SYSTEM_PROMPTS),
        default="hardened",
        help=(
            "agent system prompt. plain is a true no-prompt-defense control; "
            "hardened warns the model about untrusted tool output"
        ),
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.0,
        help="sampling temperature, recorded in manifest.json (default: 0)",
    )
    parser.add_argument(
        "--api-seed",
        action="store_true",
        help=(
            "send the repetition index as the provider's seed parameter. Off by default "
            "because not every OpenAI-compatible endpoint supports it"
        ),
    )
    parser.add_argument(
        "--shuffle-seed",
        type=int,
        help="randomize execution order reproducibly while keeping results.jsonl in matrix order",
    )
    parser.add_argument(
        "--disable-thinking",
        action="store_true",
        help=(
            "send NVIDIA/vLLM chat_template_kwargs.enable_thinking=false; recommended "
            "for Nemotron tool calling"
        ),
    )
    parser.add_argument(
        "--max-tokens", type=int, default=2048, help="maximum tokens per model response"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=RUN_TIMEOUT,
        help=(
            "seconds one run may take before it is abandoned. A slow model "
            "needs a longer leash — an abandoned run is a discarded data "
            "point, not a blocked attack"
        ),
    )
    parser.add_argument(
        "--human",
        choices=["none", "approve", "deny"],
        default="none",
        help=(
            "who stands at the approval gate. approve and deny are the two "
            "extremes and bracket what a real operator would do; none runs "
            "without a gate, so every gated call is refused"
        ),
    )

    args = parser.parse_args(argv)

    # before anything reads a file or spawns a proxy: a run that can't
    # possibly produce numbers shouldn't get halfway through pretending
    if args.agent == "claude" and not os.environ.get("ANTHROPIC_API_KEY"):
        _die(
            "ANTHROPIC_API_KEY is not set, so --agent claude has nothing to run. "
            "Export a key, or use --agent scripted to smoke-test the harness."
        )

    if args.agent in ("openai", *PROVIDERS):
        preset = PROVIDERS.get(args.agent, {})
        base_url = args.base_url or preset.get("base_url")
        key_var = preset.get("key_var", "OPENAI_API_KEY")
        if not args.model:
            hint = f" (try --model {preset['example']})" if preset.get("example") else ""
            _die(f"--agent {args.agent} needs --model{hint}")
        if base_url is None and not os.environ.get(key_var):
            _die(f"{key_var} is not set and no --base-url was given")
        # a local server usually wants no key at all, so its absence is
        # only fatal for the hosted presets
        if preset.get("needs_key") and not os.environ.get(key_var):
            _die(
                f"{key_var} is not set, so --agent {args.agent} has nothing to run. "
                f"Get one at {preset.get('signup', 'the provider')}."
            )

    if args.runs < 1:
        _die(f"--runs {args.runs} measures nothing")

    if args.concurrency < 1:
        _die(f"--concurrency {args.concurrency} runs nothing")

    conditions = [c.strip() for c in args.conditions.split(",") if c.strip()]
    if not conditions:
        _die("--conditions is empty")
    # a condition is any policy file in --policy-dir, so an ablation runs
    # without the runner needing a new concept
    for c in conditions:
        try:
            policy_for(c, Path(args.policy_dir))
        except GymError as e:
            _die(str(e))

    try:
        scenarios = load_corpus(args.scenarios)
    except (ScenarioError, OSError) as e:
        _die(str(e))
    if args.scenario:
        requested = set(args.scenario)
        known = {scenario.id for scenario in scenarios}
        missing = sorted(requested - known)
        if missing:
            _die("unknown --scenario id(s): " + ", ".join(missing))
        scenarios = [scenario for scenario in scenarios if scenario.id in requested]

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    policy_dir = Path(args.policy_dir)

    def agent_for(scenario: Scenario, condition: str, seed: int):
        if args.agent == "scripted":
            return ScriptedAgent(scripted_calls(scenario))
        if args.agent == "claude":
            options = {
                "system_prompt": SYSTEM_PROMPTS[args.prompt_profile],
                "temperature": args.temperature,
            }
            return (
                ClaudeAgent(model=args.model, **options) if args.model else ClaudeAgent(**options)
            )
        preset = PROVIDERS.get(args.agent, {})
        return OpenAICompatAgent(
            model=args.model,
            base_url=args.base_url or preset.get("base_url"),
            api_key=os.environ.get(preset.get("key_var", "OPENAI_API_KEY")),
            temperature=args.temperature,
            system_prompt=SYSTEM_PROMPTS[args.prompt_profile],
            seed=seed if args.api_seed else None,
            max_tokens=args.max_tokens,
            extra_body=(
                {"chat_template_kwargs": {"enable_thinking": False}}
                if args.disable_thinking
                else None
            ),
        )

    async def go() -> list[RunResult]:
        return await run_matrix(
            scenarios,
            conditions,
            agent_for,
            args.runs,
            policy_dir,
            _progress,
            human=args.human,
            concurrency=args.concurrency,
            timeout=args.timeout,
            shuffle_seed=args.shuffle_seed,
        )

    # concurrency is named in the banner even at 1, because it belongs
    # with the numbers: it changes nothing about what is measured, and
    # everything about what else the machine was doing at the time
    print(
        f"{len(scenarios)} scenarios x {len(conditions)} conditions x {args.runs} "
        f"runs = {len(scenarios) * len(conditions) * args.runs} runs, "
        f"agent={args.agent}, concurrency={args.concurrency}",
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
        json.dumps(
            {
                s.condition: _summary_row(s, [r for r in results if r.condition == s.condition])
                for s in summaries
            },
            indent=2,
        )
        + "\n"
    )

    manifest = build_manifest(
        repo=GYM.parent,
        scenarios=args.scenarios,
        policy_dir=args.policy_dir,
        conditions=conditions,
        settings=public_settings(args),
        results=results,
        results_path=results_path,
        scenario_ids={scenario.id for scenario in scenarios},
    )
    manifest_path = write_manifest(manifest, out / "manifest.json")

    print(_table(summaries))
    print(
        f"\nwrote {results_path}, {summary_path}, and {manifest_path} "
        f"(run_id={manifest['run_id']})",
        file=sys.stderr,
    )

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
