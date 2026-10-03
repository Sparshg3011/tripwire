"""Audit paired benign traces without claiming counterfactual task recovery.

Only completed, error-free, uniquely paired traces are accepted. Tool arguments
and message contents stay in the private raw artifacts, not the public report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

CONDITIONS = {"direct", "tripwire-deny"}


def diagnose(root: Path, expected_pairs: int = 85) -> dict:
    pairs: dict[tuple[str, str], dict] = {}
    hashes = {}
    for path in sorted(root.rglob("*.json")):
        relative = path.relative_to(root)
        if "traces" not in relative.parts or "benign" not in relative.parts:
            continue
        if len(relative.parts) < 3 or relative.parts[1] not in CONDITIONS:
            raise ValueError(f"unexpected benign trace location: {relative}")
        content = path.read_bytes()
        trace = json.loads(content)
        if (
            type(trace.get("utility")) is not bool
            or "error" not in trace
            or trace["error"] is not None
        ):
            raise ValueError(f"incomplete or errored trace: {relative}")
        if trace.get("injection_task_id") is not None:
            raise ValueError(f"attacked trace in benign population: {relative}")
        suite, condition = relative.parts[:2]
        task = trace.get("user_task_id")
        if trace.get("suite_name") != suite or not isinstance(task, str) or not task:
            raise ValueError(f"invalid task identity: {relative}")
        key = (suite, task)
        pair = pairs.setdefault(key, {})
        if condition in pair:
            raise ValueError(f"duplicate {condition} case: {key}")
        if condition == "tripwire-deny":
            receipt = trace.get("tripwire_enforcement")
            if not isinstance(receipt, dict) or not isinstance(receipt.get("events"), list):
                raise ValueError(f"missing enforcement receipt: {relative}")
            if receipt.get("task_id") != task or receipt.get("task_kind") != "user":
                raise ValueError(f"mismatched enforcement receipt: {relative}")
            for event in receipt["events"]:
                if (
                    type(event.get("executed")) is not bool
                    or event.get("decision") not in {"allow", "gate", "block"}
                    or not isinstance(event.get("rule"), str)
                    or not isinstance(event.get("tool"), str)
                ):
                    raise ValueError(f"invalid enforcement event: {relative}")
                if event["executed"] != (event["decision"] == "allow"):
                    raise ValueError(f"not a strict deny-gate trace: {relative}")
        pair[condition] = trace
        hashes[str(relative)] = hashlib.sha256(content).hexdigest()
    if len(pairs) != expected_pairs or expected_pairs < 1:
        raise ValueError(f"expected {expected_pairs} pairs, found {len(pairs)}")
    rows = []
    transitions: Counter = Counter()
    blocked_tools: Counter = Counter()
    blocked_rules: Counter = Counter()
    for (suite, task), pair in sorted(pairs.items()):
        if set(pair) != CONDITIONS:
            raise ValueError(f"missing paired condition: {(suite, task)}")
        direct, strict = pair["direct"]["utility"], pair["tripwire-deny"]["utility"]
        events = pair["tripwire-deny"]["tripwire_enforcement"]["events"]
        blocked = [event for event in events if not event["executed"]]
        transition = (
            "both_complete"
            if direct and strict
            else "regressed"
            if direct
            else "improved"
            if strict
            else "both_failed"
        )
        transitions[transition] += 1
        tools = sorted({event["tool"] for event in blocked})
        rules = sorted({event["rule"] for event in blocked})
        if transition == "regressed":
            blocked_tools.update(tools)
            blocked_rules.update(rules)
        rows.append(
            {
                "suite": suite,
                "user_task": task,
                "direct_completed": direct,
                "strict_completed": strict,
                "transition": transition,
                "intervened": bool(blocked),
                "blocked_tools": tools,
                "blocked_rules": rules,
            }
        )
    return {
        "schema_version": 1,
        "analysis": "post-hoc paired benign utility diagnosis; not a new benchmark",
        "pairs": len(rows),
        "direct_completed": sum(row["direct_completed"] for row in rows),
        "strict_completed": sum(row["strict_completed"] for row in rows),
        "transitions": dict(transitions),
        "regressions_with_intervention": sum(
            row["transition"] == "regressed" and row["intervened"] for row in rows
        ),
        "regressions_without_intervention": sum(
            row["transition"] == "regressed" and not row["intervened"] for row in rows
        ),
        "intervened_cases": sum(row["intervened"] for row in rows),
        "blocked_tools_in_regressions": dict(blocked_tools.most_common()),
        "blocked_rules_in_regressions": dict(blocked_rules.most_common()),
        "cases": rows,
        "trace_sha256": hashes,
        "analyzer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def markdown(result: dict) -> str:
    transitions = result["transitions"]
    net = result["strict_completed"] - result["direct_completed"]
    return f"""# Paired benign-utility diagnosis

This is a post-hoc diagnosis of the unchanged original AgentDojo experiment,
not a new held-out result or evidence that a proposed fix recovers tasks.

- Complete, error-free pairs: {result["pairs"]}.
- Direct completed: {result["direct_completed"]}; strict completed: {result["strict_completed"]}.
- Both completed: {transitions.get("both_complete", 0)}; both failed: {transitions.get("both_failed", 0)}.
- Direct completed / strict failed: {transitions.get("regressed", 0)}.
- Direct failed / strict completed: {transitions.get("improved", 0)}.
- Net completion change: {net} tasks.
- Regressions with a recorded intervention: {result["regressions_with_intervention"]}.
- Regressions without a recorded intervention: {result["regressions_without_intervention"]}.

Intervention is an observed event, not proof of the sole cause of failure.
Removing a refusal does not establish that the agent would finish successfully
or remain secure. Non-intervened differences can arise from model variability
or other execution differences; this audit does not determine their cause.

The JSON includes all task identities, paired outcomes, deciding rules/tools,
and hashes of every input trace. It excludes message contents and arguments.
Per-tool counts overlap: a task can attempt more than one blocked tool.

Reproduce from the private raw artifact:

```bash
.venv/bin/python scripts/diagnose_agentdojo_utility.py \\
  gym/results/agentdojo-heldout-r3 --out docs/results/utility-diagnosis
```
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = diagnose(args.root)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    (args.out / "REPORT.md").write_text(markdown(result))
    print(markdown(result))


if __name__ == "__main__":
    main()
