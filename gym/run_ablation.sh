#!/usr/bin/env bash
# Which of standard's five mechanisms actually stops the attacks?
#
#   ./gym/run_ablation.sh                  # scripted agent, free, ~4 min
#   ./gym/run_ablation.sh claude 5         # real model, 5 seeds per cell
#   ./gym/run_ablation.sh claude 5 "" 8    # 8 runs in flight
#
# Writes gym/results/ablation/{approve,deny}/ and prints condition x
# attacks-stopped with the marginal contribution of each layer.
#
# The scripted agent is the right agent for this one. The question is what
# the *firewall* contributes, so the thing that has to be held still is the
# agent — a model that improvises around a refusal moves both axes and the
# deltas stop being attributable to the layer that was added.
#
# gym/ablations/ holds the chain. standard itself is the top of it and
# lives in gym/policies/, so it runs as a second invocation against that
# directory rather than being copied into the ablation set: a duplicate
# would be one edit away from measuring a policy nobody ships.

set -euo pipefail

AGENT="${1:-scripted}"
RUNS="${2:-1}"
MODEL="${3:-}"
CONCURRENCY="${4:-1}"
OUT="gym/results/ablation"
PY="${PY:-.venv/bin/python}"

# in order: each adds one mechanism to the one before it
ABLATIONS="ablate-none,ablate-actions,ablate-constraints,ablate-limits,ablate-sequences"

if [ "$AGENT" = "claude" ] && [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "ANTHROPIC_API_KEY is not set, and --agent claude needs one." >&2
  exit 2
fi

# bracket, conditions, policy dir, out dir. A function rather than the
# command spelled out four times: macos ships bash 3.2, where expanding
# an empty array under `set -u` is a fatal error, so --model can't just
# be an array that is sometimes empty.
run_gym() {
  if [ -n "$MODEL" ]; then
    $PY -m tripwire_gym --agent "$AGENT" --runs "$RUNS" --human "$1" \
      --concurrency "$CONCURRENCY" \
      --conditions "$2" --policy-dir "$3" --out "$4" --model "$MODEL"
  else
    $PY -m tripwire_gym --agent "$AGENT" --runs "$RUNS" --human "$1" \
      --concurrency "$CONCURRENCY" \
      --conditions "$2" --policy-dir "$3" --out "$4"
  fi
}

echo "==> chain"
for NAME in $(echo "$ABLATIONS" | tr ',' ' '); do
  echo "  gym/ablations/$NAME.yaml"
done
echo "  gym/policies/standard.yaml  (the full stack)"

# Both brackets, always. Only the last link in the chain adds a gate, so
# the two brackets are identical everywhere above it — and the run is
# what proves that rather than the claim.
for BRACKET in approve deny; do
  echo "==> running: agent=$AGENT runs=$RUNS human=$BRACKET concurrency=$CONCURRENCY"
  run_gym "$BRACKET" "$ABLATIONS" gym/ablations "$OUT/$BRACKET/ablations"
  run_gym "$BRACKET" standard gym/policies "$OUT/$BRACKET/full"
  cat "$OUT/$BRACKET/ablations/results.jsonl" "$OUT/$BRACKET/full/results.jsonl" \
    > "$OUT/$BRACKET/results.jsonl"
done

echo "==> marginal contributions"
$PY - <<PYEOF
from tripwire_gym.analysis import load_results
from tripwire_gym.scoring import summarize

# (condition, what this step adds). Chain order, not the alphabetical
# order the chart sorts unknown conditions into.
CHAIN = [
    ("ablate-none", "nothing"),
    ("ablate-actions", "+ actions"),
    ("ablate-constraints", "+ constraints"),
    ("ablate-limits", "+ limits"),
    ("ablate-sequences", "+ sequences"),
    ("standard", "+ flows"),
]

def rate(hits, total):
    return f"{hits / total:>4.0%} ({hits}/{total})" if total else f"{'--':>4} (0/0)"

for bracket in ("approve", "deny"):
    rows = load_results(f"$OUT/{bracket}/results.jsonl")
    by = {}
    for r in rows:
        by.setdefault(r.condition, []).append(r.outcome)

    print(f"\n--human {bracket}")
    print(
        f"{'condition':<20} {'adds':<14} {'attacks stopped':>17} "
        f"{'marginal':>9} {'benign completion':>19} {'gates':>6}"
    )
    previous = None
    for condition, adds in CHAIN:
        outcomes = by.get(condition)
        if not outcomes:
            continue
        s = summarize(condition, outcomes)
        stopped = s.attack_runs - s.attacks_succeeded
        # points of the whole corpus, so the column sums to the headline
        share = 100 * stopped / s.attack_runs if s.attack_runs else 0.0
        step = f"{share - previous:>+6.1f}" if previous is not None else f"{'--':>6}"
        previous = share
        print(
            f"{condition:<20} {adds:<14} {rate(stopped, s.attack_runs):>17} "
            f"{step} pts {rate(s.benign_completed, s.benign_runs):>19} {s.gate_prompts:>6}"
        )
        if s.errored_runs:
            print(f"{'':<20} {s.errored_runs} errored run(s) excluded from those rates")

    # A percentage says how much a layer earned; only the ids say what it
    # earned it on, and a layer credited with nothing is the finding this
    # whole script exists to be able to state.
    print(f"\n--human {bracket}: what each layer newly stops")
    stopped_by = {}
    for r in rows:
        if r.outcome.attacked and not r.outcome.errored:
            stopped_by.setdefault(r.condition, {})[(r.scenario_id, r.seed)] = (
                not r.outcome.attack_succeeded
            )
    previous_set = None
    for condition, adds in CHAIN:
        now = stopped_by.get(condition)
        if now is None:
            continue
        if previous_set is not None:
            gained = sorted({i for i, ok in now.items() if ok and not previous_set.get(i)})
            lost = sorted({i for i, ok in now.items() if not ok and previous_set.get(i)})
            names = sorted({i[0] for i in gained})
            print(f"  {adds:<14} {len(gained):>2} newly stopped: {', '.join(names) or '(none)'}")
            # the chain only ever adds rules, so this should stay empty;
            # if it doesn't, the ablation is not the chain it claims to be
            if lost:
                print(f"  {'':<14} REGRESSION — no longer stopped: {sorted({i[0] for i in lost})}")
        previous_set = now
PYEOF

echo
echo "Read the marginal column against the benign one. A layer that stops"
echo "attacks by refusing everything is not a layer that earned anything."
