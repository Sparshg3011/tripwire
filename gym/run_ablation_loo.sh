#!/usr/bin/env bash
# Publication ablation: compare the full policy with full-minus-one-mechanism.

set -euo pipefail

AGENT="${1:-scripted}"
RUNS="${2:-1}"
MODEL="${3:-}"
CONCURRENCY="${4:-1}"
OUT="${5:-gym/results/ablation-loo}"
PY="${PY:-.venv/bin/python}"
POLICY_DIR="$OUT/generated-policies"

if [ "$AGENT" = "nvidia" ] && [ -z "${NVIDIA_API_KEY:-}" ]; then
  echo "NVIDIA_API_KEY is not set." >&2
  exit 2
fi

$PY -m tripwire_gym.ablations --policy gym/policies/standard.yaml --out "$POLICY_DIR"

run_cell() {
  BRACKET="$1"
  CONDITIONS="$2"
  POLICY_PATH="$3"
  DESTINATION="$4"
  if [ -n "$MODEL" ]; then
    $PY -m tripwire_gym --agent "$AGENT" --model "$MODEL" \
      --runs "$RUNS" --human "$BRACKET" --concurrency "$CONCURRENCY" \
      --conditions "$CONDITIONS" --policy-dir "$POLICY_PATH" --out "$DESTINATION" \
      --prompt-profile plain --temperature 0 --shuffle-seed 17229
  else
    $PY -m tripwire_gym --agent "$AGENT" \
      --runs "$RUNS" --human "$BRACKET" --concurrency "$CONCURRENCY" \
      --conditions "$CONDITIONS" --policy-dir "$POLICY_PATH" --out "$DESTINATION" \
      --prompt-profile plain --temperature 0 --shuffle-seed 17229
  fi
}

CONDITIONS="standard,loo-no-actions,loo-no-constraints,loo-no-limits,loo-no-sequences,loo-no-flows"
for BRACKET in approve deny; do
  run_cell "$BRACKET" standard gym/policies "$OUT/$BRACKET/full"
  run_cell "$BRACKET" "${CONDITIONS#standard,}" "$POLICY_DIR" "$OUT/$BRACKET/leave-one-out"
done

echo "Generated the full-versus-minus-one runs under $OUT."
echo "Aggregate them with:"
echo "$PY -m tripwire_gym.publication --root $OUT --out $OUT/summary"
