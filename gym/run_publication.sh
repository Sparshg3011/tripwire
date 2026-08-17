#!/usr/bin/env bash
# Reproducible local publication matrix. External and adaptive suites are staged separately.

set -euo pipefail

PROFILE="${1:-smoke}"
OUT="${2:-gym/results/publication-$PROFILE}"
PY="${PY:-.venv/bin/python}"
MODEL="${MODEL:-nvidia/nemotron-3-super-120b-a12b}"
CONCURRENCY="${CONCURRENCY:-6}"

case "$PROFILE" in
  smoke) RUNS=1 ;;
  feasible) RUNS=3 ;;
  paper) RUNS=5 ;;
  *) echo "profile must be smoke, feasible, or paper" >&2; exit 2 ;;
esac

if [ -z "${NVIDIA_API_KEY:-}" ]; then
  echo "NVIDIA_API_KEY is not set." >&2
  exit 2
fi
if [ -e "$OUT" ]; then
  echo "Refusing to overwrite existing publication directory: $OUT" >&2
  exit 2
fi

mkdir -p "$OUT"
$PY -m tripwire_gym.corpus --scenarios gym/scenarios --out "$OUT/corpus.json"

run_local() {
  HUMAN="$1"
  CONDITIONS="$2"
  PROMPT="$3"
  DESTINATION="$4"
  if [ "$PROFILE" = "smoke" ]; then
    $PY -m tripwire_gym --agent nvidia --model "$MODEL" \
      --scenario exfil-email-01 --scenario exfil-email-01-benign \
      --conditions "$CONDITIONS" --runs "$RUNS" --human "$HUMAN" \
      --prompt-profile "$PROMPT" --temperature 0 --disable-thinking \
      --shuffle-seed 17229 --concurrency "$CONCURRENCY" --out "$DESTINATION"
  else
    $PY -m tripwire_gym --agent nvidia --model "$MODEL" \
      --conditions "$CONDITIONS" --runs "$RUNS" --human "$HUMAN" \
      --prompt-profile "$PROMPT" --temperature 0 --disable-thinking \
      --shuffle-seed 17229 --concurrency "$CONCURRENCY" --out "$DESTINATION"
  fi
}

# One direct control, one observational control, and both approval bounds.
run_local approve undefended,shadow,standard plain "$OUT/local/plain/approve"
run_local deny standard plain "$OUT/local/plain/deny"
# Prompt defense is a separately labelled baseline, never folded into "undefended".
run_local approve undefended hardened "$OUT/local/hardened/direct"

$PY -m tripwire_gym.publication --root "$OUT/local" --out "$OUT/summary"
echo "Local publication matrix complete: $OUT/summary/REPORT.md"
