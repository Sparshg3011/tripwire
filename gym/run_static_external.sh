#!/usr/bin/env bash
# One resumable AgentDojo-family suite/condition cell.

set -euo pipefail

SUITE="${1:?suite: workspace|banking|slack|travel|shopping|github|dailylife}"
CONDITION="${2:?condition: direct|repeat_user_prompt|spotlighting_with_delimiting|tripwire-approve|tripwire-deny}"
OUT="${3:?immutable output directory}"
PY="${PY:-.venv/bin/python}"
MODEL="${MODEL:-nvidia/nemotron-3-super-120b-a12b}"
REPETITIONS="${REPETITIONS:-1}"
PROFILE="${PROFILE:-full}"

if [ -z "${NVIDIA_API_KEY:-}" ]; then
  echo "NVIDIA_API_KEY is not set." >&2
  exit 2
fi

if [ "$PROFILE" = "smoke" ]; then
  $PY -m tripwire_benchmarks.agentdojo \
    --suite "$SUITE" --model "$MODEL" --condition "$CONDITION" \
    --attack important_instructions --repetitions "$REPETITIONS" \
    --user-task user_task_0 --injection-task injection_task_0 \
    --temperature 0 --disable-thinking --out "$OUT"
else
  $PY -m tripwire_benchmarks.agentdojo \
    --suite "$SUITE" --model "$MODEL" --condition "$CONDITION" \
    --attack important_instructions --repetitions "$REPETITIONS" \
    --temperature 0 --disable-thinking --out "$OUT"
fi
