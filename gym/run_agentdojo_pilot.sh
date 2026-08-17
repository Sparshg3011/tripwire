#!/usr/bin/env bash
# Deterministic 24-pair AgentDojo pilot frozen in gym/agentdojo-pilot.yaml.

set -euo pipefail

OUT="${1:-gym/results/agentdojo-pilot}"
CONDITIONS="${2:-direct,tripwire-deny}"
PY="${PY:-.venv/bin/python}"
MODEL="${MODEL:-nvidia/nemotron-3-super-120b-a12b}"

if [ -z "${NVIDIA_API_KEY:-}" ]; then
  echo "NVIDIA_API_KEY is not set." >&2
  exit 2
fi

run_suite() {
  local suite="$1"
  local condition="$2"
  shift 2
  local args=(
    -m tripwire_benchmarks.agentdojo
    --suite "$suite"
    --model "$MODEL"
    --condition "$condition"
    --attack important_instructions
    --repetitions 1
    --temperature 0
    --disable-thinking
    --out "$OUT/$suite/$condition"
  )
  while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
    args+=(--user-task "$1")
    shift
  done
  shift
  while [ "$#" -gt 0 ]; do
    args+=(--injection-task "$1")
    shift
  done
  "$PY" "${args[@]}"
}

IFS=',' read -r -a condition_list <<< "$CONDITIONS"
for condition in "${condition_list[@]}"; do
  run_suite workspace "$condition" \
    user_task_13 user_task_19 user_task_27 -- injection_task_11 injection_task_7
  run_suite banking "$condition" \
    user_task_10 user_task_3 user_task_6 -- injection_task_5 injection_task_8
  run_suite slack "$condition" \
    user_task_1 user_task_13 user_task_14 -- injection_task_1 injection_task_4
  run_suite travel "$condition" \
    user_task_17 user_task_18 user_task_9 -- injection_task_0 injection_task_1
done

"$PY" -m tripwire_benchmarks.report --root "$OUT" --out "$OUT/summary"
echo "AgentDojo pilot complete: $OUT/summary/REPORT.md"
