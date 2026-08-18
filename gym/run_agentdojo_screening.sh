#!/usr/bin/env bash
# Reuse the frozen development pilot and add only the missing cheap baselines.

set -euo pipefail

PY="${PY:-.venv/bin/python}"
OUT="${1:-gym/results/agentdojo-screening}"
SOURCE="${SOURCE:-gym/results/agentdojo-pilot-live}"
MODEL="${MODEL:-nvidia/nemotron-3-super-120b-a12b}"
export HF_HOME="${HF_HOME:-$PWD/.cache/huggingface}"

if [ -z "${NVIDIA_API_KEY:-}" ]; then
  echo "NVIDIA_API_KEY is not set." >&2
  exit 2
fi

for suite in workspace banking slack travel; do
  for condition in direct tripwire-deny; do
    source_result="$SOURCE/$suite/$condition/results.json"
    target_dir="$OUT/$suite/$condition"
    if [ ! -f "$source_result" ]; then
      echo "Missing reusable pilot result: $source_result" >&2
      exit 2
    fi
    mkdir -p "$target_dir"
    if [ ! -f "$target_dir/results.json" ]; then
      cp "$source_result" "$target_dir/results.json"
    elif ! cmp -s "$source_result" "$target_dir/results.json"; then
      echo "Existing screening result differs from frozen pilot: $target_dir" >&2
      exit 2
    fi
  done
done

MODEL="$MODEL" PY="$PY" ./gym/run_agentdojo_pilot.sh \
  "$OUT" \
  repeat_user_prompt,spotlighting_with_delimiting,transformers_pi_detector

cp gym/agentdojo-screening.yaml "$OUT/screening-plan.yaml"
echo "AgentDojo screening complete: $OUT/summary/REPORT.md"
