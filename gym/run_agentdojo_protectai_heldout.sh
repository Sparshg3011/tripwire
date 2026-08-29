#!/usr/bin/env bash
# Frozen secondary ProtectAI comparison; source .env before invoking this script.

set -euo pipefail

PY="${PY:-.venv/bin/python}"
OUT="${1:-gym/results/agentdojo-protectai-heldout}"
PRIMARY_ROOT="${2:-gym/results/agentdojo-heldout}"
export HF_HOME="${HF_HOME:-$PWD/.cache/huggingface}"
EXTRA_ARGS=()

if [ "${ALLOW_TRANSPORT_RESUME:-0}" = "1" ]; then
  EXTRA_ARGS+=(--allow-transport-resume)
fi

if [ -z "${NVIDIA_API_KEY:-}" ]; then
  echo "NVIDIA_API_KEY is not set." >&2
  exit 2
fi

"$PY" -m tripwire_benchmarks.protectai_heldout \
  --out "$OUT" \
  --primary-root "$PRIMARY_ROOT" \
  --workers 1 \
  --shard-size 100 \
  "${EXTRA_ARGS[@]}"
