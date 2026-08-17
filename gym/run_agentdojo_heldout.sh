#!/usr/bin/env bash
# Frozen held-out AgentDojo matrix; source .env before invoking this script.

set -euo pipefail

PY="${PY:-.venv/bin/python}"
OUT="${1:-gym/results/agentdojo-heldout}"
WORKERS="${WORKERS:-1}"
SHARD_SIZE="${SHARD_SIZE:-100}"

if [ -z "${NVIDIA_API_KEY:-}" ]; then
  echo "NVIDIA_API_KEY is not set." >&2
  exit 2
fi

"$PY" -m tripwire_benchmarks.heldout \
  --out "$OUT" \
  --workers "$WORKERS" \
  --shard-size "$SHARD_SIZE" \
  --conditions direct,tripwire-deny
