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

# The optional flag joins the command rather than an array of its own:
# macos ships bash 3.2, where expanding an empty array under `set -u` is
# a fatal error.
COMMAND=("$PY" -m tripwire_benchmarks.heldout \
  --out "$OUT" \
  --workers "$WORKERS" \
  --shard-size "$SHARD_SIZE" \
  --conditions direct,tripwire-deny)

if [ "${ALLOW_TRANSPORT_RESUME:-0}" = "1" ]; then
  COMMAND+=(--allow-transport-resume)
fi

"${COMMAND[@]}"
