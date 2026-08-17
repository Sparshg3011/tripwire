#!/usr/bin/env bash
# Install pinned AgentDyn and AutoDojo checkouts in isolated environments.

set -euo pipefail

ROOT="${1:-.benchmark-deps}"
PYTHON="${PYTHON:-python3}"
AGENTDYN_COMMIT="5353cf7615b135cace8d07c8f12dac53a16b6db3"
AUTODOJO_COMMIT="bf2e4cb321f4cfc47b1ed9d227176a0eb8df71a2"

clone_at() {
  URL="$1"
  DIRECTORY="$2"
  COMMIT="$3"
  if [ ! -d "$DIRECTORY/.git" ]; then
    git clone "$URL" "$DIRECTORY"
  fi
  CURRENT="$(git -C "$DIRECTORY" rev-parse HEAD)"
  if [ "$CURRENT" != "$COMMIT" ]; then
    DIRTY="$(git -C "$DIRECTORY" status --porcelain)"
    if [ -n "$DIRTY" ]; then
      echo "Refusing to change a modified benchmark checkout: $DIRECTORY" >&2
      exit 2
    fi
    git -C "$DIRECTORY" fetch origin "$COMMIT"
    git -C "$DIRECTORY" checkout --detach "$COMMIT"
  fi
}

mkdir -p "$ROOT"
clone_at https://github.com/SaFo-Lab/AgentDyn.git "$ROOT/AgentDyn" "$AGENTDYN_COMMIT"
clone_at https://github.com/xhOwenMa/AutoDojo.git "$ROOT/AutoDojo" "$AUTODOJO_COMMIT"

$PYTHON -m venv .venv-agentdyn
.venv-agentdyn/bin/python -m pip install -e .
.venv-agentdyn/bin/python -m pip install -e "$ROOT/AgentDyn"

$PYTHON -m venv .venv-autodojo
.venv-autodojo/bin/python -m pip install -e .
.venv-autodojo/bin/python -m pip install -e "$ROOT/AutoDojo/agentdojo"
.venv-autodojo/bin/python -m pip install json-repair nltk

echo "Pinned environments are ready:"
echo "  AgentDyn: .venv-agentdyn/bin/python"
echo "  AutoDojo: .venv-autodojo/bin/python"
