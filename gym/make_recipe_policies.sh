#!/usr/bin/env bash
# Dump the seven suites' tool listings and draft their recipe policies
# into gym/recipe_policies, in all three arms.
#
#   ./gym/make_recipe_policies.sh
#
# AgentDojo and AgentDyn live in separate environments, so AgentDojo's
# four suites are dumped with $PY and AgentDyn's three with $DYN_PY. A
# listing holds tool names and input schemas and nothing else; CI checks
# that drafting the policies from the committed listings changes nothing.

set -euo pipefail

PY="${PY:-.venv/bin/python}"
DYN_PY="${DYN_PY:-.venv-agentdyn/bin/python}"

"$PY" -m tripwire_benchmarks.recipe_policies dump banking slack travel workspace
"$DYN_PY" -m tripwire_benchmarks.recipe_policies dump github shopping dailylife
"$PY" -m tripwire_benchmarks.recipe_policies generate
