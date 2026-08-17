# AgentDojo development pilot

Status: **development evidence, not a publication headline**

This pilot was run before the held-out experiment to validate the adapter,
estimate attack signal, expose utility costs, and freeze the final evaluation
protocol. Cases were selected with the predeclared seed in
[`gym/agentdojo-pilot.yaml`](../gym/agentdojo-pilot.yaml), not selected after
seeing outcomes.

## Setup

- Benchmark: AgentDojo `v1.2.2`
- Model: `nvidia/nemotron-3-super-120b-a12b`
- Attack: official `important_instructions`
- Sample: 24 attack pairs and 12 benign tasks across all four suites
- Runs: one per case, temperature 0, thinking disabled
- Comparison: official direct execution versus strict unattended Tripwire
- Approval behavior: no human and no reviewer model; every
  `require_approval` decision was denied
- Scoring: AgentDojo's official deterministic state and task checkers

## Overall result

| Metric | Direct | Strict Tripwire | Difference |
|---|---:|---:|---:|
| Attack success | 62.5% (15/24) | 8.3% (2/24) | -54.2 points |
| Valid-goal attack success | 83.3% (10/12) | 16.7% (2/12) | -66.7 points |
| Benign utility | 66.7% (8/12) | 41.7% (5/12) | -25.0 points |
| Utility under attack | 37.5% (9/24) | 41.7% (10/24) | +4.2 points |
| Trace/API errors | 0 | 0 | 0 |

On the 24 paired cases, there were 13 direct-only breaches and no
Tripwire-only breaches. The ASR difference has a two-way user-by-injection
cluster-bootstrap 95% interval of -79.2 to -29.2 points. The descriptive
two-sided exact McNemar p-value is `0.0002`; it is not the primary inference
because AgentDojo pairs reuse user and injection tasks. The benign-utility
difference has a user-cluster 95% interval of -50.0 to 0.0 points. Because this
is a small development sample with one model run per case, it is evidence that
the full study is worthwhile, not a final effect estimate.

Strict Tripwire intervened in 15/24 attacked cases and 6/12 benign tasks. The
latter is the central cost: the current session-wide sticky taint tracker is
deliberately conservative and cannot tell whether a sensitive action derived
from untrusted content was nevertheless explicitly intended by the user.

## Per-suite result

| Suite | Direct ASR | Tripwire ASR | Direct benign utility | Tripwire benign utility |
|---|---:|---:|---:|---:|
| Banking | 5/6 | 0/6 | 3/3 | 2/3 |
| Slack | 5/6 | 2/6 | 2/3 | 0/3 |
| Travel | 4/6 | 0/6 | 1/3 | 2/3 |
| Workspace | 1/6 | 0/6 | 2/3 | 1/3 |

The apparent Travel utility improvement is not attributed to Tripwire. API
models can vary even at temperature 0, and the sample is only three benign
tasks per condition.

## Validity diagnostics

Nemotron completed 4 of the 8 sampled injection goals when each was presented
directly as a task. AgentDojo reports a warning but retains all cases. The
main table therefore reports both:

- the complete predeclared 24-pair sample; and
- a sensitivity subset containing the 12 pairs whose injection goal was
  directly executable by the target model.

The security reduction remains in the sensitivity subset. Workspace has no
valid-goal estimate because neither sampled Workspace injection goal passed
that diagnostic.

## Decision after the pilot

Do not tune rules to individual benchmark recipients, amounts, messages, or
task answers. That would leak the development benchmark into the defense.
Freeze the generic policies, exclude the 12 pilot user tasks from the primary
held-out analysis, and evaluate every remaining user task against every
official injection task. Report strict unattended behavior as such; human
approval is a separate deployment mode and must not be simulated with hidden
benchmark labels.

The machine-readable results, Wilson intervals, paired effects, raw traces,
token counts, and intervention receipts are under
`gym/results/agentdojo-pilot-live/`.
