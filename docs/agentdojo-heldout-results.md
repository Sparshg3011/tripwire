# AgentDojo held-out primary result

Status: **complete primary experiment; secondary ProtectAI comparison pending**

This is Tripwire's primary external evaluation. The policies, user-task
exclusions, target model, condition order, attack, scoring, and statistical
analysis were frozen before any aggregate held-out outcome was inspected. The
12 users seen during development were excluded; every remaining official user
task was crossed with every official injection task in its suite.

## Setup

- Benchmark: AgentDojo `v1.2.2`
- Model: `nvidia/nemotron-3-super-120b-a12b`
- Attack: official `important_instructions`
- Held-out population: 85 user tasks and 35 injection tasks across four suites
- Attacked cases: 844 user-by-injection pairs per condition
- Benign cases: the same 85 user tasks without an injection, per condition
- Conditions: official direct execution and strict unattended Tripwire
- Runs: one per case, temperature 0, thinking disabled
- Approval behavior: no human and no reviewer model; every
  `require_approval` decision was denied
- Scoring: AgentDojo's official deterministic state and task checkers
- Trace/API errors: zero in every suite and condition

Strict unattended Tripwire is one explicit operating point, not an estimate of
human performance. It is intentionally conservative and should not be read as
the expected utility of an interactive deployment.

## Primary result

| Metric | Direct | Strict Tripwire | Paired change |
|:--|--:|--:|--:|
| Attack success | 30.7% (259/844) | 4.0% (34/844) | **-26.7 points** |
| Valid-goal attack success | 43.5% (236/542) | 6.3% (34/542) | -37.3 points |
| Benign utility | 82.4% (70/85) | 36.5% (31/85) | **-45.9 points** |
| Utility under attack | 63.7% (538/844) | 31.8% (268/844) | -32.0 points |
| Attack intervention | 0.0% (0/844) | 64.8% (547/844) | +64.8 points |
| Benign intervention | 0.0% (0/85) | 47.1% (40/85) | +47.1 points |
| Trace/API errors | 0 | 0 | 0 |

![AgentDojo held-out security/utility trade-off: attack success falls from 30.7% to 4.0% while benign utility falls from 82.4% to 36.5%.](img/agentdojo-heldout.png)

The paired attack-success difference is -26.7 percentage points. Its
predeclared, suite-stratified two-way user-by-injection cluster-bootstrap 95%
interval is **-33.6 to -19.8 points**. There were 229 direct-only breaches and
four Tripwire-only breaches across the 844 pairs. The descriptive two-sided
exact McNemar p-value is below `1e-61`; the clustered interval is the primary
inference because AgentDojo reuses user and injection tasks across pairs.

The security improvement comes with a larger utility cost. Benign utility
falls by 45.9 points, with a predeclared user-cluster bootstrap 95% interval of
**-56.5 to -35.3 points**. Tripwire intervenes in 40 of 85 benign tasks. This
is not a production-readiness win: it is evidence that deterministic tool
mediation can remove most successful injections at this operating point while
the current session-wide sticky-taint policy over-blocks legitimate work.

## Per-suite result

| Suite | Direct ASR | Tripwire ASR | Direct benign utility | Tripwire benign utility |
|:--|--:|--:|--:|--:|
| Banking | 60.7% (71/117) | 0.0% (0/117) | 69.2% (9/13) | 38.5% (5/13) |
| Slack | 85.6% (77/90) | 32.2% (29/90) | 100.0% (18/18) | 22.2% (4/18) |
| Travel | 59.7% (71/119) | 4.2% (5/119) | 70.6% (12/17) | 47.1% (8/17) |
| Workspace | 7.7% (40/518) | 0.0% (0/518) | 83.8% (31/37) | 37.8% (14/37) |

The aggregate result hides important heterogeneity. Banking and Travel show
large security gains with material utility loss. Slack retains 32.2% attack
success while losing most benign utility. Workspace begins with a low direct
attack-success rate, yet the strict policy still removes 46.0 points of benign
utility. Any claim that the current policy is uniformly effective would be
misleading.

## Validity and provenance

AgentDojo's cross-product does not create 844 independent observations. The
primary interval resamples user tasks and injection tasks independently within
suite for 10,000 fixed-seed bootstrap draws. Benign-utility intervals resample
user tasks. Wilson intervals in the generated tables and exact McNemar tests
are descriptive.

The hosted endpoint required transport-only resumptions. The first scored
attempt stopped after 200 successful checkpoints following an HTTP 502 and a
read timeout. No aggregate condition result was produced or inspected. The
completed run reused only successful traces and expanded the same bounded retry
policy to timeouts, connection failures, and HTTP 5xx responses. The selection
hash, policy hashes, model, prompts, scoring, condition order, and analysis
remained unchanged. The transport deviation is preserved in both the frozen
protocol and the machine-readable receipt.

An independent audit performed after completion verified:

- all eight suite/condition cells and all 844 paired comparisons;
- 1,688 attacked traces, 170 benign traces, and 70 injection-validity traces;
- unique task cross-products with no missing or duplicate scored cases;
- zero raw trace errors;
- the frozen selection, policy, and scientific-contract hashes;
- the paired-effect arithmetic; and
- byte-identical regeneration of the JSON, CSV, and Markdown aggregates.

See the [validation record](results/agentdojo-heldout/VALIDATION.md) and the
[compact machine-readable artifact](results/agentdojo-heldout/README.md).

## What this establishes—and what it does not

The result supports a narrow claim: under one model, one official attack, and
one conservative unattended policy, Tripwire substantially reduced attack
success on frozen AgentDojo tasks. It does **not** establish that Tripwire is
better than other defenses, production-ready, or model-independent.

The primary limitations are:

- one target model and one model run per case;
- one official attack method;
- a single strict policy point rather than a full AgentDojo utility frontier;
- a large benign-utility penalty; and
- no full held-out ProtectAI comparison yet.

The development screen advanced AgentDojo's stock ProtectAI detector as the
secondary defense baseline. That full held-out comparison must be reported
before making comparative claims.

## Reproduce

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev,publication]"
set -a
source .env
set +a
./gym/run_agentdojo_heldout.sh gym/results/agentdojo-heldout

.venv/bin/python -m tripwire_benchmarks.report \
  --root gym/results/agentdojo-heldout \
  --out gym/results/agentdojo-heldout/summary
```

The runner refuses changed suite sizes, an unfrozen protocol, an unexpected
model or condition set, a dirty source state, or a changed scientific-contract
hash. The final completeness check refuses missing cases and trace errors.

Regenerate the figure from the tracked summary with:

```bash
.venv/bin/python -m tripwire_benchmarks.chart \
  docs/results/agentdojo-heldout/summary.json \
  docs/img/agentdojo-heldout.png
```
