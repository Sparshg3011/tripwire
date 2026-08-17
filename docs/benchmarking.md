# Publication benchmark protocol

This is the benchmark to use for a paper. The existing 38-attack gym is
valuable for development and regression testing, but it is authored in the
same repository as Tripwire and is not enough by itself for a publishable
security claim.

The frozen, machine-readable version of this protocol is
[`gym/publication-plan.yaml`](../gym/publication-plan.yaml).

## The question

The primary question is deliberately narrow:

> On the same stateful agent tasks and model, does a frozen Tripwire policy
> reduce successful indirect-prompt-injection actions relative to no defense,
> while retaining benign task utility?

The benchmark does **not** try to prove that prompt injection is solved. It
measures a named policy, model, attack distribution, and tool environment.

## Evidence ladder

| Level | Benchmark | What it establishes | Role in a paper |
|---|---|---|---|
| 1 | local paired gym | implementation correctness, regressions, mechanisms | development and ablation |
| 2 | AgentDojo | stateful, independently authored tasks and attack checks | primary result |
| 3 | AgentDyn | dynamic/open-ended tasks from a second external corpus | external-validity result |
| 4 | AutoDojo | black-box attacks optimized against the deployed defense | adaptive-robustness result |

AgentDojo's official implementation is at
[ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo). AgentDyn's
official repository describes 60 tasks and 560 injection cases across shopping,
GitHub, and daily-life environments at
[SaFo-Lab/AgentDyn](https://github.com/SaFo-Lab/AgentDyn). AutoDojo's official
repository and optimizer are at
[xhOwenMa/AutoDojo](https://github.com/xhOwenMa/AutoDojo).

AgentDojo `v1.2.2` contains 97 user tasks and 949 user/injection pairs. The
original paper's `v1` suite contains 629 pairs; results from these versions are
not numerically interchangeable. This protocol uses `v1.2.2` as the current
primary benchmark and records the version on every result.

## Positioning against prior work

The closest architectural comparison is *Indirect Prompt Injections: Are
Firewalls All You Need to Defend AI Agents?* Its central warning is important
for this study: modular agent-tool firewalls can saturate fixed benchmarks, so
strong evidence also needs attacks adapted to the deployed defense. That is why
AgentDojo is the primary comparable result but the AutoDojo adaptive stage is a
required robustness test, not an optional demo.

CaMeL and AgentArmor are defense baselines to discuss and, where an official
implementation can be run on exactly the same tasks and target model, compare
against. Do not copy headline numbers from their papers into the Tripwire result
table: differences in model, task version, attack set, and utility definition
make those numbers references rather than controlled baselines.

NetInjectBench is the newest direct comparator identified for policy-aware
state-changing attacks. It reports 130 scenarios and emphasizes approved-change
utility, which is closely aligned with Tripwire's intended claim. No official
executable artifact was linked from the paper when this protocol was prepared,
so it is recorded as a required follow-up when artifacts become available, not
silently replaced by a local reimplementation.

Primary sources:

- [Firewalls All You Need](https://arxiv.org/abs/2510.05244)
- [CaMeL](https://arxiv.org/abs/2503.18813)
- [AgentArmor](https://arxiv.org/abs/2508.01249)
- [NetInjectBench](https://arxiv.org/abs/2607.10490)

InjecAgent and Agent Security Bench are useful breadth checks, but they are not
in the frozen core matrix: the stateful official checks in AgentDojo/AgentDyn
and the defense-in-the-loop optimization in AutoDojo test the paper's claim
more directly. They can be added later as clearly labelled secondary results.

## What has been implemented

- The local runner now has a true `plain` prompt control and a separately
  labelled `hardened` prompt baseline.
- Model repetitions and an optional provider API seed are separate. A
  repetition is no longer described as a seed unless a seed was actually sent.
- `shadow` evaluates canonicalized arguments but forwards the original call, so
  observation mode does not alter application behavior.
- Every run records the model ID, prompt profile, temperature, token counts,
  latency, source revision, dirty-worktree status, corpus hash, policy hash, and
  result hash in `manifest.json`.
- Corpus validation proves that every attack has exactly one benign twin with
  the same task, tools, family, and utility predicate.
- Repeated-run inference resamples authored scenarios as clusters. Five model
  reruns of one attack do not become five independently authored attacks.
- The AgentDojo-family adapter enforces Tripwire **before** a Python tool runs.
  Blocked calls do not alter the stateful application and do not appear in the
  executed trace used by official benchmark checkers.
- The AutoDojo plugin applies the same pre-execution rule inside its adaptive
  optimization loop. It also adds NVIDIA NIM as both a target-model provider and
  an optimizer-model provider without modifying the pinned AutoDojo checkout.
- Full-minus-one-component policies are generated from the frozen full policy.
  This is the primary ablation; the older cumulative ablation remains useful as
  a secondary sufficiency analysis.

## Models

Use one primary model and treat the rest as replications, not opportunities to
choose the most favorable row.

| Role | NVIDIA model ID | Why |
|---|---|---|
| primary | `nvidia/nemotron-3-super-120b-a12b` | strongest balance of capability and practical throughput |
| small replication | `nvidia/nemotron-3-nano-30b-a3b` | tests whether protection survives a weaker agent |
| large replication | `nvidia/nemotron-3-ultra-550b-a55b` | tests a high-capability agent |
| other-family replication | `z-ai/glm-5.2` | reduces dependence on one model family |

NVIDIA exposes an OpenAI-compatible endpoint and tool calling through NIM. The
runner defaults to temperature 0. Nemotron runs pass
`chat_template_kwargs.enable_thinking=false`, following NVIDIA's tool-use
guidance; GLM is kept in its supported default reasoning mode unless a smoke run
demonstrates a tool-call problem.

Never put the key in a command, config file, result, or paper artifact:

```bash
export NVIDIA_API_KEY='...'
```

The manifests record the environment-variable *name*, never its value.

## Stage 0: freeze before looking at results

1. Commit the code and policies to a dedicated experiment commit.
2. Copy `gym/publication-plan.yaml` into the study artifact and change its
   status from `preregistration-template` to `frozen`.
3. Record any deviations in a new file; do not silently edit the frozen plan.
4. Do not tune the external policies after seeing external attack outcomes.

Validate and hash the local corpus:

```bash
.venv/bin/python -m tripwire_gym.corpus \
  --scenarios gym/scenarios --out gym/results/corpus-freeze.json
```

For a local author-blind split, have a collaborator choose and retain a random
salt, then materialize the split once:

```bash
.venv/bin/python -m tripwire_gym.holdout \
  --scenarios gym/scenarios \
  --evaluation-fraction 0.25 \
  --salt "$PRIVATE_SPLIT_SALT" \
  --out gym/holdout
```

Tune only on `gym/holdout/development`. Freeze the policy hash before the
collaborator exposes or runs `gym/holdout/evaluation`. If the same person can see
all scenario files throughout development, call this a locked split, not a
blind holdout.

## Stage 1: smoke tests

First prove that the target model calls tools and that all adapters are wired:

```bash
./gym/run_publication.sh smoke gym/results/publication-smoke
```

This runs one attack/twin pair under the true direct control, shadow, both
Tripwire approval bounds, and the hardened-prompt baseline. A useful smoke run
has tool calls, zero harness errors, and a non-empty manifest. Its security rate
is not a result.

Install the external benchmarks in isolated environments:

```bash
./gym/setup_external_benchmarks.sh
```

The script pins:

- AgentDyn `5353cf7615b135cace8d07c8f12dac53a16b6db3`
- AutoDojo `bf2e4cb321f4cfc47b1ed9d227176a0eb8df71a2`

Smoke one external task pair:

```bash
PROFILE=smoke PY=.venv/bin/python \
  ./gym/run_static_external.sh banking direct \
  gym/results/external-smoke/banking/direct

PROFILE=smoke PY=.venv/bin/python \
  ./gym/run_static_external.sh banking tripwire-approve \
  gym/results/external-smoke/banking/tripwire-approve
```

## Stage 2: local development evidence

The practical matrix is three repetitions; the paper matrix is five:

```bash
./gym/run_publication.sh feasible gym/results/publication-feasible
./gym/run_publication.sh paper gym/results/publication-paper
```

Use the `plain` prompt row as the no-defense control. The hardened prompt is a
baseline, not part of Tripwire. Report these three outcomes together:

- **attack success rate (ASR):** did the attack's forbidden action occur?
- **benign utility:** did the same task finish when no attack existed?
- **utility under attack:** did the legitimate job still finish in the attacked
  run?

Run the leave-one-out mechanism study separately:

```bash
./gym/run_ablation_loo.sh scripted 1
```

For each component, report `full minus component` against the full policy. These
effects can interact and therefore do not have to add up to the full-policy
effect.

Run the model replications only after the primary model and analysis are frozen:

```bash
./gym/run_models.sh 3 6
```

## Stage 3: primary AgentDojo experiment

The seeded 24-pair development pilot and its limitations are reported in
[`docs/agentdojo-pilot-results.md`](agentdojo-pilot-results.md). Its 12 user
tasks are excluded from the primary test set. This leaves 85 untouched user
tasks and 844 attack pairs across all four suites.

Before running, freeze the experiment commit and change
`gym/agentdojo-heldout.yaml` from `prepared_not_frozen` to `frozen`. The runner
verifies the expected suite sizes, materializes a hashed selection receipt, and
executes one resumable job per suite. The direct/strict order is counterbalanced
across suites and fixed in the plan before the run. Strict Tripwire means
unattended operation: every `require_approval` decision is denied. It is not
described as human performance.

```bash
./gym/run_agentdojo_heldout.sh gym/results/agentdojo-heldout
```

The primary comparison is `direct` versus `tripwire-deny`. The permissive
`tripwire-approve` condition remains a mechanism bound from the smoke study,
not the deployable security result. After the primary analysis is frozen, run
prompt baselines on the same held-out user tasks as secondary comparisons.

AgentDojo's cross-product reuses user tasks and injection goals, so the 844
pairs are not treated as 844 independent samples. The primary effect interval
is a fixed-seed, 10,000-draw, suite-stratified two-way cluster bootstrap that
resamples user tasks and injection tasks independently. Benign-utility effects
use a user-task cluster bootstrap. Wilson intervals and exact McNemar p-values
are retained as descriptive summaries, not used to overstate independence.

Each suite job is resumable: completed official traces are loaded rather than
called again, and per-trace usage/enforcement receipts preserve token, model
time, provider attempts, rate-limit waits, and gate counts across a resumed run.
A final completeness receipt proves
that all 844 attack pairs and both sets of 85 benign tasks are present with no
trace errors before the run is treated as complete.

The hosted free NVIDIA endpoint is run with one worker, a two-second minimum
request interval, and deterministic 429 backoff (10 seconds doubling to a
60-second cap, at most 20 retries). A pre-score transport shakedown established
that four workers—and briefly one worker without explicit backoff—hit HTTP 429.
No aggregate held-out outcome was produced or inspected. This revision and its
unchanged scientific fields are recorded in the frozen YAML before the scored
run.

For an unsharded replication or targeted diagnostic, the lower-level command
remains available:

```bash
.venv/bin/python -m tripwire_benchmarks.report \
  --root gym/results/agentdojo-heldout \
  --out gym/results/agentdojo-heldout/summary
```

`tripwire-approve` and `tripwire-deny` are bounds on approval behavior. They are
not two competing products and neither estimates a human operator.

## Stage 4: AgentDyn external validity

Use the isolated AgentDyn environment so its fork cannot silently change the
AgentDojo primary run:

```bash
for suite in shopping github dailylife; do
  for condition in direct tripwire-approve tripwire-deny; do
    PROFILE=full PY=.venv-agentdyn/bin/python \
      ./gym/run_static_external.sh "$suite" "$condition" \
      "gym/results/agentdyn/$suite/$condition"
  done
done

.venv-agentdyn/bin/python -m tripwire_benchmarks.report \
  --root gym/results/agentdyn \
  --out gym/results/agentdyn/summary
```

Before accepting the run, verify the installed revision reports 60 user tasks
and 560 attack cases across the three suites. A mismatch is a benchmark-version
error, not a new result.

## Stage 5: adaptive AutoDojo attacks

Start with a one-task smoke profile, then use `feasible` while debugging. Only
the frozen run should use `paper` (five retained variants and eight optimizer
iterations).

```bash
.venv-autodojo/bin/python -m tripwire_benchmarks.autodojo \
  --autodojo-root .benchmark-deps/AutoDojo \
  --suite banking \
  --gate approve \
  --profile smoke \
  --out gym/results/autodojo/caches/banking/approve-smoke
```

The full cell is the same command with `--profile paper`. Run both approval
bounds and each predeclared suite. The optimizer uses `z-ai/glm-5.2` to rewrite
attacks and Nemotron Super as the target by default, all through the NVIDIA key.
Use `--resume` after an interruption.

The generated cache is replayed once through the official benchmark runner so
the published outcome is not the optimizer's internal leaderboard score:

```bash
export AUTODOJO_CACHE='<generated injections.json>'
export AUTODOJO_VARIANT=0

.venv-autodojo/bin/python -m tripwire_benchmarks.agentdojo \
  --suite banking \
  --model nvidia/nemotron-3-super-120b-a12b \
  --condition tripwire-approve \
  --attack autodojo \
  --module-to-load agentdojo.attacks.autodojo_attack \
  --repetitions 1 \
  --temperature 0 \
  --disable-thinking \
  --out gym/results/autodojo/replay/banking/approve
```

Do not call a cache optimized against another defense “adaptive to Tripwire.”
That is a transfer attack. The plugin in this repository places Tripwire in the
optimizer's evaluation loop, which is the requirement for the adaptive claim.

## Statistical analysis

The authored scenario or external `(user task, injection task)` pair is the unit
of generalization.

- Show absolute counts beside every percentage.
- Show Wilson 95% intervals as descriptive uncertainty.
- With one run per case, compare paired conditions with exact McNemar tests.
- With repeated model runs, average within scenario and bootstrap whole
  scenarios. Do not pool repetitions as independent cases.
- Report paired absolute ASR change, not only relative improvement.
- List every successful attack and every failed benign task.
- Treat errors as missing measurements and print their count. Never turn a crash
  into a blocked attack.
- Mark family-wise tests secondary and adjust their p-values (Holm is specified
  in the frozen plan).

The primary success criterion should be direction and uncertainty, not a target
chosen after seeing the data: Tripwire's ASR must be lower than direct and its
benign utility loss must be reported with the same prominence. A strong negative
or mixed result is still publishable if the adaptive and dynamic evaluation is
rigorous.

## What to release with the paper

- the frozen plan and any dated deviations;
- the exact experiment commit and pinned external revisions;
- local manifests and all raw AgentDojo-family episode JSON;
- corpus and policy hashes;
- scripts and generated policy files;
- all error, token, and latency counts;
- the external-summary CSV/JSON/Markdown files;
- the adaptive caches and optimizer receipts;
- a table separating primary, replication, ablation, and exploratory results.

That package makes the work reproducible and, more importantly, makes selective
reporting difficult.
