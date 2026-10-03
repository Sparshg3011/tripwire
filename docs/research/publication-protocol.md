# Publication protocol

The plan for Tripwire's external evaluation, written in August 2026 before the
AgentDojo runs. [What was implemented for it](#what-was-implemented-for-it) has
been kept up to date with the code since. Its machine-readable version is
[`gym/publication-plan.yaml`](../../gym/publication-plan.yaml). What has been
run is in [EVIDENCE.md](../../EVIDENCE.md), and the commands for it are in
[benchmarking.md](../benchmarking.md).

The 38-attack gym is useful for development and regression testing, but it is
written in the same repository as Tripwire and is not enough on its own for a
publishable security claim.

## The question

The primary question is deliberately narrow:

> On the same stateful agent tasks and model, does a fixed Tripwire policy
> reduce successful indirect-prompt-injection actions relative to no defense,
> while retaining benign task utility?

The benchmark does not try to prove that prompt injection is solved. It
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
not numerically interchangeable. This protocol uses `v1.2.2` and records the
version on every result.

## Positioning against prior work

The closest architectural comparison is *Indirect Prompt Injections: Are
Firewalls All You Need to Defend AI Agents?* Its central warning matters for
this study: modular agent-tool firewalls can saturate fixed benchmarks, so
strong evidence also needs attacks adapted to the deployed defense. That is why
AgentDojo is the primary comparable result but the AutoDojo adaptive stage is a
required robustness test, not an optional demo.

CaMeL and AgentArmor are defense baselines to discuss and, where an official
implementation can be run on exactly the same tasks and target model, compare
against. Their headline numbers don't belong in Tripwire's result table:
differences in model, task version, attack set, and utility definition make
them references rather than controlled baselines.

NetInjectBench is the newest direct comparator identified for policy-aware
state-changing attacks. It reports 130 scenarios and emphasizes approved-change
utility, which is close to Tripwire's intended claim. No official executable
artifact was linked from the paper when this protocol was written, so it is a
follow-up for when artifacts become available, not something to replace with a
local reimplementation.

Primary sources:

- [Firewalls All You Need](https://arxiv.org/abs/2510.05244)
- [CaMeL](https://arxiv.org/abs/2503.18813)
- [AgentArmor](https://arxiv.org/abs/2508.01249)
- [NetInjectBench](https://arxiv.org/abs/2607.10490)

InjecAgent and Agent Security Bench are useful breadth checks, but they are not
in the core matrix: the stateful official checks in AgentDojo/AgentDyn and the
defense-in-the-loop optimization in AutoDojo test the claim more directly. They
can be added later as clearly labelled secondary results.

## What was implemented for it

- The local runner has a true `plain` prompt control and a separately labelled
  `hardened` prompt baseline.
- Model repetitions and an optional provider API seed are separate. A
  repetition is not described as a seed unless a seed was actually sent.
- `shadow` evaluates canonicalized arguments but forwards the original call, so
  observation mode does not alter application behavior.
- Every run records the model ID, prompt profile, temperature, token counts,
  latency, source revision, dirty-worktree status, corpus hash, policy hash, and
  result hash in `manifest.json`.
- Corpus validation proves that every attack has exactly one benign twin with
  the same task, tools, family, and utility predicate.
- Repeated-run inference resamples authored scenarios as clusters. Five model
  reruns of one attack do not become five independently authored attacks.
- The AgentDojo-family adapter enforces Tripwire before a Python tool runs.
  Blocked calls do not alter the stateful application and do not appear in the
  executed trace used by the official checkers. Each task runs through the
  proxy's own Interceptor, with the suite's functions as its upstream, the
  task's prompt as its task text, and a hash-chained audit log written beside
  the task's trace (`<injection task or none>.tripwire.jsonl`, whose sha256 the
  trace records). A test replays what the adapter saw through the real proxy
  and a stdio server and gets the same audit records. AgentDojo still receives
  each function's own result and error; a refused call's error is the proxy's
  refusal, which for a gated call ends with the gate's answer ("The approval
  gate denied this call."). The v0.1 held-out runs predate this and handed the
  model the verdict's reason alone.
- The AutoDojo plugin applies the same pre-execution rule inside its adaptive
  optimization loop. It also adds NVIDIA NIM as both a target-model provider and
  an optimizer-model provider without modifying the pinned AutoDojo checkout.
- Full-minus-one-component policies are generated from the full policy. This
  is the primary ablation; the older cumulative ablation remains a secondary
  sufficiency analysis.

## Models

One primary model, with the rest as replications rather than a chance to pick
the most favorable row.

| Role | NVIDIA model ID | Why |
|---|---|---|
| primary | `nvidia/nemotron-3-super-120b-a12b` | balance of capability and practical throughput |
| small replication | `nvidia/nemotron-3-nano-30b-a3b` | tests whether protection survives a weaker agent |
| large replication | `nvidia/nemotron-3-ultra-550b-a55b` | tests a high-capability agent |
| other-family replication | `z-ai/glm-5.2` | reduces dependence on one model family |

NVIDIA exposes an OpenAI-compatible endpoint and tool calling through NIM. The
runner defaults to temperature 0. Nemotron runs pass
`chat_template_kwargs.enable_thinking=false`, following NVIDIA's tool-use
guidance; GLM is kept in its default reasoning mode unless a smoke run shows a
tool-call problem.

## Stage 0: fix the protocol before looking at results

1. Commit the code and policies to a dedicated experiment commit.
2. Copy `gym/publication-plan.yaml` into the study artifact and change its
   status from `preregistration-template` to `frozen`.
3. Record any deviations in a new file; do not edit the fixed plan.
4. Do not tune the external policies after seeing external attack outcomes.

Validate and hash the local corpus:

```bash
.venv/bin/python -m tripwire_gym.corpus \
  --scenarios gym/scenarios --out gym/results/corpus-freeze.json
```

For a local author-blind split, have a collaborator choose and keep a random
salt, then materialize the split once:

```bash
.venv/bin/python -m tripwire_gym.holdout \
  --scenarios gym/scenarios \
  --evaluation-fraction 0.25 \
  --salt "$PRIVATE_SPLIT_SALT" \
  --out gym/holdout
```

Tune only on `gym/holdout/development`. Fix the policy hash before the
collaborator exposes or runs `gym/holdout/evaluation`. If the same person can see
all scenario files throughout development, call this a locked split, not a
blind holdout.

## Stage 1: smoke tests

First show that the target model calls tools and that all adapters are wired:

```bash
./gym/run_publication.sh smoke gym/results/publication-smoke
```

This runs one attack/twin pair under the direct control, shadow, both Tripwire
approval bounds, and the hardened-prompt baseline. A useful smoke run has tool
calls, zero harness errors, and a non-empty manifest. Its security rate is not
a result.

Smoke one external task pair once the external benchmarks are installed:

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
baseline, not part of Tripwire. Report three outcomes together:

- **attack success rate (ASR):** did the attack's forbidden action occur?
- **benign utility:** did the same task finish when no attack existed?
- **utility under attack:** did the legitimate job still finish in the attacked
  run?

Run the leave-one-out mechanism study separately. For each component, report
`full minus component` against the full policy; these effects can interact and
don't have to add up to the full-policy effect. Run the model replications
only after the primary model and analysis are fixed.

## Stage 3: primary AgentDojo experiment

Before spending calls on secondary baselines, screen them on the 12-user
development pilot. Direct and strict Tripwire results are reused; only the two
prompt defenses and AgentDojo's local ProtectAI detector make new target-model
calls. The screening rule is in
[`gym/agentdojo-screening.yaml`](../../gym/agentdojo-screening.yaml); the
[screening](agentdojo-screening-results.md) and the
[pilot](agentdojo-pilot-results.md) are reported separately. The pilot's 12
users are excluded from the test set, which leaves 85 untouched user tasks and
844 attack pairs across four suites.

The experiment was fixed at protocol revision 3 before a complete aggregate
outcome was produced. The runner checks the expected suite sizes, writes a
hashed selection, and runs one resumable job per suite. The direct/strict order
is counterbalanced across suites and set in the plan before the run. Strict
Tripwire means unattended operation: every `require_approval` decision is
denied. It is not described as human performance. `tripwire-approve` and
`tripwire-deny` are bounds on approval behavior, not two competing products,
and neither estimates a human operator.

ProtectAI is the secondary defense comparison, run as a separate protocol that
does not change the primary one. It checks the SHA-256 of the four Direct
result files, rebuilds the same 85-user/844-pair selection, and runs only
AgentDojo's stock `TransformersBasedPIDetector`, with its weights pinned to
Hugging Face revision `90c9989b1a342275dd0d1a95aad283c04e075671`.

## Stage 4: AgentDyn external validity

Use the isolated AgentDyn environment so its fork cannot change the AgentDojo
primary run:

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

Before accepting the run, check that the installed revision reports 60 user
tasks and 560 attack cases across the three suites. A mismatch is a
benchmark-version error, not a new result.

## Stage 5: adaptive AutoDojo attacks

Start with a one-task smoke profile, then use `feasible` while debugging. Only
the final run should use `paper` (five retained variants and eight optimizer
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

The generated cache is replayed once through the official benchmark runner, so
the reported outcome is not the optimizer's internal leaderboard score:

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

A cache optimized against another defense is a transfer attack, not one
adaptive to Tripwire. The plugin in this repository puts Tripwire in the
optimizer's evaluation loop, which the adaptive claim requires.

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
  in the plan).

AgentDojo's cross-product reuses user tasks and injection goals, so its pairs
are not independent samples. The primary effect interval is a fixed-seed,
10,000-draw, suite-stratified two-way cluster bootstrap that resamples user
tasks and injection tasks independently; benign-utility effects use a user-task
cluster bootstrap.

The success criterion is direction and uncertainty, not a target chosen after
seeing the data: Tripwire's ASR must be lower than direct, and its benign
utility loss is reported with the same prominence. A negative or mixed result
is still publishable if the adaptive and dynamic evaluation is rigorous.

## What to release with the paper

- the fixed plan and any dated deviations;
- the exact experiment commit and pinned external revisions;
- local manifests and all raw AgentDojo-family episode JSON;
- corpus and policy hashes;
- scripts and generated policy files;
- all error, token, and latency counts;
- the external-summary CSV/JSON/Markdown files;
- the adaptive caches and optimizer outputs;
- a table separating primary, replication, ablation, and exploratory results.

That package makes the work reproducible and makes selective reporting
difficult.
