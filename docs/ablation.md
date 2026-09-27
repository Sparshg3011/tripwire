# Full-minus-one policy ablation

Status: complete scripted experiment, 912 runs, zero runner errors.

This experiment asks how the full policy changes when exactly one of its five
mechanisms is removed. It covers 38 attacks and their 38 benign twins under
the full policy and five reduced policies, with every approval either granted
or denied. That is 76 scenarios × 6 policies × 2 approval brackets = 912 runs.

The scripted agent executes fixed attempts. These results measure the policy's
mechanisms on the authored corpus; they do not estimate a model's adaptability
or real human approval behavior. The separate
[AgentDojo held-out experiment](agentdojo-heldout-results.md) evaluates a live
model on external tasks.

## Results

Attack success is lower-is-better; benign completion is higher-is-better.
Every denominator below is 38. Each cell ran once with no model API calls.

| Policy | Attack successes: approve all | Attack successes: deny all | Benign completions: approve all | Benign completions: deny all |
|:--|--:|--:|--:|--:|
| Full standard policy | 11 (28.9%) | 0 (0.0%) | 20 (52.6%) | 3 (7.9%) |
| Without tool actions | 12 (31.6%) | 1 (2.6%) | 20 (52.6%) | 3 (7.9%) |
| Without argument constraints | 28 (73.7%) | 1 (2.6%) | 31 (81.6%) | 6 (15.8%) |
| Without budgets | 12 (31.6%) | 0 (0.0%) | 20 (52.6%) | 3 (7.9%) |
| Without sequence rules | 11 (28.9%) | 0 (0.0%) | 20 (52.6%) | 3 (7.9%) |
| Without information-flow rules | 11 (28.9%) | 11 (28.9%) | 20 (52.6%) | 20 (52.6%) |

Removing argument constraints has the largest measured effect when every
approval is granted: 17 additional attacks succeed, a 44.7-point increase,
while 11 additional benign tasks complete, a 28.9-point increase. Tool actions
and budgets each prevent one additional attack in that bracket. Removing
sequence rules produces no net change on this corpus, which does not establish
that sequence rules are unnecessary for other attacks.

When every approval is denied, removing information-flow rules raises attack
success from 0 to 11 and benign completion from 3 to 20. The extra protection
therefore depends on denied approvals and has a substantial utility cost.
Neither approval bracket is an estimate of how a person would respond.

These differences are conditional on the remaining mechanisms. They are not
additive contributions and should not be summed into an overall score. In
particular, removing constraints also removes the canonicalization they
drive. Only the arguments a rule reads are canonicalized, so without
constraints every argument but a budget's field is forwarded as it
arrived, and no numeric string is parsed into a number for that budget.

## Reproduce and audit

From a source checkout with the development dependencies installed:

```bash
./gym/run_ablation_loo.sh scripted 1 '' 1 gym/results/ablation-loo
.venv/bin/python -m tripwire_gym.publication \
  --root gym/results/ablation-loo --out gym/results/ablation-loo/summary
.venv/bin/python scripts/validate_ablation.py gym/results/ablation-loo
```

The [compact artifact](results/ablation-loo/README.md) includes metrics,
manifests, a completeness receipt, and hashes. Its four manifests record the
same clean source commit and corpus. The raw episode files remain local.
Descriptive Wilson intervals are available in the generated report; this
fixed, authored corpus does not support a claim of population-wide statistical
significance.

The earlier cumulative ablation remains reproducible with
`gym/run_ablation.sh`. Its incremental effects depend on the order in which
mechanisms are added and differ from the full-minus-one effects above.
