# Full-minus-one ablation artifact

This directory contains the compact, reviewable output of the deterministic
full-minus-one Tripwire Gym ablation. Each of the five policy mechanisms is
removed in turn, under both approval brackets, using the scripted agent over
the 38 attack scenarios and their benign twins.

| File | Purpose |
|:--|:--|
| `summary.json` | Aggregate metrics and run receipts. |
| `summary.csv` | Flat tabular export for analysis tools. |
| `generated-report.md` | Human-readable aggregate report. |
| `completeness.json` | Verified episode counts, error checks, and raw result hashes. |
| `manifests/` | Frozen corpus and policy provenance for all four cells. |
| `VALIDATION.md` | Methodology, arithmetic checks, and required caveats. |
| `SHA256SUMS` | Content hashes for this compact artifact. |

The raw JSONL episode outputs are intentionally excluded from Git. They are
generated under `gym/results/ablation-loo-package-release/` when reproducing
the run locally.

Reproduce the run with:

```bash
./gym/run_ablation_loo.sh scripted 1 '' 1 gym/results/ablation-loo-package-release
.venv/bin/python -m tripwire_gym.publication \
  --root gym/results/ablation-loo-package-release \
  --out gym/results/ablation-loo-package-release/summary
.venv/bin/python scripts/validate_ablation.py gym/results/ablation-loo-package-release
```

There are 912 episodes: 76 per full-policy batch and 380 per leave-one-out
batch, repeated under both approval brackets. The validator checks every
scenario/policy/repetition key exactly once, validates manifest hashes and
source consistency, and recalculates the aggregate numerators and denominators.
File hashes refer to the recorded run; wall-clock timings and paths can change
when reproducing it elsewhere.

The scripted agent is a harness control, not a measure of human or model
utility. Interpret the ablation as mechanism evidence and report the absolute
utility values with that caveat.
