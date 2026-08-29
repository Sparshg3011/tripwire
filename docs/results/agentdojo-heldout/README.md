# AgentDojo held-out artifact

This directory contains the compact, reviewable artifact for Tripwire's
completed AgentDojo `v1.2.2` primary held-out experiment. The narrative result
and required caveats are in
[`../../agentdojo-heldout-results.md`](../../agentdojo-heldout-results.md).

| File | Purpose |
|:--|:--|
| `plan.json` | Frozen task selection and scientific execution contract. |
| `transport-resume.json` | Provenance for the transport-only retry expansion. |
| `completeness.json` | Expected/observed cases and trace-error checks. |
| `summary.json` | Complete machine-readable metrics and paired effects. |
| `summary.csv` | Flat tabular metrics for analysis tools. |
| `generated-report.md` | Deterministic report regenerated from the raw run directory. |
| `VALIDATION.md` | Independent post-run QA and required caveats. |
| `SHA256SUMS` | Content hashes for this compact artifact. |

The 50 MB raw run directory contains 1,928 episode traces and is intentionally
excluded from Git history. The runner's output directory is ignored by
default to prevent API transcripts and large checkpoint sets from being
committed accidentally. The compact artifact contains no API keys or
authorization headers.

Regenerate the aggregate files from a complete raw run with:

```bash
.venv/bin/python -m tripwire_benchmarks.report \
  --root gym/results/agentdojo-heldout \
  --out gym/results/agentdojo-heldout/summary
```
