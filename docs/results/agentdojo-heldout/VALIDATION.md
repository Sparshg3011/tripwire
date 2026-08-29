# Held-out result validation

## Overall assessment: Share with noted caveats

The primary direct-versus-Tripwire result is internally consistent,
reproducible from the completed run directory, and suitable to share with the
limitations in the main report. It is not sufficient for a superiority or
production-readiness claim.

Validated: 2026-08-27 (America/Los_Angeles)

## Methodology review

- The 12 development users are excluded from the 85-user held-out population.
- Every remaining user is crossed with every injection task in its suite.
- Direct and strict Tripwire use the same task pairs and official checkers.
- Suite condition order was counterbalanced and frozen before execution.
- The primary ASR interval uses the predeclared two-way user-by-injection
  cluster bootstrap; benign utility clusters by user.
- Transport retries do not change cases, policies, prompts, scoring, or
  analysis and are recorded in a dedicated resume receipt.

## Calculation spot-checks

| Check | Result |
|:--|:--|
| Suite attack totals | 117 + 90 + 119 + 518 = 844 |
| Suite benign totals | 13 + 18 + 17 + 37 = 85 |
| Direct attack successes | 71 + 77 + 71 + 40 = 259 |
| Tripwire attack successes | 0 + 29 + 5 + 0 = 34 |
| ASR paired change | (34 - 259) / 844 = -26.6588 points |
| Direct benign successes | 9 + 18 + 12 + 31 = 70 |
| Tripwire benign successes | 5 + 4 + 8 + 14 = 31 |
| Benign-utility change | (31 - 70) / 85 = -45.8824 points |
| Discordant attack pairs | 229 direct-only; 4 Tripwire-only |
| Trace errors | 0 in all eight cells and all 1,928 raw traces |
| Aggregate regeneration | JSON, CSV, and Markdown outputs byte-identical |

## Provenance checks

- Selection SHA-256:
  `aa9cabea1a787a4a12c5bef0c816057cbe77cb68ce12981bc0e945d533798e94`
- Scientific contract SHA-256:
  `3b43ae804d4ab2f31b2af114bbfbacbf35227599f6e7e21166ef99ed17aef16d`
- Planned source tree is preserved on public `main` at `6397b3e`.
- Transport-resume source tree is preserved on public `main` at `4c1784e`.
- All four policy hashes match the frozen plan.
- Compact published artifacts contain no API-key or authorization markers.

## Required caveats

- Results use one model, one official attack, and one repetition per case.
- Crossed pairs reuse users and injection goals; Wilson intervals and McNemar
  p-values are descriptive, not independent-sample inference.
- Strict unattended Tripwire denies every approval request and is not human
  performance.
- The 45.9-point benign-utility loss must accompany the 26.7-point ASR
  reduction wherever the result is summarized.
- ProtectAI has only development-screen evidence until its held-out run
  completes.

## Files checked

- `plan.json`: frozen selection, execution contract, policy hashes, and source
- `transport-resume.json`: bounded transport-only deviation
- `completeness.json`: expected and observed cases for every cell
- `summary.json`: full aggregate metrics and paired effects
- `summary.csv`: tabular export
- `generated-report.md`: deterministic report generated from the run directory
