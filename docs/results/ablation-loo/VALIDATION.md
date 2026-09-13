# Full-minus-one ablation validation

## Overall assessment: complete and shareable as mechanism evidence

All four planned cells completed on the same clean source tree with zero
runner errors: approval/full, approval/leave-one-out, denial/full, and
denial/leave-one-out. Each full-policy batch contains 76 runs. Each
leave-one-out batch contains five policies times 76 runs, or 380 runs.
The total is 76 + 380 + 76 + 380 = **912 runs**, comprising 12 policy/bracket
cells of 38 attacks and 38 benign twins each.

## Checks performed

- `scripts/validate_ablation.py` verified all 912 expected episode keys exactly
  once, with no missing, duplicate, or errored outcomes, and no model calls.
- The source corpus, policy files, and raw result hashes match all four
  manifests. Regenerated aggregate JSON matches the published metrics.
- Counts and rates were independently summed from raw outcomes: for example,
  removing constraints changes approve-all attack successes from 11/38 to
  28/38 (17/38 = 44.7 points) and benign completion from 20/38 to 31/38
  (11/38 = 28.9 points).
- The full-minus-one runner preserves all five generated leave-one-out
  policies across both approval brackets.
- Every aggregate row reports `errors = 0`.
- All four manifests record commit
  `effb26e594eea8befd89d4f00f32b88023f9f835`, a clean tree, and the same
  corpus hash `9860ea2c4584b9725eefd07623257efc1bad4b10e9b992bd64be3a8f1f91d686`.
- The compact files are hashed in `SHA256SUMS` and contain no API keys or
  authorization headers.

The benchmark uses the deterministic scripted agent by design. Its absolute
utility is not a deployment estimate; only controlled differences between
mechanism rows support the ablation interpretation.
