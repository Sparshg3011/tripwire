# The same firewall, four models

Tripwire's rule engine never sees the model. So the question worth
asking isn't whether it works on one model — it's whether its
contribution survives changing the model underneath it.

38 attacks, 38 benign twins, `undefended` against `standard`, one seed
per cell, `--human approve` — the bracket where the operator says yes to
everything, so nothing below is a human's doing.

| model | size | model alone | with `standard` | firewall adds | benign work |
|---|---|---|---|---|---|
| `nvidia/nemotron-3-ultra-550b-a55b` | 550B | 61% | 87% | **+26** | 95% → 95% |
| `nvidia/nemotron-3.5-lightning-30b-a3b` | 30B | 53% | 79% | **+26** | 97% → 95% |
| `meta/muse-glimmer-30b` | 30B | 82% | 97% | **+16** | 100% → 95% |
| `z-ai/glm-5.2`&nbsp;† | — | 83% | 97% | **+14** | 97% → 100% |

† `glm-5.2` is scored on 36 of the 38 attacks; see [the caveat](#the-glm-row-is-not-like-the-others).

Every row is scored the same way: a scenario counts only if **both** its
`undefended` and its `standard` cell completed. For the top three that
is all 38, because they produced no errors at all. Pairing matters only
for the GLM row, and it is applied to every row so the column means one
thing.

## Read the "model alone" column first

It ranges from 53% to 83%. That spread has nothing to do with
tripwire — it is how much each model refuses on its own, and it is the
largest single term in the table. A benchmark that quotes a defended
number without this column beside it is reporting the model's work as
the tool's.

Once you account for it the "firewall adds" column stops looking
inconsistent. A model that already refuses 83% has only 6 attacks left
to protect against; one that refuses 53% has 18. The same defence
must score a smaller lift on the first. So the comparable measure is
what happens to the attacks each model *missed*:

| model | attacks it missed | of those, tripwire caught | left standing |
|---|---|---|---|
| `nemotron-3-ultra-550b-a55b` | 15 of 38 | 10 (67%) | 5 |
| `nemotron-3.5-lightning-30b-a3b` | 18 of 38 | 10 (56%) | 8 |
| `muse-glimmer-30b` | 7 of 38 | 6 (86%) | 1 |
| `glm-5.2` | 6 of 36 | 5 (83%) | 1 |

Between half and six-sevenths of what each model missed gets caught,
whether that was 6 attacks or 18. The rate moves around — 56% to 86% —
but those are fractions of single-digit and low-double-digit counts at
one seed each, so most of the spread is small denominators and noise.
What the column does establish is a floor: **on every model tested, the
firewall removed at least half of the residual risk the model left
behind.**

The two 30B-class models from different labs, muse and glm, land within
two points of each other on both axes despite nothing in the setup
coordinating that. The two nemotrons gain the same +26 from baselines
eight points apart. Neither is proof, but both are the shape you want
from a defence that never sees the model.

## The practical read

The largest gains land on the models that refuse least. That is the
argument for this kind of defence in production: a weaker model isn't
merely riskier, it is riskier by an amount a rule engine can take back,
and the engine costs the same to run in front of either. Utility barely
moves in any row — whatever the model, `standard` is close to free on
benign work.

## The GLM row is not like the others

It is here with an asterisk, and the asterisk is worth reading.

`z-ai/glm-5.2` reasons at length on every turn, and a run is roughly ten
turns. At six runs in flight, **24 of its 304 cells (7.9%) hit the
per-run timeout** and were dropped — 8 of 152 in the `approve` bracket
scored above, 16 of 152 in `deny`. Dropping runs is exactly the kind of
thing that manufactures a good number, so:

- The drops are spread over 20 distinct scenarios, with no scenario
  losing every cell, and they fall on both conditions about evenly
  (11 `undefended`, 13 `standard`).
- They skew toward the longest scenarios — `destruct-cleanup` and
  `unauth-refund-cap` lost three cells each — so the surviving set is
  mildly biased toward simpler runs. Read the absolute rates with that
  in mind.
- The reported figures are paired: only the 36 attacks that completed
  under *both* conditions are counted, so the +14 lift is a
  within-scenario difference rather than a comparison of two different
  subsets. Standard fixed 5 scenarios and broke 0 (exact McNemar
  p = 0.06).

Re-running it to remove the asterisk is not practical at the timeout
that avoids the drops: about sixteen minutes per run, nineteen hours for
one seed of this matrix. That is a fact about long-thinking models on
multi-turn benchmarks rather than a fault in the model, and it is worth
knowing before you queue one up overnight.

## Caveats

One seed per cell. The `shadow` control in the [full matrix](../RESULTS.md)
put the noise floor near five points, so treat individual lifts as
approximate and the ordering of the three 30B-class rows as unresolved.

Regenerate the top three with `./gym/run_models.sh`.

The GLM row is not regenerated by that script. Its matrix crashed while
writing the second bracket's summary, so the per-run records are gone
and the row is reconstructed from what the harness printed as it went:
[`gym/results/models/glm-5.2/run.log`](../gym/results/models/glm-5.2/run.log).
The harness's own summary line for the surviving bracket — `undefended`
16% attack success, `standard` 3% — is in that file and agrees with the
table above, which is the only reason the row is here at all rather than
discarded.
