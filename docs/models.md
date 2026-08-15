# The same firewall, three models

Tripwire's rule engine never sees the model. So the question worth
asking isn't whether it works on one model — it's whether its
contribution survives changing the model underneath it.

38 attacks, 38 benign twins, `undefended` against `standard`, one seed
per cell, `--human approve` — the bracket where the operator says yes to
everything, so nothing below is a human's doing. 1368 runs, 0 errors.

| model | size | model alone | with `standard` | firewall adds | benign work |
|---|---|---|---|---|---|
| `nvidia/nemotron-3-ultra-550b-a55b` | 550B | 61% | 87% | **+26** | 95% → 95% |
| `nvidia/nemotron-3.5-lightning-30b-a3b` | 30B | 53% | 79% | **+26** | 97% → 95% |
| `meta/muse-glimmer-30b` | 30B | 82% | 97% | **+16** | 100% → 95% |

## Read the "model alone" column first

It ranges from 53% to 82%. That spread has nothing to do with
tripwire — it is how much each model refuses on its own, and it is the
largest single term in the table. A benchmark that quotes a defended
number without this column beside it is reporting the model's work as
the tool's.

Once you account for it the "firewall adds" column stops looking
inconsistent. A model that already refuses 82% has only 7 attacks left
to protect against; one that refuses 53% has 18. The same defence
must score a smaller lift on the first. So the comparable measure is
what happens to the attacks each model *missed*:

| model | attacks it missed | of those, tripwire caught | left standing |
|---|---|---|---|
| `nemotron-3-ultra-550b-a55b` | 15 of 38 | 10 (67%) | 5 |
| `nemotron-3.5-lightning-30b-a3b` | 18 of 38 | 10 (56%) | 8 |
| `muse-glimmer-30b` | 7 of 38 | 6 (86%) | 1 |

Between half and six-sevenths of what each model missed gets caught,
whether that was 7 attacks or 18. The rate moves around a lot — 56% to
86% — but those are fractions of 7, 15 and 18 attacks at one seed each,
so the spread is mostly small denominators and the noise floor. What the
column does establish is a floor: **on every model tested, the firewall
removed at least half of the residual risk the model left behind.**

## The practical read

The two nemotrons gain the same +26 from very different starting points
(61% and 53%), which is the behaviour you want from a defence that never
sees the model. Muse gains less in absolute terms because it had less
left to lose.

The consequence for deployment: a weaker model isn't merely riskier, it
is riskier by an amount a rule engine can take back, and the engine
costs the same to run in front of either. Utility barely moves in any
row — whatever the model, `standard` is close to free on benign work.

## Caveats

One seed per cell. The `shadow` control in the [full matrix](../RESULTS.md)
put the noise floor near five points, so treat individual lifts as
approximate and the ordering of the two 30B rows as unresolved.

`z-ai/glm-5.2` is absent on purpose. It ran without errors but reasons
at length every turn, and a run is roughly ten turns — about sixteen
minutes each, nineteen hours for one seed of this matrix. That is a fact
about long-thinking models on multi-turn benchmarks, not a fault in the
model, and it is worth knowing before you queue one up overnight.

Regenerate with `./gym/run_models.sh`.
