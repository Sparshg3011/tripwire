# Deviation from the v0.2 preregistration

Written on 2026-10-03, after the event below and before any outcome of
the v0.2 study had been looked at: only counts of finished traces were
read to write it. [The preregistration](preregistration-v0.2.md) itself
is unchanged.

## What happened

The provider retired the primary model. From 2026-10-03T09:00Z every
request for `nvidia/nemotron-3-super-120b-a12b` returns HTTP 410: "has
reached its end of life ... and is no longer available." Cells had also
seen intermittent 403 "Authorization failed" responses in the days
before, and were resumed each time. The repository's earlier notes
mentioned a retirement notice for this model; no date could be found
for it, and choosing it as primary anyway was a mistake in the plan.

When it went, the primary model had finished:

| arm | benign tasks | attacked pairs |
|---|---|---|
| AgentDyn `direct` | 60 / 60 | 120 / 560 |
| AgentDyn `tripwire-deny/taint` | 60 / 60 | 105 / 560 |
| AgentDyn `tripwire-deny/primary` | 60 / 60 | 105 / 560 |
| AgentDojo `tripwire-deny/primary` | 85 / 85 | 273 / 844 |

Each cell also holds one attacked trace with no score, a task cut off
when the cell stopped; it is not counted. (The first version of this
note counted trace files, which also include each suite's runs of the
injection goals alone; the table above counts scored pairs.)

The attacked pairs ran in suite order, user task by user task, so the
finished ones are the earlier user tasks of each suite, not a random
sample of all 560.

## What changes

1. **Hypothesis 1 (utility) is decided on the primary model as
   planned.** Its benign set is complete in every arm.
2. **Hypotheses 2 and 3 (security) cannot be decided on the primary
   model.** They are reported on the attacked pairs finished in every
   arm being compared, labelled incomplete, with no decision drawn from
   them alone.
3. **The second model, `nvidia/nemotron-3.5-lightning-30b-a3b`, chosen
   before the study, runs to completion, and all three hypotheses are
   tested on it with the preregistered rules.** It becomes the only
   model with a complete result, and is reported as such, not as a
   replacement chosen after the fact.
4. The primary model's later cells (the detector and `strict` on
   AgentDyn, AgentDojo `taint`) are cancelled. The AgentDojo regression
   compares v0.1 and v0.2 on its 85 benign tasks, which both have in
   full, and on the attacked pairs both have.
5. The second model's AgentDojo cells run after its AgentDyn cells
   finish, as the preregistration ordered. If they are not complete
   when the results are written up, they are reported as not run.

Nothing else changes: code, policies, conditions, tests and the
analysis are those at the tag `prereg-v0.2`.
