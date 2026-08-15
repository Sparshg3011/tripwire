# Which layer actually does the work

`standard` stacks five mechanisms and reports one number. This takes them
away one at a time to find out what each is worth.

Run with the scripted agent, 38 attacks, both human brackets:

```bash
./gym/run_ablation.sh
```

| layer added | attacks stopped | marginal | benign completion |
|---|---|---|---|
| nothing | 0% (0/38) | — | 100% |
| + tool actions | 3% (1/38) | +2.6 pts | 100% |
| **+ argument constraints** | **68% (26/38)** | **+65.8 pts** | 53% |
| + budgets | 71% (27/38) | +2.6 pts | 53% |
| + sequence rules | 71% (27/38) | **+0.0 pts** | 53% |
| + information flow (human approves) | 71% (27/38) | +0.0 pts | 53% |
| + information flow (human denies) | 100% (38/38) | +28.9 pts | 8% |

## Three things worth saying out loud

**Boring allowlists do almost all of it.** Argument constraints alone
account for 66 of the 71 points — recipient allowlists, host allowlists,
a path prefix, a numeric bound. Not the taint tracker, not the sequence
engine. If you only ever write one thing in a policy, write the
constraints.

**The sequence rules earn nothing.** Zero attacks, in either bracket.
Two rules that fire on no scenario in the corpus. That's either a
feature that doesn't pay for itself or a corpus that doesn't test it
properly, and I currently can't tell you which — every attack that
*could* have tripped a sequence rule was already stopped a stage
earlier by a constraint. Keeping it in the policy language is defensible
(order-of-operations attacks are real); claiming it contributes to the
71% is not.

**The information-flow layer's entire value is the human.** With a
maximally cooperative human it contributes exactly nothing: +0.0 points.
With a maximally cautious one it contributes +28.9 and takes benign
completion from 53% to 8%. So the taint-and-gate machinery — the most
architecturally interesting part of tripwire — buys you nothing on its
own. It buys you a *place to put a human*, and everything it's worth
depends on what that human does.

## What this changes about how to read the headline

The published "standard stops 71%" is, more precisely: allowlists stop
68%, budgets add 3%, and the flow layer adds between 0 and 29 more
depending entirely on who is answering the gate.

That's a less impressive sentence and a more useful one.

## Caveats

The ablation uses the scripted agent on purpose. The question is what
the *firewall* contributes, so the agent has to be held still — a model
that improvises around a refusal moves both axes and the deltas stop
being attributable to the layer that was just added. The absolute
utility numbers here are therefore the pessimistic floor described in
[gym.md](gym.md), and only the *differences between rows* are the
result.

One measurement wrinkle: removing the constraint layer also removes the
numeric-string canonicalization it switches on, because rule C5 only
applies to fields a policy constrains as numbers. Read the constraints
row as "constraints plus the canonicalization they enable", which is
what you would actually be turning off. Details in
[../gym/ablations/README.md](../gym/ablations/README.md).
