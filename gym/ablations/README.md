# Ablations

For publication, use `../run_ablation_loo.sh`. It generates the full policy
minus exactly one mechanism and compares each generated policy to the full
stack. The cumulative chain below remains a secondary analysis because its
attribution depends on the order in which mechanisms are added.

`standard` stacks five mechanisms, and its headline number is their sum.
These files take them away one at a time so you can see what each one is
actually worth.

| condition | actions | constraints | limits | sequences | flows |
|---|---|---|---|---|---|
| `ablate-none` | | | | | |
| `ablate-actions` | ✓ | | | | |
| `ablate-constraints` | ✓ | ✓ | | | |
| `ablate-limits` | ✓ | ✓ | ✓ | | |
| `ablate-sequences` | ✓ | ✓ | ✓ | ✓ | |
| `standard` (in `../policies/`) | ✓ | ✓ | ✓ | ✓ | ✓ |

Each file is `standard` with the later layers deleted and nothing else
touched, so the difference between two consecutive rows is one mechanism.
`ablate-none` should stop roughly nothing — it's there to prove the dial
is connected.

Run them with:

```bash
./gym/run_ablation.sh
```

Use the scripted agent. The question is what the *firewall* contributes,
so the agent has to be held still: a model that improvises around a
refusal moves both axes and the deltas stop being attributable to the
layer you just added.

## One wrinkle worth knowing

Canonicalization reads the policy too. It rewrites only the arguments a
tool's rule reads, and rule C5 parses a numeric string only on fields
constrained with `type: number`. So in `ablate-actions`, where no rule
reads any argument, nothing is canonicalized at all: a fullwidth
recipient reaches the tool as it was sent, and `issue_refund`'s `amount`
arrives as a string. In `ablate-constraints` the recipient is folded
and `amount` arrives as a float.

That isn't slippage in the ablation — removing the constraint layer
genuinely removes the canonicalization it drives — but it does mean the
constraints step is measured with canonicalization on and the step below
it with it off. Read that delta as "constraints plus the canonicalization
they switch on", which is what you'd actually be turning off in practice.
