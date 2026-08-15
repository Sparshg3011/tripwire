# Ablations

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

Canonicalization rule C5 parses a numeric string only on fields the
policy constrains with `type: number`, and it reads that off the policy.
So with no constraints there are no numeric fields, and `issue_refund`'s
`amount` arrives as a string in `ablate-actions` and as a float in
`ablate-constraints`.

That isn't slippage in the ablation — removing the constraint layer
genuinely removes the parsing it drives — but it does mean the
constraints step is measured with C5 on and the step below it with C5
off. Read that delta as "constraints plus the canonicalization they
switch on", which is what you'd actually be turning off in practice.
