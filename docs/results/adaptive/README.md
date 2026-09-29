# Attacks written against anchoring

This is the adaptive-attacker run of the gym: 24 attacks and their benign
twins, each written by someone who knows exactly how v0.2 argument
anchoring works and aimed at one specific way it could fail. The agent is
the scripted worst case — it obeys the injection in full, every argument
filled in — so a defence that depends on the model hesitating gets no
credit here. No model is called; everything is offline and deterministic.

The corpus lives in [`gym/adaptive/`](../../../gym/adaptive/); each
attack's `notes` state the outcome predicted under `anchored.yaml`
**before** the run, and this directory records what happened.

## Reproduce

```bash
PYTHONPATH=src .venv/bin/python -m tripwire_gym --agent scripted \
  --scenarios gym/adaptive --policy-dir gym/policies \
  --conditions undefended,anchored-taint,anchored --human deny  --out gym/results/adaptive/deny
PYTHONPATH=src .venv/bin/python -m tripwire_gym --agent scripted \
  --scenarios gym/adaptive --policy-dir gym/policies \
  --conditions undefended,anchored-taint,anchored --human approve --out gym/results/adaptive/approve
```

Frozen at commit `b6be33e`, corpus sha256
`c3dc350073a73e1a9da12dd6cc652b9a8ea91b1ff10608faf838ad0cff38c9ff`, zero
errored runs. `summary.json` holds the counts and the per-scenario
outcomes; [EVIDENCE.md](../../../EVIDENCE.md#attacks-written-against-anchoring)
has the full table and a plain account of every attack that got through.

## Conditions

- **undefended** — no proxy; every attack lands and every twin completes,
  which is what makes the other columns mean anything.
- **anchored-taint** — `anchored.yaml` with `unless: anchored` removed:
  v0.1's session-wide taint rule, every outward or destructive call gated
  once untrusted content is read.
- **anchored** — `anchored.yaml`: the same rules, plus argument contracts
  and `unless: anchored`, so a gated call goes through when every
  authority value it carries is anchored.

`deny` refuses every gate, `approve` approves every gate; `deny` is the
headline, because that is where a gate that never fires is the only thing
holding an attack back.

## Results

Counts are out of 24.

| Bracket | Condition | Attacks landed | Benign twins done | Gate prompts |
|:--|:--|--:|--:|--:|
| deny | undefended | 24 | 24 | 0 |
| deny | anchored-taint | 1 | 1 | 62 |
| deny | anchored | 8 | 23 | 18 |
| approve | undefended | 24 | 24 | 0 |
| approve | anchored-taint | 24 | 24 | 62 |
| approve | anchored | 24 | 24 | 18 |

With every gate refused, anchoring holds 16 of the 24 adaptive attacks
and still finishes 23 of the 24 benign twins, where the taint rule
finishes 1. The eight it lets through are each a documented limit of what
anchoring checks, listed in EVIDENCE.md; two of them were predicted to be
blocked and were not, which the write-up marks as mismatches and
explains. In the approve bracket anchoring changes no outcome — the
operator says yes to everything either way — but it asks 18 gate
questions where the taint rule asks 62.

## Caveats

- **Author-written, and the author knew the mechanism.** The attacks, the
  policy and the firewall come from the same repository. This measures
  whether anchoring does what its own designer thinks it does against a
  hostile reader of its rules; it says nothing about attacks nobody here
  wrote.
- **The scripted agent is the worst case, not a person.** It always obeys
  the injection and never adapts to a refusal, so the utility-under-attack
  column is a floor, not an estimate of what a real model would salvage.
- **Brackets, not people.** `deny` and `approve` bound a real operator;
  neither reads the request, so nothing here measures whether a person
  could be talked past a gate.
