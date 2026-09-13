# Paired benign-utility diagnosis

This is a post-hoc diagnosis of the unchanged original AgentDojo experiment,
not a new held-out result or evidence that a proposed fix recovers tasks.

- Complete, error-free pairs: 85.
- Direct completed: 70; strict completed: 31.
- Both completed: 30; both failed: 14.
- Direct completed / strict failed: 40.
- Direct failed / strict completed: 1.
- Net completion change: -39 tasks.
- Regressions with a recorded intervention: 36.
- Regressions without a recorded intervention: 4.

Intervention is an observed event, not proof of the sole cause of failure.
Removing a refusal does not establish that the agent would finish successfully
or remain secure. Non-intervened differences can arise from model variability
or other execution differences; this audit does not determine their cause.

The JSON includes all task identities, paired outcomes, deciding rules/tools,
and hashes of every input trace. It excludes message contents and arguments.
Per-tool counts overlap: a task can attempt more than one blocked tool.

Reproduce from the private raw artifact:

```bash
.venv/bin/python scripts/diagnose_agentdojo_utility.py \
  gym/results/agentdojo-heldout-r3 --out docs/results/utility-diagnosis
```
