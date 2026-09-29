# Research notes

The lab notebook: plans, pilots and diagnoses written while Tripwire was being
evaluated, kept so the path to each result can be checked. Each note records
what was known when it was written. [EVIDENCE.md](../../EVIDENCE.md) has the
current numbers, and where a note disagrees with it, EVIDENCE.md is right.

Roughly in the order they were written:

| Note | What it is |
|:--|:--|
| [writeup.md](writeup.md) | The original write-up of the gym, extended after the AgentDojo run. It has the cumulative ablation. |
| [publication-protocol.md](publication-protocol.md) | The plan for the external evaluation: evidence ladder, prior work, stages and statistics. |
| [agentdojo-pilot-results.md](agentdojo-pilot-results.md) | The 24-pair AgentDojo pilot that fixed the held-out protocol. |
| [agentdojo-screening-results.md](agentdojo-screening-results.md) | Which secondary defenses went on to the held-out run, and why ProtectAI did. |
| [ablation.md](ablation.md) | The full-minus-one ablation, with the scenarios behind each count. |
| [utility-recovery-research.md](utility-recovery-research.md) | The plan for an LLM action reviewer to win back v0.1's lost utility, and its first smoke run. |
| [reviewer-failure-diagnosis.md](reviewer-failure-diagnosis.md) | Why the reviewer's development run failed where it did. |
| [release-evidence-review.md](release-evidence-review.md) | What the reviewer work did and didn't establish, and what a release claim would need. |
| [releasing.md](releasing.md) | How a release is built, checked and published. |

The reviewer only ever ran in the research adapter, never in the proxy, and
v0.2 went the argument-anchoring route instead.
