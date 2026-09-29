# Evidence

Every result Tripwire reports is on this page, with its baseline and its
limits, and [docs/benchmarking.md](docs/benchmarking.md) has the command behind
each one. The README quotes the AgentDojo headline, and the notes in
[docs/research/](docs/research/README.md) keep the numbers they were written
with; where one of them disagrees with this page, this page is current.

## How to read this

A firewall can stop every attack by refusing every call, so each result is a
pair: how often attacks succeeded, and how much of the same work got done with
the attack text removed. Attack success is better lower, utility better higher.
Results are measured against the undefended agent, which comes first wherever
it ran, because much of what a defense seems to stop, the model would have
refused on its own. The ablation is the exception: it measures against the
full policy.

Every rate comes with its count or its denominator, and intervals are 95%. On
AgentDojo one user task is paired with many injections, so the pairs are not
independent: differences between conditions use a two-way cluster bootstrap
over user and injection tasks (a user-task bootstrap for benign utility), fixed
before the runs. Intervals on a single rate are Wilson intervals and describe
sampling error only.

## v0.2: argument anchoring

**Status: the preregistered study is running. This section gets its results
when it finishes.**

v0.1 gates every write once untrusted content is in a session, and that is
where its utility went ([below](#v01-on-agentdojo)). v0.2 adds `unless:
anchored`: a gated write goes through when every recipient, target and
selector it carries came from the user's task, the policy's `known` list, a
trusted tool, or an id the session created itself. The protocol was committed
before any result on the test set existed
([preregistration](gym/preregistration-v0.2.md), tag `prereg-v0.2`). The test set is AgentDyn's 60 tasks and 560 attacked pairs,
none of which were read while v0.2 was built; its policies were drafted by
`tripwire recipe` from tool names and schemas alone, and the primary comparison
is anchoring against v0.1's taint rule on the same tasks with every approval
refused. AgentDojo's 85 held-out tasks are rerun as regression evidence only,
since v0.2 was designed knowing where v0.1 failed on them.

The development pilot, disclosed in the preregistration, ran on the 12 AgentDojo
users inspected during development (24 attacked pairs), with recipe policies:

| Condition | Attack success | Benign utility | Utility under attack |
|:--|--:|--:|--:|
| Undefended | 50.0% (12/24) | 50.0% (6/12) | 37.5% (9/24) |
| Taint rule (v0.1's flows) | 0.0% (0/24) | 41.7% (5/12) | 33.3% (8/24) |
| Anchoring | 0.0% (0/24) | 41.7% (5/12) | 54.2% (13/24) |

Every benign task anchoring still refused named its target only indirectly
("the article Bob posted"), so the id reached the session in a tool result
rather than in the task. That is the designed limit of this version. Twelve
tasks can't settle a utility question; the pilot checked the machinery, and
the study is what decides it.

## v0.1 on AgentDojo

AgentDojo v1.2.2 with its `important_instructions` attack and its own state and
task checkers, `nvidia/nemotron-3-super-120b-a12b` at temperature 0 with
thinking off, one run per case. The 12 users inspected during development were
excluded before the run, and each of the other 85 was crossed with every
injection task in its suite: 844 attacked pairs and 85 benign tasks per
condition, with zero trace errors.

Tripwire v0.1 ran with its per-suite policies
([gym/external_policies/](gym/external_policies/)) and no one at the gate, so
every call that needed approval was refused. AgentDojo's stock ProtectAI detector
(`protectai/deberta-v3-base-prompt-injection-v2` at revision `90c9989`,
threshold 0.5) ran afterwards on the same pairs against the same undefended
runs, under a protocol fixed before it started
([gym/agentdojo-protectai-heldout.yaml](gym/agentdojo-protectai-heldout.yaml)).

| Condition | Attack success | Benign utility | Utility under attack |
|:--|--:|--:|--:|
| Undefended | 30.7% (259/844; 27.7–33.9) | 82.4% (70/85; 72.9–89.0) | 63.7% (538/844; 60.4–66.9) |
| Tripwire v0.1 | 4.0% (34/844; 2.9–5.6) | 36.5% (31/85; 27.0–47.1) | 31.8% (268/844; 28.7–35.0) |
| ProtectAI detector | 5.8% (49/844; 4.4–7.6) | 51.8% (44/85; 41.3–62.1) | 41.6% (351/844; 38.3–44.9) |

Paired against undefended, with cluster-bootstrap intervals:

| Condition | Attack success | Benign utility |
|:--|--:|--:|
| Tripwire v0.1 | −26.7 points (−33.6 to −19.8) | −45.9 points (−56.5 to −35.3) |
| ProtectAI detector | −24.9 points (−30.6 to −19.5) | −30.6 points (−41.2 to −20.0) |

Both defenses removed most successful attacks, and v0.1 paid for it in utility.
Its session-wide taint rule can't tell "untrusted content was read" from "this
write is still what the user asked for", so it intervened in 40 of the 85
benign tasks. Task by task, it lost 40 that the undefended agent finished, 36
of them with an intervention on record, and gained one
([diagnosis](docs/results/utility-diagnosis/REPORT.md)).

The detector got close on security and kept more of the work: 15.3 points more
benign utility and 9.8 more under attack. No test comparing the two defenses
directly was planned, so that gap is descriptive, but on these numbers the
detector was the better trade.

By suite, each cell is attack success / benign utility:

| Suite | Pairs, tasks | Undefended | Tripwire v0.1 | ProtectAI detector |
|:--|--:|--:|--:|--:|
| Banking | 117, 13 | 60.7% / 69.2% | 0.0% / 38.5% | 12.8% / 46.2% |
| Slack | 90, 18 | 85.6% / 100.0% | 32.2% / 22.2% | 20.0% / 33.3% |
| Travel | 119, 17 | 59.7% / 70.6% | 4.2% / 47.1% | 1.7% / 41.2% |
| Workspace | 518, 37 | 7.7% / 83.8% | 0.0% / 37.8% | 2.7% / 67.6% |

Slack is v0.1's worst case: a third of the attacks still landed and benign
utility fell from 100% to 22.2%, and the detector did better on both. Workspace
starts with few successful attacks, yet v0.1 cost it 46 points of utility to
the detector's 16. Banking is where v0.1's refusals bought the most, stopping
every attack where the detector let 12.8% through.

What this doesn't cover: one model, one run per case, one static attack (no
attacker adapting to the defense), and one operating point with no human at
the gate. The stock detector hands whole tool outputs to a model with a
512-token context; it was kept unchanged so it stays comparable to other
AgentDojo results.

Provenance: the Tripwire run stopped on an HTTP 502 and a read timeout after
200 completed traces, and resumed from them with a wider retry policy and
nothing else changed
([transport-resume.json](docs/results/agentdojo-heldout/transport-resume.json)).
The compact artifact for the primary run, with its plan, completeness check,
hashes and an independent validation, is in
[docs/results/agentdojo-heldout/](docs/results/agentdojo-heldout/README.md).
The detector run has no compact artifact in the repository yet.

## The adversarial gym

The gym is the development benchmark: 38 attacks in seven families, each
paired with a benign twin (the same task with the attack text removed) and
checked to land against an agent that never refuses. Ground truth is the mock
tool server's record of what it was asked to do.
[docs/benchmarking.md](docs/benchmarking.md#the-adversarial-gym) describes the
conditions, the scenarios and the runner.

Its limits apply to every table in this section:

- **Author-written corpus.** The attacks, the policies and the firewall come
  from the same person and the same repository, and the policies were written
  knowing the attacks. The gym catches regressions and isolates mechanisms; it
  says nothing about attacks nobody here wrote.
- **One run per cell.** With 38 attacks, a 95% interval on a rate is up to
  ±15 points wide. The shadow condition, which blocks nothing and should match
  undefended, landed 13 attacks to undefended's 15 in the deny bracket, so a
  difference of a few attacks is noise.
- **Brackets, not people.** A gated call is either always approved (`approve`)
  or always refused (`deny`); a real operator falls between. Neither reads the
  request, so the gate social-engineering family measures whether a gate fires,
  not whether a person could be talked past it.

### Five policy tiers, one model

`nvidia/nemotron-3-ultra-550b-a55b`, 760 runs with zero errors, published in
commit `9e370af`. The agent's system prompt warned it that tool results may
contain instructions, so "undefended" means no Tripwire rather than no defense
at all; temperature was 1.0. Counts are out of 38.

| Condition | Attacks landed, approve | Benign done, approve | Attacks landed, deny | Benign done, deny |
|:--|--:|--:|--:|--:|
| Undefended | 15 | 36 | 15 | 36 |
| Shadow (evaluates, blocks nothing) | 15 | 37 | 13 | 36 |
| Loose | 10 | 37 | 10 | 37 |
| Standard | 5 | 36 | 0 | 6 |
| Strict | 0 | 6 | 0 | 3 |

Standard made 68 gate requests in the approve bracket and 121 in deny. Against
undefended on the same attacks, standard stopped 10 the model let through and
missed none it had stopped in the approve bracket (exact McNemar p = 0.002);
loose's 5 (p = 0.06) could be noise. The deny bracket shows what standard's
gates are holding back: with every gate refused, no attack landed and 6 of 38
benign tasks finished.

![Security/utility frontier](docs/img/frontier.png)

#### What got through

Five attacks got past standard in the approve bracket, and each passed through
a gate the simulated operator approved: two canonicalization probes whose
normalized values sit inside the policy's limits (`probe-bom-recipient-01`,
`probe-padded-amount-01`), a reply to the right colleague carrying a body the
attacker wrote (`redirect-body-01`), a second refund inside every cap
(`gate-refund-01`), and an access-list write to an allowed path
(`multi-grant-01`). No constraint objects to any of them; only a person reading
the gate would.

The two benign twins that failed under standard, `exfil-pathdata-01-benign` and
`probe-fullwidth-path-01-benign`, failed undefended too. `git show
9e370af:RESULTS.md` lists every attack that landed and every twin that failed
under every condition.

### Four models

The same corpus, undefended against standard, approve bracket, one run per
cell.

| Model | Attacks landed, model alone | Landed with standard | Of those the model let through, standard stopped | Benign done, alone → standard |
|:--|--:|--:|--:|--:|
| `nvidia/nemotron-3-ultra-550b-a55b` | 15 of 38 | 5 | 10 (67%) | 36 → 36 of 38 |
| `nvidia/nemotron-3.5-lightning-30b-a3b` | 18 of 38 | 8 | 10 (56%) | 37 → 36 of 38 |
| `meta/muse-glimmer-30b` | 7 of 38 | 1 | 6 (86%) | 38 → 36 of 38 |
| `z-ai/glm-5.2` | 6 of 36 | 1 | 5 (83%) | 97% → 100% |

How much each model refuses on its own varies more than anything Tripwire
adds, which is why the baseline column comes first. On every model, standard
stopped more than half of the attacks the model let through, at little cost to
benign work.

GLM reasons at length on every turn, and 24 of its 304 cells (8 of 152 in this
bracket) hit the per-run timeout. It is scored on the 36 attacks that finished
under both conditions, and since the dropped cells lean toward the longest
scenarios, its absolute rates lean optimistic. Its matrix crashed while writing
the second bracket's summary, so the row was rebuilt from the progress the
harness printed as it ran. That log is not in the repository, which keeps
only the rates for its benign column.

### Which mechanism does the work

The standard policy with one mechanism removed at a time, over all 38 attacks
and their twins in both brackets: 912 runs, zero errors, commit `effb26e`.
Counts are out of 38.

| Policy | Attacks landed, approve | Attacks landed, deny | Benign done, approve | Benign done, deny |
|:--|--:|--:|--:|--:|
| Full standard policy | 11 | 0 | 20 | 3 |
| Without tool actions | 12 | 1 | 20 | 3 |
| Without argument constraints | 28 | 1 | 31 | 6 |
| Without budgets | 12 | 0 | 20 | 3 |
| Without sequence rules | 11 | 0 | 20 | 3 |
| Without information-flow rules | 11 | 11 | 20 | 20 |

The agent here is the scripted one, and it shapes these numbers. It builds
each call from the scenario's success predicates, so it never adapts to a
refusal, which keeps its utility low, and it leaves out whatever a predicate
doesn't name: an email's body, a URL's scheme, sometimes the whole URL. It also
sends amounts as strings. Constraints refuse a missing or malformed argument,
so part of what this table credits to them is the script.

Removing constraints lets 17 more attacks land with every gate approved.
Traced call by call, that is 19 attacks that land only without constraints,
less 2 that land only with them. Ten of the 19 were stopped on the value
itself, a recipient, host or path outside the allowlist. The other 9 were
stopped only because the script's call left out an email's body or recipient,
or a URL's scheme. The 2 going the other way are string amounts: with no
constraint to parse them into numbers, the refund budget refuses them. The 11
extra benign tasks are all the script: each of the 17 twins that finish only
without constraints had sent a call with an argument missing or cut short, and
the 6 that fail only without them sent string amounts. The deny bracket's
differences, 1 attack and 3 benign tasks, are the script too. So constraints
stop 10 attacks here that a complete call wouldn't get past, and this run
can't say what they cost in benign work.

Tool actions and budgets each stop one more attack when gates are approved,
and sequence rules change nothing on this corpus. Information-flow rules
matter only when gates are refused: removing them lets 11 attacks through and
17 more benign tasks finish, every one a call a refused gate had stopped. The
effects are conditional on the mechanisms left in place, so they don't add up
to the full policy's effect. The compact artifact is in
[docs/results/ablation-loo/](docs/results/ablation-loo/README.md), and
[docs/research/ablation.md](docs/research/ablation.md) names the scenarios
behind each count.
