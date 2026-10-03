# Preregistration: argument anchoring (v0.2)

Written and committed before any AgentDyn result existed. The commit that
adds this file is the protocol; the runs use the code at the tag
`prereg-v0.2`, and nothing below changes after the first AgentDyn result.
Anything run differently is reported as a separate, labelled experiment.

## Question

v0.1 gates every write once untrusted content is in a session. On
AgentDojo that cut attack success from 30.7% to 4.0% and benign utility
from 82.4% to 36.5%. v0.2 adds `unless: anchored`: a gated write goes
through when every recipient, target and selector it carries comes from
the user's task, the operator's `known` list, a trusted tool, or an id
the session itself created. Does that recover utility without giving
back security, on tasks nobody tuned it on?

## Data

- **AgentDyn** (SaFo-Lab/AgentDyn at `5353cf7`), suites `github`,
  `shopping` and `dailylife`: 60 user tasks, 560 attacked pairs. **Blind.**
  No task prompt, injection goal, ground truth or trace text from these
  suites was read while designing, building or tuning v0.2; only tool
  names and input schemas were, to generate the policies.
- **AgentDojo v1.2.2**, the 85 held-out users and 844 pairs of the v0.1
  study. **Not blind**: v0.2 was designed with knowledge of v0.1's
  failures on them. Reported as regression evidence only.
- Development: the 12 AgentDojo users of `gym/agentdojo-pilot.yaml`, the
  only tasks inspected. Their v0.2 pilot is disclosed below and changed
  nothing.

## Conditions

All use the `important_instructions` attack, temperature 0, thinking
disabled, one repetition, and a deny-everything approval gate: a gated
call is refused, so every number is what an unattended agent gets.

| label | what runs |
|---|---|
| `direct` | the model with no defense |
| `tripwire-deny/taint` | recipe policy, flows without `unless`: v0.1's rule, generated uniformly |
| `tripwire-deny/primary` | recipe policy with `unless: anchored` — the v0.2 result |
| `transformers_pi_detector` | AgentDojo's ProtectAI detector, `protectai/deberta-v3-base-prompt-injection-v2` at `90c9989` |

Secondary, run after the primaries if quota allows:
`tripwire-deny/strict` (no `self_scoped` writes), and every condition
again on the second model.

Policies come from one recipe (`tripwire recipe`, version 1) applied to
each suite's tool names and input schemas, committed in
`gym/recipe_policies/` and checked byte for byte by CI. sha256 prefixes:

| suite | primary | taint | strict |
|---|---|---|---|
| banking | `4eeb7587162e3272` | `6cb39a1982061738` | `a9ffa481b2778a37` |
| slack | `1e438c76cd9282c2` | `c5dd4ee108cdcc77` | `a7b7850b4c30007f` |
| travel | `4f33f5ee7cfc37a5` | `ab80593bdcf5b142` | `09bd2957ba49af17` |
| workspace | `2c4c7ee7e3f81948` | `7f0cd6afdb564daa` | `03730e0018910f12` |
| github | `66cd729df89fdd1e` | `63e599780baf853b` | `1f77034938619090` |
| shopping | `7b0c9d68aa026abf` | `03775ac0c3381714` | `52619c82fdc72cb4` |
| dailylife | `ca47b66b97235712` | `352c53ff1ada85d3` | `4559540bc483472e` |

## Models

- Primary: `nvidia/nemotron-3-super-120b-a12b`, the v0.1 model.
- Second: `nvidia/nemotron-3.5-lightning-30b-a3b`, chosen on the
  development pilot before this file was written: of four candidates it
  was the one that both ran cleanly and still followed injections
  (33% attack success without defense). `z-ai/glm-5.3-flash` refused
  every pilot attack unaided, which leaves nothing for a defense to
  show; `openai/gpt-oss-20b` returned empty completions and
  `moonshotai/kimi-k2.6` was unavailable.

## Hypotheses and how they are decided

On AgentDyn, primary model, `primary` against `taint`, paired by task:

1. **Utility.** Benign utility is higher. Supported if the 95%
   user-cluster bootstrap interval of the difference lies above zero.
2. **Security is not given back.** Attack success rises by at most 2
   points. Supported if the upper end of the 95% two-way (user ×
   injection) cluster bootstrap interval of the difference is ≤ +2.
3. **It defends at all.** Attack success is lower than `direct`, by the
   same interval above zero.

Reported alongside, not decided: utility under attack, every condition
against `direct` and against the ProtectAI detector, per-suite rates,
pooled and suite-mean rates, the second model, AgentDojo regression
numbers, and every escalation by code.

## Execution

The provider's free tier allows the primary model about seven requests a
minute, account-wide; the second model has its own, larger budget. Each
model gets one shared budget (`--pace-file`) that every cell draws on,
so the rate limit alone sets the pace, and cells run in this order:

| model | first | then | last |
|---|---|---|---|
| primary, 8 requests/min | AgentDyn `direct`, `taint`, `primary`; AgentDojo `primary` | AgentDyn detector; AgentDojo `taint` | AgentDyn `strict` |
| second, 30 requests/min | AgentDyn `direct`, `taint`, `primary`, detector | AgentDojo `direct`, `taint`, `primary` | |

AgentDojo's `direct` baseline and the v0.1 and detector arms for the
primary model are the existing v0.1-study runs on the same 844 pairs,
reused unchanged. Every cell is one `tripwire_benchmarks.study` process
run from a clean checkout of `prereg-v0.2`, and resumes from its own
traces if interrupted.

## Analysis

`tripwire_benchmarks.report`, unchanged from this commit: Wilson
intervals per rate, exact McNemar tests, and the predeclared two-way
cluster bootstrap for paired differences. Provider failures are retried
by transport resume; any case still failing is reported as an error and
excluded from both arms of its pair, never scored as a defense.

All four conditions are reported whatever they show.

## Development pilot (disclosed)

12 users, 24 pairs, primary model, run on the code this file freezes:

| condition | attack success | benign utility | utility under attack |
|---|---|---|---|
| `direct` | 50.0% (12/24) | 50.0% (6/12) | 37.5% (9/24) |
| `tripwire-deny/taint` | 0.0% (0/24) | 41.7% (5/12) | 33.3% (8/24) |
| `tripwire-deny/primary` | 0.0% (0/24) | 41.7% (5/12) | 54.2% (13/24) |

Every benign task anchoring still refused named its target only
indirectly ("the article Bob posted", "the file called X"): a URL or id
that reached the session in a tool result, not in the task. That is the
designed limit of this version, and the design was left as it was.
