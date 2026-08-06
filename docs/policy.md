# The policy language

One YAML file drives everything tripwire does. This page is the full
reference: every key, the order rules are evaluated in, and the exact
text-normalization rules applied before any rule looks at an argument.

A policy that doesn't validate doesn't run — `tripwire validate
policy.yaml` tells you why, with the path to the offending key. Unknown
keys are errors, not warnings: a typo in a security policy must fail
loudly, not silently allow.

## Shape

```yaml
version: 1                     # required, literally 1
enforce: true                  # false = shadow mode (see below)

defaults:
  unknown_tools: block         # allow | block | require_approval
  gate_timeout_seconds: 120    # how long a human has to answer

sources:                       # who taints the session
  read_email: untrusted
  fetch_url: untrusted
  read_calendar: trusted
  "*": untrusted               # the default class; strict by default

tools:
  send_email:
    action: require_approval   # allow | block | require_approval
    constraints:
      to:   { regex: "^[^@]+@mycompany\\.com$" }
      body: { max_length: 10000 }
    limits: { per_session: 3 }

  issue_refund:
    action: allow
    constraints:
      amount: { type: number, min: 0, max: 100 }
    limits:
      sum_per_session: { field: amount, max: 500 }

  delete_file:
    action: block
    reason: "Destructive; disabled."

sequences:                     # order-of-operations rules
  - deny: execute_code
    within_turns_after: fetch_url
    turns: 3

flows:                         # information-flow rules; tighten only
  - when: context_tainted
    tools: [send_email, http_post, execute_code, write_file]
    action: require_approval   # or block — never allow
    reason: "Untrusted content in context; external actions gated."
```

## Evaluation order

Every call is judged in five stages. The first hard **block**
short-circuits; otherwise stages may only escalate the verdict
(allow → gate → block), never relax it.

1. **Tool lookup.** No entry in `tools:` → the verdict is
   `defaults.unknown_tools`. An entry with `action: block` ends it
   here. `allow` / `require_approval` set the provisional verdict and
   evaluation continues.
2. **Constraints**, on canonicalized arguments (below). A constraint on
   an argument the call didn't provide **blocks** — absence is not a
   free pass. `regex` must match the whole value; `max_length` bounds
   `len()`; `type: number` accepts int/float and nothing else (not
   `True`); `min`/`max` are inclusive.
3. **Limits**, counting the current call. `per_session: 3` means calls
   1–3 pass and call 4 blocks. `sum_per_session` adds the current
   call's `field` value to the running total; over `max` blocks,
   exactly `max` is fine. A missing or non-numeric `field` blocks.
4. **Sequences.** `deny: X within_turns_after: Y turns: N` blocks X
   when Y ran at turn *t* and the current turn is within *t + N*.
5. **Flows.** With `when: context_tainted`, once the session has seen
   any result from an `untrusted` source, listed tools escalate to the
   flow's action. Flows cannot allow — the schema rejects it.

Every verdict carries the id of the rule that decided it
(`tools.send_email.constraints.to`, `sequences[0]`, …) and a
human-readable reason. Both go in the audit log; the reason is also
what the agent reads in the refusal.

## Canonicalization

Attackers rarely attack the rule; they attack the *spelling* of the
value the rule reads. Before evaluation, tripwire normalizes arguments
— and forwards the normalized form upstream, so what was checked is
what runs:

| # | Rule |
|---|------|
| C2 | Invisible formatting characters are stripped: U+200B/200C/200D, U+2060, U+FEFF. A zero-width space inside `corp.com` comes out. |
| C1 | Then Unicode NFKC: fullwidth `ａdmin` → `admin`, ligature `ﬁle` → `file`. (Invisibles first, then NFKC — the order makes the whole thing idempotent.) |
| C3 | At comparison time, both sides are casefolded when a constraint sets `case_insensitive: true`. |
| C4 | Host-like fields (`url`, `host`, `hostname`, `domain`, `to`, `recipient`, `email`, `address`) lose all trailing dots: `corp.com.` → `corp.com`. |
| C5 | Fields constrained with `type: number` parse plain numeric strings: `"1e2"` → `100.0`, `" 42 "` → `42.0`. Only a strict pattern qualifies — `"1_000"`, `"nan"`, `"inf"`, and non-ASCII digits do not, and stay strings for the evaluator to block. |

Just as important is what canonicalization **doesn't** do: no HTML
entity decoding, no percent-decoding, no base64, no homoglyph folding.
The boundary is explicit; [THREAT_MODEL.md](../THREAT_MODEL.md)
explains why, and what it means for how you write rules (short
version: write allowlists, not blocklists).

## Shadow mode

`enforce: false` evaluates everything and blocks nothing. Every
decision is still made and logged with a `shadow` flag, so the audit
log shows exactly what *would* have been blocked. That's the adoption
path: run shadow behind your real traffic, read the report, tighten
the policy, then flip `enforce` on. Gates don't prompt anyone in
shadow mode — nothing is stopped, and no human gets paged for a
hypothetical.

## Taint

`sources:` declares which tools return attacker-controllable content.
One result from an `untrusted` source marks the session tainted, for
good — including errored results, since error text comes from the same
place. Tools not listed fall back to the `"*"` entry, and if there is
no `"*"` entry, to `untrusted`. You can declare `"*": trusted`, but
you have to type it out and mean it.

Taint is deliberately blunt in v0.1 (session-wide, sticky, no
declassification). The trade and its cost are discussed in the threat
model; the benchmark measures the cost instead of hiding it.
