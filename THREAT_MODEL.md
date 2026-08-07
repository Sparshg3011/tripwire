# Threat model

Tripwire is a deterministic policy firewall between an AI agent and its
MCP tool servers. This document says exactly what that defends, what it
doesn't, and what each design decision costs. The residual-risk section
gets its numbers from the adversarial benchmark; until the full corpus
runs, entries there are design-time expectations and marked as such.

## The attacker

The attacker controls **content the agent reads**: an email body, a web
page, a file, a tool result. They do not control the agent's code, the
policy file, tripwire's process, or the host. Their goal is to make the
agent *do* something — exfiltrate data, take an unauthorized action,
destroy something — using the tools it legitimately has.

This is the prompt-injection threat in its practical form. We assume
the model **can** be fooled; the entire design follows from refusing to
bet on the model.

## What tripwire defends

- **Tool-mediated harm.** Every tool call crosses the proxy, and the
  proxy enforces policy the model cannot talk its way around: argument
  constraints, call and spend budgets, order-of-operations rules, and
  information-flow rules that tighten once untrusted content is in
  play. Within MCP there is no second path to the tools.
- **The record.** Every decision is logged with the rule that made it
  and the reason, in a hash chain that makes rewriting history visible.
  If tripwire cannot write the log, it stops the world rather than act
  unrecorded.
- **The retry hole.** A duplicated side-effectful call (agent retry,
  transport hiccup) replays the first result instead of running twice.

## What tripwire does not defend

Named plainly, because a security tool that oversells is a hazard:

- **Non-MCP side channels.** An agent that can also run shell commands,
  call raw HTTP from its own process, or use non-MCP plugins has doors
  tripwire never sees. Tripwire mediates MCP; it does not sandbox the
  agent process.
- **A compromised host.** Root on the machine can edit the policy, kill
  the proxy, or truncate the log (see below). Tripwire's guarantees are
  against a *content* attacker, not a *host* attacker.
- **Harm without tool calls.** If the model is talked into writing
  something false, cruel, or secret-revealing *in its reply text*,
  no tool call happens and tripwire never enters the picture.
- **A malicious upstream server.** Tripwire constrains what the agent
  asks tools to do. A tool server that lies about what it did, or does
  extra things on the side, is upstream of every proxy-level guarantee.
  Choose tool servers the way you choose dependencies.
- **In-policy harm.** If the policy allows refunds up to $100 and the
  attacker gets one $99 refund approved, tripwire worked and the policy
  was wrong. The firewall enforces the policy you wrote, not the one
  you meant.

## Design decisions and what they cost

**Session taint is sticky and session-wide (v0.1).** One untrusted
result taints the session until it ends; nothing washes it off. This is
the sound direction — it can over-block, never under-block — and the
over-blocking is real: after one `fetch_url`, every flow-guarded tool
needs a human for the rest of the session. The benchmark measures that
cost as lost task completion instead of hiding it. Per-message taint
and declassification are v0.2 design work, not v0.1 promises.

**Canonicalization stops where stated.** NFKC, invisible-character
stripping, trailing-dot hosts, numeric-string parsing — and nothing
else. No HTML-entity decoding, no percent-decoding, no base64, no
homoglyph folding. A decoder that handles four of five encodings moves
the bypass somewhere less obvious, so the boundary is explicit instead
of half-built. The failure direction is the safe one for allowlists: a
Cyrillic 'а' in a domain fails to match the ASCII allowlist and the
call blocks. The same property inverted: **blocklist policies are weak
against encodings we don't fold** — write allowlists.

**Checked args are forwarded args.** The proxy sends upstream the
canonicalized form it evaluated, not the original bytes. Checking one
form and sending another would make the check theatre. The cost: tools
receive a lightly rewritten string, which is why the rewrites are
small, enumerated, and tested.

**The audit chain does not protect the tail.** Two related gaps, both
inherent to a chain with no external anchor:

- Deleting the last k lines leaves a prefix that still verifies.
- The **final** record is covered by no other record's hash, so its
  contents can be rewritten and the chain still verifies. Only when a
  later record is appended does the previous one become fixed.

So the log is tamper-evident for everything except its own end. Fixing
that needs an anchor outside the file — a periodically published head
hash, or a second append-only sink. v0.1 documents it rather than
pretending. Rewriting or removing anything before the tail is detected
and located exactly.

**One writer per audit log, enforced.** Each writer caches the chain
head when it opens the file, so two proxies appending to one log would
each build on a stale hash and shred the chain for both — silently,
discovered only by whoever later tried to use it as evidence. The
second process now fails to take an exclusive lock and refuses to
start. Give every proxy its own log.

**Forensic output is escaped, not trusted.** Tool names, arguments and
reasons are all partly attacker-authored and all get printed by
`tripwire trace`. Unprintable characters are escaped so injected
newlines can't draw extra steps into an incident report — forged
evidence in a log whose hash chain verifies perfectly, because nothing
was tampered with. `trace`, `report` and `replay` also check the chain
before printing and say loudly when it's broken.

**The tx ledger trusts a tool's own error report.** A result flagged
`isError` clears its intent row so transient failures stay retryable. A
tool that performs the side effect *and then* reports failure will
perform it again on retry. That is the tool lying about its own
outcome — see "malicious upstream" above. The ledger also stores tool
results unredacted; the db file deserves the same protection as the
audit log.

**The approval gate assumes the human reads.** Gate prompts show the
tool, the exact arguments, the rule that fired, and the taint trail —
context an approval box needs to be more than a click-yes box. It
remains a human decision, and "make the human tired of saying yes" is a
real attack family the benchmark exercises. The web gate binds to
127.0.0.1 and requires a per-run token precisely because a browser will
submit forms to localhost from any page: without the token, injected
content could steer the user's own browser into approving the
attacker's call.

**Sessions are serialized.** One call at a time per session, including
human think-time on gates. Parallel calls could otherwise race past
budgets that had room for one. The cost is throughput and, during a
gate, latency for queued calls; the benchmark's benign twins price it.

## Residual risks (design-time expectations, pending benchmark numbers)

1. **Multi-step attacks that stay inside policy.** Each call
   individually legal, the harm in the composition. Sequence rules
   catch the shapes you anticipated; they do not catch the ones you
   didn't.
2. **Gate social-engineering.** Content that coaches the model to make
   the request look routine or urgent to the approving human.
3. **Policy gaps.** Unknown-tool defaults and `"*"` taint classes are
   strict, but a permissive rule someone wrote in a hurry is enforced
   exactly as written.

These three are expected to be the surviving attack families in the
benchmark's failure analysis. If the numbers say otherwise, this
section changes — in whichever direction the data points.
