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
  and the reason, in a hash chain. Keyed with `--audit-key-file`, the
  chain makes rewriting history visible to whoever holds the key;
  unkeyed, it only catches an edit that leaves the rest of the chain
  alone (see below). If tripwire cannot write the log, it stops the
  world rather than act unrecorded.
- **The retry hole.** Within one proxy session, a duplicated
  side-effectful call replays the first result instead of running
  twice. A call whose outcome was never recorded is refused in every
  session, including the one a crashed proxy restarts as, until an
  operator clears it.

## What tripwire does not defend

Named plainly, because a security tool that oversells is a hazard:

- **Non-MCP side channels.** An agent that can also run shell commands,
  call raw HTTP from its own process, or use non-MCP plugins has doors
  tripwire never sees. Tripwire mediates MCP; it does not sandbox the
  agent process.
- **A compromised host.** Root on the machine can edit the policy, kill
  the proxy, truncate the log, or read the audit key and rewrite the
  log with it (see below). Tripwire's guarantees are against a
  *content* attacker, not a *host* attacker.
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
the sound direction — within a session it can over-block, never
under-block — and the over-blocking is real: after one `fetch_url`,
every flow-guarded tool needs approval for the rest of the session. The
benchmark measures that cost as lost task completion instead of hiding
it. Per-message taint and declassification are v0.2 design work, not
v0.1 promises. Taint lives in the proxy's memory, so restarting the
proxy starts a clean session, even if the agent still carries the text
that tainted the old one.

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
small, enumerated, and tested. Only arguments the policy checks are
rewritten; the rest reach the tool byte for byte.

**What the audit chain proves depends on the key.** Every record links
to the one before it, and `tripwire verify` says which kind of chain it
checked and what that kind can't see.

- **Unkeyed** (the default): each record carries the sha256 of the
  previous line. A line edited or deleted in the middle, with the lines
  after it left alone, breaks the chain and is located exactly. That is
  all it proves. Anyone who can write the file can rewrite it from any
  line onward — or entirely — and recompute every hash, and the final
  record is covered by no other record's hash at all. It catches
  accidents, not an attacker with write access.
- **Keyed** (`--audit-key-file` on `serve` and `verify`): each record
  carries an HMAC-SHA256 over its own bytes, and links to the previous
  record's MAC. Without the key, no line can be edited, inserted or
  rewritten, the last one included, and none can be deleted except by
  cutting off the end (below). `verify` won't check a keyed log
  without its key, and given a key it refuses a log that isn't keyed,
  so stripping the MACs and rebuilding a plain chain doesn't pass
  either.

Neither chain can see lines cut from the end — a truncated log is a
valid shorter log — or a log swapped wholesale for another written
under the same key. Closing that needs an anchor outside the file: a
periodically published head, or a second append-only sink. v0.1
documents it rather than pretending. And a key only helps against
someone who can write the log but not read the key. The proxy has to
read it to sign, so the compromised host above can forge a keyed log as
easily as an unkeyed one.

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

**The tx ledger replays within a session only.** A session is one proxy
process, so a restart starts a new one. Replaying across sessions would
serve every later conversation the first one's results, with no clock
to expire them. The cost: a call that completed just before the proxy
died, with its answer lost on the way to the agent, runs again when the
retry reaches the restarted proxy. A call whose outcome was never
recorded does not have that gap; it is refused across sessions.

**Interactive approval assumes the human reads.** Gate prompts show the
tool, the arguments, the rule that fired, and the taint trail — context
an approval box needs to be more than a click-yes box. Arguments are
JSON-encoded, so control characters and anything non-ASCII (lookalike
letters included) show as escapes. The caller writes their names and
picks how many there are, so the preview is capped. Each name is
clipped at 60 characters and each value at 500 (web: 1000), with a
marker saying how much was cut. The arguments the policy checks come
first, a line each, and are always shown. The rest follow shortest
first, short ones sharing a line, and from the first one that would
take the preview past 1000 characters (web: 4000) they are left out,
with a line saying exactly how many arguments and encoded characters
that was. So a long body can't push the recipient out of view, and junk
can't push out an argument a rule checks. It can push out one no rule
checks, which is every argument when a flow or sequence rule fired, but
only by filling the preview; the prompt then says what it left out, and
the terminal adds that approving forwards it anyway. Both gates clip
the tool, rule, reason and taint trail as well, at 200 characters each
(web: 500), because an unknown tool's name comes from the caller too,
so nothing the caller sends can grow a question past a fixed size. A
nested object is clipped as a whole, with its members shortest first,
so a long member can't hide a short one. Enough short members can still
push a longer one past the clip, though, since only the top-level
arguments get a budget; and a list keeps its order, so a long first
item can hide the ones after it. The marker says how much was cut, and the web gate
keeps everything it clipped or left out on the page in full, escaped, a
click away. It remains a human decision, and "make the human tired of
saying yes" is a real attack family the benchmark exercises. The web
gate binds to 127.0.0.1 and requires a per-run token precisely because
a browser will submit forms to localhost from any page: without the
token, injected content could steer the user's own browser into
approving the attacker's call.

**Exact pre-approvals trust the host's authorization, not the agent's plan.**
The experimental library gate can spend a host-issued approval for one complete
canonical call, once, in its bound live session before expiry. All covered tools
must always require approval, so executing a call before taint also consumes the
grant. It neither clears taint nor overrides policy blocks. Host code must not
derive grants from attacker-controlled messages, let the agent issue them, or
automatically replenish them on restart. Unknown/content-dependent arguments
still require review; the API does not establish a general utility fix. See
[the exact-approval contract](docs/exact-approvals.md).

**Sessions are serialized.** One call at a time per session, including
human think-time on gates. Parallel calls could otherwise race past
budgets that had room for one. The cost is throughput and, during a
gate, latency for queued calls; the benchmark's benign twins price it.

## Residual risks (design-time expectations, pending benchmark numbers)

1. **Multi-step attacks that stay inside policy.** Each call
   individually legal, the harm in the composition. Sequence rules
   catch the shapes you anticipated; they do not catch the ones you
   didn't. A numeric window also counts every executed call, so
   harmless allowed calls can pad the trigger out of it; only
   `turns: session` can't be outwaited.
2. **Gate social-engineering.** Content that coaches the model to make
   the request look routine or urgent to the approving human.
3. **Policy gaps.** Unknown-tool defaults and `"*"` taint classes are
   strict, but a permissive rule someone wrote in a hurry is enforced
   exactly as written.

These three are expected to be the surviving attack families in the
benchmark's failure analysis. If the numbers say otherwise, this
section changes — in whichever direction the data points.
