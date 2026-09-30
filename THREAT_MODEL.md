# Threat model

Tripwire is a deterministic policy firewall between an AI agent and its
MCP tool servers. This document says exactly what that defends, what it
doesn't, and what each design decision costs. The residual risks at the
end are checked against what got through in [EVIDENCE.md](EVIDENCE.md).

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
- **The retry hole.** Within one enforcing proxy session, a duplicated
  side-effectful call replays the first result instead of running
  twice. A call whose outcome was never recorded is refused in every
  enforcing session, including the one a crashed proxy restarts as,
  until an operator clears it.

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

**Anchoring discharges one flow and nothing else.** A flow with `unless:
anchored` lets a tainted call through when every target, selector and
credential value is anchored: named by the user's task text, listed
under `known`, first seen in a trusted tool's field, or minted by the
session's own create call. It never lowers a constraint, limit,
sequence, other flow or `require_approval`. What it doesn't stop:
swapping one anchored value for another (a task-named recipient given
the wrong document, a payee named in the task paid twice or paid the
wrong amount under the limit); an attacker's address or host the user
typed into the task, negated or not; content with no link or target in
it sent to an anchored recipient, whether the attacker wrote it or the
agent gathered it; a self-scoped write carrying injected content; a
URL copied whole from injected text to a host that anchors, with the
attacker's path and query, which forges a request to that host; a link
to a host the task mentions only as a file name, where the extension is
also a top-level domain; a write under a known path to a file that runs
code but isn't on the control list, such as a build, test or CI
configuration; a URL a tool assembles from separate values the agent
sent it, which the tool then wrote first; a trusted tool whose store
other people can write to; and anything the proxy never sees, such as
another server's results or text the agent only restates in chat, since
arguments sent before untrusted content are recorded as nothing. It
also costs utility on purpose: a value seen first in untrusted content
never anchors through a trusted tool or a create call, so an attacker
who names the right address, or an id a tool will assign in sequence,
before the session meets it sends the honest call to the gate. Task
text and provenance live in memory like taint,
with no ledger across sessions, so a value laundered through a store in
one session starts fresh in the next. A denial tells the agent which of
its own values failed and where the session first saw it, nothing it
hadn't seen, but each refused call still answers one yes-or-no question.

**The task file is as trusted as whatever can write it.** `tripwire
serve --task-file` reads the user's task from a file before each call,
and Claude Code's prompt hook writes it there. What the file names
anchors, so it has to be out of the agent's reach. The proxy does its
part: no call naming the file in any argument, content included, is
discharged by anchoring, and no `TRIPWIRE_` variable reaches the
upstream. That keeps the path out of what the server it wraps is
handed, not out of its reach: running as the same user, the server can
read the proxy's command line and environment, and a server that
misuses what it finds there is the malicious upstream above. Tools
that don't go through tripwire are another matter: Claude Code's own
Write, Edit and Bash can reach it, and the deny rule in
[docs/claude-code.md](docs/claude-code.md) covers the first two but not
a shell. The file holds the latest prompt only, read when a call
arrives, so a prompt replaced before any call is lost; that costs
anchors, never adds them.

**A drafted policy is only as good as the names it was drafted from.**
`tripwire recipe` reads tool and argument names, never descriptions, so
nothing a server writes about its tools can loosen the draft. But a
name can mislead: a tool named like a read (`check_and_fix`, or
`write_query`, whose only word in a table is `query`) is left ungated,
one that runs code, sends somewhere or sets a credential under a name
no word table knows (`disable_2fa`) is an ordinary write, `self_scoped`
in the primary arm, and an argument named like content is never
anchored: server-filesystem's `move_file(source, destination)` moves
any file after untrusted content but a control file or tripwire's own.
The draft says in a comment what each inference rests on; read them
before enforcing it.

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
- **Keyed** (`--audit-key-file` on `serve` and on every command that
  reads a log): each record carries an HMAC-SHA256 over its own bytes,
  and links to the previous record's MAC. Without the key, no line can
  be edited, inserted or rewritten, the last one included, and none can
  be deleted except by cutting off the end, which it doesn't catch
  (below). No command vouches for a keyed log without its key, or,
  given a key, for a log that isn't keyed, so stripping the MACs and
  rebuilding a plain chain doesn't pass either.

Neither chain can see lines cut from the end on a line boundary — a
truncated log is a valid shorter log — or a log swapped wholesale for
another written under the same key. Only a cut through the middle of a
line shows, as a torn last record the writer refuses to continue. A
clean cut doesn't stay at the end, either: the next proxy to open the
log carries on from its new last line, so after a restart the missing
records sit in the middle of a log that still verifies, keyed or not.
Closing these needs an anchor outside the file: a periodically
published head, or a second append-only sink. v0.1 documents it rather
than pretending. And a key only helps against
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
by `verify`'s rules before printing, and say loudly when it's broken or
can't be checked.

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
recorded does not have that gap; it is refused across sessions. Shadow
mode bypasses the ledger entirely, so under `enforce: false` a retry
runs again exactly as it would without tripwire.

**Interactive approval assumes the human reads.** Gate prompts show the
tool, the arguments, the rule that fired, and the taint trail — context
an approval box needs to be more than a click-yes box. Arguments are
JSON-encoded, so control characters and anything non-ASCII (lookalike
letters included) show as escapes. The caller writes their names and
picks how many there are, so the preview is capped. Each name is
clipped at 60 characters and each value at 500 (web: 1000), with a
marker saying how much was cut. The arguments the policy checks come
first, a line each, and are always shown. When anchoring ran, the
tool's authority arguments lead, in contract order, then a content
argument that failed anchoring, each with a note after its value saying
where its values came from: "anchored: task", or the first that didn't
anchor and where it was first seen. The rest follow shortest first,
short ones sharing a line, and from the first one that would take the
preview past 1000 characters (web: 4000) they are left out, with a line
saying exactly how many arguments and encoded characters that was. So a
long body can't push the recipient out of view, and junk can't push
out an argument a rule checks. It can push out one no rule checks,
which is every argument of a tool with no constraints or budget, such
as an unknown tool, but only by filling the preview; the prompt then
says what it left out, and the terminal adds that approving forwards it
anyway. Both gates escape each note and clip it, with the tool, rule,
reason and taint trail, at 200 characters (web: 500), because an
unknown tool's name comes from the caller too, and so do the dict keys
in a value's path; and there is one note an argument, however many
values it holds, so nothing the caller sends can grow a question past a
fixed size. A nested object is clipped as a whole, with its members
shortest first, so a long member can't hide a short one. Enough short
members can still push a longer one past the clip, though, since only
the top-level arguments get a budget; and a list keeps its order, so a
long first item can hide the ones after it.
The marker says how much was cut, and the web gate keeps everything it
clipped or left out on the page in full, escaped, a click away. It
remains a human decision, and "make the human tired of saying yes" is a
real attack family the benchmark exercises. The web gate binds to
127.0.0.1 and requires a per-run token precisely because a browser will
submit forms to localhost from any page: without the token, injected
content could steer the user's own browser into approving the
attacker's call.

**Exact pre-approvals trust the host's authorization, not the agent's plan.**
The experimental library gate can spend a host-issued approval for one complete
canonical call, once, in its bound live session before expiry. All covered tools
must always require approval, so executing a call before taint also consumes the
grant. It neither clears taint nor overrides policy blocks. Host code must not
derive grants from attacker-controlled messages, let the agent issue them, or
automatically replenish them on restart. Unknown/content-dependent arguments
still require review; the API does not establish a general utility fix. See
[the exact-approval contract](docs/production.md#exact-pre-approvals).

**Sessions are serialized.** One call at a time per session, including
human think-time on gates. Parallel calls could otherwise race past
budgets that had room for one. The cost is throughput and, during a
gate, latency for queued calls; the benchmark's benign twins price it.

## Residual risks

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
4. **Allowed calls carrying the attacker's content.** A constraint says
   where a call may act, not what it says. A reply to the right
   colleague with a body the attacker wrote passes every rule, and so
   does a value that normalizes to something inside the policy's
   limits.

The first three were written down before the gym's full corpus ran; the
fourth is what it added. With every gate approved, five attacks got past
the standard policy, and each is one of these: an access-list write to an
allowed path, set up over several steps (1), a second refund inside every
cap (2), and an attacker's reply body and two canonicalization probes
(4). Each went through a gate the benchmark's operator approved without
reading, and with every gate refused none got through
([what got through](EVIDENCE.md#what-got-through)). In the gym, then,
these risks come down to a person reading the gate, which the benchmark
can't measure.
