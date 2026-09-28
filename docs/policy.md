# The policy language

One YAML file drives everything tripwire does. This page is the full
reference: every key, the order rules are evaluated in, and the exact
text-normalization rules applied before any rule looks at an argument.

A policy that doesn't validate doesn't run — `tripwire validate
policy.yaml` tells you why, with the path to the offending key. Unknown
keys are errors, not warnings: a typo in a security policy must fail
loudly, not silently allow. So is a key given twice in one mapping,
a `<<` merge key included, which plain YAML would settle by quietly
keeping the last one.

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
    allowed_args: [subject]    # with to and body, the only arguments accepted
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
    turns: 3                   # or session: for the rest of the session

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

1. **Tool lookup.** An entry in `tools:` with `action: block` ends it
   here. `allow` / `require_approval` set the provisional verdict and
   evaluation continues. A tool with no entry gets
   `defaults.unknown_tools` as its action: `block` ends it here too,
   while `allow` / `require_approval` have no constraints or limits to
   check but still go through sequences and flows, which may name
   tools that have no entry of their own.
2. **Constraints**, on canonicalized arguments (below). If the tool
   sets `allowed_args`, an argument named neither there, nor under
   `constraints`, nor as the `field` its `sum_per_session` adds up
   **blocks** (`tools.<name>.allowed_args`). An argument contract
   (`args`, under [Anchoring](#anchoring)) admits its own arguments the
   same way, and once it is set an argument named nowhere in the rule
   blocks with `tools.<name>.args`. Without either,
   arguments nothing constrains pass unchecked, so an allowlist on `to`
   alone still lets a `bcc` through. A constraint on an argument the
   call didn't provide **blocks** — absence is not a free pass.
   `max_length` bounds `len()`, and is checked before `regex`, so an
   over-long value never reaches the pattern; `regex` must match the
   whole value, read two ways (below); `type: number` accepts a finite
   int/float and nothing else (not `True`, not NaN or ±Infinity);
   `min`/`max` are inclusive and also refuse anything that isn't a
   finite number. The bounds themselves must be finite, and
   `allowed_args` may not name an argument twice, or the policy doesn't
   load. Last, a target in the argument contract that can't be read as
   one value of its type (`a@x.com,evil`, a URL with userinfo or `%` in
   its host, a float) **blocks**, tainted session or not.
3. **Limits**, counting the current call. `per_session: 3` means calls
   1–3 pass and call 4 blocks. `sum_per_session` adds the current
   call's `field` value to the running total; over `max` blocks,
   exactly `max` is fine. A missing, non-numeric or non-finite `field`
   blocks, and a non-finite value is never added to the total.
4. **Sequences.** `deny: X within_turns_after: Y turns: N` blocks X
   when Y ran at turn *t* and the current turn is within *t + N*.
   `turns: session` blocks X for the rest of the session once Y has
   run. Every executed call is a turn, so a numeric window can be
   padded: a caller who gets N harmless calls allowed after Y has aged
   Y out of the window before calling X. Use `session` when no amount
   of distance should make X safe.
5. **Flows.** With `when: context_tainted`, once the session has seen
   any result from an `untrusted` source, listed tools escalate to the
   flow's action. Flows cannot allow — the schema rejects it. A flow
   with `unless: anchored` skips a call whose every authority value is
   anchored, and nothing else: it never lowers what another stage,
   another flow or the tool's own `action` decided.

Regexes are Python's, and a value has to match twice, in ASCII mode and
under Unicode rules, since each reading is the strict one somewhere.
`\d`, `\s` and `\w` admit ASCII characters only, so `\d+` doesn't admit
digits from other scripts, which the tool on the far side may still
read as a number. `\D`, `\S`, `\W` and `[^\s]` refuse whatever Unicode
counts as a digit, whitespace or a word character, so `[^@\s]+` still
refuses a U+2028 line separator. Ignoring case, whether by
`case_insensitive: true` or an inline `(?i)`, admits ASCII case
variants and nothing else: `ADMIN` passes for `admin`, `admın` doesn't.
Where a pattern refuses, as a lookahead does, Unicode case rules are
the stricter: ignoring case, `(?!javascript:)` refuses `javascrıpt:` as
well. A pattern that asks for Unicode rules with `(?u)` doesn't load.

Every verdict carries the id of the rule that decided it
(`tools.send_email.constraints.to`, `sequences[0]`, …) and a
human-readable reason. Both go in the audit log; the reason is also
what the agent reads in the refusal. A verdict an argument contract or
anchoring decided also carries a code (below).

## Canonicalization

Attackers rarely attack the rule; they attack the *spelling* of the
value the rule reads. Before evaluation, tripwire normalizes the
arguments the policy checks for that tool — its constraint keys, the
field its `sum_per_session` adds up, and its contract's target,
selector and credential arguments — and forwards the normalized form
upstream, so what was checked is what runs. Every other argument is
forwarded exactly as it arrived:

| # | Rule |
|---|------|
| C2 | Invisible formatting characters are stripped: U+200B/200C/200D, U+2060, U+FEFF. A zero-width space inside `corp.com` comes out. |
| C1 | Then Unicode NFKC: fullwidth `ａdmin` → `admin`, ligature `ﬁle` → `file`. (Invisibles first, then NFKC — the order makes the whole thing idempotent.) |
| C3 | At comparison time, a constraint with `case_insensitive: true` matches its regex ignoring case (`re.IGNORECASE`), in both readings, so it admits ASCII case variants only. Nothing is rewritten: `\D` in the pattern still means `\D`, and the value is checked as it will be sent. |
| C4 | Checked host-like fields (`url`, `host`, `hostname`, `domain`, `to`, `recipient`, `email`, `address`) lose all trailing dots: `corp.com.` → `corp.com`. |
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
place. So does a call that failed upstream, whatever its source: the
agent is handed the exception's text instead of a result. Tools not
listed fall back to the `"*"` entry, and if there is no `"*"` entry, to
`untrusted`. You can declare `"*": trusted`, but you have to type it
out and mean it.

Taint is deliberately blunt in v0.1 (session-wide, sticky, no
declassification). The trade and its cost are discussed in the threat
model; the benchmark measures the cost instead of hiding it.

For trusted hosts that can authorize a complete action before a session,
the experimental [exact pre-approval API](exact-approvals.md) can approve that
one call without clearing taint or overriding hard blocks. It does not infer
intent or remove the documented utility limitation for content-dependent tasks.

## Anchoring

After the first untrusted result, a flow gates every call it lists. A
flow with `unless: anchored` skips a call when every value that decides
who the call reaches, what it acts on, or which secret it sets came
from somewhere the attacker can't write to:

```yaml
known:                          # operator attestations
  email: ["@corp.example"]      # "@domain": any address at that domain
  host: [".corp.example"]       # ".domain": that host and every host under it
  path: ["/Users/me/project"]   # also a prefix for match: under
tools:
  send_email:
    action: allow
    args:                       # the argument contract
      to: target                # short for {role: target}
      cc: {role: target, type: email}
      subject: content
      body: content
  delete_file:
    action: allow
    destructive: true
    args: {file_id: selector}
  write_file:
    action: allow
    args:
      path: {role: selector, type: path, match: under}
      text: content
  create_event:
    action: allow
    self_scoped: true           # may run with no authority value at all
    args: {title: content, participants: target}
flows:
  - when: context_tainted
    tools: [send_email, delete_file, write_file, create_event]
    action: require_approval
    unless: anchored
```

**Roles.** A `target` is who receives the effect, a `selector` the
existing object it acts on, a `credential` a secret it sets, and
`content` anything else. `type` (`auto`, `email`, `url`, `host`,
`iban`, `phone`, `path`, `id`, `name`) says how a value is read; `auto`
goes by its shape. Every scalar under an authority argument, in lists
and nested objects too, is a value that must anchor, and a list of
addresses in one string is split into addresses. A content argument
takes no `type` or `match`, `match: under` needs a path, and a tool
can't be both `destructive` and `self_scoped`.

**Sources.**

| Role | Anchored by |
|---|---|
| target | task, known, trusted |
| selector | task, known, trusted, self; on a `destructive` tool: task, known, trusted |
| credential | task, known |

- **task**: the user's task text. A library host adds it with
  `await interceptor.add_task(text, source)`, up to 64 KiB a segment.
  `tripwire serve --task-file PATH` (or `TRIPWIRE_TASK_FILE`) reads the
  file before each call and adds it as a segment whenever it changed;
  `tripwire hook claude-code` writes each prompt there
  ([Claude Code](claude-code.md)). Segments add up for the rest of the
  session, and the audit log gets their hash and size, never the text.
  An id under 6 characters anchors only after a label: `id 13`, or a
  word of the argument's name (`file 13` for `file_id`). With `match:
  under`, a path below a task path of two or more components anchors
  too.
- **known**: an entry under `known` of the value's type; a path below a
  known path anchors with `match: under`.
- **trusted**: a whole field of a result from a `trusted` source, unless
  the value was seen first somewhere untrusted: in the text or fields of
  an untrusted or errored result, in an upstream error, in the tool
  listing, or in anything the agent sent after untrusted content. So a
  value the agent wrote and then read back from a trusted tool never
  anchors, and a trusted tool repeating a value it was asked about
  vouches for nothing.
- **self**: the one fresh id this session's own create-like call
  (`create`, `new`, `add`, `copy`, `make`, `upload`) returned. The word
  must come before any read verb in the tool's name, so `add_contact`
  mints and `get_new_request` doesn't.

Values are compared as normalized keys, exactly: a lookalike letter, a
longer address around an anchored one, or a path through `..`, `~` or a
control file (`.git`, `.claude`, `CLAUDE.md`, …) never anchors. Neither
does the policy file, the audit log, the tx database or the task file
under any spelling. Content is held to the same files, since a tool may
take a file name as content: a call with a content value that, read as
a path, names a control file or one of tripwire's own is never
discharged.

**Content** of a tool with a target argument is checked too. A value
that is wholly an address, an IBAN or a URL is checked as a target;
every link in it, whatever its scheme (`//host/...` and a bare
`host.com/...` included), must read as an http(s) URL to a host the
task names (a file name the task mentions counts), a known host, or one
a trusted tool returned; and a URL with a path, query or fragment must
appear exactly as the task or a tool wrote it, so it can't carry what
the session gathered. That is the URL as the call sends it, invisible
characters and all; only a link in prose may end in a closing bracket
and a punctuation mark that nobody wrote. A tool counts only where it
wrote the URL before the agent did: one repeating what it was sent, in
its result or its error, vouches for nothing.

A call with no authority value at all escalates on a `destructive` tool
and on any tool that isn't `self_scoped`. Null and `""` are no value, so
don't make a tool that sets a secret `self_scoped`: a call emptying it
would go through. A tool the flow names without an `args` contract is
never discharged, and `tripwire validate` warns about it. `tripwire
explain policy.yaml` prints, for each tool, the flows that skip its
anchored calls, each argument's role, and what anchors it, with the
same warnings.

**Codes.** The first failure decides:

| Code | Rule id | When |
|---|---|---|
| `unexpected_argument` | `tools.<t>.args` | an argument outside the rule; any time |
| `invalid_value` | `tools.<t>.args.<arg>` | a target that can't be read; any time |
| `unanchored_argument` | `tools.<t>.args.<arg>` | an authority value no accepted source vouches for |
| `url_not_verbatim` | `tools.<t>.args.<arg>` | a URL with a suffix nobody wrote |
| `link_unanchored` | `tools.<t>.args.<arg>` | a link to an unvouched host |
| `destructive_needs_anchor` | `tools.<t>.destructive` | no authority value on a destructive tool |
| `vacuous_write` | `tools.<t>.self_scoped` | no authority value, and not self-scoped |
| `no_contract` | `flows[i]` | the tool has no `args` |

The refusal starts with the usual `tripwire_blocked:` line, then says
what would pass, then gives a JSON object, which is also in the result's
`_meta["io.github.tripwire/denial"]`: the code, the rule, the failed
value as the agent sent it, where it was first seen, which sources
would have anchored it, and whether retrying can help. It never quotes
the task or what a tool returned. The decision record carries the code
and each checked value's role, status, source and key hash, and each
result adds a `provenance_observed` record. `tripwire trace` shows a
failed value as, for example, `to: first seen in free text from
read_email, turn 3; accepted: task, known, trusted`, and for a call
anchoring let through, each value and what anchored it (`to: anchored
via task`), with a reason naming the flow it skipped. An approval gate
lists the authority arguments first, each with a note on its values:
`"to": "bob@corp.example"  anchored: task`, or `"cc": [...]  unanchored
at cc[1]: first seen in free text from read_email, turn 3; accepted:
task, known, trusted`.

**Bounds.** What a session remembers is capped (200,000 keys, 2 MiB of
text per observation, 4 MiB in all). When something untrusted goes past
a cap, or can't be read whole (an image, fields nested past 64 levels),
the session degrades for good: trusted and self anchors stop, only the
task and `known` still anchor, and only the task makes a URL verbatim. Like taint, all of this lives in the
proxy's memory, and a restarted proxy starts with none of it.

## Drafting a policy

`tripwire recipe` drafts a starting policy from an MCP server's tool
listing, and prints it:

```bash
tripwire recipe --upstream "npx -y @modelcontextprotocol/server-filesystem /path" > policy.yaml
tripwire recipe --tools tools.json > policy.yaml   # a saved tools/list result
```

It reads tool names, the names and `format`s of their arguments, and
`destructiveHint`, and never a description, which the server writes.
Every tool is `untrusted` and unknown tools block. A tool whose first
verb word is a read (`get`, `list`, `search`, …) is allowed as it is,
unless it takes a URL: then it is a fetch, and its URL must anchor.
Every other tool is a write. A write is limited to 5 calls a session,
or 1 with a password, token or key argument; gets an argument contract
whose roles come from its argument names (`to`, `email` and `url` are
targets; ids, paths, named objects like `repo_name` and postal
addresses are selectors, the last so that a long address is never
refused as unreadable; `password` is a credential; the rest content);
and is `self_scoped` unless it is destructive or sets a credential. One
flow gates every write and fetch once the session is tainted, `unless:
anchored`. A write that runs code (`run`, `exec`, a `command` or
`query` argument) or sends somewhere it doesn't name (`push`, or
`reply` with no target) gets no contract, so that flow gates it every
time; so does one whose schema admits arguments it doesn't name.
`--strict` makes no write `self_scoped`, so a write naming nothing
anchorable is gated too.

A comment names the word behind each tool's kind and each argument's
role, and the header records the recipe version and the sha256 of the
listing and of the word tables, so the same listing always drafts the
same file. It is a draft: read every role before you enforce it. A name
no table knows drafts as content: the filesystem server's
`move_file(source, destination)` becomes a `self_scoped` write that
moves any file but a control file or tripwire's own, so give its
arguments a path role. The full rules are in
[`src/tripwire/recipe.py`](../src/tripwire/recipe.py).
