# Running tripwire for real

The short version: **never turn enforcement on first.** Watch, read,
tighten, then enforce. Every tool in this page exists to make that
sequence safe.

## The rollout

### 1. Shadow

Start with `enforce: false`. Every rule is evaluated and every verdict
is logged; nothing is stopped. Your agent behaves exactly as it did
yesterday, and you start collecting evidence.

```yaml
version: 1
enforce: false
defaults: { unknown_tools: block }
sources: { "*": untrusted }
tools:
  # list what you know; unknown tools are recorded, not refused, in shadow
  read_file: { action: allow }
  write_file: { action: require_approval }
```

Leave it a few days, or however long it takes for your agent to do the
unusual things it does monthly.

### 2. Read

```bash
tripwire report ~/.tripwire/audit.jsonl
```

```
412 call(s) across 37 session(s)
  allowed outright   381
  blocked by policy  0
  sent to a human    0  (approved 0, refused 0)
  WOULD have been stopped (shadow mode)  31
  sessions that saw untrusted content  22

rules that fired:
    24  tools.write_file.action
     7  defaults.unknown_tools
```

Two numbers matter. **31 would have been stopped** — that's the friction
you're about to introduce. **7 hit `unknown_tools`** — that's a tool
your policy doesn't know about, and you need to decide about it before
enforcing, because it'll be refused the moment you flip the switch.

Then look at individual incidents:

```bash
tripwire trace ~/.tripwire/audit.jsonl <session-id>
```

### 3. Tighten, and check before you ship

This is the step people get wrong. Edit a copy of the policy, then ask
what it *would* have done to traffic you've already seen:

```bash
tripwire replay ~/.tripwire/audit.jsonl --policy candidate.yaml
```

```
session a1b2c3d4: 23 call(s) re-judged under candidate.yaml

  TIGHTER turn 4   write_file: allow -> gate
          tools.write_file.action: needs a human
  LOOSER  turn 9   http_post: block -> allow
          tools.http_post.action: allowed

  1 call(s) the new policy would stop, 1 it would let through.
  Check the looser ones before shipping this.
```

Anything under LOOSER is a hole you just opened. Replay won't tell you
what the agent would have done *next* after a changed verdict — a
blocked call changes the rest of the conversation — but it will tell
you exactly which decisions move.

### 4. Enforce

Flip `enforce: true` and restart. Blocked calls now come back to the
agent as `tripwire_blocked: <reason> (rule: <rule>)`, which the model
reads and can explain to the user.

Configure a gate before you enforce anything with `require_approval`,
or those calls are simply refused:

- `--gate web` — approvals at `http://127.0.0.1:<port>`, token printed
  to stderr at startup. The right choice under Claude Desktop, which
  gives the proxy no terminal.
- `--gate cli` — prompts on the controlling terminal. Only works when
  you started tripwire from a shell.

## Operations

**One audit log per proxy.** Enforced: a second process trying to write
the same log refuses to start. Two writers would each cache the chain
head and shred it for both.

**Rotate by moving, not truncating.** The chain lives in the file, so
`mv audit.jsonl audit-2026-08.jsonl` and let tripwire open a fresh one
on restart. Truncating a live log breaks the chain and tripwire will
refuse to continue it. Keep the archives — they're your evidence.

**Check integrity before you trust a log.**

```bash
tripwire verify ~/.tripwire/audit.jsonl
```

`trace`, `report` and `replay` also check it and warn loudly if the
chain is broken, but they still print — so read the warning.

**Watch the exit codes.** `2` means refused to start (bad policy, dead
upstream, unwritable log, unusable gate). `70` means it started and
then lost the audit log, and killed itself rather than act unrecorded.
Both should page someone; neither should be auto-restarted in a loop.

**Disk.** Every call writes a few records. The audit log grows roughly
linearly with tool traffic; budget for it and rotate.

## Redaction

Arguments are recorded, including on refused calls — that's the point,
since a refused call's arguments are exactly what you want after an
incident. If some of those arguments shouldn't be on disk, pass a
redactor:

```python
def redact(data):
    if "body" in data.get("args", {}):
        data["args"]["body"] = "<redacted>"
    return data

AuditLog(path, session_id=sid, redact=redact)
```

The redacted form is what gets hashed, so the chain still verifies. The
original never touches disk.

Two limits worth knowing: the tx ledger stores tool results and the
redactor does **not** reach it, so give the database the same file
permissions as the log; and redaction is lossy by design — you cannot
later recover what you chose not to record.

## What to watch for

| Symptom | Usually means |
|---|---|
| Tools vanish from the agent | Proxy refused to start. Check its stderr; under Claude Desktop that's the MCP log. |
| Everything refused | `unknown_tools: block` plus a tool your policy doesn't list. `tripwire report` names the rule. |
| Gated calls always refused | No `--gate`, or nobody answered inside `gate_timeout_seconds`. |
| Agent retries the same call in a loop | It's reading the refusal and trying again. Consider whether the rule should be a gate rather than a block. |
| `report` shows lots of `unknown_tools` | Your upstream added tools. Review them, then add them to the policy. |

## Upgrading

The policy schema is versioned and `version: 1` will keep loading.
A breaking schema change means a major version bump, and the README
says so. Re-run `tripwire validate` after any upgrade — it's instant,
and a policy that no longer validates means the proxy won't start.
