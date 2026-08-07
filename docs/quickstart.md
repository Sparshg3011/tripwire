# Secure a Claude Desktop MCP server in five minutes

You already have an MCP server wired into Claude Desktop. This puts
tripwire in front of it, so every tool call is checked against a policy
you control before it reaches the tool. No code changes, one edited
config line.

## 1. Install

```bash
pip install tripwire-agent
```

## 2. Write a policy

Start in **shadow mode** — evaluate everything, block nothing. You want
to see what your agent actually does before you start refusing things.

`~/.tripwire/policy.yaml`:

```yaml
version: 1
enforce: false                  # shadow: log decisions, stop nothing

defaults:
  unknown_tools: block          # ...once enforce is on
  gate_timeout_seconds: 120

sources:
  "*": untrusted                # anything a tool returns is untrusted

tools:
  # name the tools your server actually has
  read_file:
    action: allow
  write_file:
    action: require_approval
  list_directory:
    action: allow
```

Check it before you wire it up:

```bash
tripwire validate ~/.tripwire/policy.yaml
```

## 3. Point Claude Desktop at tripwire

Open `claude_desktop_config.json`:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

Find your server. It looks something like this:

```json
{
  "mcpServers": {
    "files": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/work"]
    }
  }
}
```

Wrap it — tripwire becomes the server Claude talks to, and the old
command becomes tripwire's `--upstream`:

```json
{
  "mcpServers": {
    "files": {
      "command": "tripwire",
      "args": [
        "serve",
        "--policy", "/Users/me/.tripwire/policy.yaml",
        "--upstream", "npx -y @modelcontextprotocol/server-filesystem /Users/me/work",
        "--audit", "/Users/me/.tripwire/audit.jsonl",
        "--gate", "web"
      ]
    }
  }
}
```

Use **absolute paths** — Claude Desktop doesn't run in your shell, so
`~` and a bare `tripwire` on `$PATH` may not resolve. `which tripwire`
gives you the full path.

Restart Claude Desktop. Your tools appear exactly as before, because
tripwire re-advertises them unchanged.

## 4. Watch it work

Use the agent normally for a bit, then read what happened:

```bash
tripwire report ~/.tripwire/audit.jsonl
```

```
23 call(s) across 3 session(s)
  allowed          23
  blocked          0
  sent to a human  0
  WOULD have been stopped (shadow mode)  4
  sessions that saw untrusted content  2

rules that fired:
     4  tools.write_file.action
```

Four calls would have been stopped. Look at one in detail:

```bash
tripwire trace ~/.tripwire/audit.jsonl
```

```
session a1b2c3d4 — 4 call(s)

  turn 0   ok     read_file
      args   {"path": "/Users/me/work/notes.md"}
      rule   tools.read_file.action
      →      this result tainted the session

  turn 1   GATE   write_file
      args   {"path": "/Users/me/work/out.txt", "contents": "..."}
      rule   tools.write_file.action
      NOTE   shadow mode: this ran anyway

  untrusted content entered at turn 0 via read_file; every later verdict
  was decided with that in mind.
```

## 5. Turn it on

When the report stops surprising you, flip one line:

```yaml
enforce: true
```

Restart Claude Desktop. Now `write_file` opens an approval page at
`http://127.0.0.1:8642` (tripwire prints the URL, with its access
token, to stderr on startup) and waits for you. No answer within the
timeout means no.

Blocked calls come back to the agent as a readable refusal —
`tripwire_blocked: <reason> (rule: <rule>)` — so the model can tell you
it wasn't allowed instead of silently failing.

## Checking the log hasn't been touched

```bash
tripwire verify ~/.tripwire/audit.jsonl
```

```
ok: chain intact, 137 records
```

Every record carries the hash of the one before it, so an edited or
deleted line breaks the chain from that point on and `verify` says
exactly where.

## Where to go next

- [docs/policy.md](policy.md) — the full policy language: constraints,
  budgets, sequence rules, information-flow rules, canonicalization
- [THREAT_MODEL.md](../THREAT_MODEL.md) — what this defends, what it
  doesn't, and what each choice costs

## Troubleshooting

**Tools vanished from Claude Desktop.** tripwire refused to start —
it does that rather than run without enforcement. Its stderr goes to
Claude Desktop's MCP log (`~/Library/Logs/Claude/mcp*.log` on macOS).
The usual causes are a policy that doesn't validate, an `--upstream`
command that isn't right, or a relative path in the config.

**Everything is blocked.** `defaults.unknown_tools` is `block` and your
policy doesn't list the tool being called. `tripwire report` shows
which rule is firing.

**Gated calls always refuse.** No `--gate` is configured (the default is
`none`, which refuses anything needing a human), or nobody answered
before `gate_timeout_seconds`. Use `--gate web` under Claude Desktop —
`--gate cli` needs a terminal, which an app-launched process doesn't
have.
