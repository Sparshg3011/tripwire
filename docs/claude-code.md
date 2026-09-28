# Claude Code

With [anchoring](policy.md#anchoring), a call made after untrusted
content can still go through when the values that decide who it reaches
come from what you asked for. tripwire only knows what you asked for if
Claude Code tells it: a `UserPromptSubmit` hook writes each prompt you
submit to a file, and the proxy reads that file before it judges each
call. Two pieces of configuration, and both name the same file.

Make its directory first; the hook won't create it:

```bash
mkdir -p ~/.tripwire
```

## 1. The hook

In `.claude/settings.json` for one project, or `~/.claude/settings.json`
for all of them:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "tripwire hook claude-code --task-file ~/.tripwire/claude-task.txt"
          }
        ]
      }
    ]
  },
  "permissions": {
    "deny": ["Edit(~/.tripwire/**)"]
  }
}
```

The hook replaces the file with your prompt and does nothing else. It
prints nothing, because Claude Code hands a prompt hook's output to the
model, and it always exits 0, so a hook that can't write never holds up
your prompt.

Whatever is in that file anchors, so the agent mustn't be able to write
it. The deny rule keeps Claude Code's own file tools out of the
directory; they don't pass through tripwire.

## 2. The server

In `.mcp.json`, wrap the server as usual and give tripwire the same file:

```json
{
  "mcpServers": {
    "mail": {
      "command": "tripwire",
      "args": [
        "serve",
        "--policy", "${HOME}/.tripwire/policy.yaml",
        "--upstream", "npx -y some-mail-server",
        "--audit", "${HOME}/.tripwire/audit.jsonl",
        "--task-file", "${HOME}/.tripwire/claude-task.txt"
      ]
    }
  }
}
```

`TRIPWIRE_TASK_FILE` in the entry's `env` does the same as the flag.
tripwire passes neither it nor any other `TRIPWIRE_` variable on to the
server it wraps. If Claude Code can't find `tripwire`, use the full
path `which tripwire` prints.

## What happens

Before each call, the proxy checks whether the file changed, and if it
did, adds what it holds to the task: up to 64 KiB of UTF-8, and anything
else is refused and logged as `intent_rejected`. What each prompt names
anchors for the rest of the session. The audit log gets each prompt's
hash and length, never its text. Until the file exists there is no
task, and only `known` values, trusted tools and the session's own ids
anchor.

`tripwire explain policy.yaml` shows what can anchor each argument your
policy names.

## Limits

- Claude Code's own Bash can still write the file. If the agent runs
  shell commands without asking you, it can name its own anchors.
- The proxy reads the file when a call arrives. Submit two prompts
  before the agent calls a tool through tripwire and only the second
  counts: fewer anchors, never more.
- Sessions that share a file share their prompts. Give a project its own
  file if that matters.
- No argument naming the file anchors, nor any path with a part of the
  same name, so give it a name nothing else uses.
