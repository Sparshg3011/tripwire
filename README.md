# tripwire

A firewall for AI agents that use tools. It sits between an agent and its
[MCP](https://modelcontextprotocol.io/) servers and decides, for every tool
call, whether the call runs. The decision is ordinary code, not another model.

[![CI](https://github.com/Sparshg3011/tripwire/actions/workflows/ci.yml/badge.svg)](https://github.com/Sparshg3011/tripwire/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%E2%80%933.14-blue)](pyproject.toml)

![tripwire demo: an injected email asks the agent to mail the inbox to an attacker; the send is blocked, and the reply the user asked for goes through](docs/img/demo.gif)

## Why

An agent that can read your email and send email can be told what to do by
anyone who emails you. The injected instruction arrives as ordinary text in a
tool result, and the model has no reliable way to tell it apart from yours.
Models are getting better at ignoring these instructions, but "usually" isn't
a security property, and a second model asked to spot the attack can be
fooled by the same text.

tripwire starts from the other end: assume the model will sometimes be
fooled, and make sure a fooled model can't do much. Every call is checked
against a policy you write before it reaches the server, and every decision
is written to a hash-chained log with the rule that made it.

```text
agent ── MCP ──▶ tripwire ── MCP ──▶ tool server
```

## How it decides

Most injections need the agent to send something somewhere the attacker
chose: an email address, an account number, a URL. tripwire records where
each value in a session first appeared. Once untrusted content has entered
the session, a call that sends, pays, deletes or fetches goes through only if
the values that decide *where it goes* came from the user's request, from a
list you trust, or from a tool you marked trusted. The attacker's address
only ever appeared inside the email, so a send to it is stopped. The reply to
the colleague the user named goes through.

```yaml
tools:
  read_inbox: {action: allow}
  send_email:
    action: allow
    args: {to: target, cc: target, subject: content, body: content}
    limits: {per_session: 5}
flows:
  - when: context_tainted       # after the first untrusted tool result,
    tools: [send_email]         # a send needs approval
    action: require_approval
    unless: anchored            # unless its recipients came from the task
```

That is argument anchoring, new in 0.2. Around it sit the controls you would
expect from a policy engine:

| Control | What it does |
|:--|:--|
| Tool actions | Allow, block or require approval per tool. Unknown tools are blocked. |
| Argument constraints | Regexes, lengths and numeric ranges, checked after Unicode normalization. |
| Budgets | Call counts and running sums per session, such as a refund total. |
| Sequences | Deny one tool within some turns of another, or for the rest of the session. |
| Approval gates | Ask a human in the terminal or a token-protected local web page. |
| Audit | Every verdict in a hash-chained log, optionally keyed; `trace`, `report`, `replay`, `verify`. |

## Try it

```bash
pip install tripwire-agent
tripwire demo
```

`tripwire demo` runs the session in the recording above, offline, through the
real proxy and policy engine.

To put it in front of a server of your own, draft a policy from the server's
tool list, read it, then serve:

```bash
tripwire recipe --upstream "npx -y @modelcontextprotocol/server-filesystem ~/work" > policy.yaml
tripwire explain policy.yaml
tripwire serve --policy policy.yaml \
  --upstream "npx -y @modelcontextprotocol/server-filesystem ~/work" \
  --audit ~/.tripwire/audit.jsonl --gate web
```

The recipe marks every argument as a target, selector or content by its name
and schema and comments each guess. Treat it as a first draft, and start with
`enforce: false` to watch what the policy would do before it blocks anything
([production guide](docs/production.md)).

Anchoring to the user's request needs the request. With Claude Code, a
one-line hook hands each prompt to the proxy ([setup](docs/claude-code.md)).
Without it, values can still anchor through your `known` list and trusted
tools, and everything else falls back to the approval rule.

## Evidence

A defense that refuses everything stops every attack, so every number here
comes with the utility it cost, measured on the same tasks with no attack.

**0.1 on AgentDojo.** 85 held-out tasks and 844 attacked pairs,
`nemotron-3-super-120b`, every approval refused:

| | Attack success | Benign tasks completed |
|:--|--:|--:|
| No defense | 30.7% | 82.4% |
| ProtectAI injection classifier | 5.8% | 51.8% |
| tripwire 0.1 | 4.0% | 36.5% |

0.1 bought its security with utility: after the first untrusted read it gated
every write, and an unattended agent could then only read. The classifier
made the better trade. That result is why 0.2 exists.

**0.2 on AgentDyn.** The study that tests anchoring was
[preregistered](gym/preregistration-v0.2.md) before any result existed, on a
benchmark none of its code or policies were tuned on. It is running; this
section gets its numbers when it finishes, whatever they are.

Confidence intervals, per-suite results, the internal 38-attack corpus and
what each mechanism contributes are in [EVIDENCE.md](EVIDENCE.md).

## What it doesn't do

- It sees MCP tool calls and nothing else. It is not a sandbox: an agent
  with a shell or raw network access can go around it.
- Anchoring checks where a value came from, not whether the agent should use
  it. If the user names a colleague, an injection can still choose what the
  agent sends that colleague.
- Tasks that hand authority to data, like "pay the bill in this file", can't
  be anchored. Those calls go to the approval gate.
- The audit log detects edits. With a key it detects rewrites too, but not a
  log cut short at the end.

The [threat model](THREAT_MODEL.md) goes through each of these.

## Documentation

- [Quickstart](docs/quickstart.md): a Claude Desktop server behind tripwire
- [Policy language](docs/policy.md): every rule, evaluation order, normalization
- [Claude Code](docs/claude-code.md): passing prompts to the proxy
- [Production](docs/production.md): shadow mode, logs, gates, failure modes
- [Benchmarks](docs/benchmarking.md): reproducing every number
- [Threat model](THREAT_MODEL.md) and [evidence](EVIDENCE.md)

## Development

```bash
git clone https://github.com/Sparshg3011/tripwire.git && cd tripwire
python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev,gym]"
.venv/bin/pytest -q
```

Attack scenarios and policies for real MCP servers are the most useful
contributions; [CONTRIBUTING.md](CONTRIBUTING.md) says how. Report security
issues privately through
[GitHub](https://github.com/Sparshg3011/tripwire/security/advisories/new), not
in public issues.

Apache 2.0.
