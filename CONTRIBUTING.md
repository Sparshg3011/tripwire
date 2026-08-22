# Contributing

## Setup

```bash
git clone https://github.com/Sparshg3011/tripwire
cd tripwire
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev,gym]"
.venv/bin/pytest -q
```

Everything CI runs, you can run:

```bash
ruff check src tests
ruff format --check src tests
mypy --strict src/tripwire/policy src/tripwire/tx
pytest -q
python -m tripwire_gym --agent scripted --conditions undefended,standard --out /tmp/gym
```

## Attack scenarios are the most welcome contribution

If you can get something past tripwire, that's the most useful thing
you can send. A scenario is one YAML file in `gym/scenarios/` plus its
benign twin — [docs/gym.md](docs/gym.md) has the schema and a worked
example.

The bar is that it has to be **machine-checkable**. "The model said
something alarming" isn't a scenario; "the agent called `send_email`
with a recipient outside the allowlist" is. If you can't express the
attack as a call that did or didn't happen with matching arguments, it
can't be run a hundred times, and a benchmark that needs a human to
read the transcripts isn't a benchmark.

Hand-verify both halves before sending: run the attack undefended and
confirm it lands, run the twin and confirm the task completes. A
scenario whose attack never works even with no defence measures
nothing.

## Policy packs

Real policies for real MCP servers — filesystem, GitHub, Slack — are
genuinely useful and easy to get subtly wrong. Send them with a note
about what you're protecting and what you deliberately allowed.

## Code

A few house rules that come from what this thing is:

- **Fail closed.** Any new path that can error must end in a refusal,
  not a traceback and not a silent allow. If you add a branch, ask what
  it does when the thing it depends on is broken.
- **The evaluator stays pure.** No I/O, no clock, no randomness. It's
  what makes decisions reproducible from the log, and it's why the
  property tests can hammer it.
- **Every decision gets logged with its reason.** A refusal the operator
  can't explain afterwards is a support ticket.
- Comments explain *why*, not what. If a line needs a comment to say
  what it does, the line is the problem.

Tests: unit tests for pure logic, and at least one test that goes
through the real proxy for anything touching the request path. Fakes
are fine at the seams (`canonicalize`, `evaluate`, the gate) — that's
what they're injectable for.

## Commit history

Keep each commit focused on one reviewable concern. Write the subject in
imperative sentence case, keep it concise, and use the body to explain why
the change exists when the diff cannot do that on its own.

Good subjects describe an outcome:

- `Harden AgentDojo runs against API rate limits`
- `Add completeness receipts to publication reports`
- `Document the shadow-to-enforcement rollout`

Avoid subjects such as `changes`, `formatting`, or `fix stuff`. Before opening
a pull request, squash local fixups into their logical parent commits. Never
rewrite a branch that other contributors may already be using.

## Security issues

Please don't open a public issue. See [SECURITY.md](SECURITY.md).
