# tripwire

A deterministic firewall for AI agent tool calls.

Agents read untrusted content — emails, web pages, files. Attackers put
instructions in that content, and models can't reliably tell data from
instructions. You can't stop a model from being fooled, but you can make
sure a fooled model can't do damage.

Tripwire sits between your agent and its MCP tool servers and enforces
policy on every call — outside the model, where no prompt can rewrite
it:

```
agent ──MCP──▶ tripwire ──MCP──▶ your tool server
```

```bash
pip install tripwire-agent
tripwire serve --policy policy.yaml --upstream "npx some-mcp-server" --gate web
```

One policy file says what each tool may do, how much, in what order,
and what needs a human:

```yaml
version: 1
sources:
  fetch_url: untrusted        # taints the session
tools:
  send_email:
    action: allow
    constraints:
      to: { regex: "^[^@]+@mycompany\\.example$" }
    limits: { per_session: 3 }
  delete_file: { action: block, reason: "Destructive; disabled." }
flows:                        # once untrusted content is in play, tighten
  - when: context_tainted
    tools: [send_email, execute_code]
    action: require_approval
```

## I attacked it 38 ways

The repo ships a benchmark that runs a real agent against real attacks
through the real proxy, and publishes both numbers — how many attacks
got stopped, **and what the defence cost when there was no attack at
all.** One figure without the other is marketing.

![security/utility frontier](docs/img/frontier.png)

38 attacks across seven families, each with a benign twin, each verified
to land when undefended. Agent:
`nvidia/nemotron-3-ultra-550b-a55b`, one seed per cell, 760 runs, no
errors.

| condition | attacks stopped | benign tasks still completed |
|---|---|---|
| undefended | 61% (23/38) | 95% |
| shadow | 61% — evaluates, blocks nothing | 97% |
| loose | 74% | 97% |
| **standard** | **87%** | **95%** |
| strict | 100% | 16% |

**The undefended row is not zero, and that is the first finding.** A
competent model refuses most injections by itself — 23 of 38 here. Any
benchmark that reports a firewall stopping "87% of attacks" without
telling you the model already stopped 61% is taking credit for the
model's work.

So the number that matters is the marginal one:

> Of the **15 attacks the model fell for**, tripwire stopped **10** — at
> a cost of ~0% benign completion. With a cautious human at the gate it
> stopped all 15, at a cost of most of the work.

`strict` stops everything and completes 16% of the tasks. That is not a
recommendation, it is the end of the axis — the honest way to show that
"block everything" is not a security posture.

Reproduce it:

```bash
./gym/run_benchmark.sh                    # scripted agent, free, ~4 min
./gym/run_benchmark.sh nvidia 1 nvidia/nemotron-3-ultra-550b-a55b 6
```

### How much of this is noise

`shadow` evaluates every rule and blocks nothing, so it must score
exactly what `undefended` scores. It did in the permissive bracket and
missed by two scenarios in the other one.

That gap is the noise floor. With one seed per cell and a
nondeterministic model, **differences smaller than about five points
are not real**, and the gap between `standard` and `loose` is the only
one here comfortably outside it. Published numbers should use three
seeds or more; these use one, and say so.

### What got through

Five attacks beat `standard` even with the model's own judgement in
front of them: `gate-refund-01`, `multi-grant-01`,
`probe-bom-recipient-01`, `probe-padded-amount-01`, `redirect-body-01`.

They are all the same shape — **the tool was allowed to do exactly
this.** A refund inside every cap. A write to a legal path. A reply to
an allowlisted colleague carrying a body the attacker chose. Constraints
describe *where* a call may act, never *whether it should*. No allowlist
closes this; only a human, or a rule that reads content, does.

### Which layer actually does the work

Taking `standard` apart one mechanism at a time
([full table](docs/ablation.md)):

| layer | marginal contribution |
|---|---|
| tool actions | +2.6 pts |
| **argument constraints** | **+65.8 pts** |
| budgets | +2.6 pts |
| sequence rules | **+0.0 pts** |
| information flow | +0.0 to +28.9 pts, depending entirely on the human |

Boring allowlists do almost all of it. The sequence rules stop nothing
on this corpus. And the taint-and-gate layer — the most architecturally
interesting part — buys you *a place to put a human* and nothing else.

Full methodology, and what these numbers can't tell you, in
[docs/gym.md](docs/gym.md).

## Guarantees

1. **Fail closed.** Unknown tool, malformed policy, evaluator error,
   gate timeout, unwritable audit log — the answer is no, or the proxy
   refuses to run at all.
2. **Pure evaluation.** Policy decisions are a pure function of
   (call, session state, policy): no I/O, no clock, no randomness.
3. **Total mediation.** Tools are discovered from the upstream server
   and re-advertised; within MCP there is no route around the proxy.
4. **Every decision is logged with its reason**, in a hash-chained,
   tamper-evident audit log.
5. **No side effect without a record.** If the log can't be written,
   nothing gets executed.
6. **Monotonic tightening.** Later policy stages can escalate a
   verdict, never relax one.

Tripwire doesn't inspect your content; it controls where content can
flow. There is no classifier in the decision path — decisions are
deterministic, explainable, and reproducible from the log.

## After an incident

```
$ tripwire trace audit.jsonl
session a1b2c3d4 — 4 call(s)

  turn 0   ok     read_email
      args   folder="inbox"
      rule   tools.read_email.action
      →      this result tainted the session

  turn 2   BLOCK  send_email
      args   to="archive@evil.example"
      rule   tools.send_email.constraints.to
      reason to fails the constraint on send_email
      result not forwarded

  untrusted content entered at turn 0 via read_email; every later verdict
  was decided with that in mind.
```

Also: `tripwire report` (what your policy is actually doing),
`tripwire replay --policy candidate.yaml` (what a policy change *would*
have done to traffic you've already seen), and `tripwire verify` (prove
the log hasn't been edited).

## Docs

- [Quickstart](docs/quickstart.md) — secure a Claude Desktop MCP server in 5 minutes
- [Policy language](docs/policy.md) — every rule, evaluation order, canonicalization
- [Production](docs/production.md) — shadow → read → replay → enforce
- [The gym](docs/gym.md) — benchmark methodology and its limits
- [Writeup](docs/writeup.md) — the launch post: problem, design, and what got through
- [Ablation](docs/ablation.md) — which layer actually stops the attacks (answer: the boring one)
- [Threat model](THREAT_MODEL.md) — what this defends, what it doesn't, and what each choice costs

## Related work

NeMo Guardrails, LlamaFirewall and AgentArmor are detection stacks and
voluntary pipelines: they classify, and the agent cooperates. Tripwire
is interposed enforcement — the agent has no route around it — and
publishes a live-agent adversarial benchmark rather than asking you to
trust the design.

## License

Apache-2.0
