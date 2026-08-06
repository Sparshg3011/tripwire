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
    action: require_approval
    constraints:
      to: { regex: "^[^@]+@mycompany\\.com$" }
    limits: { per_session: 3 }
  delete_file: { action: block, reason: "Destructive; disabled." }
flows:                        # once untrusted content is in play, tighten
  - when: context_tainted
    tools: [send_email, execute_code]
    action: require_approval
```

## Guarantees

1. **Fail closed.** Unknown tool, malformed policy, evaluator error,
   gate timeout, unwritable audit log — the answer is no, or the proxy
   refuses to run at all.
2. **Pure evaluation.** Policy decisions are a pure function of
   (call, session state, policy): no I/O, no clock, no randomness.
3. **Total mediation.** Tools are discovered from the upstream server
   and re-advertised; within MCP there is no route around the proxy.
4. **Every decision is logged with its reason**, in a hash-chained,
   tamper-evident audit log (`tripwire verify`).
5. **No side effect without a record.** If the log can't be written,
   nothing gets executed.
6. **Monotonic tightening.** Later policy stages can escalate a
   verdict, never relax one.

Tripwire doesn't inspect your content; it controls where content can
flow. There is no classifier in the decision path — decisions are
deterministic, explainable, and reproducible from the log.

## Status

Work in progress, moving fast — v0.1 lands this month, together with
an adversarial benchmark: a live-agent gym that attacks this thing a
hundred ways and publishes what got through.

See [THREAT_MODEL.md](THREAT_MODEL.md) for exactly what this defends
and what it deliberately does not.

## License

Apache-2.0
