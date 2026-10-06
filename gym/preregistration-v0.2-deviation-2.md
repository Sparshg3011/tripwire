# Second deviation: AgentDyn ran without enforcement

Written on 2026-10-03, after [the first deviation](preregistration-v0.2-deviation.md),
before any rerun below had produced a result.

## What happened

AgentDyn runs in its own environment, and its dependencies (through
`pydantic-ai`) installed `mcp` 2.2.0 over the 1.x tripwire requires.
`mcp` 2 renamed `CallToolResult.isError`, which the interceptor reads
after every call. So on AgentDyn each guarded call ran, the interceptor
raised after it, and the adapter, seeing that the call had run, handed
its result back with nothing recorded. No result was observed, no
session was tainted, and no flow with or without `unless: anchored` was
ever consulted. Only the rules that act before a call runs (unknown
tools, argument contracts, limits) applied.

AgentDojo runs in the main environment, on `mcp` 1.29.0, and was not
affected: its audit logs hold a result for every forwarded call, and its
gates fired 509 times.

It was found while rebuilding the primary model's results from traces:
the summary showed no intervention at all in either tripwire arm, which
the policies make impossible, and the audit logs showed calls forwarded
with no result after them. Those summaries measure a policy that never
engaged; they are not reported as results. The smoke test before the
study checked for errors and tool calls, not for enforcement, which is
how this got past it.

## What changes

1. **The tripwire arms on AgentDyn are void, for both models.** They
   are kept, for audit, under `gym/results/v0.2/invalid-mcp2/`.
2. **No hypothesis is decided on the primary model.** Its AgentDyn
   tripwire arms are void and it can no longer be run. This replaces
   item 1 of the first deviation. Its valid arms, AgentDyn `direct` and
   AgentDojo `tripwire-deny/primary`, are reported as such.
3. **The second model's `tripwire-deny/taint` and
   `tripwire-deny/primary` cells on AgentDyn are rerun from scratch**
   at the tag `prereg-v0.2-r1`: `prereg-v0.2` plus the harness fix and
   nothing else (4 files, 65 lines). tripwire now refuses to import
   under `mcp` 2, and the adapter raises when the interceptor fails
   after a call ran, so such a case can't be scored. Decision code,
   policies, conditions and analysis are unchanged.
4. The second model's `direct` and detector cells have no tripwire in
   their path, so they stand and keep running. The AgentDyn environment
   is pinned to `mcp` 1.29.0, and `pip check` passes in it.

All three hypotheses are decided on the second model, as the first
deviation already said, by the preregistered rules.
