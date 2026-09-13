# Exact pre-approvals (experimental library API)

`ExactApprovalGate` lets a trusted host authorize a **complete, known tool call
once** before an agent session starts. The call can then execute after reading
untrusted content without approving arbitrary future actions or clearing taint.
The default CLI and existing policies are unchanged.

This is useful for tasks with known arguments: an explicitly approved payment,
fixed message, or specific record update. It does **not** infer user intent,
validate arbitrary generated summaries, or resolve targets from untrusted data.
It is not yet a demonstrated recovery of AgentDojo's lost benign utility.

## Embed it

The application, not the agent, obtains approval for the exact canonical tool
name and every argument through a trusted control surface. Then, before any
calls or untrusted observations in the session:

```python
from tripwire.gate import ExactApprovalGate
from tripwire.policy import load_policy
from tripwire.policy.types import ToolCall
from tripwire.proxy.interceptor import Interceptor
from tripwire.session import SessionState

policy = load_policy("policy.yaml")
session = SessionState(policy)

# Supplied by the trusted host after explicit authorization, not extracted
# from an agent plan, email, webpage, or benchmark solution.
gate = ExactApprovalGate(
    session,
    [ToolCall("send_email", {
        "to": "colleague@example.com",
        "subject": "Meeting",
        "body": "The meeting is confirmed for 10:00.",
    })],
    ttl_seconds=300,
)
# audit is an AuditLog; upstream is an already-started MCP Upstream.
interceptor = Interceptor(policy, audit, upstream, session, gate=gate)
# Send the agent's calls through interceptor.handle(...).
# When this task ends, revoke remaining grants:
# gate.close()
```

Every tool with a grant must have `action: require_approval` **unconditionally**:

```yaml
version: 1
defaults: {unknown_tools: block}
sources: {read_email: untrusted}
tools:
  read_email: {action: allow}
  send_email:
    action: require_approval
    constraints:
      body: {type: string, max_length: 1000}
    limits: {per_session: 1}
```

Flow-only approval is rejected at registration: otherwise the same call could
execute before taint without consuming its grant, then execute again afterwards.
Other sensitive tools still need explicit policy rules; this example is not a
complete policy for an arbitrary upstream server.

## Contract and limits

- Exact full-argument matching, including nested values and extra/missing
  keys. No wildcard recipients, variable payloads, regex grants, or implicit
  argument defaults. The host must authorize the full call it expects.
- Registration uses the existing policy canonicalizer. The host's approval is
  for those **canonical values**, which are also what the proxy forwards.
  JSON scalar types remain distinct unless the policy canonicalizes them.
- One use per registered call, in one live `SessionState`, with a finite
  lifetime (default five minutes). Either its monotonic or wall-clock deadline
  expires the grant, including across system sleep. Duplicate canonical calls
  are rejected instead of silently increasing the allowed execution count.
- Consume before forwarding. Errors, cancellations, and uncertain outcomes do
  not restore an approval. Obtain a new authorization only after checking what
  actually happened; do not automatically recreate gates to retry.
- No override of policy blocks, constraints, limits, or sequences. Taint stays
  set. A changed policy or an unobserved execution invalidates approvals when
  detected; do not mutate policies during a session.
- No MCP endpoint to issue grants. Keep host code, policy files, and approval
  inputs outside the agent's write authority. A compromised host can bypass
  this defense, as it can bypass the proxy itself.
- Grants are in-memory, not a durable cross-process exactly-once guarantee.
  A new gate is new authority, not a restart/resume mechanism. Use upstream
  idempotency and durable task ownership where side effects require them.
- A grant authorizes an action, not its ordering or a prerequisite. Express
  order restrictions separately; exact approval alone cannot require a read
  or business validation to happen first.
- No claim of human review is fabricated: the audit records the gate type,
  and refusal text says the gate denied the call.

The gate is intentionally library-only while its workflow is evaluated. It
does not add an unattended permissive mode to `tripwire serve`.

## Evidence and remaining work

Contract tests cover a real MCP upstream plus recipient, amount, body, and
extra-field substitution, one-use consumption before and after taint, replay,
cross-session use, concurrency, expiry, revocation, invalid data, cancelled and
failed forwarding, and hard-policy blocks. Run:

```bash
pytest -q tests/test_exact_gate.py
```

Those are regression tests, **not** agent completion or attack-success rates.
The [paired utility diagnosis](results/utility-diagnosis/REPORT.md) identifies
the original failure population without claiming that this gate repairs it.

Before a practical-use release claim:

1. Evaluate a real trusted-host approval workflow on development cases. Count
   how many tasks have sufficient information for exact authorization and how
   often the user must intervene. Do not fill grants from a task checker,
   attack label, expected answer, or successful baseline trace.
2. Measure completion, attack success, and approval burden together. Failed
   runs remain visible. A refusal becoming an approval is not task recovery.
3. Freeze the revised workflow and run an independent evaluation. The original
   held-out outcomes are now known: rerunning that population after tuning is
   exploratory, not a new untouched held-out result.

Tasks requiring arbitrary content-dependent mutations remain unresolved by
exact pre-approval and still require interactive review or a separately
validated authorization design.
