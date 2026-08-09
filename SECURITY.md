# Security policy

## Reporting a vulnerability

Please report privately, through GitHub's private vulnerability
reporting: **[open a draft advisory](https://github.com/Sparshg3011/tripwire/security/advisories/new)**.

Don't open a public issue for anything that lets an attacker get past
enforcement — the people running tripwire deserve a fix before the
technique is public.

**What to expect:** an acknowledgement within 3 days, an assessment
within 7, and a fix or a clear explanation of why it isn't one. If you
want credit in the advisory, say so; if you'd rather not be named,
that's fine too.

## What counts

Anything that breaks one of the guarantees in the README:

- A tool call reaching an upstream server without a verdict
- A verdict that should have been a block or a gate coming back as allow
- A side effect with no audit record, or a record that can be altered
  without breaking the chain
- Getting the proxy to fail *open* rather than closed
- Reaching the approval gate's decision endpoint without the token, or
  otherwise approving a call the human didn't approve
- Argument spellings that pass a constraint but reach the tool meaning
  something else

Attacks on the gym's scoring also count. A benchmark that can be made
to report a better number than reality is a security problem in its
own right.

## What doesn't

These are documented limits, not vulnerabilities — see
[THREAT_MODEL.md](THREAT_MODEL.md) for the reasoning:

- Anything requiring control of the host, the policy file, or the
  tripwire process itself
- Harms an agent causes without making a tool call
- Non-MCP side channels (an agent that can also run shell commands has
  doors tripwire never sees)
- A malicious upstream server lying about what it did
- A permissive policy doing what it says (tripwire enforces the policy
  you wrote, not the one you meant)
- Tail truncation of the audit log, and the final record being
  unauthenticated until another follows it

If you're unsure which side of that line something falls on, report it
anyway. A false alarm costs a few minutes; the alternative doesn't.

## Supported versions

Pre-1.0: fixes land on `main` and in the next release. There are no
backports yet.
