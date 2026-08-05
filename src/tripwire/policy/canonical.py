"""One spelling per value, before any rule looks at it.

Attacks on string matching rarely attack the rule. They attack the
*spelling*: a zero-width space inside a domain, a fullwidth 'ａ' in
"admin", a trailing dot on a hostname. The rule still says exactly what
it said; the value just stops looking like what it is.

canonicalize() collapses those spellings before evaluation, and the
proxy forwards *these* args upstream rather than the originals. That is
deliberate: if we checked one form and sent another, the check would be
theatre. The cost is that we hand the tool a lightly-rewritten string,
which is why the rewrites below are small, boring, and enumerated.

Rules for v1 — each one gets attacked in the gym. They are numbered in
policy-doc order, but note the application order in C1/C2: invisibles go
first, and that ordering is load-bearing.

  C2  Drop invisible formatting characters: U+200B zero-width space,
      U+200C, U+200D, U+2060 word joiner, U+FEFF BOM. A zero-width space
      wedged into "corp.com" comes back out.

  C1  Then Unicode NFKC over every string value, anywhere in the args
      (including inside nested dicts and lists). Folds compatibility
      forms: fullwidth "ａdmin" -> "admin", ligature "ﬁle" -> "file".

      Strip-then-normalize, not the other way round, because deleting an
      invisible can leave two characters adjacent that then compose:
      "e" + U+200B + combining acute has to end up as "é", and it only
      does if NFKC runs last. Run in the other order the function isn't
      idempotent, and a rule that gives a different answer the second
      time you ask it isn't a rule.

      Dict *keys* are left alone. Normalizing them can collide two
      distinct keys into one ({"ａmount": 1, "amount": 2}) and silently
      drop a value, which is a worse bug than the one it would fix.

  C3  (not here — comparison time, inside the evaluator) casefold both
      sides when a constraint sets case_insensitive.

  C4  Strip *all* trailing dots from host-like top-level fields, so
      "corp.com." and "corp.com.." both become "corp.com". "Host-like"
      is a fixed field-name list: url, host, hostname, domain, to,
      recipient, email, address. A DNS name with a trailing dot resolves
      the same as one without, so the spellings must not evaluate
      differently — and stripping only one would leave "corp.com.."
      still dotted while also making the function non-idempotent.

  C5  On top-level fields the policy constrains with type: number, parse
      a numeric string to float — "1e2" -> 100.0, " 42 " -> 42.0.
      "Numeric" means exactly this, after stripping surrounding ascii
      whitespace, and nothing else:

          ^[+-]?([0-9]+\\.?[0-9]*|\\.[0-9]+)([eE][+-]?[0-9]+)?$

      Spelled out as a pattern rather than "whatever float() accepts",
      because float() also takes "1_000", "nan", "inf", and non-ascii
      digits like "١٢" that NFKC does not fold. Anything that doesn't
      match, or parses to a non-finite value, is left exactly as it was
      so the evaluator blocks it. Bools are never touched (True is not 1
      here).

Deliberately NOT in v1. These are named in THREAT_MODEL.md instead of
being half-built, because a decoder that handles four of five encodings
is worse than none — it moves the bypass somewhere less obvious:

  * no HTML entity unescaping        * no URL percent-decoding
  * no base64 or nested decoding     * no homoglyph/confusable folding

That last one is a real gap with a safe failure mode: Cyrillic 'а' in
"аdmin@corp.com" stays Cyrillic, so it simply fails an ASCII allowlist
and the call is blocked. Under-matching an allowlist fails closed.

Contract: pure, total, deterministic, and idempotent — canonicalizing
twice gives what canonicalizing once gave. No I/O, no clock, no
randomness, no mutation of the input mapping. It must never raise: args
come straight off the wire, so anything at all can be in there.

Values it doesn't know how to canonicalize (a set, some object a future
transport hands us) pass through untouched rather than causing a raise.
JSON in, JSON out — and since MCP args arrive as parsed JSON, that's
every real call.

The spec above is executable in tests/test_canonical.py. Delete the skip
line there and make it green.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tripwire.policy.schema import Policy

HOST_FIELDS = frozenset(
    {"url", "host", "hostname", "domain", "to", "recipient", "email", "address"}
)

# spelled out rather than pasted — you can't review a character you
# can't see, which is the entire reason this set exists
INVISIBLE = frozenset("\u200b\u200c\u200d\u2060\ufeff")


def canonicalize(tool: str, args: Mapping[str, Any], policy: Policy) -> dict[str, Any]:
    raise NotImplementedError("canonicalize not written yet — see module docstring")
