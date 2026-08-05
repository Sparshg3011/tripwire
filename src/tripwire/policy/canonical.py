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

Rules for v1 — each one gets attacked in the gym:

  C1  Unicode NFKC on every string, anywhere in the args (including
      inside nested dicts and lists). Folds compatibility forms:
      fullwidth "ａdmin" -> "admin", ligature "ﬁle" -> "file".

  C2  Drop invisible formatting characters: U+200B zero-width space,
      U+200C, U+200D, U+2060 word joiner, U+FEFF BOM. A zero-width space
      wedged into "corp.com" comes back out. Applied after C1.

  C3  (not here — comparison time, inside the evaluator) casefold both
      sides when a constraint sets case_insensitive.

  C4  Strip one trailing dot from host-like top-level fields, so
      "corp.com." -> "corp.com". "Host-like" is a fixed field-name list:
      url, host, hostname, domain, to, recipient, email, address.
      A DNS name with a trailing dot resolves the same as one without,
      so the two spellings must not evaluate differently.

  C5  On top-level fields the policy constrains with type: number, parse
      a numeric string to float when the parse is exact and finite —
      "1e2" -> 100.0, " 42 " -> 42.0. Anything that doesn't parse, or
      parses to nan/inf, is left exactly as it was so the evaluator
      blocks it. Bools are never touched (True is not 1 here).

Deliberately NOT in v1. These are named in THREAT_MODEL.md instead of
being half-built, because a decoder that handles four of five encodings
is worse than none — it moves the bypass somewhere less obvious:

  * no HTML entity unescaping        * no URL percent-decoding
  * no base64 or nested decoding     * no homoglyph/confusable folding

That last one is a real gap with a safe failure mode: Cyrillic 'а' in
"аdmin@corp.com" stays Cyrillic, so it simply fails an ASCII allowlist
and the call is blocked. Under-matching an allowlist fails closed.

Contract: pure, total, deterministic. No I/O, no clock, no randomness,
no mutation of the input mapping. It must never raise — args come
straight off the wire, so anything at all can be in there. Returns a
plain JSON-serializable dict (the proxy forwards it, so it may not
contain Decimals, sets, or custom objects).

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
