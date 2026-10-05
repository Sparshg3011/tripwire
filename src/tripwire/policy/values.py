"""Typed keys for argument values, and the texts that anchor or poison them.

Anchoring compares one argument value against everything the session has
seen, so the value first needs exactly one spelling. normalize() reduces a
leaf to one of three outcomes:

  Key(vtype, key)        the value's one spelling, under one type
  Invalid(reason)        malformed, or a spelling parsers may read two
                         ways. An Invalid target blocks at any taint level.
  Unanchorable(reason)   well formed, but nothing may vouch for it

None means absent: null, "", or a string the pre-step empties.

Pre-step, on every string: C2 (drop the five invisibles), C1 (NFKC), trim.
It is canonicalize()'s own C2-then-C1, so a key is computed from the form
that is forwarded. Any Cc, Cf or Cs character left over makes the value
Invalid; the bidi controls U+202A-202E and U+2066-2069 are all Cf.

Type detection for `auto`, first match wins:

  1. a JSON int is an id (its decimal string); float and bool are Invalid
  2. starts with http://, https:// or www.         -> url
  3. contains @                                   -> email; a list joined
     with , or ; whose every part is an email is split (normalize_all)
  4. IBAN shape: uppercase, no spaces or hyphens   -> iban
  5. starts with +                                 -> phone
  6. starts with /, ./ or ~                        -> path
  7. one atom, 2+ labels, last one a pinned TLD,   -> host
     lowercase already and no trailing dot
  8. one atom with a digit or one of _.:-#/        -> id
  9. anything else                                 -> name

Under auto nothing says the value is not a case-sensitive id or file
name, so rules 4 and 7 take only spellings their normalizers keep as they
are: "Report.md" and "fe12-release-candidate" are ids, not the host
"report.md" or the IBAN "FE12RELEASECANDIDATE".

Normalizers:

  email  unwrap `Name <a>` and mailto:, lowercase, strip the domain's
         trailing dots. Invalid outside [a-z0-9._%+-]+@label(.label)*.tld,
         with `..`, a local part over 64 or a total over 254. A domain
         label is [a-z0-9-]+: RFC 5321 gives a mail domain no underscore,
         though a host may have one. Non-ASCII is Unanchorable. Plus tags
         and Gmail dots are not folded.
  host   host[:port]: lowercase, strip trailing dots, drop one leading
         www., fold ports 80 and 443. Labels are LDH, and any but the last
         may hold underscores where it may hold hyphens; an underscore is
         kept, so shop_center.com and shop-center.com are two keys.
         Invalid: any other label, fewer than 2 labels, any IPv4 spelling
         but dotted decimal, non-canonical bracketed IPv6, a bad port.
         Non-ASCII is Unanchorable; xn-- labels compare as ASCII. A host
         named like a control file (claude.md) is Unanchorable.
  url    the key is the host key of its authority, so a URL anchors by
         host[:port]; path, query and fragment are content. Invalid: a
         scheme other than http(s), userinfo, a backslash, whitespace, % in
         the authority.
  iban   drop spaces and hyphens, uppercase; Invalid outside
         [A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}
  phone  drop " ().-", a leading 00 becomes +; Invalid unless 7-15 digits
  path   POSIX, case-sensitive: drop empty and . segments, keep a leading
         / or // (a network share on Windows; /// is /). Invalid with a
         backslash. Unanchorable: `..` anywhere, a key that starts with ~
         or that the pre-step would trim, a control segment, or a
         protected path (below).
  id     as given, [A-Za-z0-9_.:/#-]{1,128}, case-sensitive
  name   lowercase, collapse whitespace; a leading @ or # stays, since
         "@random" and "#random" can name two things on one API. Invalid
         over 128 characters or 8 words. Unanchorable under 3 characters
         past the sigil, with no letter, or reserved (unless normalizing a
         `known` entry).

Control segments (data/control_paths.txt) are compared the way APFS and
NTFS read a segment: NFKC and casefolded, whole and part by part between
colons, since NTFS reads a drive prefix ("C:.git") and a stream suffix
("CLAUDE.md::$DATA") off the name, and without the trailing dots and
spaces Win32 drops (".git.").
A segment shaped like an 8.3 short name ("GIT~1") can alias any of them and
counts as one. A path, id or name with a control segment, split at slashes
and backslashes, is Unanchorable under every type, auto included.

A protected path (the policy file, the audit log, the tx db, the task
file) makes a path, id, name or host key Unanchorable when the key is at
or under it, or when any segment of the key, read as control segments
are, is the protected path's last one. Relative spellings and symlinked
prefixes (/tmp for /private/tmp) reach the same file, and nothing here
may resolve them. forbidden_path() puts both tests to a string that no
type reads, such as a file name a tool takes as content.

Every key is a fixed point: normalizing key.key under key.vtype gives the
key back. TaskIndex.anchors() leans on that to refuse hand-built keys.

Extraction runs in two directions and is asymmetric on purpose:

  TaskIndex    conservative. Maximal tokens bounded on both sides, so a
               token that is part of something longer anchors nothing; a
               hidden character (a mark, a format character or another
               default-ignorable one) left inside a token after NFKC
               joins it. Ids only at 6+ characters or next to a label;
               names only as whole phrases, not glued by -./@#' and the
               like to a longer token.
  scan_poison  greedy. The same extractors with every limit removed, plus
               the text itself in the forms is_poisoned()'s text rule
               reads, over the text as written and as a reader may take
               it: with its JSON string escapes decoded, its hidden
               characters deleted, or both. Whatever the task extractors
               find in a text, and whatever key a whole field of it
               registers, that text scanned as poison poisons. A scan
               stops at MAX_SCAN_KEYS typed keys and then poisons every
               key.

whole_fields() lists the leaves of a JSON value that can register as keys:
strings of at most 256 characters and 8 words, ints, and dict keys of at
most 256 characters, each under every type that accepts it, walked in
sorted key order. A host or IBAN key registers only from its own
spelling, as under auto.

Comparison is exact on normalized keys. There is no confusable folding: a
Cyrillic 'а' in an address fails to match, which fails closed.

Contract: pure, total, deterministic. The two pinned lists under
tripwire/data are read once at import; after that no I/O, no clock, no
randomness, no mutation of inputs. Nothing raises: values come off the
wire, so deep nesting, cycles, non-string keys, lone surrogates and huge
strings all get an answer, and an input nothing can read gets the answer
that fails closed. Extraction is linear in the text.

The spec above is executable in tests/test_values.py.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from importlib.resources import files
from typing import Literal, Self, TypeAlias

from tripwire.policy.canonical import _clean

ValueType = Literal["email", "url", "host", "iban", "phone", "path", "id", "name"]
VType = Literal["auto", "email", "url", "host", "iban", "phone", "path", "id", "name"]
# no "url": a URL's key is its host key
KeyType = Literal["email", "host", "iban", "phone", "path", "id", "name"]

VALUE_TYPES: tuple[ValueType, ...] = (
    "email",
    "url",
    "host",
    "iban",
    "phone",
    "path",
    "id",
    "name",
)


@dataclass(frozen=True, slots=True)
class Key:
    vtype: KeyType
    key: str


@dataclass(frozen=True, slots=True)
class Invalid:
    reason: str


@dataclass(frozen=True, slots=True)
class Unanchorable:
    reason: str


Outcome: TypeAlias = Key | Invalid | Unanchorable


def _fold(text: str) -> str:
    # NFKC then casefold. Checked exhaustively over single code points to
    # be idempotent; the other order is not ("㎒" -> "MHz").
    return unicodedata.normalize("NFKC", text).casefold()


def _pinned(name: str) -> frozenset[str]:
    text = (files("tripwire") / "data" / name).read_text(encoding="utf-8")
    lines = (line.strip() for line in text.splitlines())
    return frozenset(line for line in lines if line and not line.startswith("#"))


TLDS = frozenset(tld.lower() for tld in _pinned("tlds.txt"))
CONTROL_SEGMENTS = frozenset(_fold(segment) for segment in _pinned("control_paths.txt"))

# A bare host ending in one of these, without www., is usually a file name:
# common file extensions that are also delegated TLDs. Not "com": a DOS
# executable is rarer than a bare .com host by far. "ly" is in: the bare
# .ly hosts people write are link shorteners, which vouch for nothing.
FILE_EXT_TLDS = frozenset(
    {
        # source and build files
        "ac",
        "am",
        "cc",
        "cl",
        "coffee",
        "cr",
        "gs",
        "in",
        "java",
        "la",
        "ly",
        "mk",
        "ml",
        "mm",
        "pl",
        "pm",
        "py",
        "re",
        "rs",
        "sc",
        "sh",
        "so",
        "st",
        "sv",
        "tf",
        # configuration
        "cf",
        "fish",
        "work",
        # documents, data, archives and bundles
        "ai",
        "app",
        "bz",
        "cab",
        "md",
        "mo",
        "mobi",
        "mov",
        "nc",
        "ps",
        "pt",
        "pub",
        "run",
        "zip",
    }
)

RESERVED_NAMES = frozenset(
    {
        "all",
        "everyone",
        "channel",
        "here",
        "me",
        "admin",
        "root",
        "owner",
        "administrator",
        "null",
        "none",
        "undefined",
    }
)

# sentence punctuation that ends a URL token rather than belonging to it
TRAILING = ".,;:!?)]}'\""

MAX_FIELD_CHARS = 256
MAX_FIELD_WORDS = 8
# the per-result depth cap on what provenance walks
MAX_FIELD_DEPTH = 64
# typed keys one poison scan may hold: the per-session key cap, so that one
# 2 MiB result can't allocate past it before any session cap applies
MAX_SCAN_KEYS = 200_000

# --- pre-step ----------------------------------------------------------------

_CONTROL_CATEGORIES = frozenset({"Cc", "Cf", "Cs"})
_ASCII_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SURROGATE = re.compile("[\ud800-\udfff]")
_SPACE = re.compile(r"\s")


def _has_control(text: str) -> bool:
    if _ASCII_CONTROL.search(text):
        return True
    if text.isascii():
        return False
    return any(unicodedata.category(c) in _CONTROL_CATEGORIES for c in text if c > "\x7f")


def _prestep(value: str) -> str | Invalid:
    text = _clean(value).strip()
    if _has_control(text):
        return Invalid("control_char")
    return text


def _decimal(value: int) -> str | None:
    # str() of an int past sys.get_int_max_str_digits() raises, and nothing
    # that long is a valid key of any type
    if int.bit_length(value) > 430:
        return None
    return int.__repr__(value)


# --- normalizers -------------------------------------------------------------

_EMAIL = re.compile(r"[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,63}")
# a display name that could itself read as an address, or split a list,
# makes the whole value ambiguous, so it doesn't unwrap
_ANGLE = re.compile(r"([^<>@,;]*)<([^<>]*)>")
# LDH, plus underscores where a hyphen may go: browsers and resolvers read
# shop_center.com as written. Not at a label's ends, where one opens or
# closes Markdown emphasis around a host (_x.com_), which the link scanner
# reads past, or starts a DNS service label (_dmarc). Not in the last label,
# which no TLD spells with one and which decides whether a host is an IPv4
# address.
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?")
# what a URL parser treats as the last label of an IPv4 address
_NUMERIC_LABEL = re.compile(r"0x[0-9a-f]*|[0-9]+")
_DOTTED_QUAD = re.compile(r"(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}")
_PORT = re.compile(r"[0-9]{1,5}")
_AUTHORITY_END = re.compile(r"[/?#]")
_IBAN = re.compile(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}")
_PHONE = re.compile(r"\+?[0-9]{7,15}")
_PHONE_SEPARATORS = str.maketrans("", "", " ().-")
_ID = re.compile(r"[A-Za-z0-9_.:/#-]{1,128}")
_ID_HINT = re.compile(r"[0-9_.:#/-]")
_LIST_SEPARATOR = re.compile(r"[,;]")
_SEGMENT_SEPARATOR = re.compile(r"[/\\]")
_SHORT_NAME = re.compile(r"[^.~]{1,6}~[0-9]{1,6}(?:\.[^.]*)?")


def _names(text: str) -> Iterator[str]:
    """Every name a segment of text may open: the segment, and each part
    of it between colons, since NTFS reads both "C:.git" (on drive C) and
    ".git::$INDEX_ALLOCATION" as .git. None has the trailing dots and
    spaces Win32 drops."""
    for segment in _SEGMENT_SEPARATOR.split(text):
        folded = _fold(segment)
        yield folded.rstrip(". ")
        if ":" in folded:
            for part in folded.split(":"):
                yield part.rstrip(". ")


def _is_control(text: str) -> bool:
    for name in _names(text):
        if name in CONTROL_SEGMENTS or _SHORT_NAME.fullmatch(name):
            return True
    return False


def _email(text: str) -> Outcome:
    angle = _ANGLE.fullmatch(text)
    if angle is not None:
        text = angle.group(2).strip()
    if text[:7].lower() == "mailto:":
        text = text[7:]
    if not text.isascii():
        return Unanchorable("idn")
    text = text.lower().rstrip(".")
    if len(text) > 254:
        return Invalid("too_long")
    if _EMAIL.fullmatch(text) is None or ".." in text:
        return Invalid("email")
    if len(text.partition("@")[0]) > 64:
        return Invalid("too_long")
    return Key("email", text)


def _hostname(host: str) -> str | Invalid:
    labels = host.split(".")
    if len(labels) < 2:
        return Invalid("labels")
    if len(host) > 253:
        return Invalid("too_long")
    if "_" in labels[-1] or any(_LABEL.fullmatch(label) is None for label in labels):
        return Invalid("label")
    if _NUMERIC_LABEL.fullmatch(labels[-1]):
        # octal, hex and short forms all reach an address; only canonical
        # dotted decimal is one spelling of one address
        if _DOTTED_QUAD.fullmatch(host) and all(int(label) <= 255 for label in labels):
            return host
        return Invalid("ipv4")
    # one www. only, and only when what is left is still a host: dropping
    # it from "www.www.x.com" would make the key normalize again differently
    if labels[0] == "www" and len(labels) > 2 and labels[1] != "www":
        return ".".join(labels[1:])
    return host


def _ipv6(host: str) -> str | Invalid:
    inner = host[1:-1]
    if "%" in inner:
        return Invalid("ipv6")
    try:
        address = ipaddress.IPv6Address(inner)
    except ValueError:
        return Invalid("ipv6")
    # An IPv4 address mapped into IPv6 reaches the IPv4 host, and Python
    # prints one dotted or not depending on its release, so the canonical
    # spelling below would accept it on some and not others.
    if address.ipv4_mapped is not None or address.compressed != inner:
        return Invalid("ipv6")
    return host


def _host(text: str) -> Outcome:
    """host[:port]. A port is accepted so that a URL's key is a host key
    and normalizes back to itself."""
    if not text.isascii():
        return Unanchorable("idn")
    text = text.lower()
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            return Invalid("ipv6")
        host, rest = text[: end + 1], text[end + 1 :]
    else:
        host, colon, port = text.partition(":")
        rest = colon + port

    suffix = ""
    if rest:
        digits = rest[1:]
        if not rest.startswith(":") or _PORT.fullmatch(digits) is None:
            return Invalid("port")
        number = int(digits)
        if not 0 < number <= 65535:
            return Invalid("port")
        if number not in (80, 443):
            suffix = f":{number}"

    name = _ipv6(host) if host.startswith("[") else _hostname(host.rstrip("."))
    if isinstance(name, Invalid):
        return name
    # "CLAUDE.md" is a host by shape; as a file it must never anchor
    if _is_control(name):
        return Unanchorable("control_path")
    return Key("host", name + suffix)


def _url(text: str) -> Outcome:
    if "\\" in text:
        return Invalid("backslash")
    if _SPACE.search(text):
        return Invalid("whitespace")
    head = text[:8].lower()
    if head.startswith("http://"):
        rest = text[7:]
    elif head.startswith("https://"):
        rest = text[8:]
    elif head.startswith("www."):
        rest = text
    else:
        return Invalid("scheme")
    authority = _AUTHORITY_END.split(rest, maxsplit=1)[0]
    if "@" in authority:
        return Invalid("userinfo")
    if "%" in authority:
        return Invalid("percent")
    return _host(authority)


def _iban_form(text: str) -> str | None:
    # ASCII first: upper() turns "ß" into "SS"
    if not text.isascii():
        return None
    return text.replace(" ", "").replace("-", "").upper()


def _iban(text: str) -> Outcome:
    compact = _iban_form(text)
    if compact is None or _IBAN.fullmatch(compact) is None:
        return Invalid("iban")
    return Key("iban", compact)


def _phone(text: str) -> Outcome:
    compact = text.translate(_PHONE_SEPARATORS)
    if compact.startswith("00"):
        compact = "+" + compact[2:]
    if _PHONE.fullmatch(compact) is None:
        return Invalid("phone")
    return Key("phone", compact)


def _path_key(text: str) -> str:
    segments = [segment for segment in text.split("/") if segment not in ("", ".")]
    # POSIX leaves a leading "//" to the system, and Windows and Cygwin
    # read "//host/share" as a network share; three or more are one "/"
    if text.startswith("//") and not text.startswith("///"):
        root = "//"
    elif text.startswith("/"):
        root = "/"
    else:
        root = ""
    return root + "/".join(segments)


def _protected_root(entry: object) -> str | None:
    if not isinstance(entry, str):
        return None
    root = _fold(_path_key(_clean(str.__str__(entry)).strip()))
    return root or None


def _is_protected(key: str, protected_paths: Sequence[str]) -> bool:
    if not protected_paths:
        return False
    folded = _fold(key)
    names = set(_names(key))
    for entry in protected_paths:
        root = _protected_root(entry)
        if root is None:
            continue
        if folded == root or is_under(folded, root):
            return True
        # "tripwire.yaml", "./audit.jsonl" and "/tmp/x/audit.jsonl" may all
        # be /private/tmp/x/audit.jsonl; only its last segment is certain
        base = root.rpartition("/")[2].rstrip(". ")
        if base and base in names:
            return True
    return False


def _path(text: str) -> Outcome:
    if "\\" in text:
        return Invalid("backslash")
    if ".." in text:
        return Unanchorable("dotdot")
    key = _path_key(text)
    if not key:
        return Unanchorable("empty")
    # read off the key, which is what normalizes again: "./~notes/x" has
    # the key "~notes/x", and "./ x" one the pre-step trims to "x"
    if key.startswith("~"):
        return Unanchorable("home")
    if key != key.strip():
        return Unanchorable("whitespace")
    if _is_control(key):
        return Unanchorable("control_path")
    return Key("path", key)


def _id(text: str) -> Outcome:
    if _ID.fullmatch(text) is None:
        return Invalid("id")
    # ".git/hooks/pre-commit" is an id by shape
    if _is_control(text):
        return Unanchorable("control_path")
    return Key("id", text)


def _name(text: str, known: bool) -> Outcome:
    # lower(), not casefold(): an upstream that ignores case lowercases,
    # and keeps "straße" apart from "strasse"
    name = " ".join(text.lower().split())
    bare = name[1:].lstrip() if name[:1] in ("@", "#") else name
    if bare[:1] in ("@", "#"):
        return Unanchorable("prefix")
    if len(name) > 128:
        return Invalid("too_long")
    if len(name.split(" ")) > 8:
        return Invalid("words")
    if len(bare) < 3:
        return Unanchorable("short")
    if not any(c.isalpha() for c in bare):
        return Unanchorable("no_letter")
    if bare in RESERVED_NAMES and not known:
        return Unanchorable("reserved")
    if _is_control(name):
        return Unanchorable("control_path")
    return Key("name", name)


def _by_type(text: str, vtype: str, known: bool) -> Outcome:
    if vtype == "email":
        return _email(text)
    if vtype == "url":
        return _url(text)
    if vtype == "host":
        return _host(text)
    if vtype == "iban":
        return _iban(text)
    if vtype == "phone":
        return _phone(text)
    if vtype == "path":
        return _path(text)
    if vtype == "id":
        return _id(text)
    if vtype == "name":
        return _name(text, known)
    return Invalid("type")


def _typed(text: str, vtype: str, known: bool, protected_paths: Sequence[str]) -> Outcome:
    outcome = _by_type(text, vtype, known)
    # as with control files: "tripwire.yaml" is an id under auto and
    # "policy.sh" a host, and a declared id or name may be the file too
    if (
        isinstance(outcome, Key)
        and outcome.vtype in ("host", "path", "id", "name")
        and _is_protected(outcome.key, protected_paths)
    ):
        return Unanchorable("protected_path")
    return outcome


def _detect(text: str) -> ValueType:
    if text[:8].lower().startswith(("http://", "https://", "www.")):
        return "url"
    if "@" in text:
        return "email"
    if _IBAN.fullmatch(text):
        return "iban"
    if text.startswith("+"):
        return "phone"
    if text.startswith(("/", "./", "~")):
        return "path"
    if _SPACE.search(text) is None:
        labels = text.rstrip(".").split(".")
        if (
            len(labels) >= 2
            and labels[-1].lower() in TLDS
            # non-ASCII is Unanchorable as a host either way
            and (not text.isascii() or (text.islower() and not text.endswith(".")))
        ):
            return "host"
        if _ID_HINT.search(text):
            return "id"
    return "name"


def detect_type(value: object) -> ValueType | None:
    """The type `auto` resolves to. None when no type applies: the value is
    absent, or not a string or an int (bools are not ints here)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return "id"
    if not isinstance(value, str):
        return None
    try:
        text = _clean(str.__str__(value)).strip()
    except Exception:
        # an object that claims str's class but isn't one
        return None
    return _detect(text) if text else None


def _normalize(
    value: object, vtype: str, known: bool, protected_paths: Sequence[str]
) -> Outcome | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return Invalid("bool")
    if isinstance(value, int):
        text = _decimal(value)
        if text is None:
            return Invalid("too_long")
        return _typed(text, "id" if vtype == "auto" else vtype, known, protected_paths)
    if isinstance(value, float):
        return Invalid("float")
    if not isinstance(value, str):
        return Invalid("not_scalar")
    cleaned = _prestep(str.__str__(value))
    if isinstance(cleaned, Invalid):
        return cleaned
    if not cleaned:
        return None
    return _typed(cleaned, _detect(cleaned) if vtype == "auto" else vtype, known, protected_paths)


def normalize(
    value: object,
    vtype: VType = "auto",
    *,
    known: bool = False,
    protected_paths: Sequence[str] = (),
) -> Outcome | None:
    """One leaf's outcome under one type; None when the leaf is absent.

    known: the value is an operator's `known` entry, which may name a
    reserved name. protected_paths: absolute paths (the policy file, the
    audit log, the tx db, the task file) that no path, id, name or host
    may reach.
    """
    try:
        return _normalize(value, vtype, known, protected_paths)
    except Exception:
        # Total by contract. A value nothing can read is a value nothing
        # can vouch for, and an Invalid target blocks.
        return Invalid("unreadable")


def normalize_all(
    value: object,
    vtype: VType = "auto",
    *,
    known: bool = False,
    protected_paths: Sequence[str] = (),
) -> tuple[Outcome, ...]:
    """Every outcome a leaf has to anchor: one per address when the leaf is
    a , or ; joined list whose every part is an email, else normalize()'s
    one. () when the leaf is absent."""
    if vtype in ("auto", "email") and isinstance(value, str):
        try:
            cleaned = _prestep(str.__str__(value))
        except Exception:
            return (Invalid("unreadable"),)
        if (
            isinstance(cleaned, str)
            and _LIST_SEPARATOR.search(cleaned)
            and (vtype == "email" or _detect(cleaned) == "email")
        ):
            parts = [_email(part.strip()) for part in _LIST_SEPARATOR.split(cleaned)]
            if all(isinstance(part, Key) for part in parts):
                return tuple(parts)
    outcome = normalize(value, vtype, known=known, protected_paths=protected_paths)
    return () if outcome is None else (outcome,)


def forbidden_path(value: object, *, protected_paths: Sequence[str] = ()) -> Unanchorable | None:
    """Unanchorable("control_path") when a string, after the pre-step and
    split at slashes and backslashes, has a control segment, and
    Unanchorable("protected_path") when it reaches a protected path as a
    path key would; None otherwise, and for anything but a string. It
    reads the whole string as a path, whatever type it would detect as:
    ".git/hooks/pre-commit" and "notes x/../.git/config" alike."""
    if not isinstance(value, str):
        return None
    try:
        text = _clean(str.__str__(value)).strip()
        if _is_control(text):
            return Unanchorable("control_path")
        if _is_protected(_path_key(text), protected_paths):
            return Unanchorable("protected_path")
    except Exception:
        return Unanchorable("unreadable")
    return None


def is_under(path: str, prefix: str) -> bool:
    """Whether path key `path` is strictly below path key `prefix`,
    component by component: "/a/b" is under "/a", "/ab" is not."""
    if not prefix or path == prefix:
        return False
    return path.startswith(prefix if prefix.endswith("/") else prefix + "/")


# --- task text: conservative ---------------------------------------------------

# Each pattern takes maximal tokens: the lookbehind refuses to start inside
# a longer token and the lookahead refuses to stop inside one, so
# "xalice@corp.com" yields nothing rather than "alice@corp.com". A
# backslash joins a token as a slash does: C:\repo\evil.com is a path.
#
# An address starts only after whitespace, a delimiter or a quote: not
# after RFC 5322 atext, nor after anything past ASCII, which SMTPUTF8 lets
# a local part hold, so "o'brien@corp.com", the same with a typographic
# apostrophe, and "r&d@corp.com" yield nothing. A quote starts one only
# where it doesn't follow such a character itself ("'a@corp.com'").
_T_EMAIL = re.compile(
    r"(?<![^\s<>()\[\],;:\"'`\u2018\u2019\u201c\u201d])"
    r"(?<![^\s<>()\[\],;:\"]['`\u2018\u2019\u201c\u201d])"
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,63}"
    r"(?![\w@\\-]|\.[\w-])"
)
# a quoted local part, which makes '"attacker@evil.com"@corp.com' one address
_T_QUOTED = re.compile(r'"[^"]*"(?=@)')
# no path character before it either, so a masked URL never splits a path
_T_URL = re.compile(r"(?<![\w.~/\\+-])(?i:https?)://[^\s<>\"'`]+")
# not after / or ~ either: "src/a.py", "/srv/example.com/x" and
# "backup~corp.com" are paths. An underscore is part of the token, so
# "x_corp.com" is one host and never corp.com.
_T_HOST = re.compile(
    r"(?<![\w@./\\~-])(?>[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)(?>(?::[0-9]+)?)(?![\w@\\-]|\.[\w-])"
)
# unspaced, or the printed form in groups of four
_T_IBAN = re.compile(
    r"(?<!\w)[A-Z]{2}[0-9]{2}(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?)(?!\w)"
)
# A number doesn't start inside a run either, past a digit and one or two
# separators: the rest of a run is no number of its own, and restarting at
# each of its digits after the lookahead fails would be quadratic.
_T_PHONE = re.compile(
    r"(?<![\w+.:/\\#@%-])(?<![0-9][ ().-])(?<![0-9][ ().-]{2})"
    r"(?:\+|\()?[0-9](?:[ ().-]{0,2}[0-9])*+(?![\w@%\\]|[.:/#-]\w)"
)
_T_PATH = re.compile(r"(?<![\w.~/\\@-])[\w.~/-]++(?![@\\])")
_STEM_EXT = re.compile(r"[\w-][\w.-]*\.[A-Za-z0-9]{1,8}")
# not inside a path token either: "GIT~1/config"
_T_ID = re.compile(r"(?<![\w@%+.:/\\#~-])[A-Za-z0-9_.:/#-]++(?![\w@%+\\])")

# The label word an id may follow: "id 13", "ID: 13". Callers add words of
# their own (an argument's noun). "#", "no.", "number" and ":" only part a
# label from its id ("invoice no. 13"): "#1 priority" and "the number 2
# option" have no label, and neither has "id no13".
_ID_LABELS = (r"id",)
_ID_SEPARATOR = r"(?i:\#|no(?:\.|\b)|number\b|:)"
# the id ends where its token ends; sentence dots and colons may follow
_ID_END = r"(?=[.:]*+(?![\w.:/\\#@%+-]))"

# A mark or format character left after NFKC renders inside the token
# around it ("ab\u0301cd.com", "co\u00adrp.com"), and so does any other
# default-ignorable code point: the Hangul fillers, and those Unicode
# reserves. \w matches few of them. The extractors see this letter in its
# place instead: it joins the token and is in no ASCII key, and a path
# holding it is dropped.
_JOINER = "\u02b0"
_JOINING = frozenset({"Mn", "Mc", "Me", "Cf"})
_IGNORABLE = re.compile("[\u115f\u1160\u2065\u3164\uffa0\ufff0-\ufff8\U000e0000-\U000e0fff]")
# What sets a name apart from a word beside it: whitespace, and the
# punctuation that ends or quotes a phrase. Anything else between two words
# joins them into one token: "acme-labs", "o'brien", "col\u00b7lega", and
# the same with any dash, slash, quote or dot smart punctuation writes.
_BREAKS = frozenset(' ,;!?"()[]{}<>\u201c\u201d\u201e\u00ab\u00bb')


def _text(text: str) -> str:
    # lone surrogates can't be encoded; U+FFFD matches no key character
    return _SURROGATE.sub("\ufffd", _clean(text))


def _hidden(c: str) -> bool:
    return unicodedata.category(c) in _JOINING or _IGNORABLE.match(c) is not None


def _plain(text: str) -> str:
    if text.isascii():
        return text
    return "".join(_JOINER if _hidden(c) else c for c in text)


def _mask(text: str, spans: Sequence[tuple[int, int]]) -> str:
    if not spans:
        return text
    parts: list[str] = []
    end = 0
    for start, stop in spans:
        parts.append(text[end:start])
        parts.append(" " * (stop - start))
        end = stop
    parts.append(text[end:])
    return "".join(parts)


def _wordlike(c: str) -> bool:
    # a sigil too: "#random" is not the name "random"
    return c.isalnum() or c in "_@#" or _hidden(c)


def _starts(text: str, i: int) -> bool:
    before = text[i - 1 : i]
    return not before or (
        not _wordlike(before) and (before in _BREAKS or i == 1 or not _wordlike(text[i - 2]))
    )


def _ends(text: str, i: int) -> bool:
    after = text[i : i + 1]
    return not after or (
        not _wordlike(after) and (after in _BREAKS or not _wordlike(text[i + 1 : i + 2] or " "))
    )


def _has_phrase(folded: str, phrase: str) -> bool:
    """Whether phrase occurs in folded as a whole token: next to no word
    character, sigil or mark, and not glued to one ("acme-labs/widgets",
    "alice.smith@corp.com", "o'brien"). A possessive 's may follow."""
    start = folded.find(phrase)
    while start >= 0:
        end = start + len(phrase)
        if _starts(folded, start) and (
            _ends(folded, end)
            or folded[end : end + 2] in ("'s", "\u2019s")
            and _ends(folded, end + 2)
        ):
            return True
        start = folded.find(phrase, start + 1)
    return False


def _task_keys(text: str) -> tuple[set[Key], set[Key], str]:
    keys: set[Key] = set()
    mentioned: set[Key] = set()

    def add(outcome: Outcome) -> None:
        if isinstance(outcome, Key):
            keys.add(outcome)

    # A quoted local part is one token: nothing is read out of it, so
    # '"attacker@evil.com"@corp.com' anchors nothing.
    text = _mask(text, [m.span() for m in _T_QUOTED.finditer(text)])

    for m in _T_EMAIL.finditer(text):
        add(_email(m.group()))

    # A URL is one token: hosts and paths are not read out of it again, so
    # "https://evil.com@corp.com" anchors nothing rather than evil.com.
    spans: list[tuple[int, int]] = []
    for m in _T_URL.finditer(text):
        spans.append(m.span())
        add(_url(m.group().rstrip(TRAILING)))
    masked = _mask(text, spans)

    for m in _T_HOST.finditer(masked):
        token = m.group()
        labels = token.partition(":")[0].lower().split(".")
        if labels[-1] not in TLDS:
            continue
        outcome = _host(token)
        if not isinstance(outcome, Key):
            continue
        if labels[0] != "www" and labels[-1] in FILE_EXT_TLDS:
            mentioned.add(outcome)
        else:
            keys.add(outcome)

    for m in _T_IBAN.finditer(text):
        add(_iban(m.group()))

    for m in _T_PHONE.finditer(text):
        token = m.group()
        if token.startswith("+") or sum(c in "0123456789" for c in token) >= 10:
            add(_phone(token))

    for m in _T_PATH.finditer(masked):
        token = m.group().rstrip(".")
        if _JOINER in token:
            continue
        if "/" in token or _STEM_EXT.fullmatch(token):
            outcome = _path(token)
            # a lone "/" in prose is not the root directory
            if isinstance(outcome, Key) and outcome.key != "/":
                keys.add(outcome)

    for m in _T_ID.finditer(text):
        token = m.group().rstrip(".:")
        if len(token) >= 6:
            add(_id(token))

    return keys, mentioned, masked


@dataclass(frozen=True, slots=True, repr=False)
class TaskIndex:
    """What one task segment anchors. Built once, by build(); names and
    labelled ids are matched against the text at query time."""

    keys: frozenset[Key] = frozenset()
    # hosts the task names only as file names: notes.md, report.zip
    mentioned: frozenset[Key] = frozenset()
    # task paths of 2+ components, sorted: prefixes for `match: under`
    under_prefixes: tuple[str, ...] = ()
    # NFKC, URLs blanked, marks as _JOINER, whitespace-collapsed: for
    # labelled ids
    text: str = ""
    # NFKC, lowercased, whitespace-collapsed: for names
    folded: str = ""

    def __repr__(self) -> str:
        # counts only: every field is task text or cut from it, and task
        # text belongs in no log line or error message
        return f"TaskIndex(keys={len(self.keys)}, mentioned={len(self.mentioned)})"

    @classmethod
    def build(cls, text: str) -> TaskIndex:
        if not isinstance(text, str):
            return cls()
        try:
            source = _text(str.__str__(text))
        except Exception:
            # a task nothing can read anchors nothing
            return cls()
        keys, mentioned, masked = _task_keys(_plain(source))
        prefixes = sorted(
            k.key for k in keys if k.vtype == "path" and sum(1 for s in k.key.split("/") if s) >= 2
        )
        return cls(
            keys=frozenset(keys),
            mentioned=frozenset(mentioned - keys),
            under_prefixes=tuple(prefixes),
            text=" ".join(masked.split()),
            folded=" ".join(source.lower().split()),
        )

    def anchors(self, key: Key, *, labels: Iterable[str] = ()) -> bool:
        """Whether the task text anchors this key. An id under 6 characters
        anchors only after a label: "id 13", "id #13", or one of `labels`
        ("invoice no. 13" with labels=["invoice"]); "#13" and "No. 13" have
        none. Only keys normalize() could have produced are considered."""
        try:
            if not isinstance(key, Key) or normalize(key.key, key.vtype) != key:
                return False
            if key.vtype == "name":
                return _has_phrase(self.folded, key.key)
            if key in self.keys:
                return True
            return key.vtype == "id" and self._labelled(key.key, labels)
        except Exception:
            return False

    def mentions(self, key: Key) -> bool:
        """anchors(), or a host the task names only as a file name."""
        try:
            return self.anchors(key) or key in self.mentioned
        except Exception:
            return False

    def _labelled(self, key: str, labels: Iterable[str]) -> bool:
        words = list(_ID_LABELS)
        for label in labels:
            if isinstance(label, str):
                parts = _plain(_clean(str.__str__(label))).split()
                if parts:
                    words.append(r"\s+".join(re.escape(part) for part in parts))
        alternatives = "|".join(words)
        head = rf"(?<!\w)(?i:{alternatives})(?!\w)\s*{_ID_SEPARATOR}?\s*"
        return re.search(head + re.escape(key) + _ID_END, self.text) is not None


# --- poison: greedy ------------------------------------------------------------

# Every task pattern with its limits removed. The lookbehinds left, on
# hosts, only stop a pattern restarting inside a run it has already
# rejected, which would be quadratic; a match can always start where the
# run starts.
_P_URL = re.compile(r"(?i:https?)://[^\s<>\"'`]+")
# Trailing dots before a port too: "h.:8443" is the host key "h:8443". The
# port is read ahead, not consumed, since a task host may start inside it:
# "a.io:1b.com". An underscore joins a run, as it does a task host.
_P_HOST = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+\.*(?=(:[0-9]+)?)")
# The same runs split at underscores, so that the hosts on either side of
# one are sighted too: the text rule doesn't hold a short one that a
# letter past ASCII touches at its other end ("x_ab.io中文").
_P_LDH_HOST = re.compile(r"(?<![A-Za-z0-9-])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\.*(?=(:[0-9]+)?)")
_P_IPV6 = re.compile(r"\[[0-9A-Fa-f:.]*\](?::[0-9]+)?")
_P_IBAN = re.compile(r"[A-Za-z]{2}(?:[\s.()-]*[0-9]){2}(?:[\s.()-]*[A-Za-z0-9]){11,30}")
_P_PHONE = re.compile(r"\+?[0-9](?:[\s.()-]*[0-9])*")
_P_PATH = re.compile(r"[\w.~/-]+")
_P_ID = re.compile(r"[A-Za-z0-9_.:/#-]+")
_P_LOCAL = re.compile(r"[A-Za-z0-9._%+-]*\Z")
_P_DOMAIN = re.compile(r"[A-Za-z0-9.-]*")
_P_AT = re.compile("@")
_P_SEPARATORS = re.compile(r"[\s.()-]")
_P_WHITESPACE = re.compile(r"\s")
_P_COMPACT = re.compile(r"[\s().-]")
# what _path_key() drops: empty and . segments
_P_EMPTY_SEGMENTS = re.compile(r"/(?:\.?/)+")
# what _host() drops: dots before a port, zeros leading one
_P_PORT_PADDING = re.compile(r"\.+(?=:[0-9])|(?<=:)0+(?=[0-9])")
# a JSON string escape under any number of backslashes, for JSON in JSON
_P_ESCAPE = re.compile(r"\\+(?:u([0-9A-Fa-f]{4})|([\"\\/bfnrt]))")
_P_CONTROL_ESCAPES = {"b": " ", "f": " ", "n": " ", "r": " ", "t": " "}


@dataclass(frozen=True, slots=True, repr=False)
class PoisonScan:
    """One poison text: its typed sightings, and the text itself in the
    stored forms the text rule of is_poisoned() reads. A truncated scan
    stopped short, at MAX_SCAN_KEYS or on a text it could not read, and
    poisons every key."""

    keys: frozenset[Key]
    # NFKC, casefolded, whitespace-collapsed: a line for the text, and one
    # for each other reading of it that differs: its JSON string escapes
    # decoded, its hidden characters deleted, or both
    folded: str
    # each line of folded, with whitespace and -.() removed
    compact: str
    # folded, respelled as path keys and host keys spell it: every "//"
    # and "/./" run made "/", a path key's leading "//" too when compared;
    # the dots before a port and the zeros leading one dropped. Each is the
    # same object as folded when nothing changes.
    paths: str = ""
    hosts: str = ""
    truncated: bool = False

    def __repr__(self) -> str:
        # a scan can run to megabytes; its size is what a log line needs
        return f"PoisonScan(keys={len(self.keys)}, chars={len(self.folded)})"


class _Full(Exception):
    """A scan reached MAX_SCAN_KEYS."""


def _emails(text: str, add: Callable[[Outcome], None]) -> None:
    """Every @-anchored suffix of the local part: "xattacker@evil.com"
    yields itself and "attacker@evil.com". Built from one validated
    domain, since any suffix of a valid local part is valid."""
    done: set[tuple[str, str]] = set()
    for at in _P_AT.finditer(text):
        i = at.start()
        tail = _P_LOCAL.search(text, max(0, i - 64), i)
        domain = _P_DOMAIN.match(text, i + 1)
        local = tail.group() if tail else ""
        run = domain.group() if domain else ""
        # nothing before the @, or no dot after it: no address to validate
        if not local or "." not in run:
            continue
        outcome = _email("a@" + run)
        if not isinstance(outcome, Key):
            continue
        host = outcome.key.partition("@")[2]
        cut = local.rfind("..")
        if cut >= 0:
            local = local[cut + 1 :]
        if (local, host) in done:
            continue
        done.add((local, host))
        for start in range(len(local)):
            suffix = local[start:].lower()
            if len(suffix) + 1 + len(host) <= 254:
                add(Key("email", f"{suffix}@{host}"))


def scan_poison(text: str) -> PoisonScan:
    """Greedy extraction over one poison text: untrusted text and string
    leaves, post-taint argument strings, the tool listing, error text."""
    if not isinstance(text, str):
        return PoisonScan(frozenset(), "", "")
    try:
        return _scan(str.__str__(text))
    except Exception:
        # past MAX_SCAN_KEYS, or an object that claims str's class but
        # isn't one: what the text held is unknown, so it poisons all
        return PoisonScan(frozenset(), "", "", truncated=True)


def _unmarked(text: str) -> str:
    """text with every hidden character deleted, as a reader may drop what
    it can't see. Decomposed first, so that a mark NFKC composed into the
    letter before it goes too, as U+0301 after the m of "evil.com" does."""
    if text.isascii():
        return text
    decomposed = unicodedata.normalize("NFD", text)
    hidden = {ord(c): None for c in set(decomposed) if c > "\x7f" and _hidden(c)}
    if not hidden:
        return text
    return unicodedata.normalize("NFKC", decomposed.translate(hidden))


def _unescaped(text: str) -> str:
    """text with its JSON string escapes decoded, as a reader of a string
    leaf that holds JSON takes them: an escaped "/" or "@" is one."""
    if "\\" not in text:
        return text
    decoded = _P_ESCAPE.sub(_unescape, text)
    # an escaped surrogate pair is one astral character
    joined = decoded.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")
    return _text(joined)


def _unescape(m: re.Match[str]) -> str:
    if m.group(1):
        return chr(int(m.group(1), 16))
    return _P_CONTROL_ESCAPES.get(m.group(2), m.group(2))


def _scan(text: str) -> PoisonScan:
    # prepared exactly as task text is, so every token a task extractor
    # can find here is a token the greedy ones see too; and read again as
    # a reader may take it, with its JSON string escapes decoded and
    # without the hidden characters that split what they sit in
    source = _text(text)
    unescaped = _unescaped(source)
    copies = dict.fromkeys((source, unescaped, _unmarked(source), _unmarked(unescaped)))
    keys: set[Key] = set()

    def add(outcome: Outcome) -> None:
        if isinstance(outcome, Key):
            keys.add(outcome)
            if len(keys) > MAX_SCAN_KEYS:
                raise _Full

    for copy in copies:
        _sight(copy, add)

    lines = [" ".join(copy.casefold().split()) for copy in copies]
    folded = "\n".join(lines)
    return PoisonScan(
        frozenset(keys),
        folded,
        "\n".join(_P_COMPACT.sub("", line) for line in lines),
        _P_EMPTY_SEGMENTS.sub("/", folded),
        _P_PORT_PADDING.sub("", folded),
    )


def _sight(source: str, add: Callable[[Outcome], None]) -> None:
    _emails(source, add)

    for m in _P_URL.finditer(source):
        add(_url(m.group()))
        add(_url(m.group().rstrip(TRAILING)))

    for pattern in (_P_HOST, _P_LDH_HOST):
        for m in pattern.finditer(source):
            add(_host(m.group()))
            if m.group(1):
                add(_host(m.group() + m.group(1)))

    for m in _P_IPV6.finditer(source):
        add(_host(m.group()))

    for m in _P_IBAN.finditer(source):
        add(_iban(_P_SEPARATORS.sub("", m.group())))

    for m in _P_PHONE.finditer(source):
        add(_phone(_P_WHITESPACE.sub("", m.group())))

    # a token without / is its own path key, which the text rule covers
    for m in _P_PATH.finditer(source):
        token = m.group()
        if "/" in token:
            add(_path(token))
            add(_path(token.rstrip(".")))

    for m in _P_ID.finditer(source):
        add(_id(m.group()))
        add(_id(m.group().rstrip(".:")))


def is_poisoned(key: Key, scans: Iterable[PoisonScan], *, self_key: bool = False) -> bool:
    """The poison test against earlier poison texts (the caller passes only
    scans from before the sighting in question). Poisoned when:

      1. a scan sighted the key as typed, or
      2. a scan's text holds it: casefolded and whitespace-collapsed as the
         text is, as a substring when the key is 6+ characters, else as a
         token no alphanumeric extends at an end where the key has one
         ("#13" is in "id#13", "13" is not in "113"); path and host keys
         also against the text respelled their way; IBAN and phone keys
         also against the compacted text, a phone by its digits so that
         "00 49..." and "+49..." match, or
      3. a scan is truncated.

    self_key: testing a `self` id, for which a key under 6 characters is
    tested by rules 1 and 3 alone. A key that isn't one, or that can't be
    read, counts as poisoned.
    """
    try:
        return _is_poisoned(key, scans, self_key)
    except Exception:
        return True


def _is_poisoned(key: Key, scans: Iterable[PoisonScan], self_key: bool) -> bool:
    if not isinstance(key, Key) or not isinstance(key.key, str):
        return True
    text = str.__str__(key.key)
    folded = " ".join(text.casefold().split())
    short = len(text) < 6
    text_rule = not (self_key and short)
    held = _held(folded, short)
    held_as_path = held
    if key.vtype == "path":
        # the text respelled as paths holds a key's leading "//" as one "/"
        held_as_path = _held(_P_EMPTY_SEGMENTS.sub("/", folded), short)
    compact: str | None = None
    if key.vtype == "iban":
        compact = folded
    elif key.vtype == "phone":
        compact = text.lstrip("+")

    for scan in scans:
        if scan.truncated or key in scan.keys:
            return True
        if not text_rule:
            continue
        if held(scan.folded):
            return True
        if key.vtype == "path" and held_as_path(scan.paths):
            return True
        if key.vtype == "host" and held(scan.hosts):
            return True
        if compact is not None and compact in scan.compact:
            return True
    return False


def _held(needle: str, short: bool) -> Callable[[str], bool]:
    if not short:
        return lambda form: needle in form
    # no alphanumeric may extend the key where it has one at that end: "13"
    # is not in "113", but "#13" is in "id#13"
    head = r"(?<![^\W_])" if needle[:1].isalnum() else ""
    tail = r"(?![^\W_])" if needle[-1:].isalnum() else ""
    pattern = re.compile(head + re.escape(needle) + tail)
    return lambda form: pattern.search(form) is not None


# --- whole fields ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WholeField:
    """A leaf that may register as a key: a string of at most 256 characters
    and 8 words, an int, or a dict key of at most 256 characters."""

    path: tuple[str | int, ...]
    value: str | int
    # every key its value normalizes to, under every type that accepts it;
    # host and IBAN only from their own spelling
    keys: tuple[Key, ...]
    # a dict key, at the path of the value it names
    is_key: bool = False


class WholeFields(tuple[WholeField, ...]):
    """whole_fields()'s result: a tuple of fields that also says whether
    part of the value went unread."""

    truncated: bool

    def __new__(cls, fields: Iterable[WholeField], truncated: bool) -> Self:
        self = super().__new__(cls, fields)
        self.truncated = truncated
        return self


def _candidates(value: str | int) -> tuple[Key, ...]:
    # Nobody declared the field's type, so a host or IBAN key registers only
    # from its own spelling, as under auto: "Report.md" may be a file that
    # "report.md" is not.
    own = _prestep(value) if isinstance(value, str) else None
    keys = {
        outcome
        for vtype in VALUE_TYPES
        for outcome in normalize_all(value, vtype)
        if isinstance(outcome, Key) and (vtype not in ("host", "iban") or outcome.key == own)
    }
    return tuple(sorted(keys, key=lambda k: (k.vtype, k.key)))


def _field(value: object, is_key: bool) -> tuple[str | int, tuple[Key, ...]] | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        leaf: str | int = int.__int__(value)
    elif isinstance(value, str):
        leaf = str.__str__(value)
        if len(leaf) > MAX_FIELD_CHARS or (not is_key and len(leaf.split()) > MAX_FIELD_WORDS):
            return None
    else:
        return None
    keys = _candidates(leaf)
    return (leaf, keys) if keys else None


_JSON_FLOATS = {"nan": "NaN", "inf": "Infinity", "-inf": "-Infinity"}


def _json_key(name: object) -> str | None:
    # json.dumps's key conversions; anything else is not JSON. An int past
    # sys.get_int_max_str_digits() raises here as it does there.
    if isinstance(name, str):
        return str.__str__(name)
    if isinstance(name, bool):
        return "true" if name else "false"
    if name is None:
        return "null"
    if isinstance(name, int):
        return int.__repr__(name)
    if isinstance(name, float):
        text = float.__repr__(name)
        return _JSON_FLOATS.get(text, text)
    return None


def whole_fields(value: object, *, max_depth: int = MAX_FIELD_DEPTH) -> WholeFields:
    """Every whole field in a JSON value that registers at least one key,
    walking dicts in sorted key order.

    Only dicts, lists and tuples are walked, iteratively, each container
    once, so sharing and cycles cost nothing extra. Nothing with a path
    longer than max_depth is reported and no container past it is entered;
    the provenance caps stop there too, and it keeps a deep value from
    costing its depth squared. A non-string dict key takes the string
    json.dumps would give it and sorts after the string keys; one json.dumps
    would reject is skipped with its value.

    The result is truncated when a container past max_depth, a skipped
    key's value or a leaf that can't be read went unread; for an untrusted
    result that is a result over its caps.
    """
    out: list[WholeField] = []
    seen: set[int] = set()
    truncated = False
    stack: list[tuple[tuple[str | int, ...], object]] = [((), value)]
    while stack:
        path, node = stack.pop()
        try:
            if isinstance(node, (dict, list, tuple)):
                if id(node) in seen:
                    continue
                if len(path) >= max_depth:
                    truncated = True
                    continue
                seen.add(id(node))
            if isinstance(node, dict):
                entries: list[tuple[str, int, object]] = []
                for name, child in dict.items(node):
                    try:
                        text = _json_key(name)
                    except Exception:
                        text = None
                    if text is None:
                        truncated = True
                    else:
                        entries.append((text, 0 if isinstance(name, str) else 1, child))
                entries.sort(key=lambda entry: entry[:2])
                for text, _, _ in entries:
                    found = _field(text, is_key=True)
                    if found is not None:
                        out.append(WholeField((*path, text), *found, is_key=True))
                stack.extend(((*path, text), child) for text, _, child in reversed(entries))
            elif isinstance(node, (list, tuple)):
                items = list(
                    list.__iter__(node) if isinstance(node, list) else tuple.__iter__(node)
                )
                stack.extend(((*path, i), child) for i, child in reversed(list(enumerate(items))))
            else:
                found = _field(node, is_key=False)
                if found is not None:
                    out.append(WholeField(path, *found))
        except Exception:
            # an object that claims a JSON type's class but isn't one
            truncated = True
    return WholeFields(out, truncated)
