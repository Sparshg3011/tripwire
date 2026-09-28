"""A starting policy for an MCP server, drafted from its tool listing.

recipe() reads each tool's name, the names and formats of its input
schema's properties, and its destructiveHint. Never a description: an
upstream writes those, and nothing an upstream writes may loosen what
the policy asks of it. The header records the recipe version and the
sha256 of the listing and of the word tables below, so the same listing
drafts the same YAML, byte for byte, and can be diffed; reordering its
tools or their properties changes only the listing's hash.

Words. A name splits at _, -, ., case changes and digits, lowercased,
an acronym's plural kept whole: "getUserURL" is get, user, url, and
"messageIDs" message, ids.

Kind. A tool's verb is the first of its words in a verb table (READ,
DESTRUCTIVE, EXEC, INDIRECT, CREATE, LOGIN). A READ verb makes it a read,
unless it has destructiveHint: true; any other verb, or none, a write.
readOnlyHint never turns a write into a read. A read with a URL
argument, one with a URL word or format uri, is a fetch, whether or not
its schema names every argument it takes.

  write        destructive when a word is in DESTRUCTIVE, or it has
               destructiveHint: true. exec when a word is in EXEC or an
               argument is named in EXEC_ARGS; indirect when exec, or when
               a word is in INDIRECT and no argument is a target.

Roles, per write argument, from its words; the first rule that matches:

  1. a word in CREDENTIAL, or "key" after a word in KEY_KINDS
                                      credential; content on a LOGIN verb
  2. a word in AMOUNT                 content
  3. its last word in ID              selector, type id
  4. a word in PATH                   selector, type path; match: under
                                      unless the tool is destructive
  5. filename, or file then name      content on a CREATE verb, else
                                      selector, type path
  6. a word in TARGET or URL          target; type url for a URL word
  7. a word in PLACE                  selector: auto reads a postal
                                      address as a name, which may run
                                      past 8 words, and an Invalid target
                                      would block
  8. name(s) with a word in OBJECT and none in PERSON, or one word in
     OBJECT                           selector, type name
  9. anything else                    content

A property with format email or uri, or items with one, is read as that
type (url for uri), and as a target when the rules make it content. On a
fetch, arguments with a URL word or format uri are targets of type url,
and every other argument is content.

The policy, per arm:

  every tool   untrusted; unknown tools block
  read         allow, nothing else
  fetch        allow, with an args contract
  write        allow, per_session: 5, or 1 with a rule-1 argument; an
               args contract unless it is exec or indirect;
               destructive: true when destructive; self_scoped: true when
               it has a contract, is not destructive and has no
               credential argument, which an empty value would otherwise
               set unchecked (primary and taint)
  flow         one, over every write and fetch: require_approval once
               the session is tainted, unless: anchored (not in taint)

Nor does a write or fetch get a contract when its schema doesn't name
every argument it takes (it has patternProperties, or
additionalProperties other than false), or names one a contract can't
hold.

So an exec or indirect write is never discharged, nor is a call naming
no target, selector or credential to a write that takes a credential,
and in the strict arm to any write. A comment
names the cue behind each tool's kind, each argument's role, a missing
contract, destructive: true and per_session: 1. Comments quote only the
tables' words, never a name the upstream chose.

Contract: pure and deterministic. RecipeError for a source that isn't a
listing; anything a listing may hold past that gets an answer.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from itertools import pairwise
from typing import Any, Literal

import yaml

from tripwire.policy.schema import _ARG_NAME, Role
from tripwire.policy.values import VType

RECIPE_VERSION = 1

Arm = Literal["primary", "strict", "taint"]
Kind = Literal["read", "fetch", "write"]

READ = frozenset(
    {
        "get",
        "list",
        "search",
        "find",
        "read",
        "view",
        "show",
        "fetch",
        "browse",
        "lookup",
        "query",
        "check",
        "describe",
        "count",
        "retrieve",
    }
)
DESTRUCTIVE = frozenset(
    {
        "delete",
        "remove",
        "cancel",
        "revoke",
        "transfer",
        "reset",
        "purge",
        "destroy",
        "wipe",
        "erase",
        "clear",
        "drop",
        "kill",
        "terminate",
        "uninstall",
        "unshare",
    }
)
EXEC = frozenset(
    {
        "run",
        "exec",
        "execute",
        "eval",
        "evaluate",
        "shell",
        "bash",
        "sh",
        "command",
        "script",
        "sql",
        "invoke",
        "spawn",
    }
)
EXEC_ARGS = frozenset({"cmd", "command", "script", "shell", "sql", "query"})
INDIRECT = frozenset(
    {"send", "share", "forward", "publish", "post", "invite", "push", "reply", "respond", "answer"}
)
CREATE = frozenset({"create", "new", "make", "upload", "save"})
LOGIN = frozenset({"login", "verify"})
CREDENTIAL = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "otp",
        "totp",
        "pin",
        "mfa",
        "credential",
        "credentials",
    }
)
KEY_KINDS = frozenset({"ssh", "api", "private", "access", "secret", "deploy", "public"})
AMOUNT = frozenset({"amount", "price", "quantity", "qty", "total", "cost"})
ID = frozenset({"id", "ids", "uuid", "guid", "sha", "ref"})
PATH = frozenset({"path", "paths", "filepath", "dir", "directory", "folder"})
TARGET = frozenset(
    {
        "to",
        "recipient",
        "recipients",
        "cc",
        "bcc",
        "email",
        "emails",
        "mail",
        "participant",
        "participants",
        "attendee",
        "attendees",
        "invitee",
        "invitees",
        "guest",
        "guests",
        "member",
        "members",
        "user",
        "users",
        "username",
        "handle",
        "collaborator",
        "collaborators",
        "assignee",
        "assignees",
        "reviewer",
        "reviewers",
        "owner",
        "payee",
        "beneficiary",
        "iban",
        "bic",
        "swift",
        "account",
        "phone",
        "channel",
        "channels",
        "room",
    }
)
PLACE = frozenset({"address", "street"})
URL = frozenset(
    {
        "url",
        "urls",
        "uri",
        "link",
        "links",
        "href",
        "endpoint",
        "webhook",
        "host",
        "hostname",
        "domain",
        "website",
        "webpage",
    }
)
NAME = frozenset({"name", "names"})
# things a user picks out by their name: containers and named entities,
# not the documents, notes or images that are as often an argument's data
OBJECT = frozenset(
    {
        "album",
        "app",
        "application",
        "board",
        "branch",
        "bucket",
        "calendar",
        "cluster",
        "collection",
        "company",
        "database",
        "dataset",
        "device",
        "group",
        "hotel",
        "model",
        "namespace",
        "org",
        "organization",
        "playlist",
        "product",
        "project",
        "queue",
        "repo",
        "repository",
        "restaurant",
        "server",
        "service",
        "shop",
        "space",
        "spreadsheet",
        "store",
        "table",
        "team",
        "topic",
        "vendor",
        "workspace",
    }
)
# words that make a name a person's: "contact_name" is who, not which
PERSON = frozenset(
    {
        "first",
        "last",
        "middle",
        "given",
        "family",
        "full",
        "display",
        "nick",
        "nickname",
        "person",
        "contact",
        "sender",
        "author",
        "customer",
        "client",
        "employee",
        "manager",
        "friend",
    }
)

LEXICON: dict[str, frozenset[str]] = {
    "read": READ,
    "destructive": DESTRUCTIVE,
    "exec": EXEC,
    "exec_args": EXEC_ARGS,
    "indirect": INDIRECT,
    "create": CREATE,
    "login": LOGIN,
    "credential": CREDENTIAL,
    "key_kinds": KEY_KINDS,
    "amount": AMOUNT,
    "id": ID,
    "path": PATH,
    "target": TARGET,
    "place": PLACE,
    "url": URL,
    "name": NAME,
    "object": OBJECT,
    "person": PERSON,
}
LEXICON_SHA256 = hashlib.sha256(
    json.dumps({k: sorted(v) for k, v in LEXICON.items()}, sort_keys=True).encode()
).hexdigest()

VERBS = READ | DESTRUCTIVE | EXEC | INDIRECT | CREATE | LOGIN

# an acronym's plural is one word: "imageURLs" is image, urls
_WORDS = re.compile(r"[A-Z]{2,}s(?![a-z])|[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
_PLAIN = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")
_FORMATS: dict[str, VType] = {"email": "email", "uri": "url"}


class RecipeError(ValueError):
    """A source recipe() can't read as a tool listing."""


@dataclass(frozen=True, slots=True)
class Argument:
    """One argument's inferred role, and the cue it was inferred from."""

    name: str
    role: Role
    vtype: VType = "auto"
    match: Literal["exact", "under"] = "exact"
    cue: str = "no cue"
    # rule 1 matched, whatever role it gave
    credential: bool = False


@dataclass(frozen=True, slots=True)
class Reading:
    """One tool as the recipe reads it. args is None when a write or a
    fetch gets no contract, and no_contract says why; destructive is the
    cue that made a write destructive."""

    name: str
    kind: Kind
    cue: str
    args: tuple[Argument, ...] | None = ()
    destructive: str | None = None
    no_contract: str | None = None
    # an argument matched rule 1
    credential: bool = False


def words(name: str) -> list[str]:
    """A name's words, lowercased: "getUserURL" is get, user, url."""
    return [word.lower() for word in _WORDS.findall(name)]


def read_listing(source: bytes) -> list[Mapping[str, Any]]:
    """The tools of a tools/list result as JSON: a list of tools, or an
    object whose `tools` is one. Every tool needs a name no other has."""
    try:
        data = json.loads(source)
    except (ValueError, RecursionError) as e:
        raise RecipeError(f"not JSON: {e}") from None
    if isinstance(data, Mapping):
        data = data.get("tools")
    if not isinstance(data, list):
        raise RecipeError('expected a list of tools, or an object with a "tools" list')
    seen: set[str] = set()
    for i, tool in enumerate(data):
        name = tool.get("name") if isinstance(tool, Mapping) else None
        if not isinstance(name, str) or not name:
            raise RecipeError(f"tools[{i}] has no name")
        if name in seen:
            raise RecipeError(f"tools[{i}] repeats the name {name!r}")
        seen.add(name)
    return data


def infer(tool: Mapping[str, Any]) -> Reading:
    """How the recipe reads one tool; see the module docstring."""
    name = str(tool["name"])
    named = words(name)
    verb = next((w for w in named if w in VERBS), None)
    annotations = tool.get("annotations")
    hinted = isinstance(annotations, Mapping) and annotations.get("destructiveHint") is True
    props = _properties(tool.get("inputSchema"))

    if verb in READ and not hinted:
        listed = _properties(tool.get("inputSchema"), every=False) or ()
        urls = [n for n, p in listed if _is_url(n, p)]
        if not urls:
            return Reading(name, "read", f'read: "{verb}"')
        cue = f'fetch: "{verb}" with a URL argument'
        if props is None or not all(_ARG_NAME.fullmatch(n) for n, _ in props):
            return Reading(name, "fetch", cue, None, no_contract=_unnamed(props))
        args = tuple(
            Argument(n, "target", "url", cue=_url_cue(n, p))
            if n in urls
            else Argument(n, "content", cue="not a URL, on a read")
            for n, p in props
        )
        return Reading(name, "fetch", cue, args)

    if verb in READ:
        cue = "write: destructiveHint"
    else:
        cue = "write: no read verb" if verb is None else f'write: "{verb}"'
    destructive = next((f'"{w}"' for w in named if w in DESTRUCTIVE), None)
    if destructive is None and hinted:
        destructive = "destructiveHint"
    if props is None:
        return Reading(name, "write", cue, None, destructive, _unnamed(props))
    args = tuple(_role(n, p, verb, destructive is not None) for n, p in props)
    credential = any(arg.credential for arg in args)
    execs = next((w for w in named if w in EXEC), None)
    exec_arg = next((n.lower() for n, _ in props if n.lower() in EXEC_ARGS), None)
    sends = next((w for w in named if w in INDIRECT), None)
    if execs is not None:
        why = f'exec: "{execs}"'
    elif exec_arg is not None:
        why = f'exec: argument "{exec_arg}"'
    elif sends is not None and not any(arg.role == "target" for arg in args):
        why = f'indirect: "{sends}" with no target'
    elif not all(_ARG_NAME.fullmatch(n) for n, _ in props):
        why = _unnamed(props)
    else:
        return Reading(name, "write", cue, args, destructive, credential=credential)
    return Reading(name, "write", cue, None, destructive, why, credential)


def recipe(source: bytes, *, arm: Arm = "primary") -> str:
    """The policy YAML for a listing (read_listing()) in one arm."""
    tools = sorted((infer(tool) for tool in read_listing(source)), key=lambda t: t.name)
    head = [
        f"# tripwire recipe {RECIPE_VERSION}, {arm} arm",
        f"# tools sha256:   {hashlib.sha256(source).hexdigest()}",
        f"# lexicon sha256: {LEXICON_SHA256}",
        "# Drafted from tool names, input schemas and annotations, never descriptions.",
        "# Review every inferred role before enforcing it.",
        "version: 1",
        "defaults:",
        "  unknown_tools: block",
        "sources:",
        '  "*": untrusted',
    ]
    lines = [*head, "tools:" if tools else "tools: {}"]
    for tool in tools:
        lines.extend(_tool(tool, arm))
    guarded = [tool.name for tool in tools if tool.kind != "read"]
    if guarded:
        lines += ["flows:", "  - when: context_tainted", "    tools:"]
        lines += [f"      - {_scalar(name)}" for name in guarded]
        lines.append("    action: require_approval")
        if arm != "taint":
            lines.append("    unless: anchored")
    return "\n".join(lines) + "\n"


def _tool(tool: Reading, arm: Arm) -> Iterator[str]:
    yield f"  {_scalar(tool.name)}:"
    cue = tool.cue
    if tool.no_contract is not None:
        cue += f"; no contract, {tool.no_contract}"
    yield f"    action: allow  # {cue}"
    if tool.kind == "read":
        return
    if tool.destructive is not None:
        yield f"    destructive: true  # {tool.destructive}"
    elif (
        tool.kind == "write"
        and tool.args is not None
        and not any(arg.role == "credential" for arg in tool.args)
        and arm != "strict"
    ):
        yield "    self_scoped: true"
    if tool.args is not None:
        yield "    args: {}" if not tool.args else "    args:"
        for arg in tool.args:
            yield f"      {_scalar(arg.name)}: {_spec(arg)}  # {arg.cue}"
    if tool.kind == "write":
        if tool.credential:
            yield "    limits: {per_session: 1}  # a credential argument"
        else:
            yield "    limits: {per_session: 5}"


def _spec(arg: Argument) -> str:
    if arg.vtype == "auto" and arg.match == "exact":
        return arg.role
    parts = [f"role: {arg.role}"]
    if arg.vtype != "auto":
        parts.append(f"type: {arg.vtype}")
    if arg.match != "exact":
        parts.append(f"match: {arg.match}")
    return "{" + ", ".join(parts) + "}"


def _scalar(text: str) -> str:
    """text as a YAML scalar that reads back as exactly text."""
    if _PLAIN.fullmatch(text) and yaml.safe_load(text) == text:
        return text
    return yaml.safe_dump(text, default_style='"', width=2**31).rstrip("\n")


def _properties(
    schema: object, *, every: bool = True
) -> list[tuple[str, Mapping[str, Any]]] | None:
    """An input schema's named arguments, sorted by name; None when it
    has no properties to read or, with every, when they aren't every
    argument it takes."""
    if not isinstance(schema, Mapping):
        return None
    props = schema.get("properties", {})
    if not isinstance(props, Mapping):
        return None
    if every and (
        schema.get("patternProperties") or schema.get("additionalProperties") not in (None, False)
    ):
        return None
    named = [(str(n), p if isinstance(p, Mapping) else {}) for n, p in props.items()]
    return sorted(named, key=lambda arg: arg[0])


def _unnamed(props: Sequence[tuple[str, Mapping[str, Any]]] | None) -> str:
    if props is None:
        return "its input schema doesn't name every argument"
    return "an argument name a contract can't hold"


def _format(prop: Mapping[str, Any]) -> VType | None:
    items = prop.get("items")
    for node in (prop, items if isinstance(items, Mapping) else {}):
        found = node.get("format")
        if isinstance(found, str) and found in _FORMATS:
            return _FORMATS[found]
    return None


def _is_url(name: str, prop: Mapping[str, Any]) -> bool:
    return not URL.isdisjoint(words(name)) or _format(prop) == "url"


def _url_cue(name: str, prop: Mapping[str, Any]) -> str:
    cue = next((w for w in words(name) if w in URL), None)
    return f'URL cue "{cue}"' if cue is not None else "format uri"


def _role(name: str, prop: Mapping[str, Any], verb: str | None, destructive: bool) -> Argument:
    arg = _by_name(name, verb, destructive)
    pinned = _format(prop)
    if pinned is None or arg.role in ("selector", "credential"):
        return arg
    shown = "uri" if pinned == "url" else pinned
    if arg.role == "content":
        return Argument(name, "target", pinned, cue=f"format {shown}", credential=arg.credential)
    return Argument(name, arg.role, pinned, cue=f"{arg.cue}, format {shown}")


def _by_name(name: str, verb: str | None, destructive: bool) -> Argument:
    w = words(name)
    pairs = list(pairwise(w))
    secret = next((x for x in w if x in CREDENTIAL), None)
    if secret is None:
        secret = next((f"{a} key" for a, b in pairs if a in KEY_KINDS and b == "key"), None)
    if secret is not None:
        if verb in LOGIN:
            cue = f'credential cue "{secret}", on a "{verb}" tool'
            return Argument(name, "content", cue=cue, credential=True)
        return Argument(name, "credential", cue=f'credential cue "{secret}"', credential=True)
    if amount := next((x for x in w if x in AMOUNT), None):
        return Argument(name, "content", cue=f'amount cue "{amount}"')
    if w and w[-1] in ID:
        return Argument(name, "selector", "id", cue=f'ends in "{w[-1]}"')
    if path := next((x for x in w if x in PATH), None):
        match: Literal["exact", "under"] = "exact" if destructive else "under"
        return Argument(name, "selector", "path", match, f'path cue "{path}"')
    if "filename" in w or ("file", "name") in pairs:
        if verb in CREATE:
            return Argument(name, "content", cue=f'file name on a "{verb}" tool')
        return Argument(name, "selector", "path", cue="file name")
    if url := next((x for x in w if x in URL), None):
        return Argument(name, "target", "url", cue=f'URL cue "{url}"')
    if target := next((x for x in w if x in TARGET), None):
        return Argument(name, "target", cue=f'target cue "{target}"')
    if place := next((x for x in w if x in PLACE), None):
        return Argument(name, "selector", cue=f'place cue "{place}"')
    thing = next((x for x in w if x in OBJECT), None)
    if thing is not None and PERSON.isdisjoint(w):
        if not NAME.isdisjoint(w):
            return Argument(name, "selector", "name", cue=f'name of object noun "{thing}"')
        if len(w) == 1:
            return Argument(name, "selector", "name", cue=f'object noun "{thing}"')
    return Argument(name, "content")
