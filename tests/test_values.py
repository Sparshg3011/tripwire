"""Worked examples and properties pinning down tripwire.policy.values, one
group per section of its docstring: the pre-step, detection, each
normalizer, the task index, the poison scanner and whole fields.
"""

import random
import string
import unicodedata
from importlib.resources import files

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from tripwire.policy.values import (
    CONTROL_SEGMENTS,
    TLDS,
    VALUE_TYPES,
    Invalid,
    Key,
    PoisonScan,
    TaskIndex,
    Unanchorable,
    WholeField,
    detect_type,
    is_poisoned,
    is_under,
    normalize,
    normalize_all,
    scan_poison,
    whole_fields,
)


def E(key):
    return Key("email", key)


def H(key):
    return Key("host", key)


def I(key):
    return Key("iban", key)


def P(key):
    return Key("phone", key)


def PA(key):
    return Key("path", key)


def D(key):
    return Key("id", key)


def N(key):
    return Key("name", key)


def anchored(task, key, **kwargs):
    return TaskIndex.build(task).anchors(key, **kwargs)


def text_only(folded):
    """A poison scan with no typed sightings, to test the text rule alone."""
    compact = "".join(c for c in folded if not c.isspace() and c not in "-.()")
    return PoisonScan(frozenset(), folded, compact)


# --- pinned data --------------------------------------------------------------


def test_pinned_lists_ship_as_package_data():
    data = files("tripwire") / "data"
    assert (data / "tlds.txt").is_file()
    assert (data / "control_paths.txt").is_file()
    header = (data / "tlds.txt").read_text(encoding="utf-8").splitlines()[:6]
    assert any("https://data.iana.org/TLD/tlds-alpha-by-domain.txt" in line for line in header)
    assert any(line.startswith("# Fetched: ") for line in header)


def test_tld_list_is_the_iana_root_zone():
    assert {"com", "io", "md", "zip", "mov", "sh", "rs", "py", "pl", "ps", "xn--p1ai"} <= TLDS
    # special-use names are not delegated, so they are not in the root zone
    assert not {"example", "test", "invalid", "localhost", "local"} & TLDS
    assert len(TLDS) > 1000


def test_control_segments_are_folded():
    assert {".git", ".claude", ".mcp.json", "claude.md", "agents.md", ".ssh"} <= CONTROL_SEGMENTS
    # Claude Code's and Claude Desktop's MCP server lists, and git's
    # core.hooksPath and core.fsmonitor
    assert {".claude.json", "claude_desktop_config.json", ".gitconfig"} <= CONTROL_SEGMENTS
    assert all(s == unicodedata.normalize("NFKC", s).casefold() for s in CONTROL_SEGMENTS)


# --- pre-step and absence -----------------------------------------------------


@pytest.mark.parametrize("value", [None, "", " ", "\u200b", "\ufeff \u2060"])
def test_absent(value):
    assert normalize(value) is None
    assert normalize_all(value) == ()
    for vtype in VALUE_TYPES:
        assert normalize(value, vtype) is None


@pytest.mark.parametrize(
    "value",
    [
        "a\u202eb@corp.com",  # right-to-left override
        "corp\u2066.com",  # left-to-right isolate
        "al\u00adice",  # soft hyphen, Cf but not one of C2's five
        "a\x00b",
        "a\x1bb",
        "abc\ud800",  # lone surrogate
    ],
)
def test_control_format_and_surrogate_characters_are_invalid(value):
    for vtype in [*VALUE_TYPES, "auto"]:
        assert normalize(value, vtype) == Invalid("control_char")


def test_pre_step_is_canonicalize_c2_then_c1_then_trim():
    assert normalize(" ａlice@cor\u200bp.com ", "email") == E("alice@corp.com")
    assert normalize("\ufeffcorp．com", "host") == H("corp.com")


@pytest.mark.parametrize(
    ("value", "outcome"),
    [
        (13, D("13")),
        (-5, D("-5")),
        (0, D("0")),
        (True, Invalid("bool")),
        (False, Invalid("bool")),
        (1.0, Invalid("float")),
        (float("nan"), Invalid("float")),
        ([1], Invalid("not_scalar")),
        ({"a": 1}, Invalid("not_scalar")),
        (b"a@b.com", Invalid("not_scalar")),
        (10**200, Invalid("too_long")),
        # past sys.get_int_max_str_digits(), where str() itself raises
        pytest.param(10**5000, Invalid("too_long"), id="int-past-str-limit"),
    ],
)
def test_non_string_scalars(value, outcome):
    assert normalize(value) == outcome


def test_ints_normalize_as_their_decimal_string_under_any_type():
    assert normalize(5551234567, "phone") == P("5551234567")
    assert normalize(123, "name") == Unanchorable("no_letter")
    assert normalize(13, "email") == Invalid("email")


def test_unknown_type_is_invalid():
    assert normalize("abc", "bogus") == Invalid("type")  # type: ignore[arg-type]


# --- detection ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "vtype"),
    [
        (13, "id"),
        (True, None),
        (1.5, None),
        (None, None),
        ("", None),
        ("  ", None),
        ([1], None),
        ("https://corp.com/x", "url"),
        ("HTTP://corp.com", "url"),
        ("www.corp.com", "url"),
        ("alice@corp.com", "email"),
        ("a@x.com,b@y.com", "email"),
        ("@alice", "email"),  # rule 3 is literal: any @
        ("https://x.com/?to=a@b.com", "url"),  # rule 2 first
        ("DE89370400440532013000", "iban"),
        # an IBAN only as its key spells it: these fold to one
        ("DE89 3704 0044 0532 0130 00", "name"),
        ("de89370400440532013000", "id"),
        ("de89-3704-0044-0532-0130-00", "id"),
        ("+1 555 123 4567", "phone"),
        ("/etc/hosts", "path"),
        ("./notes", "path"),
        ("~/notes", "path"),
        ("corp.com", "host"),
        # a host only as its key spells it
        ("corp.com.", "id"),
        ("Corp.com", "id"),
        ("Bücher.de", "host"),  # non-ASCII is Unanchorable as a host either way
        ("notes.zip", "host"),
        ("a.b.c.io", "host"),
        ("xn--80ak6aa92e.xn--p1ai", "host"),
        ("corp.example", "id"),  # not a root zone TLD
        ("corp.com:8080", "id"),
        ("corp.com/pricing", "id"),
        ("abc-123", "id"),
        ("snake_case", "id"),
        ("v1", "id"),
        ("#general", "id"),
        ("alice", "name"),
        ("Priya Raman", "name"),
        ("room 101", "name"),  # two atoms
        ("ｃｏｒｐ.com", "host"),
    ],
)
def test_detect_type(value, vtype):
    assert detect_type(value) == vtype


def test_auto_normalizes_under_the_detected_type():
    assert normalize("www.Corp.com/x") == H("corp.com")
    assert normalize("Alice <alice@corp.com>") == E("alice@corp.com")
    assert normalize("DE89370400440532013000") == I("DE89370400440532013000")
    assert normalize("+1 (555) 123-4567") == P("+15551234567")
    assert normalize("./src/a.py") == PA("src/a.py")
    assert normalize("corp.com") == H("corp.com")
    assert normalize("INV-0042") == D("INV-0042")
    assert normalize("@Priya  Raman") == Invalid("email")
    assert normalize("Priya  Raman") == N("priya raman")


# Nothing under auto says a value isn't a case-sensitive id or file name,
# so auto keeps apart what a host or IBAN normalizer would fold together,
# and so does a whole field, whose type nobody declared either.
@pytest.mark.parametrize(
    ("one", "other"),
    [
        ("Report.md", "report.md"),
        ("notes.md", "notes.md."),
        ("CORP.COM", "corp.com"),
        ("fe12-release-candidate", "FE12RELEASECANDIDATE"),
        ("FE12-RELEASE-CANDIDATE", "FE12RELEASECANDIDATE"),
        ("de89370400440532013000", "DE89370400440532013000"),
        ("DE89 3704 0044 0532 0130 00", "DE89370400440532013000"),
    ],
)
def test_auto_keeps_folded_spellings_apart(one, other):
    assert normalize(one) != normalize(other)
    for field, value in [(one, other), (other, one)]:
        registered = {key for found in whole_fields([field]) for key in found.keys}
        assert normalize(value) not in registered


def test_declared_types_still_fold():
    assert normalize("Report.md", "host") == normalize("report.md", "host") == H("report.md")
    assert normalize("fe12-release-candidate", "iban") == I("FE12RELEASECANDIDATE")


# --- email -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "key"),
    [
        ("alice@corp.com", "alice@corp.com"),
        ("Alice@Corp.COM", "alice@corp.com"),
        ("alice@corp.com.", "alice@corp.com"),
        ("alice@corp.com...", "alice@corp.com"),
        ("Alice Smith <alice@corp.com>", "alice@corp.com"),
        ('"Alice Smith" <alice@corp.com>', "alice@corp.com"),
        ("<alice@corp.com>", "alice@corp.com"),
        ("mailto:alice@corp.com", "alice@corp.com"),
        ("MAILTO:Alice@corp.com", "alice@corp.com"),
        ("Alice <mailto:alice@corp.com>", "alice@corp.com"),
        ("  alice@corp.com\n", "alice@corp.com"),
        ("alice+tag@corp.com", "alice+tag@corp.com"),  # plus tags are not folded
        ("a.l.i.c.e@gmail.com", "a.l.i.c.e@gmail.com"),  # nor gmail dots
        ("ａｌｉｃｅ@corp.com", "alice@corp.com"),
        ("ali\u200bce@corp.com", "alice@corp.com"),
        ("x_y%z-w@sub.corp.co.uk", "x_y%z-w@sub.corp.co.uk"),
        ("alice@xn--80ak6aa92e.com", "alice@xn--80ak6aa92e.com"),
        ("a@b.co", "a@b.co"),
        ("a" * 64 + "@corp.com", "a" * 64 + "@corp.com"),
        ("Zoë <zoe@corp.com>", "zoe@corp.com"),
    ],
)
def test_email_keys(value, key):
    assert normalize(value, "email") == E(key)


@pytest.mark.parametrize(
    "value",
    [
        "alice",
        "alice@corp",
        "alice@@corp.com",
        "alice..smith@corp.com",
        "alice@corp..com",
        "alice@corp.c",
        "alice@corp.c0m",
        "al ice@corp.com",
        "@corp.com",
        "alice@",
        "alice@corp.com,bob@x.com",
        '"Doe, John" <j@x.com>',  # a comma in the display name splits naive lists
        "evil@x.com <alice@corp.com>",  # a display name that is itself an address
        "Alice <alice@corp.com",
        "mailto:alice@corp.com?subject=hi",
        "mailto:",
        "alice@corp_x.com",
    ],
)
def test_email_invalid(value):
    assert normalize(value, "email") == Invalid("email")


def test_email_length_limits():
    assert normalize("a" * 65 + "@corp.com", "email") == Invalid("too_long")
    long_domain = ".".join(["b" * 50] * 5) + ".com"
    assert normalize("a@" + long_domain, "email") == Invalid("too_long")
    assert normalize("a@" + long_domain[6:], "email") == E("a@" + long_domain[6:])


@pytest.mark.parametrize("value", ["alice@bücher.de", "аlice@corp.com", "Ålice@corp.com"])
def test_email_non_ascii_is_unanchorable(value):
    assert normalize(value, "email") == Unanchorable("idn")


# --- email lists ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "vtype", "outcomes"),
    [
        ("a@x.com,evil@y.com", "auto", (E("a@x.com"), E("evil@y.com"))),
        ("a@x.com; b@y.com", "auto", (E("a@x.com"), E("b@y.com"))),
        ("Alice <a@x.com>, Bob <b@y.com>", "auto", (E("a@x.com"), E("b@y.com"))),
        ("a@x.com,b@y.com", "email", (E("a@x.com"), E("b@y.com"))),
        ("a@x.com", "auto", (E("a@x.com"),)),
        ("a@x.com,notanemail", "auto", (Invalid("email"),)),
        ("a@x.com,", "auto", (Invalid("email"),)),
        # not every part is an email, so it isn't split, and whole it is IDN
        ("a@x.com,b@bücher.de", "auto", (Unanchorable("idn"),)),
        ("https://x.com/?a=b@c.com,d", "auto", (H("x.com"),)),
        ("a,b", "id", (Invalid("id"),)),
        (None, "auto", ()),
        ("", "email", ()),
    ],
)
def test_normalize_all(value, vtype, outcomes):
    assert normalize_all(value, vtype) == outcomes


# --- host -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "key"),
    [
        ("corp.com", "corp.com"),
        ("CORP.COM", "corp.com"),
        ("corp.com.", "corp.com"),
        ("corp.com..", "corp.com"),
        ("www.corp.com", "corp.com"),
        ("WWW.Corp.Com.", "corp.com"),
        ("www.www.corp.com", "www.www.corp.com"),  # one www., and only then
        ("www.com", "www.com"),
        ("sub.corp.co.uk", "sub.corp.co.uk"),
        ("corp.com:8080", "corp.com:8080"),
        ("corp.com.:8080", "corp.com:8080"),
        ("corp.com:443", "corp.com"),
        ("corp.com:80", "corp.com"),
        ("xn--80ak6aa92e.com", "xn--80ak6aa92e.com"),
        ("1.2.3.4", "1.2.3.4"),
        ("127.0.0.1", "127.0.0.1"),
        ("[::1]", "[::1]"),
        ("[2001:db8::1]:8443", "[2001:db8::1]:8443"),
        ("c\u200borp.com", "corp.com"),
        ("ｃｏｒｐ.com", "corp.com"),
        ("corp．com", "corp.com"),  # fullwidth full stop folds under NFKC
        ("corp.example", "corp.example"),  # a host need not end in a root zone TLD
    ],
)
def test_host_keys(value, key):
    assert normalize(value, "host") == H(key)


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("localhost", "labels"),
        ("corp", "labels"),
        ("2130706433", "labels"),
        ("-corp.com", "label"),
        ("corp-.com", "label"),
        ("corp_x.com", "label"),
        ("corp..com", "label"),
        (".corp.com", "label"),
        ("corp.com/x", "label"),
        ("user@corp.com", "label"),
        ("a" * 64 + ".com", "label"),
        (".".join(["a" * 60] * 5), "too_long"),
        ("0x7f.0.0.1", "ipv4"),
        ("0177.0.0.1", "ipv4"),
        ("127.1", "ipv4"),
        ("1.2.3.256", "ipv4"),
        ("01.2.3.4", "ipv4"),
        ("corp.0x1f", "ipv4"),
        ("[::0001]", "ipv6"),
        ("[0:0:0:0:0:0:0:1]", "ipv6"),
        ("[::1", "ipv6"),
        ("[fe80::1%25eth0]", "ipv6"),
        ("[not-an-address]", "ipv6"),
        ("corp.com:", "port"),
        ("corp.com:0", "port"),
        ("corp.com:65536", "port"),
        ("corp.com:123456", "port"),
        ("corp.com:8o", "port"),
        ("c%6frp.com", "label"),
        ("[::1]x", "port"),
    ],
)
def test_host_invalid(value, reason):
    assert normalize(value, "host") == Invalid(reason)


@pytest.mark.parametrize("value", ["bücher.de", "аpple.com", "corp。com"])
def test_host_non_ascii_is_unanchorable(value):
    assert normalize(value, "host") == Unanchorable("idn")


# --- url --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "key"),
    [
        ("https://corp.com", "corp.com"),
        ("http://corp.com/path?q=1#frag", "corp.com"),
        ("HTTPS://Corp.COM/", "corp.com"),
        ("https://www.corp.com/x", "corp.com"),
        ("www.corp.com/pricing", "corp.com"),
        ("https://corp.com:8443/x", "corp.com:8443"),
        ("https://corp.com:443/", "corp.com"),
        ("http://corp.com:80", "corp.com"),
        ("https://corp.com./x", "corp.com"),
        ("https://[::1]:8080/", "[::1]:8080"),
        ("https://1.2.3.4/x", "1.2.3.4"),
        ("https://corp.com/a@b", "corp.com"),  # @ past the authority is path
        ("https://corp.com?x=a@b", "corp.com"),
        ("https://corp.com#@evil.com", "corp.com"),
        ("https://corp.com/%41", "corp.com"),
        ("https://xn--bcher-kva.de/", "xn--bcher-kva.de"),
    ],
)
def test_url_keys_are_host_keys(value, key):
    assert normalize(value, "url") == H(key)


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("ftp://corp.com", "scheme"),
        ("javascript:alert(1)", "scheme"),
        ("corp.com/x", "scheme"),
        ("https:corp.com", "scheme"),
        ("https:/corp.com", "scheme"),
        ("//corp.com", "scheme"),
        ("https://user@corp.com", "userinfo"),
        ("https://evil.com@corp.com/", "userinfo"),
        ("https://user:pw@corp.com", "userinfo"),
        ("https://corp.com;@evil.com", "userinfo"),
        ("https://corp.com\\@evil.com", "backslash"),
        ("https://corp.com /x", "whitespace"),
        ("https://corp.com/a b", "whitespace"),
        ("https://c%6frp.com", "percent"),
        ("https://corp.com%2f.evil.com", "percent"),
        ("https://corp.com:99999/", "port"),
        ("https://0x7f.0.0.1/", "ipv4"),
        ("https:///corp.com", "labels"),
        ("https://", "labels"),
    ],
)
def test_url_invalid(value, reason):
    assert normalize(value, "url") == Invalid(reason)


def test_url_idn_is_unanchorable():
    assert normalize("https://bücher.de/", "url") == Unanchorable("idn")
    assert normalize("https://аpple.com/", "url") == Unanchorable("idn")


# --- iban -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "key"),
    [
        ("DE89370400440532013000", "DE89370400440532013000"),
        ("DE89 3704 0044 0532 0130 00", "DE89370400440532013000"),
        ("de89 3704 0044 0532 0130 00", "DE89370400440532013000"),
        ("DE89-3704-0044-0532-0130-00", "DE89370400440532013000"),
        ("GB29NWBK60161331926819", "GB29NWBK60161331926819"),
        ("NO9386011117947", "NO9386011117947"),
        ("LC55HEMM000100010012001200023015", "LC55HEMM000100010012001200023015"),
        ("ＤＥ89370400440532013000", "DE89370400440532013000"),
    ],
)
def test_iban_keys(value, key):
    assert normalize(value, "iban") == I(key)


@pytest.mark.parametrize(
    "value",
    [
        "DE89370400440",
        "D189370400440532013000",
        "DEX9370400440532013000",
        "DE89 3704.0044 0532 0130 00",
        "DE89_3704_0044_0532_0130_00",
        "DE89ß70400440532013000",
        "DE89" + "1" * 31,
        "89DE370400440532013000",
    ],
)
def test_iban_invalid(value):
    assert normalize(value, "iban") == Invalid("iban")


# --- phone ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "key"),
    [
        ("+1 (555) 123-4567", "+15551234567"),
        ("+15551234567", "+15551234567"),
        ("555-123-4567", "5551234567"),
        ("(555) 123.4567", "5551234567"),
        ("0049 30 1234567", "+49301234567"),
        ("+49 30 1234567", "+49301234567"),
        ("1234567", "1234567"),
        ("+123456789012345", "+123456789012345"),
        ("＋1 555 123 4567", "+15551234567"),
    ],
)
def test_phone_keys(value, key):
    assert normalize(value, "phone") == P(key)


@pytest.mark.parametrize(
    "value",
    [
        "123456",
        "+1234567890123456",
        "555/123/4567",
        "555 123 4567 ext 2",
        "+1+5551234567",
        "١٢٣٤٥٦٧",  # Arabic-Indic digits: NFKC leaves them alone
        "phone",
    ],
)
def test_phone_invalid(value):
    assert normalize(value, "phone") == Invalid("phone")


# --- path -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "key"),
    [
        ("/Users/me/project/a.py", "/Users/me/project/a.py"),
        ("/Users/me//project/./a.py", "/Users/me/project/a.py"),
        ("./src/a.py", "src/a.py"),
        ("src/a.py/", "src/a.py"),
        ("/", "/"),
        ("notes.md", "notes.md"),
        ("/Users/Me/Project", "/Users/Me/Project"),
        ("/tmp/résumé.pdf", "/tmp/résumé.pdf"),
        ("/repo/.gitignore", "/repo/.gitignore"),
        ("/repo/.github-backup/x", "/repo/.github-backup/x"),
        ("/repo/my.claude", "/repo/my.claude"),
        ("/repo/x.git/y", "/repo/x.git/y"),
        ("/repo/notes~/y", "/repo/notes~/y"),
        ("/repo/a:b", "/repo/a:b"),
    ],
)
def test_path_keys(value, key):
    assert normalize(value, "path") == PA(key)


@pytest.mark.parametrize(
    ("value", "outcome"),
    [
        ("C:\\Users\\me", Invalid("backslash")),
        ("/a\\b", Invalid("backslash")),
        ("/a\x00b", Invalid("control_char")),
        ("~/notes.md", Unanchorable("home")),
        ("~root/x", Unanchorable("home")),
        ("/a/../b", Unanchorable("dotdot")),
        ("../x", Unanchorable("dotdot")),
        ("/a/b..c", Unanchorable("dotdot")),
        (".", Unanchorable("empty")),
        ("./", Unanchorable("empty")),
    ],
)
def test_path_invalid_and_unanchorable(value, outcome):
    assert normalize(value, "path") == outcome


@pytest.mark.parametrize(
    "value",
    [
        "/Users/me/project/.git/hooks/pre-commit",
        "project/.claude/settings.json",
        ".mcp.json",
        "/repo/CLAUDE.md",
        "/repo/claude.MD",
        "/repo/.GIT/config",
        "/repo/.ｇｉｔ/config",
        "/repo/.Claude",
        "/home/me/.ssh/authorized_keys",
        "/home/me/.zshrc",
        "/repo/.github/workflows/ci.yml",
        "AGENTS.md",
        "/x/.config/fish/config.fish",
        "/x/.vscode/settings.json",
        "/x/CLAUDE.local.md",
        "/Users/me/.claude.json",
        "/Users/me/Library/Application Support/Claude/claude_desktop_config.json",
        "/Users/me/.gitconfig",
        # what NTFS opens as a control file or directory
        "/repo/.git./hooks/pre-commit",
        "/repo/.git /hooks/pre-commit",
        "/repo/.git. ./config",
        "/repo/GIT~1/hooks/pre-commit",
        "/repo/CLAUDE~1/settings.json",
        "/repo/CLAUDE.md::$DATA",
        "/repo/CLAUDE.md.:stream",
        "/repo/.git::$INDEX_ALLOCATION/hooks/pre-commit",
    ],
)
def test_control_paths_are_unanchorable(value):
    assert normalize(value, "path") == Unanchorable("control_path")


@pytest.mark.parametrize(
    "value",
    [
        ".git/hooks/pre-commit",
        ".claude/settings.json",
        ".github/workflows/ci.yml",
        ".mcp.json",
        ".zshrc",
        "project/.git/config",
        "C:/repo/.git/hooks/pre-commit",
        "CLAUDE.md",
        "AGENTS.md",
        "My Project/.git/config",
    ],
)
def test_control_files_are_unanchorable_under_every_type(value):
    for vtype in [*VALUE_TYPES, "auto"]:
        assert not any(isinstance(o, Key) for o in normalize_all(value, vtype)), vtype
    assert whole_fields([value]) == ()
    task = TaskIndex.build(f"Don't touch {value}, or do: {value}.")
    assert not task.keys and not task.mentioned


def test_hosts_named_as_control_files_are_unanchorable():
    assert normalize("www.CLAUDE.md", "host") == Unanchorable("control_path")
    assert normalize("https://agents.md/x", "url") == Unanchorable("control_path")
    assert normalize("https://claude.md.example/x", "url") == H("claude.md.example")


@pytest.mark.parametrize(
    ("value", "protected", "outcome"),
    [
        ("/var/tw/audit.log", ["/var/tw/audit.log"], Unanchorable("protected_path")),
        ("/VAR/TW/Audit.log", ["/var/tw/audit.log"], Unanchorable("protected_path")),
        ("/var/tw/audit.log", ["/var/tw/"], Unanchorable("protected_path")),
        ("/var/tw//x/./y", ["/var/tw"], Unanchorable("protected_path")),
        ("/var/tw/audit.log.1", ["/var/tw/audit.log"], PA("/var/tw/audit.log.1")),
        ("/var/twx/y", ["/var/tw"], PA("/var/twx/y")),
        ("/var/tw", ["/var/tw/policy.yaml"], PA("/var/tw")),
        ("/var/tw/x", ["", "/other"], PA("/var/tw/x")),
        # relative and symlinked spellings: only the last segment is certain
        ("tripwire.yaml", ["/private/tmp/proj/tripwire.yaml"], Unanchorable("protected_path")),
        (
            "/tmp/proj/tripwire.yaml",
            ["/private/tmp/proj/tripwire.yaml"],
            Unanchorable("protected_path"),
        ),
        ("./audit.jsonl", ["/Users/me/proj/audit.jsonl"], Unanchorable("protected_path")),
        ("proj/audit.jsonl", ["/Users/me/proj/audit.jsonl"], Unanchorable("protected_path")),
        ("/tmp/tw-state/ledger.bin", ["/private/tmp/tw-state"], Unanchorable("protected_path")),
        ("/var/tw/Audit.log.", ["/var/tw/audit.log"], Unanchorable("protected_path")),
        ("/srv/audit.jsonl.bak", ["/Users/me/proj/audit.jsonl"], PA("/srv/audit.jsonl.bak")),
    ],
)
def test_protected_paths(value, protected, outcome):
    assert normalize(value, "path", protected_paths=protected) == outcome


@pytest.mark.parametrize(
    ("path", "prefix", "under"),
    [
        ("/a/b", "/a", True),
        ("/a/b/c", "/a", True),
        ("/a", "/a", False),
        ("/ab", "/a", False),
        ("/a/b", "/", True),
        ("/", "/", False),
        ("a/b", "a", True),
        ("/a/b", "a", False),
        ("a", "", False),
    ],
)
def test_is_under(path, prefix, under):
    assert is_under(path, prefix) is under


# --- id ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "key"),
    [
        ("abc123", "abc123"),
        ("INV-2024-0042", "INV-2024-0042"),
        ("a", "a"),
        ("13", "13"),
        ("x:y/z#1_2.3", "x:y/z#1_2.3"),
        ("  abc  ", "abc"),
        ("a" * 128, "a" * 128),
        (13, "13"),
    ],
)
def test_id_keys(value, key):
    assert normalize(value, "id") == D(key)


@pytest.mark.parametrize("value", ["a b", "a@b", "a" * 129, "abc$", "é", "a,b", "ＡＢＣ€"])
def test_id_invalid(value):
    assert normalize(value, "id") == Invalid("id")


def test_ids_are_case_sensitive():
    assert normalize("AbC123", "id") != normalize("abc123", "id")


# --- name -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "key"),
    [
        ("Alice", "alice"),
        ("  Priya   Raman ", "priya raman"),
        ("@alice", "@alice"),
        ("#general", "#general"),
        ("@ alice", "@ alice"),
        ("Straße", "straße"),
        # a final sigma stays one, as str.lower() spells it
        ("ΣΟΦΟΣ", "σοφος"),
        ("σοφος", "σοφος"),
        ("σοφοσ", "σοφοσ"),
        ("Zoë", "zoë"),
        ("ａｌｉｃｅ", "alice"),
        ("a1b", "a1b"),
        ("one two three four five six seven eight", "one two three four five six seven eight"),
        ("x" * 128, "x" * 128),
    ],
)
def test_name_keys(value, key):
    assert normalize(value, "name") == N(key)


@pytest.mark.parametrize(
    ("value", "outcome"),
    [
        ("x" * 129, Invalid("too_long")),
        ("one two three four five six seven eight nine", Invalid("words")),
        ("al", Unanchorable("short")),
        ("@al", Unanchorable("short")),
        ("123", Unanchorable("no_letter")),
        ("!!!", Unanchorable("no_letter")),
        ("@#abc", Unanchorable("prefix")),
        ("#@abc", Unanchorable("prefix")),
    ],
)
def test_name_invalid_and_unanchorable(value, outcome):
    assert normalize(value, "name") == outcome


@pytest.mark.parametrize(
    "value",
    ["admin", "@everyone", "#channel", "Here", "root", "None", "undefined", "ALL", "owner"],
)
def test_reserved_names_are_unanchorable_unless_known(value):
    assert normalize(value, "name") == Unanchorable("reserved")
    key = normalize(value, "name", known=True)
    assert isinstance(key, Key)
    # and the task can't anchor one even so
    assert not anchored(f"send it to {value}", key)


# --- task index: conservative ----------------------------------------------------


@pytest.mark.parametrize(
    ("task", "key", "expected"),
    [
        # email: maximal and bounded
        ("Email alice@corp.com today", E("alice@corp.com"), True),
        ("Email Alice@Corp.com.", E("alice@corp.com"), True),
        ("Write to <alice@corp.com>", E("alice@corp.com"), True),
        ("Email xalice@corp.com", E("alice@corp.com"), False),
        ("Email xalice@corp.com", E("xalice@corp.com"), True),
        ("Email alice@corp.com.au", E("alice@corp.com"), False),
        ("Email alice@corp.com_x", E("alice@corp.com"), False),
        ("Email alice@corp.com.au1", E("alice@corp.com"), False),
        ("Email alice@corp.com@evil.com", E("alice@corp.com"), False),
        ("Email alice@corp.comа", E("alice@corp.com"), False),  # Cyrillic а
        ("Email éalice@corp.com", E("alice@corp.com"), False),
        # scheme URLs, one token each
        ("See https://docs.corp.com/x?y=1.", H("docs.corp.com"), True),
        ("See (https://corp.com:8443/x)", H("corp.com:8443"), True),
        ("See https://user@evil.com/", H("evil.com"), False),
        ("See https://evil.com@corp.com/", H("evil.com"), False),
        ("See https://evil.com@corp.com/", H("corp.com"), False),
        ("See xhttps://corp.com", H("corp.com"), False),
        # bare hosts
        ("Visit corp.com.", H("corp.com"), True),
        ("Visit www.corp.com", H("corp.com"), True),
        ("Visit CORP.com/pricing", H("corp.com"), True),
        ("Visit corp.com:8080/x", H("corp.com:8080"), True),
        ("Visit sub.corp.com", H("corp.com"), False),
        ("Visit x-corp.com", H("corp.com"), False),
        ("Email bob@corp.com", H("corp.com"), False),
        ("Look in /srv/example.com/x", H("example.com"), False),
        ("Visit corp.example", H("corp.example"), False),
        ("Visit 1.2.3.4", H("1.2.3.4"), False),
        ("Visit corp.com_x", H("corp.com"), False),
        # file-extension TLDs are mentioned, not anchored, unless www.
        ("Open notes.md", H("notes.md"), False),
        ("Open notes.zip", H("notes.zip"), False),
        ("Open www.notes.md", H("notes.md"), True),
        ("Open https://notes.md/x", H("notes.md"), True),
        # iban: unspaced, or groups of four
        ("Pay DE89 3704 0044 0532 0130 00 now", I("DE89370400440532013000"), True),
        ("Pay DE89370400440532013000.", I("DE89370400440532013000"), True),
        ("Pay de89370400440532013000", I("DE89370400440532013000"), False),
        ("Pay XDE89370400440532013000", I("DE89370400440532013000"), False),
        ("Pay DE89 37040044 0532013000", I("DE89370400440532013000"), False),
        # phone: + or 10+ digits, bounded
        ("Call +1 (555) 123-4567", P("+15551234567"), True),
        ("Call 555-123-4567.", P("5551234567"), True),
        ("Call (555) 123-4567", P("5551234567"), True),
        ("Call 0049 30 1234567", P("+49301234567"), True),
        ("Call 123-4567", P("1234567"), False),
        ("Ref 555-123-4567-9", P("5551234567"), False),
        ("Ref x5551234567", P("5551234567"), False),
        ("tel:5551234567", P("5551234567"), False),
        # paths
        ("Edit /Users/me/project/a.py", PA("/Users/me/project/a.py"), True),
        ("Edit ./src/a.py.", PA("src/a.py"), True),
        ("Edit notes.md", PA("notes.md"), True),
        ("Edit README", PA("README"), False),
        ("Compare A / B", PA("/"), False),
        ("See https://corp.com/a/b", PA("/corp.com/a/b"), False),
        ("Email alice@corp.com", PA("corp.com"), False),
        ("Edit /repo/.git/config", PA("/repo/.git/config"), False),
        # ids: 6+ characters as a maximal token, case-sensitive
        ("Pay invoice INV-2024-0042", D("INV-2024-0042"), True),
        ("Pay invoice INV-2024-0042.", D("INV-2024-0042"), True),
        ("Pay invoice INV-2024-0042", D("2024-0042"), False),
        ("Pay invoice INV-2024-0042", D("inv-2024-0042"), False),
        ("Open file-abcdef", D("abcdef"), False),
        ("Open abcdef@corp.com", D("abcdef"), False),
        ("Open abcde", D("abcde"), False),
        # short ids only next to a label
        ("Ticket 13", D("13"), False),
        ("Pay 13 dollars", D("13"), False),
        ("id 13", D("13"), True),
        ("ID: 13", D("13"), True),
        ("id #13", D("13"), True),
        ("Fix #13.", D("13"), True),
        ("No. 13", D("13"), True),
        ("number 13", D("13"), True),
        ("id13", D("13"), False),
        ("paid 13", D("13"), False),
        ("id 13.5", D("13"), False),
        ("id 13-a", D("13"), False),
        ("C#13", D("13"), False),
        ("no 13", D("13"), False),
        # names: whole phrases in the casefolded text
        ("Send it to Priya Raman.", N("priya raman"), True),
        ("Send it to Priya Raman.", N("raman"), True),
        ("Send it to Priya  RAMAN", N("priya raman"), True),
        ("Send it to Priya Raman", N("priya ram"), False),
        ("Message @alice", N("@alice"), True),
        ("Message alice_smith", N("alice"), False),
        ("Message Zoë", N("zoë"), True),
        ("Message Straße", N("straße"), True),
        ("Message Straße", N("strasse"), False),
        # a sigil is part of the name
        ("Post the summary in #random", N("#random"), True),
        ("Post the summary in #random", N("@random"), False),
    ],
)
def test_task_extraction(task, key, expected):
    assert anchored(task, key) is expected


def test_labels_supplied_by_the_caller():
    assert anchored("Pay invoice 13", D("13"), labels=["invoice"])
    assert anchored("Pay invoice no. 13", D("13"), labels=["invoice"])
    assert anchored("Pay Invoice #13", D("13"), labels=["invoice"])
    assert anchored("Cancel the calendar event 7", D("7"), labels=["calendar event"])
    assert not anchored("Pay invoice 13", D("13"), labels=["bill"])
    assert not anchored("Pay invoice13", D("13"), labels=["invoice"])
    assert not anchored("Pay 13", D("13"), labels=["", " ", 5])  # type: ignore[list-item]


def test_hosts_named_as_files_are_mentioned():
    task = TaskIndex.build("Summarize notes.md and send it to corp.com")
    assert task.mentions(H("notes.md")) and not task.anchors(H("notes.md"))
    assert task.mentions(H("corp.com")) and task.anchors(H("corp.com"))
    assert not task.mentions(H("evil.com"))


def test_under_prefixes_are_task_paths_of_two_or_more_components():
    task = TaskIndex.build("Work in /Users/me/project, x/y/z and /tmp, not ~/a/b or /a/../b.")
    assert task.under_prefixes == ("/Users/me/project", "x/y/z")


def test_only_keys_normalize_could_produce_anchor():
    task = TaskIndex.build("Email Alice@corp.com, id abc, name everyone")
    assert not task.anchors(Key("email", "Alice@corp.com"))
    assert not task.anchors(Key("name", ""))
    assert not task.anchors(Key("name", "everyone"))
    assert not task.anchors(Key("id", "abc def"))
    assert not task.anchors(Key("url", "corp.com"))  # type: ignore[arg-type]
    assert not task.anchors("alice@corp.com")  # type: ignore[arg-type]


def test_empty_and_non_text_tasks_anchor_nothing():
    for task in [TaskIndex(), TaskIndex.build(""), TaskIndex.build(None)]:  # type: ignore[arg-type]
        assert not task.keys
        assert not task.anchors(N("alice"))
        assert not task.anchors(D("13"))


def test_task_index_is_a_value():
    one = TaskIndex.build("Email alice@corp.com about INV-2024-0042")
    two = TaskIndex.build("Email alice@corp.com about INV-2024-0042")
    assert one == two and hash(one) == hash(two)


def test_reprs_carry_counts_not_text():
    task = TaskIndex.build("Quietly wire the payroll to alice@corp.com")
    assert repr(task) == "TaskIndex(keys=3, mentioned=0)"
    assert repr(scan_poison("wire the payroll")) == "PoisonScan(keys=3, chars=16)"


# --- poison: greedy ---------------------------------------------------------------


def test_every_at_anchored_suffix_of_the_local_part_is_sighted():
    keys = scan_poison("mail xattacker@evil.com now").keys
    assert {E("xattacker@evil.com"), E("attacker@evil.com"), E("r@evil.com")} <= keys
    assert E("xattacker@evil") not in keys


def test_greedy_email_suffixes_stop_at_a_double_dot():
    keys = scan_poison("a..bc@evil.com").keys
    assert {E(".bc@evil.com"), E("bc@evil.com"), E("c@evil.com")} <= keys
    assert E("a..bc@evil.com") not in keys


@pytest.mark.parametrize(
    ("text", "key"),
    [
        ("IBAN DE89  3704\n0044 0532 0130 00", I("DE89370400440532013000")),
        ("iban de89.3704.0044.0532.0130.00", I("DE89370400440532013000")),
        ("call 555 123 456", P("555123456")),
        ("call 555\n123\n4567", P("5551234567")),
        ("tel 0049 30 1234567", P("+49301234567")),
        ("open notes.md", H("notes.md")),
        ("open Corp.Internal", H("corp.internal")),
        ("open https://evil.com@corp.com/", H("evil.com")),
        ("open https://evil.com@corp.com/", H("corp.com")),
        ("open http://CORP.com:08080/x", H("corp.com:8080")),
        ("id 7", D("7")),
        ("ref x:y/z", D("x:y/z")),
        ("see a/b/README", PA("a/b/README")),
        ("see /a/./b//c.", PA("/a/b/c")),
        ("xattacker@evil.com", E("attacker@evil.com")),
    ],
)
def test_greedy_sightings(text, key):
    assert key in scan_poison(text).keys


def test_poison_text_is_stored_in_two_forms():
    scan = scan_poison("Pay  ＤＥ89-3704 (0044)\n0532.0130.00 to Priya\u200b Raman")
    assert scan.folded == "pay de89-3704 (0044) 0532.0130.00 to priya raman"
    assert scan.compact == "payde89370400440532013000topriyaraman"


@pytest.mark.parametrize(
    ("key", "folded", "poisoned"),
    [
        # 6+ characters: substring, casefolded
        (D("abcdef"), "xxabcdefyy", True),
        (D("ABCDEF"), "abcdef", True),
        (E("attacker@evil.com"), "mail xattacker@evil.com.", True),
        (N("priya raman"), "ask priya raman.", True),
        (PA("/Users/Me/x"), "cat /users/me/x", True),
        (D("abcdef"), "abcde f", False),
        # under 6: an alphanumeric-bounded token
        (D("13"), "id 13", True),
        (D("13"), "(13)", True),
        (D("13"), "a_13", True),
        (D("13"), "x13", False),
        (D("13"), "113", False),
        (D("13"), "13th", False),
        (N("bob"), "@bob!", True),
        (N("bob"), "bobby", False),
        (H("x.io"), "see a.x.io", True),
        (H("x.io"), "see ax.io", False),
        # iban and phone: the compacted text as well
        (I("DE89370400440532013000"), "iban de89.3704.0044.0532.0130.00", True),
        (I("DE89370400440532013000"), "iban de89 3704 0044 0532 0130 00", True),
        (P("+49301234567"), "tel 0049 (30) 123-4567", True),
        (P("+15551234567"), "call 1 555 123 4567", True),
        (P("5551234567"), "call 555.123.456", False),
        (D("DE89370400440532013000"), "iban de89 3704 0044 0532 0130 00", False),
    ],
)
def test_text_rule(key, folded, poisoned):
    assert is_poisoned(key, [text_only(folded)]) is poisoned


def test_typed_rule():
    scan = PoisonScan(frozenset({D("13")}), "", "")
    assert is_poisoned(D("13"), [scan])
    assert is_poisoned(D("13"), [scan], self_key=True)
    assert not is_poisoned(D("14"), [scan])


def test_short_self_keys_skip_the_text_rule():
    assert is_poisoned(D("13"), [text_only("id 13")])
    assert not is_poisoned(D("13"), [text_only("id 13")], self_key=True)
    # 6+ characters keep it
    assert is_poisoned(D("abcdef"), [text_only("abcdef")], self_key=True)


def test_no_scans_no_poison():
    assert not is_poisoned(E("alice@corp.com"), [])
    assert not is_poisoned(E("alice@corp.com"), [scan_poison(""), scan_poison("hello there")])


def test_a_key_that_is_not_one_counts_as_poisoned():
    assert is_poisoned("abc", [])  # type: ignore[arg-type]
    assert is_poisoned(Key("id", 5), [])  # type: ignore[arg-type]


def test_scan_of_non_text_is_empty():
    assert scan_poison(None) == PoisonScan(frozenset(), "", "")  # type: ignore[arg-type]


def test_stored_texts_and_task_texts_are_always_encodable():
    scan = scan_poison("mail a@b.co\ud800 now")
    task = TaskIndex.build("id 13\udfff and a@b.co")
    for text in (scan.folded, scan.compact, task.text, task.folded):
        text.encode("utf-8")
    assert E("a@b.co") in scan.keys
    assert task.anchors(D("13")) and task.anchors(E("a@b.co"))


# --- whole fields -----------------------------------------------------------------


def test_whole_fields_walk_in_sorted_key_order():
    fields = whole_fields({"b": [1, "x@y.com"], "a": {"to": "alice@corp.com"}})
    assert [(f.path, f.value, f.is_key) for f in fields] == [
        (("a",), "a", True),
        (("b",), "b", True),
        (("a", "to"), "to", True),
        (("a", "to"), "alice@corp.com", False),
        (("b", 0), 1, False),
        (("b", 1), "x@y.com", False),
    ]


def test_whole_fields_register_under_every_accepting_type():
    [field] = whole_fields(["alice@corp.com"])
    assert field == WholeField(
        (0,),
        "alice@corp.com",
        (E("alice@corp.com"), N("alice@corp.com"), PA("alice@corp.com")),
    )
    [field] = whole_fields([5551234567])
    assert set(field.keys) == {D("5551234567"), P("5551234567"), PA("5551234567")}
    [field] = whole_fields(["https://corp.com/x"])
    assert H("corp.com") in field.keys
    [field] = whole_fields(["a@x.com,b@y.com"])
    assert {E("a@x.com"), E("b@y.com")} <= set(field.keys)


@pytest.mark.parametrize(
    "value",
    [
        "x" * 257,
        "one two three four five six seven eight nine",
        True,
        None,
        1.5,
        "a\u202eb",
        " ",
        pytest.param(10**500, id="int-past-str-limit"),
    ],
)
def test_non_fields(value):
    assert whole_fields([value]) == ()


def test_field_limits():
    assert whole_fields(["x" * 256])
    assert whole_fields(["one two three four five six seven eight"])
    # dict keys have no word limit, only the length one
    assert whole_fields({"one two three four five six seven eight nine": None})
    assert not whole_fields({"x" * 257: None})


def test_whole_fields_ignore_key_order():
    record = {"id": "abc123", "to": "alice@corp.com", "nested": {"z": 1, "a": [2, "b"]}}
    reordered = {"nested": {"a": [2, "b"], "z": 1}, "to": "alice@corp.com", "id": "abc123"}
    assert whole_fields(record) == whole_fields(reordered)


def test_non_string_keys_take_their_json_spelling():
    fields = whole_fields({3: "zz", None: "qq", True: "tt", 1.5: "ff", (1, 2): "skipped", "3": "s"})
    by_path = [(f.path, f.value) for f in fields if not f.is_key]
    assert by_path == [
        (("1.5",), "ff"),
        (("3",), "s"),
        (("3",), "zz"),
        (("null",), "qq"),
        (("true",), "tt"),
    ]


def test_cycles_and_shared_containers_are_walked_once():
    shared = ["abc123"]
    node: dict = {"a": shared, "b": shared}
    node["self"] = node
    values = [f.value for f in whole_fields(node) if not f.is_key]
    assert values == ["abc123"]


def test_depth_is_capped():
    deep: object = "alice@corp.com"
    for _ in range(100_000):
        deep = {"k": [deep]}
    fields = whole_fields(deep)
    assert len(fields) == 32
    assert all(f.value == "k" and f.is_key and len(f.path) <= 64 for f in fields)

    shallow = [[["abc123"]]]
    assert [f.value for f in whole_fields(shallow, max_depth=3)] == ["abc123"]
    assert whole_fields(shallow, max_depth=2) == ()


# --- hostile inputs -----------------------------------------------------------------


class HostileStr(str):
    def strip(self, *args):
        raise RuntimeError

    def __iter__(self):
        raise RuntimeError

    def casefold(self):
        raise RuntimeError

    def __lt__(self, other):
        raise RuntimeError


class HostileInt(int):
    def __repr__(self):
        raise RuntimeError

    def bit_length(self):
        raise RuntimeError


class HostileDict(dict):
    def items(self):
        raise RuntimeError

    def __iter__(self):
        raise RuntimeError


class HostileList(list):
    def __iter__(self):
        raise RuntimeError


def test_subclasses_are_read_as_their_base_types():
    assert normalize(HostileStr("Alice@corp.com")) == E("alice@corp.com")
    assert normalize(HostileInt(13)) == D("13")
    assert detect_type(HostileStr("corp.com")) == "host"
    assert normalize_all(HostileStr("a@x.com,b@y.com")) == (E("a@x.com"), E("b@y.com"))
    assert TaskIndex.build(HostileStr("id 13")).anchors(D("13"))
    assert E("alice@corp.com") in scan_poison(HostileStr("alice@corp.com")).keys
    fields = whole_fields(HostileDict({HostileStr("k"): HostileList([HostileInt(7)])}))
    assert [(f.path, f.value) for f in fields] == [(("k",), "k"), (("k", 0), 7)]


def test_huge_values():
    huge = "a" * 1_000_000
    outcomes = {vtype: normalize(huge, vtype) for vtype in [*VALUE_TYPES, "auto"]}
    # a path has no length limit here; the filesystem has its own
    assert [vtype for vtype, o in outcomes.items() if isinstance(o, Key)] == ["path"]
    scan = scan_poison(huge + "@b.co " + "1" * 100_000 + " " + "a." * 100_000)
    assert E("a" * 64 + "@b.co") in scan.keys
    assert TaskIndex.build(huge + " id 13 " + "x@" * 50_000).anchors(D("13"))


# --- properties ---------------------------------------------------------------------

SETTINGS = settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])

emails = st.from_regex(r"[a-z0-9._%+-]{1,12}@[a-z0-9-]{1,10}\.[a-z]{2,6}", fullmatch=True)
hosts = st.from_regex(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,8}[a-z0-9])?\.){1,3}(?:com|org|io|net|dev|de)", fullmatch=True
)
urls = st.builds(
    lambda scheme, host, port, rest: f"{scheme}://{host}{port}{rest}",
    st.sampled_from(["http", "https", "HTTPS"]),
    hosts,
    st.sampled_from(["", ":80", ":443", ":8080", ":0443"]),
    st.from_regex(r"(?:/[A-Za-z0-9._~%-]{0,8}){0,3}(?:\?[a-z]=[a-z0-9@.]{0,6})?", fullmatch=True),
)
ibans = st.from_regex(r"[A-Za-z]{2}[0-9]{2}(?:[ -]?[A-Z0-9]){11,30}", fullmatch=True)
phones = st.from_regex(r"(?:\+|00)?[0-9](?:[ ().-]?[0-9]){6,14}", fullmatch=True)
paths = st.from_regex(r"(?:/|\./)?(?:[A-Za-z0-9._-]{1,8}/){0,4}[A-Za-z0-9._-]{1,8}", fullmatch=True)
ids = st.from_regex(r"[A-Za-z0-9_.:/#-]{1,24}", fullmatch=True)
names = st.from_regex(r"[@#]?[A-Za-z][A-Za-z0-9]{2,8}(?: [A-Za-z]{1,8}){0,3}", fullmatch=True)
plausible = st.one_of(emails, hosts, urls, ibans, phones, paths, ids, names)
anything = st.one_of(plausible, st.text(max_size=40), st.integers(), st.none())

junk = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(),
        st.floats(allow_nan=True, allow_infinity=True),
        st.text(max_size=30),
        plausible,
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(
            st.one_of(st.text(max_size=10), st.integers(), st.booleans(), st.none(), st.floats()),
            children,
            max_size=4,
        ),
    ),
    max_leaves=20,
)

vtypes = st.sampled_from([*VALUE_TYPES, "auto"])


@given(value=anything, vtype=vtypes)
@SETTINGS
def test_normalizers_are_idempotent(value, vtype):
    for outcome in normalize_all(value, vtype):
        if isinstance(outcome, Key):
            assert normalize(outcome.key, outcome.vtype) == outcome
            assert normalize_all(outcome.key, outcome.vtype) == (outcome,)


@given(value=junk, vtype=st.one_of(vtypes, st.text(max_size=8)), known=st.booleans())
@SETTINGS
def test_normalizers_are_total(value, vtype, known):
    outcome = normalize(value, vtype, known=known, protected_paths=["/tmp", "", "x"])
    assert outcome is None or isinstance(outcome, (Key, Invalid, Unanchorable))
    assert all(isinstance(o, (Key, Invalid, Unanchorable)) for o in normalize_all(value, vtype))
    assert detect_type(value) in (*VALUE_TYPES, None)


@given(text=st.text(max_size=200), key=st.builds(Key, st.sampled_from(VALUE_TYPES), st.text()))
@SETTINGS
def test_task_and_poison_are_total(text, key):
    task = TaskIndex.build(text)
    assert isinstance(task.anchors(key, labels=[text[:5]]), bool)
    assert isinstance(task.mentions(key), bool)
    scan = scan_poison(text)
    assert isinstance(is_poisoned(key, [scan]), bool)
    assert isinstance(is_poisoned(key, [scan], self_key=True), bool)


@given(value=junk)
@SETTINGS
def test_whole_fields_are_total_and_their_keys_normalize(value):
    for field in whole_fields(value):
        assert field.keys
        for key in field.keys:
            assert normalize(key.key, key.vtype) == key


@given(value=anything, vtype=vtypes, text=st.text(max_size=120))
@settings(max_examples=100)
def test_deterministic(value, vtype, text):
    assert normalize_all(value, vtype) == normalize_all(value, vtype)
    assert detect_type(value) == detect_type(value)
    assert TaskIndex.build(text) == TaskIndex.build(text)
    assert scan_poison(text) == scan_poison(text)


@given(value=junk, seed=st.integers(0, 2**32 - 1))
@settings(max_examples=150)
def test_whole_fields_ignore_insertion_order(value, seed):
    rng = random.Random(seed)

    def shuffled(node):
        if isinstance(node, dict):
            items = list(node.items())
            rng.shuffle(items)
            return {k: shuffled(v) for k, v in items}
        if isinstance(node, list):
            return [shuffled(v) for v in node]
        return node

    assert whole_fields(value) == whole_fields(shuffled(value))


# no substring anchoring: a value that contains an anchored one, and is not
# a spelling of it, anchors nothing
anchorable = st.one_of(
    st.tuples(st.just("email"), emails),
    st.tuples(st.just("host"), hosts),
    st.tuples(
        st.just("id"),
        st.from_regex(r"[A-Za-z0-9_-][A-Za-z0-9_.:/#-]{4,20}[A-Za-z0-9]", fullmatch=True),
    ),
)
affix = st.text(alphabet=string.ascii_letters + string.digits + "._-+@:/#%", max_size=6)


@given(
    item=anchorable,
    before=affix,
    after=affix,
    context=st.sampled_from(["{}", "Please send {} today.", "({})"]),
)
@SETTINGS
def test_no_substring_anchoring(item, before, after, context):
    vtype, value = item
    key = normalize(value, vtype)
    assume(isinstance(key, Key))
    task = TaskIndex.build(context.format(value))
    assume(task.anchors(key))
    candidate = before + value + after
    assume(candidate != value)
    outcome = normalize(candidate, vtype)
    if isinstance(outcome, Key) and outcome != key:
        assert not task.anchors(outcome)


# One substitution by a lookalike that NFKC does not fold back to ASCII.
CONFUSABLES = {
    ascii_char: [c for c in candidates if unicodedata.normalize("NFKC", c) != ascii_char]
    for ascii_char, candidates in {
        "a": ["а", "ɑ", "α"],
        "c": ["с", "ϲ"],
        "e": ["е", "ҽ"],
        "i": ["і", "ı", "ί"],
        "j": ["ј"],
        "l": ["ӏ", "ɩ"],
        "o": ["о", "ο", "օ"],
        "p": ["р", "ρ"],
        "s": ["ѕ"],
        "x": ["х"],
        "y": ["у"],
        "0": ["О", "Ο"],
        "1": ["Ӏ"],
        "-": ["‐", "−"],
        ".": ["․"],
    }.items()
}


@given(
    item=st.one_of(
        st.tuples(st.just("email"), emails),
        st.tuples(st.just("host"), hosts),
        st.tuples(st.just("url"), urls),
        st.tuples(st.just("id"), ids),
        st.tuples(st.just("name"), names),
        st.tuples(st.just("path"), paths),
    ),
    data=st.data(),
)
@SETTINGS
def test_confusable_substitutions_never_anchor(item, data):
    vtype, value = item
    key = normalize(value, vtype)
    assume(isinstance(key, Key))
    # a URL's key is its authority; the rest of it is content
    start, end = 0, len(value)
    if vtype == "url":
        start = value.index("//") + 2
        end = next((i for i in range(start, end) if value[i] in "/?#"), end)
    positions = [i for i in range(start, end) if CONFUSABLES.get(value[i].lower())]
    assume(positions)
    i = data.draw(st.sampled_from(positions))
    lookalike = data.draw(st.sampled_from(CONFUSABLES[value[i].lower()]))
    spoofed = value[:i] + lookalike + value[i + 1 :]

    task = TaskIndex.build(f"Please use {value} for this.")
    outcome = normalize(spoofed, vtype)
    assert not (isinstance(outcome, Key) and task.anchors(outcome))
    # and the other way round: a task that names the lookalike
    spoofed_task = TaskIndex.build(f"Please use {spoofed} for this.")
    assert not spoofed_task.anchors(key, labels=["use"])


def _cased(draw, text):
    return "".join(draw(st.sampled_from([c.lower(), c.upper()])) for c in text)


dots = st.sampled_from(["", ".", ".."])


@given(value=st.one_of(hosts, ibans, ids), data=st.data())
@SETTINGS
def test_auto_hosts_and_ibans_key_only_their_own_spelling(value, data):
    spelled = _cased(data.draw, value) + data.draw(dots)
    assume(not spelled.lower().startswith("www."))
    outcome = normalize(spelled)
    if isinstance(outcome, Key) and outcome.vtype in ("host", "iban"):
        assert outcome.key == spelled
    for field in whole_fields([spelled]):
        assert all(k.key == spelled for k in field.keys if k.vtype in ("host", "iban"))


# Greedy superset: whatever the task extractors anchor from a text, the same
# text scanned as poison poisons.
@given(
    value=plausible,
    before=st.text(max_size=12),
    after=st.text(max_size=12),
    label=st.sampled_from(["", "id ", "#", "no. "]),
)
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_poison_covers_every_task_anchor(value, before, after, label):
    text = before + label + value + after
    task = TaskIndex.build(text)
    scan = scan_poison(text)
    for key in task.keys | task.mentioned:
        assert is_poisoned(key, [scan]), key
    for vtype in VALUE_TYPES:
        for outcome in normalize_all(value, vtype):
            if isinstance(outcome, Key) and task.anchors(outcome):
                assert is_poisoned(outcome, [scan]), outcome


@given(
    prefix=st.from_regex(r"(/[a-z]{1,6}){0,3}", fullmatch=True),
    segment=st.sampled_from(sorted(CONTROL_SEGMENTS)),
    rest=st.from_regex(r"(/[a-z]{1,6}){0,2}", fullmatch=True),
    data=st.data(),
)
@SETTINGS
def test_no_path_with_a_control_segment_anchors(prefix, segment, rest, data):
    spelled = "".join(data.draw(st.sampled_from([c, c.upper()])) for c in segment)
    path = f"{prefix}/{spelled}{rest}"
    assert normalize(path, "path") == Unanchorable("control_path")
    task = TaskIndex.build(f"Work in {prefix or '/'} and edit {path}")
    assert not any(k.vtype == "path" and k.key.casefold() == path.casefold() for k in task.keys)


# Nor under any other type, relative or NTFS-spelled: a control file never
# anchors, and neither does anything a task names inside it.
@given(
    prefix=st.from_regex(r"(?:/?[a-z]{1,6}/){0,3}", fullmatch=True),
    segment=st.sampled_from(sorted(CONTROL_SEGMENTS)),
    suffix=st.sampled_from(["", ".", " ", ". ", "::$DATA", ":x"]),
    rest=st.from_regex(r"(/[a-z]{1,6}){0,2}", fullmatch=True),
    data=st.data(),
)
@SETTINGS
def test_no_value_with_a_control_segment_anchors(prefix, segment, suffix, rest, data):
    value = "".join(data.draw(st.sampled_from([c, c.upper()])) for c in segment) + suffix
    value = f"{prefix}{value}{rest}"
    for vtype in [*VALUE_TYPES, "auto"]:
        assert not any(isinstance(o, Key) for o in normalize_all(value, vtype)), vtype
    assert whole_fields([value]) == ()
    task = TaskIndex.build(f"Update {value} now")
    assert not any(segment in k.key.casefold() for k in task.keys | task.mentioned)


# Unlabelled short ids never anchor from task text.
@given(text=st.text(alphabet=string.ascii_letters + string.digits + " ,.-_:/", max_size=80))
@SETTINGS
def test_short_ids_need_a_label(text):
    lowered = text.lower()
    assume(not any(label in lowered for label in ("id", "no.", "number")))
    task = TaskIndex.build(text)
    for token in set(text.replace(",", " ").split()):
        for piece in {token, token.strip(".:-_/")}:
            key = normalize(piece, "id")
            if isinstance(key, Key) and len(key.key) < 6:
                assert not task.anchors(key)
