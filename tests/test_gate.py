"""Both gates against the real thing: actual HTTP for the web gate, an
actual pty for the cli gate. No fakes here — the whole point of a gate
is the wire a human sits on, so that wire is what gets exercised. The
argument previews are also driven directly by hypothesis, since a real
terminal per example would leave it too slow to search.
"""

import html
import http.client
import json
import os
import pty
import re
from html.parser import HTMLParser
from urllib.parse import urlencode

import anyio
import pytest
from hypothesis import given
from hypothesis import strategies as st

from tripwire.gate.base import ApprovalRequest, GateUnavailable, encode_args
from tripwire.gate.cli import ARG_PREVIEW as CLI_PREVIEW
from tripwire.gate.cli import CliGate, _arg_lines
from tripwire.gate.web import ARG_PREVIEW as WEB_PREVIEW
from tripwire.gate.web import WebGate, _args_html


def req(tool="send_email", **kw):
    kw.setdefault("args", {"to": "boss@corp.com"})
    kw.setdefault("rule_id", "flows.0")
    kw.setdefault("reason", "untrusted content in context")
    return ApprovalRequest(tool=tool, **kw)


# --- argument previews ---

# the long email body that used to push `to` off the end of the prompt
LONG_BODY = {"body": "x" * 20_000, "to": "attacker@evil.example"}

# what an attacker would put in an argument, names included: markup, an
# entity, terminal escapes, line breaks, a bidi override, the clip
# marker's own ellipsis. Random characters alone almost never spell a tag.
tricks = st.sampled_from(
    ["<b>", "</pre>", "<details>", "&amp;", '"', "\x00", "\x1b[2J", "\x7f", "\r\n", "\u202e", "…"]
)
nasty = st.lists(st.text(max_size=5) | tricks, max_size=5).map("".join)
json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | nasty,
    lambda children: st.lists(children, max_size=3) | st.dictionaries(nasty, children, max_size=3),
    max_leaves=8,
)
# long enough to be clipped by either gate
long_text = (st.text(min_size=1, max_size=3) | tricks).map(lambda s: s * 1000)
arg_dicts = st.dictionaries(nasty, json_values | long_text, min_size=1, max_size=6)

DECODER = json.JSONDecoder()


def test_short_scalars_come_before_long_strings():
    args = {"body": "hello " * 50, "to": "boss@corp.com", "amount": 5, "cc": []}
    assert [name for name, _ in encode_args(args)] == ['"cc"', '"amount"', '"to"', '"body"']


@given(value=json_values)
def test_every_nested_object_lists_its_members_shortest_first(value):
    def members_in_order(pairs):
        sizes = [sum(map(len, encode_args({key: item})[0])) for key, item in pairs]
        assert sizes == sorted(sizes)
        return dict(pairs)

    [(_, encoded)] = encode_args({"arg": value})
    assert json.loads(encoded, object_pairs_hook=members_in_order) == value


# --- web gate ---

# a card is <b>tool</b> ... then its rid in a hidden input; non-greedy so
# the second form of one card can't pair with the next card's title
CARD_RE = re.compile(r"<b>(.*?)</b>.*?name=\"rid\" value=\"([^\"]+)\"", re.DOTALL)


def get(gate, path):
    conn = http.client.HTTPConnection("127.0.0.1", gate.port, timeout=5)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, resp.read().decode()
    finally:
        conn.close()


def post(gate, **fields):
    conn = http.client.HTTPConnection("127.0.0.1", gate.port, timeout=5)
    try:
        conn.request(
            "POST",
            "/decide",
            urlencode(fields),
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        conn.close()


@pytest.fixture
def web():
    gate = WebGate(port=0)
    yield gate
    gate.close()


async def test_approve_over_real_http(web):
    decisions = []

    async def ask():
        decisions.append(await web.request(req(tainted=True, tainted_by=("fetch_url",))))

    async with anyio.create_task_group() as tg:
        tg.start_soon(ask)
        await anyio.sleep(0.05)

        status, page = get(web, f"/?k={web.token}")
        assert status == 200
        assert "send_email" in page
        assert "boss@corp.com" in page
        assert "flows.0" in page
        assert "untrusted content in context" in page
        assert "tainted session" in page
        assert "fetch_url" in page

        rid = CARD_RE.search(page).group(2)
        assert post(web, k=web.token, rid=rid, action="approve") == 303

    assert decisions == [True]


async def test_deny_returns_false(web):
    decisions = []

    async def ask():
        decisions.append(await web.request(req()))

    async with anyio.create_task_group() as tg:
        tg.start_soon(ask)
        await anyio.sleep(0.05)
        _, page = get(web, f"/?k={web.token}")
        post(web, k=web.token, rid=CARD_RE.search(page).group(2), action="deny")

    assert decisions == [False]


async def test_junk_action_string_denies(web):
    decisions = []

    async def ask():
        decisions.append(await web.request(req()))

    async with anyio.create_task_group() as tg:
        tg.start_soon(ask)
        await anyio.sleep(0.05)
        _, page = get(web, f"/?k={web.token}")
        # "yes" is not the exact string "approve", so it must read as no
        post(web, k=web.token, rid=CARD_RE.search(page).group(2), action="yes")

    assert decisions == [False]


async def test_get_without_the_token_is_forbidden(web):
    assert get(web, "/")[0] == 403
    assert get(web, "/?k=not-the-token")[0] == 403


async def test_forged_post_is_forbidden_and_touches_nothing(web):
    decisions = []

    async def ask():
        decisions.append(await web.request(req()))

    async with anyio.create_task_group() as tg:
        tg.start_soon(ask)
        await anyio.sleep(0.05)
        _, page = get(web, f"/?k={web.token}")
        rid = CARD_RE.search(page).group(2)

        assert post(web, k="not-the-token", rid=rid, action="approve") == 403
        await anyio.sleep(0.3)  # a full poll cycle: a decided request would have returned
        assert decisions == []

        # the request is still open and still answerable
        assert post(web, k=web.token, rid=rid, action="approve") == 303

    assert decisions == [True]


async def test_unknown_path_is_404(web):
    assert get(web, f"/nope?k={web.token}")[0] == 404


async def test_dangerous_arg_is_escaped_in_the_page(web):
    payload = "<script>alert(1)</script>"

    async def ask():
        await web.request(req(args={"body": payload}))

    async with anyio.create_task_group() as tg:
        tg.start_soon(ask)
        await anyio.sleep(0.05)
        _, page = get(web, f"/?k={web.token}")
        assert payload not in page
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
        post(web, k=web.token, rid=CARD_RE.search(page).group(2), action="deny")


async def test_a_long_value_cannot_hide_the_recipient_on_the_page(web):
    async def ask():
        await web.request(req(args=LONG_BODY))

    async with anyio.create_task_group() as tg:
        tg.start_soon(ask)
        await anyio.sleep(0.05)
        _, page = get(web, f"/?k={web.token}")
        preview = html.unescape(re.search(r"<pre>(.*?)</pre>", page, re.DOTALL).group(1))
        body = json.dumps(LONG_BODY["body"])
        assert preview.split("\n") == [
            '"to": "attacker@evil.example"',
            f'"body": {body[:WEB_PREVIEW]}…[+{len(body) - WEB_PREVIEW} chars]',
        ]
        assert html.escape(body) in page  # clipped in the preview, not gone
        post(web, k=web.token, rid=CARD_RE.search(page).group(2), action="deny")


async def test_the_page_holds_still_while_a_question_is_open(web):
    _, idle = get(web, f"/?k={web.token}")
    assert 'http-equiv="refresh"' in idle

    async def ask():
        await web.request(req(args=LONG_BODY))

    async with anyio.create_task_group() as tg:
        tg.start_soon(ask)
        await anyio.sleep(0.05)
        _, page = get(web, f"/?k={web.token}")
        # a reload would fold the full body away while the human reads it
        assert "<details>" in page
        assert 'http-equiv="refresh"' not in page
        post(web, k=web.token, rid=CARD_RE.search(page).group(2), action="deny")


class Rendered(HTMLParser):
    """The tags a browser would build from some markup, and the text it
    would show inside each <pre> and <summary>."""

    def __init__(self, markup):
        super().__init__()
        self.tags = []
        self.text = {"pre": [], "summary": []}
        self._inside = None
        self.feed(markup)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        if tag in self.text:
            self._inside = tag
            self.text[tag].append("")

    def handle_endtag(self, tag):
        self._inside = None

    def handle_data(self, data):
        if self._inside:
            self.text[self._inside][-1] += data


@given(args=arg_dicts)
def test_the_page_names_every_arg_and_keeps_every_value_inert(args):
    rendered = Rendered(_args_html(args))
    assert set(rendered.tags) <= {"pre", "details", "summary"}

    preview, *whole = rendered.text["pre"]
    lines = preview.split("\n")
    shown = {}
    for line in lines:
        name, end = DECODER.raw_decode(line)
        assert line[end : end + 2] == ": "
        shown[name] = line[end + 2 :]
    assert len(lines) == len(args)
    assert shown.keys() == args.keys()

    for summary, value in zip(rendered.text["summary"], whole, strict=True):
        name, _ = DECODER.raw_decode(summary)
        assert shown[name] == f"{value[:WEB_PREVIEW]}…[+{len(value) - WEB_PREVIEW} chars]"
        shown[name] = value
    assert {name: json.loads(value) for name, value in shown.items()} == args


async def test_two_pending_requests_are_decided_independently(web):
    decisions = {}

    async def ask(tool):
        decisions[tool] = await web.request(req(tool=tool))

    async with anyio.create_task_group() as tg:
        tg.start_soon(ask, "send_email")
        tg.start_soon(ask, "delete_file")
        await anyio.sleep(0.05)

        _, page = get(web, f"/?k={web.token}")
        assert page.count('<div class="card">') == 2
        rids = dict(CARD_RE.findall(page))
        assert set(rids) == {"send_email", "delete_file"}

        post(web, k=web.token, rid=rids["send_email"], action="approve")
        post(web, k=web.token, rid=rids["delete_file"], action="deny")

    assert decisions == {"send_email": True, "delete_file": False}


async def test_a_decided_request_leaves_the_page(web):
    async def ask():
        await web.request(req())

    async with anyio.create_task_group() as tg:
        tg.start_soon(ask)
        await anyio.sleep(0.05)
        _, page = get(web, f"/?k={web.token}")
        post(web, k=web.token, rid=CARD_RE.search(page).group(2), action="deny")

    _, page = get(web, f"/?k={web.token}")
    assert "send_email" not in page
    assert "Nothing waiting for approval." in page


async def test_cancelled_request_cleans_up_after_itself(web):
    with anyio.move_on_after(0.5) as scope:
        await web.request(req())

    assert scope.cancelled_caught
    assert web._pending == {}


# --- cli gate ---


@pytest.fixture
def tty():
    # a real pty, opened by the real constructor, through its real path
    master, slave = pty.openpty()
    gate = CliGate(os.ttyname(slave), timeout=5)
    os.close(slave)
    yield master, gate
    gate.close()
    os.close(master)


async def type_after_prompt(master, line):
    """Reply the way a human does: after the question is on screen.

    Typing before the prompt appears is exactly the type-ahead the gate
    flushes, so a test that pre-loads the pty is testing the timeout.
    """
    await anyio.sleep(0.15)
    os.write(master, line.encode())


def drain(master):
    # everything the gate wrote is already in the pty buffer by the time
    # request() returns, so a non-blocking read gets all of it
    os.set_blocking(master, False)
    out = b""
    while True:
        try:
            out += os.read(master, 4096)
        except BlockingIOError:
            return out.decode()


@pytest.mark.parametrize(
    ("line", "verdict"),
    [("y\n", True), ("yes\n", True), ("Y\n", True), ("n\n", False), ("\n", False)],
)
async def test_only_an_explicit_yes_approves(tty, line, verdict):
    master, gate = tty
    async with anyio.create_task_group() as tg:
        tg.start_soon(type_after_prompt, master, line)
        assert await gate.request(req()) is verdict


async def test_prompt_gives_the_human_the_full_picture(tty):
    master, gate = tty
    async with anyio.create_task_group() as tg:
        tg.start_soon(type_after_prompt, master, "n\n")
        await gate.request(req(tainted=True, tainted_by=("fetch_url", "read_file")))

    prompt = drain(master)
    assert "send_email" in prompt
    assert "flows.0" in prompt
    assert "untrusted content in context" in prompt
    assert "TAINTED" in prompt
    assert "fetch_url, read_file" in prompt


async def test_huge_args_are_truncated_not_dumped(tty):
    master, gate = tty
    async with anyio.create_task_group() as tg:
        tg.start_soon(type_after_prompt, master, "n\n")
        await gate.request(req(args={"body": "x" * 20_000}))

    prompt = drain(master)
    assert f"…[+{20_002 - CLI_PREVIEW} chars]" in prompt
    assert len(prompt) < 2_000


async def test_a_long_value_cannot_hide_the_recipient_at_the_terminal(tty):
    master, gate = tty
    async with anyio.create_task_group() as tg:
        tg.start_soon(type_after_prompt, master, "n\n")
        await gate.request(req(args=LONG_BODY))

    prompt = drain(master)
    assert '"to": "attacker@evil.example"' in prompt
    assert prompt.index('"to":') < prompt.index('"body":')


async def test_a_long_nested_value_cannot_hide_a_nested_recipient(tty):
    master, gate = tty
    async with anyio.create_task_group() as tg:
        tg.start_soon(type_after_prompt, master, "n\n")
        await gate.request(req(args={"message": LONG_BODY}))

    assert '"message": {"to": "attacker@evil.example", "body": "xxx' in drain(master)


async def test_control_characters_never_reach_the_terminal(tty):
    master, gate = tty
    async with anyio.create_task_group() as tg:
        tg.start_soon(type_after_prompt, master, "n\n")
        await gate.request(
            req(args={"to\x1b[2K": "boss@corp.com\r\x1b[1A", "body": "hi\x7f\u202e\nbcc: x"})
        )

    prompt = drain(master).replace("\r\n", "\n")  # the pty's own line endings
    assert not {"\x1b", "\x7f", "\u202e", "\r"} & set(prompt)
    args = prompt.split("  args:")[1].split("  rule:")[0]
    assert len(args.strip().split("\n")) == 2  # an injected newline drew no extra line


@given(args=arg_dicts)
def test_the_terminal_names_every_arg_on_one_plain_line(args):
    lines = _arg_lines(args)
    assert len(lines) == len(args)
    names = set()
    for line in lines:
        name, end = DECODER.raw_decode(line)
        assert line[end : end + 2] == ": "
        value, marker, cut = line[end + 2 :].partition("…")
        # the clip marker is the only thing on the line the args didn't write
        assert all(0x20 <= ord(c) < 0x7F for c in line[:end] + value)
        if marker:
            assert len(value) == CLI_PREVIEW
            assert re.fullmatch(r"\[\+\d+ chars\]", cut)
        else:
            assert json.loads(value) == args[name]
        names.add(name)
    assert names == args.keys()


def test_no_terminal_refuses_at_startup():
    with pytest.raises(GateUnavailable):
        CliGate("/nonexistent/tty")
