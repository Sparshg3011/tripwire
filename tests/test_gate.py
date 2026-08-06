"""Both gates against the real thing: actual HTTP for the web gate, an
actual pty for the cli gate. No fakes here — the whole point of a gate
is the wire a human sits on, so that wire is what gets exercised.
"""

import http.client
import os
import pty
import re
from urllib.parse import urlencode

import anyio
import pytest

from tripwire.gate.base import ApprovalRequest, GateUnavailable
from tripwire.gate.cli import CliGate
from tripwire.gate.web import WebGate


def req(tool="send_email", **kw):
    kw.setdefault("args", {"to": "boss@corp.com"})
    kw.setdefault("rule_id", "flows.0")
    kw.setdefault("reason", "untrusted content in context")
    return ApprovalRequest(tool=tool, **kw)


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
    assert "more chars" in prompt
    assert len(prompt) < 2_000


def test_no_terminal_refuses_at_startup():
    with pytest.raises(GateUnavailable):
        CliGate("/nonexistent/tty")
