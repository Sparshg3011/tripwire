"""The executor's contract, executable. One intent, one execution: a
duplicate call gets the first result back, an unknown outcome gets
refused, and a tool-reported error stays retryable.
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from mcp import types

from tripwire.tx.executor import DuplicateInFlight, TxError, TxExecutor, intent_key


def ok(text="ok"):
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)])


def failed(text="tool said no"):
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], isError=True)


def make_forward(result):
    async def forward():
        forward.calls += 1
        return result

    forward.calls = 0
    return forward


def broken_forward(exc):
    async def forward():
        forward.calls += 1
        raise exc

    forward.calls = 0
    return forward


@pytest.fixture
def db(tmp_path):
    return tmp_path / "ledger.db"


# --- intent_key -------------------------------------------------------------


def test_same_intent_gives_the_same_key():
    assert intent_key("s1", "add", {"a": 1}) == intent_key("s1", "add", {"a": 1})


def test_key_is_64_lowercase_hex():
    key = intent_key("s1", "add", {"a": 1})
    assert len(key) == 64
    assert set(key) <= set("0123456789abcdef")


def test_every_component_feeds_the_key():
    base = intent_key("s1", "add", {"a": 1})
    assert intent_key("s2", "add", {"a": 1}) != base
    assert intent_key("s1", "sub", {"a": 1}) != base
    assert intent_key("s1", "add", {"a": 2}) != base


def test_arg_order_does_not_matter():
    assert intent_key("s1", "add", {"a": 1, "b": 2}) == intent_key("s1", "add", {"b": 2, "a": 1})


# --- run: first time and replay ---------------------------------------------


async def test_first_call_forwards_once(db):
    ex = TxExecutor(db, "s1")
    forward = make_forward(ok("first"))
    result, replayed = await ex.run("add", {"a": 1}, forward)

    assert forward.calls == 1
    assert replayed is False
    assert result.content[0].text == "first"
    ex.close()


async def test_identical_call_replays_the_stored_result(db):
    ex = TxExecutor(db, "s1")
    first, _ = await ex.run("add", {"a": 1}, make_forward(ok("first")))

    forward = make_forward(ok("second"))
    again, replayed = await ex.run("add", {"a": 1}, forward)

    assert forward.calls == 0
    assert replayed is True
    assert again.content[0].text == first.content[0].text
    assert not again.isError
    ex.close()


async def test_different_args_run_fresh(db):
    ex = TxExecutor(db, "s1")
    await ex.run("add", {"a": 1}, make_forward(ok()))

    forward = make_forward(ok())
    _, replayed = await ex.run("add", {"a": 2}, forward)

    assert forward.calls == 1
    assert replayed is False
    ex.close()


async def test_sessions_do_not_share_a_ledger_even_in_one_db(db):
    a = TxExecutor(db, "s1")
    await a.run("add", {"a": 1}, make_forward(ok()))

    b = TxExecutor(db, "s2")
    forward = make_forward(ok())
    _, replayed = await b.run("add", {"a": 1}, forward)

    assert forward.calls == 1
    assert replayed is False
    a.close()
    b.close()


async def test_replay_survives_a_restart(db):
    first = TxExecutor(db, "s1")
    await first.run("send_email", {"to": "a@b.com"}, make_forward(ok("sent")))
    first.close()

    second = TxExecutor(db, "s1")
    forward = make_forward(ok("resent"))
    result, replayed = await second.run("send_email", {"to": "a@b.com"}, forward)

    assert forward.calls == 0
    assert replayed is True
    assert result.content[0].text == "sent"
    second.close()


# --- run: errors and the poison pill ----------------------------------------


async def test_error_results_stay_retryable(db):
    ex = TxExecutor(db, "s1")
    result, replayed = await ex.run("fetch_url", {"url": "x"}, make_forward(failed("rate limited")))

    assert replayed is False
    assert result.isError

    retry = make_forward(ok("got it"))
    result, replayed = await ex.run("fetch_url", {"url": "x"}, retry)

    assert retry.calls == 1
    assert replayed is False
    assert result.content[0].text == "got it"
    ex.close()


async def test_a_raise_mid_call_poisons_the_key(db):
    ex = TxExecutor(db, "s1")
    with pytest.raises(RuntimeError):
        await ex.run("send_email", {"to": "a@b.com"}, broken_forward(RuntimeError("wire cut")))

    # nobody knows whether the email went out, so the answer is no — every time
    retry = make_forward(ok())
    for _ in range(3):
        with pytest.raises(DuplicateInFlight):
            await ex.run("send_email", {"to": "a@b.com"}, retry)
    assert retry.calls == 0
    ex.close()


async def test_the_poison_is_per_key_not_per_executor(db):
    ex = TxExecutor(db, "s1")
    with pytest.raises(RuntimeError):
        await ex.run("send_email", {"to": "a@b.com"}, broken_forward(RuntimeError("wire cut")))

    forward = make_forward(ok())
    _, replayed = await ex.run("send_email", {"to": "c@d.com"}, forward)

    assert forward.calls == 1
    assert replayed is False
    ex.close()


# --- two executors, one db --------------------------------------------------


async def test_a_second_executor_replays_what_the_first_completed(db):
    a = TxExecutor(db, "s1")
    b = TxExecutor(db, "s1")
    await a.run("add", {"a": 1}, make_forward(ok("from a")))

    forward = make_forward(ok("from b"))
    result, replayed = await b.run("add", {"a": 1}, forward)

    assert forward.calls == 0
    assert replayed is True
    assert result.content[0].text == "from a"
    a.close()
    b.close()


# --- the file itself --------------------------------------------------------


async def test_the_ledger_is_a_real_file_that_outlives_close(db):
    ex = TxExecutor(db, "s1")
    await ex.run("add", {"a": 1}, make_forward(ok()))

    assert db.exists()
    assert db.stat().st_size > 0
    ex.close()
    assert db.exists()


def test_an_unwritable_db_path_fails_at_construction(tmp_path):
    # if the ledger can't be written nothing may execute; finding out at
    # construction beats finding out mid-call
    with pytest.raises(TxError):
        TxExecutor(tmp_path / "nowhere" / "ledger.db", "s1")


async def test_run_after_close_is_a_txerror_not_a_sqlite_traceback(db):
    ex = TxExecutor(db, "s1")
    ex.close()
    with pytest.raises(TxError):
        await ex.run("add", {"a": 1}, make_forward(ok()))


# --- totality ---------------------------------------------------------------

json_values = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(),
        st.floats(allow_nan=False, allow_infinity=False),
        st.text(max_size=20),
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.text(max_size=10), children, max_size=3),
    ),
    max_leaves=8,
)


@given(args=st.dictionaries(st.text(max_size=10), json_values, max_size=4))
@settings(max_examples=200)
def test_intent_key_is_total_and_stable(args):
    first = intent_key("s1", "some_tool", args)
    assert intent_key("s1", "some_tool", args) == first
    assert len(first) == 64
    assert set(first) <= set("0123456789abcdef")
