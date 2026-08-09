"""The simulated operator, against the real gate.

Gates are the one place tripwire's protection depends on somebody
outside the software, so the gym runs the two extremes and reports both
rather than inventing one plausible person. These tests pin that both
extremes actually work — an approver that silently failed would look
exactly like a policy that blocks everything.
"""

import anyio
import pytest

from tripwire.gate import ApprovalRequest, WebGate
from tripwire_gym.human import Human, find_gate_url

STARTUP = "tripwire: approvals at http://127.0.0.1:8642/?k=tok-en_123\n"


@pytest.fixture
def gate():
    g = WebGate(port=0)
    yield g
    g.close()


def request(**kw):
    base = {
        "tool": "send_email",
        "args": {"to": "a@b.com"},
        "rule_id": "flows[0]",
        "reason": "untrusted content in context",
    }
    return ApprovalRequest(**{**base, **kw})


async def answered_by(gate, answer, count=1):
    """Run `count` approvals past a Human and give back what the gate said."""
    said = []
    human = Human(gate.url, answer=answer)
    async with anyio.create_task_group() as tg:
        tg.start_soon(human.watch)
        for _ in range(count):
            said.append(await gate.request(request()))
        tg.cancel_scope.cancel()
    return said, human


# --- reading the gate address off the proxy's stderr ---


def test_finds_the_gate_url_the_proxy_printed():
    assert find_gate_url(STARTUP) == "http://127.0.0.1:8642/?k=tok-en_123"


def test_finds_the_url_among_other_stderr_noise():
    noisy = f"mock_server: scenario (2 tools)\n{STARTUP}tripwire: session abcd\n"
    assert find_gate_url(noisy) == "http://127.0.0.1:8642/?k=tok-en_123"


def test_no_url_before_the_gate_has_announced_itself():
    assert find_gate_url("") is None
    assert find_gate_url("tripwire: session abcd\n") is None


# --- answering ---


async def test_approving_human_approves(gate):
    said, human = await answered_by(gate, "approve")
    assert said == [True]
    assert human.answered == 1


async def test_denying_human_denies(gate):
    said, human = await answered_by(gate, "deny")
    assert said == [False]
    assert human.answered == 1


async def test_answers_every_prompt_in_a_run(gate):
    said, human = await answered_by(gate, "approve", count=3)
    assert said == [True, True, True]
    assert human.answered == 3


async def test_carries_the_token_from_the_url(gate):
    human = Human(gate.url, answer="approve")
    assert human.token == gate.token


def test_a_human_can_only_be_yes_or_no():
    with pytest.raises(ValueError, match="approve or deny"):
        Human("http://127.0.0.1:1/?k=x", answer="maybe")


async def test_a_gate_that_goes_away_is_counted_not_raised():
    gate = WebGate(port=0)
    human = Human(gate.url, answer="approve")
    gate.close()

    with anyio.move_on_after(0.5):
        await human.watch()

    assert human.answered == 0
    assert human.poll_failures > 0  # noticed, rather than silently idle
    assert human.last_failure
