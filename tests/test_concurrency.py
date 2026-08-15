"""Running the matrix in parallel must not change the matrix.

Concurrency exists so a real-model run takes hours instead of a day. It
is only safe to turn on if it changes when a run happens and nothing
about what the run decides — and since the flag is set on the command
that produces published numbers, that equality is worth pinning rather
than assuming.
"""

import anyio

from tripwire_gym import load_scenario
from tripwire_gym.agent import ScriptedAgent
from tripwire_gym.runner import GYM, run_matrix

CORPUS = GYM / "scenarios"

# a handful is enough to catch ordering bugs, and keeps this test honest
# about wall time — every run spawns a proxy and a mock
SCENARIOS = [
    load_scenario(CORPUS / f"{name}.yaml")
    for name in ("exfil-email-01", "exfil-email-01-benign", "gate-refund-01")
]
CALLS = [("read_email", {"folder": "inbox"}), ("send_email", {"to": "a@b.example"})]


def agent_for(scenario, condition, seed):
    return ScriptedAgent(CALLS)


async def matrix(concurrency, seen=None):
    return await run_matrix(
        SCENARIOS,
        ("undefended", "standard"),
        agent_for,
        on_result=None if seen is None else seen.append,
        concurrency=concurrency,
    )


async def test_parallel_and_sequential_agree():
    one = await matrix(1)
    many = await matrix(4)

    assert [(r.scenario_id, r.condition, r.seed) for r in one] == [
        (r.scenario_id, r.condition, r.seed) for r in many
    ]
    assert [r.outcome for r in one] == [r.outcome for r in many]


async def test_results_come_back_in_matrix_order():
    # results.jsonl ordering is part of reproducing a number, so it can't
    # depend on which run happened to finish first
    results = await matrix(4)
    expected = [(s.id, c, 0) for s in SCENARIOS for c in ("undefended", "standard")]
    assert [(r.scenario_id, r.condition, r.seed) for r in results] == expected


async def test_progress_fires_once_per_run_either_way():
    seen_one, seen_many = [], []
    await matrix(1, seen_one)
    await matrix(4, seen_many)

    assert len(seen_one) == len(SCENARIOS) * 2
    assert len(seen_many) == len(seen_one)

    # completion order is allowed to differ; the set of runs is not
    def key(r):
        return (r.scenario_id, r.condition, r.seed)

    assert sorted(map(key, seen_many)) == sorted(map(key, seen_one))


async def test_concurrency_below_one_is_refused():
    from tripwire_gym.runner import GymError

    try:
        await matrix(0)
    except GymError as e:
        assert "runs nothing" in str(e)
    else:
        raise AssertionError("concurrency 0 should not be accepted")


async def test_parallel_is_actually_faster():
    # if it isn't, the limiter isn't doing what the flag promises
    start = anyio.current_time()
    await matrix(1)
    sequential = anyio.current_time() - start

    start = anyio.current_time()
    await matrix(4)
    parallel = anyio.current_time() - start

    assert parallel < sequential
