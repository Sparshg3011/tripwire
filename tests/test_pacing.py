import threading
import time

import pytest

from tripwire_benchmarks.agentdojo import parse_args
from tripwire_benchmarks.pacing import SharedPacer

GAP = 0.05


def test_one_process_is_spaced(tmp_path):
    pacer = SharedPacer(tmp_path / "pace", 60 / GAP)
    started = time.time()
    for _ in range(5):
        pacer.wait()
    assert time.time() - started >= 4 * GAP * 0.9


def test_separate_openers_share_one_budget(tmp_path):
    path = tmp_path / "pace"
    stamps: list[float] = []
    lock = threading.Lock()

    def worker():
        pacer = SharedPacer(path, 60 / GAP)
        for _ in range(4):
            pacer.wait()
            with lock:
                stamps.append(time.time())

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    stamps.sort()
    assert len(stamps) == 12
    assert stamps[-1] - stamps[0] >= 11 * GAP * 0.9


def test_a_rate_limit_holds_every_process(tmp_path):
    path = tmp_path / "pace"
    SharedPacer(path, 6000).back_off(0.3)
    assert SharedPacer(path, 6000).wait() >= 0.25


def test_back_off_never_pulls_the_next_slot_in(tmp_path):
    pacer = SharedPacer(tmp_path / "pace", 6000)
    pacer.back_off(0.3)
    pacer.back_off(0.0)
    assert pacer.wait() >= 0.25


def test_an_unreadable_slot_file_does_not_stall(tmp_path):
    path = tmp_path / "pace"
    path.write_text("not a time", encoding="ascii")
    assert SharedPacer(path, 6000).wait() < 0.05


@pytest.mark.parametrize("rate", [0, -1, float("nan")])
def test_rate_must_be_positive(tmp_path, rate):
    with pytest.raises(ValueError):
        SharedPacer(tmp_path / "pace", rate)


BASE = ["--suite", "banking", "--model", "m", "--condition", "direct", "--out", "x"]


@pytest.mark.parametrize(
    "extra",
    [["--pace-file", "p"], ["--per-minute", "6"], ["--pace-file", "p", "--per-minute", "0"]],
)
def test_pacing_flags_go_together(extra):
    with pytest.raises(SystemExit):
        parse_args([*BASE, *extra])


def test_pacing_flags_parse():
    args = parse_args([*BASE, "--pace-file", "p", "--per-minute", "6"])
    assert (args.pace_file, args.per_minute) == ("p", 6.0)
