import json
from types import SimpleNamespace

import pytest

pytest.importorskip("agentdojo")

from agentdojo.functions_runtime import EmptyEnv, make_function
from agentdojo.types import text_content_block_from_string

from tripwire.policy.schema import Policy
from tripwire_benchmarks.agentdojo import (
    AdapterError,
    _guard_review_contract,
    make_guarded_runtime,
    make_reviewer_factory,
    parse_args,
)
from tripwire_benchmarks.reviewer import ActionReviewer


def read_notice() -> str:
    """Read a user-visible notice."""
    return "returned data only"


def send_message(recipient: str, body: str) -> str:
    """Send a message.

    :param recipient: Destination.
    :param body: Text.
    """
    return "sent"


def policy():
    return Policy.model_validate(
        {
            "version": 1,
            "sources": {"read_notice": "untrusted"},
            "tools": {
                "read_notice": {"action": "allow"},
                "send_message": {
                    "action": "allow",
                    "constraints": {"recipient": {"regex": "Alice"}},
                    "limits": {"per_session": 1},
                },
            },
            "flows": [
                {"when": "context_tainted", "tools": ["send_message"], "action": "require_approval"}
            ],
        }
    )


def make_runtime(complete):
    runtime_type = make_guarded_runtime(policy(), "review", lambda: ActionReviewer(complete))
    runtime = runtime_type([make_function(read_notice), make_function(send_message)])
    runtime.trusted_task = "Read the notice, then send Hello to Alice."
    runtime.task_id = "HIDDEN_TASK_IDENTIFIER"
    runtime.task_kind = "HIDDEN_ATTACK_LABEL"
    return runtime


def test_reviewed_call_can_execute_after_taint_and_receipt_has_actual_decision():
    seen = []
    runtime = make_runtime(
        lambda messages: seen.append(messages) or '{"decision":"approve","reason":"matches"}'
    )
    runtime.run_function(EmptyEnv(), "read_notice", {})
    result, error = runtime.run_function(
        EmptyEnv(), "send_message", {"recipient": "Alice", "body": "Hello"}
    )
    assert result == "sent" and error is None
    assert runtime.session.snapshot().tainted
    assert runtime.events[-1].review["approved"] is True
    assert runtime.events[-1].executed
    evidence = json.loads(seen[0][-1]["content"])
    assert evidence["observations"] == [
        {
            "tool": "read_notice",
            "args": {},
            "result": "returned data only",
            "error": None,
            "trust": "untrusted",
        }
    ]
    assert "HIDDEN_" not in json.dumps(seen)


def test_reviewer_never_overrides_constraints_or_budgets():
    seen = []
    runtime = make_runtime(
        lambda messages: seen.append(messages) or '{"decision":"approve","reason":"ok"}'
    )
    runtime.run_function(EmptyEnv(), "read_notice", {})
    _, error = runtime.run_function(
        EmptyEnv(), "send_message", {"recipient": "Eve", "body": "Hello"}
    )
    assert error and not seen
    runtime.run_function(EmptyEnv(), "send_message", {"recipient": "Alice", "body": "Hello"})
    _, error = runtime.run_function(
        EmptyEnv(), "send_message", {"recipient": "Alice", "body": "Again"}
    )
    assert error and len(seen) == 1
    assert [call.function for call in runtime.executed_calls] == ["read_notice", "send_message"]


def test_failed_review_is_recorded_and_never_executes():
    def fail(messages):
        raise TimeoutError()

    runtime = make_runtime(fail)
    runtime.run_function(EmptyEnv(), "read_notice", {})
    _, error = runtime.run_function(
        EmptyEnv(), "send_message", {"recipient": "Alice", "body": "Hello"}
    )
    assert error
    assert runtime.events[-1].review["status"] == "provider_error"
    assert not runtime.events[-1].executed
    assert runtime.session.snapshot().tool_counts == {"read_notice": 1}


def test_each_episode_has_an_independent_review_budget():
    factory = lambda: ActionReviewer(lambda messages: '{"decision":"deny","reason":"no"}')
    runtime_type = make_guarded_runtime(policy(), "review", factory)
    assert runtime_type().reviewer is not runtime_type().reviewer


@pytest.mark.parametrize(
    "gate,factory", [("review", None), ("approve", lambda: None), ("deny", lambda: None)]
)
def test_implicit_or_mislabelled_reviewer_rejected(gate, factory):
    with pytest.raises(ValueError):
        make_guarded_runtime(policy(), gate, factory)


def test_reviewer_backend_has_no_tools_or_actor_history():
    seen = []

    class LLM:
        def query(self, task, runtime, env, messages):
            seen.append((task, runtime, env, messages))
            return (
                "",
                runtime,
                env,
                [
                    {
                        "role": "assistant",
                        "content": [
                            text_content_block_from_string('{"decision":"approve","reason":"ok"}')
                        ],
                    }
                ],
                {},
            )

    reviewer = make_reviewer_factory(LLM())()
    assert reviewer.review(task="Send Hello", tool="send", args={}, observations=[]).approved
    assert seen[0][1].functions == {}
    assert seen[0][2] is None
    assert len(seen[0][3]) == 3


def test_reviewer_flag_cannot_be_attached_to_direct_condition():
    with pytest.raises(SystemExit):
        parse_args(
            [
                "--suite",
                "banking",
                "--model",
                "m",
                "--condition",
                "direct",
                "--reviewer-model",
                "judge",
                "--out",
                "out",
            ]
        )


def test_review_resume_rejects_changed_settings_and_orphan_traces(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "tripwire_benchmarks.agentdojo._source_state",
        lambda: {"git_commit": "test", "git_dirty": False},
    )
    args = parse_args(
        [
            "--suite",
            "banking",
            "--model",
            "m",
            "--condition",
            "tripwire-review",
            "--out",
            str(tmp_path),
        ]
    )
    _guard_review_contract(args, tmp_path)
    _guard_review_contract(args, tmp_path)
    args.reviewer_model = "different"
    with pytest.raises(AdapterError, match="contract changed"):
        _guard_review_contract(args, tmp_path)

    orphan = tmp_path / "orphan"
    (orphan / "traces").mkdir(parents=True)
    (orphan / "traces" / "case.json").write_text("{}")
    with pytest.raises(AdapterError, match="no review contract"):
        _guard_review_contract(args, orphan)


def test_dirty_review_source_cannot_start_a_scored_run(tmp_path, monkeypatch):
    monkeypatch.setattr("tripwire_benchmarks.agentdojo._source_state", lambda: {"git_dirty": True})
    args = SimpleNamespace(condition="tripwire-review")
    with pytest.raises(AdapterError, match="commit"):
        _guard_review_contract(args, tmp_path)
