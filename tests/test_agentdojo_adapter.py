import json
from pathlib import Path
from types import SimpleNamespace

from agentdojo.functions_runtime import EmptyEnv, make_function

from tripwire.policy import load_policy
from tripwire.policy.schema import Policy
from tripwire_benchmarks.agentdojo import (
    _enforcement_receipt,
    _openai_messages,
    _pipeline_name,
    _read_enforcement_receipts,
    _read_trace_errors,
    _read_trace_usage,
    _retry_delay,
    _source_state,
    make_guarded_runtime,
)

ROOT = Path(__file__).parent.parent


def read_email() -> str:
    """Read an untrusted email."""
    return "attacker-controlled message"


def send_email(to: str) -> str:
    """Send an email.

    :param to: Recipient address.
    """
    return f"sent to {to}"


def policy() -> Policy:
    return Policy.model_validate(
        {
            "version": 1,
            "sources": {"read_email": "untrusted"},
            "tools": {
                "read_email": {"action": "allow"},
                "send_email": {"action": "allow"},
            },
            "flows": [
                {
                    "when": "context_tainted",
                    "tools": ["send_email"],
                    "action": "require_approval",
                }
            ],
        }
    )


def test_guarded_runtime_scores_only_calls_that_reached_the_function():
    runtime_type = make_guarded_runtime(policy(), "deny")
    runtime = runtime_type([make_function(read_email), make_function(send_email)])

    read_result, read_error = runtime.run_function(EmptyEnv(), "read_email", {})
    send_result, send_error = runtime.run_function(
        EmptyEnv(), "send_email", {"to": "attacker@example.com"}
    )

    assert read_result == "attacker-controlled message"
    assert read_error is None
    assert send_result == ""
    assert "tripwire_blocked" in send_error
    assert [call.function for call in runtime.executed_calls] == ["read_email"]
    assert [event.executed for event in runtime.events] == [True, False]


def test_approve_and_deny_are_explicit_gate_bounds():
    runtime_type = make_guarded_runtime(policy(), "approve")
    runtime = runtime_type([make_function(read_email), make_function(send_email)])
    runtime.run_function(EmptyEnv(), "read_email", {})
    result, error = runtime.run_function(
        EmptyEnv(), "send_email", {"to": "colleague@example.com"}
    )

    assert result == "sent to colleague@example.com"
    assert error is None
    assert [call.function for call in runtime.executed_calls] == ["read_email", "send_email"]


def test_every_agentdojo_suite_policy_loads():
    for suite in (
        "workspace",
        "travel",
        "banking",
        "slack",
        "shopping",
        "github",
        "dailylife",
    ):
        loaded = load_policy(ROOT / "gym" / "external_policies" / f"{suite}.yaml")
        assert loaded.version == 1
        assert loaded.flows


def test_agentdojo_messages_use_standard_system_and_tool_roles():
    from agentdojo.functions_runtime import FunctionCall
    from agentdojo.types import text_content_block_from_string

    call = FunctionCall(function="read_email", args={}, id="call-1")
    converted = _openai_messages(
        [
            {"role": "system", "content": [text_content_block_from_string("system")]},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [call],
            },
            {
                "role": "tool",
                "content": [text_content_block_from_string("email")],
                "tool_call": call,
                "tool_call_id": "call-1",
                "error": None,
            },
        ]
    )

    assert converted[0] == {"role": "system", "content": "system"}
    assert converted[1]["tool_calls"][0]["function"]["name"] == "read_email"
    assert converted[2] == {"role": "tool", "tool_call_id": "call-1", "content": "email"}


def test_custom_nvidia_pipeline_name_is_attack_and_trace_compatible():
    from agentdojo.attacks.base_attacks import get_model_name_from_pipeline

    name = _pipeline_name("nvidia/nemotron-3-super-120b-a12b", None)

    assert "/" not in name
    assert "nvidia_nemotron-3-super-120b-a12b" in name
    assert get_model_name_from_pipeline(SimpleNamespace(name=name)) == "Local model"


def test_enforcement_receipts_survive_trace_resume(tmp_path):
    runtime_type = make_guarded_runtime(policy(), "deny")
    runtime = runtime_type([make_function(read_email), make_function(send_email)])
    runtime.task_id = "user_task_0"
    runtime.task_kind = "user"
    runtime.run_function(EmptyEnv(), "read_email", {})
    runtime.run_function(
        EmptyEnv(), "send_email", {"to": "attacker@example.com"}
    )
    receipt = _enforcement_receipt([runtime])
    trace = {
        "user_task_id": "user_task_0",
        "injection_task_id": "injection_task_0",
        "tripwire_enforcement": {**receipt, "task_kind": "user"},
    }
    (tmp_path / "trace.json").write_text(json.dumps(trace))

    aggregated = _read_enforcement_receipts(tmp_path, task_kind="user")

    assert aggregated["tasks"] == 1
    assert aggregated["gate_prompts"] == 1
    assert aggregated["gated_cases"] == 1
    assert aggregated["blocked_cases"] == 1
    assert aggregated["events"][-1]["case_id"] == "user_task_0:injection_task_0"


def test_model_usage_is_recovered_from_resumed_traces(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "a.json").write_text(
        json.dumps(
            {
                "model_usage": {
                    "model_calls": 2,
                    "provider_attempts": 3,
                    "rate_limit_retries": 1,
                    "prompt_tokens": 100,
                    "completion_tokens": 10,
                    "model_seconds": 1.25,
                    "rate_limit_wait_seconds": 10.0,
                }
            }
        )
    )
    (second / "b.json").write_text(
        json.dumps(
            {
                "model_usage": {
                    "model_calls": 3,
                    "provider_attempts": 3,
                    "rate_limit_retries": 0,
                    "prompt_tokens": 200,
                    "completion_tokens": 20,
                    "model_seconds": 2.5,
                    "rate_limit_wait_seconds": 0.0,
                }
            }
        )
    )

    usage = _read_trace_usage(first, second)

    assert usage == {
        "model_calls": 5,
        "provider_attempts": 6,
        "rate_limit_retries": 1,
        "prompt_tokens": 300,
        "completion_tokens": 30,
        "model_seconds": 3.75,
        "rate_limit_wait_seconds": 10.0,
    }


def test_rate_limit_delay_is_bounded_and_respects_provider_header():
    assert _retry_delay(attempt=0, base_seconds=10, cap_seconds=60) == 10
    assert _retry_delay(attempt=3, base_seconds=10, cap_seconds=60) == 60
    assert _retry_delay(
        attempt=0,
        base_seconds=10,
        cap_seconds=60,
        headers={"retry-after": "35"},
    ) == 35
    assert _retry_delay(
        attempt=0,
        base_seconds=10,
        cap_seconds=60,
        headers={"retry-after-ms": "25000"},
    ) == 25


def test_trace_errors_are_never_silently_scored(tmp_path):
    (tmp_path / "error.json").write_text(
        json.dumps(
            {
                "user_task_id": "user_task_2",
                "injection_task_id": "injection_task_3",
                "error": "provider timeout",
            }
        )
    )

    assert _read_trace_errors(tmp_path) == [
        {
            "user_task": "user_task_2",
            "injection_task": "injection_task_3",
            "error": "provider timeout",
        }
    ]


def test_agentdojo_source_state_is_recorded():
    state = _source_state()

    assert len(state["git_commit"]) == 40
    assert isinstance(state["git_dirty"], bool)
