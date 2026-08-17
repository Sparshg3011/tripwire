"""AutoDojo external-defense plugin for adaptive attacks against Tripwire.

AutoDojo's ordinary plugin hook runs after a tool has executed. Tripwire must
decide before execution, so installation also routes Tripwire-labelled suite
runs through the guarded stateful runtime from :mod:`tripwire_benchmarks.agentdojo`.
"""

from __future__ import annotations

import importlib
import os
from functools import cache
from pathlib import Path
from typing import Any

from tripwire.policy import load_policy
from tripwire_benchmarks.agentdojo import (
    NVIDIA_BASE_URL,
    AdapterError,
    OpenAICompatibleLLM,
    protect_suite,
)

DEFENSE_NAME = "tripwire"
NIM_PREFIX = "nim:"


def _enabled_as_plugin() -> bool:
    modules = {
        item.strip()
        for item in os.environ.get("AGENTDOJO_DEFENSE_PLUGINS", "").split(",")
        if item.strip()
    }
    return __name__ in modules


def _tripwire_policy_path(suite_name: str) -> Path:
    explicit = os.environ.get("TRIPWIRE_POLICY")
    if explicit:
        return Path(explicit)
    directory = Path(
        os.environ.get(
            "TRIPWIRE_POLICY_DIR",
            str(Path(__file__).resolve().parents[2] / "gym" / "external_policies"),
        )
    )
    return directory / f"{suite_name}.yaml"


@cache
def _policy(path: str):
    candidate = Path(path)
    if not candidate.exists():
        raise AdapterError(f"no Tripwire policy for adaptive suite: {candidate}")
    return load_policy(candidate)


def _is_tripwire_pipeline(pipeline: Any) -> bool:
    return str(getattr(pipeline, "name", "")).endswith(f"/{DEFENSE_NAME}")


def install() -> None:
    """Register NIM model support and pre-execution Tripwire enforcement."""
    module = importlib.import_module("agentdojo.agent_pipeline.agent_pipeline")
    if getattr(module, "_tripwire_plugin_installed", False):
        return
    if not hasattr(module, "register_defense"):
        raise AdapterError(
            "Tripwire's adaptive plugin requires the pinned AutoDojo fork; "
            "upstream AgentDojo does not expose its defense hook"
        )

    base_element = importlib.import_module(
        "agentdojo.agent_pipeline.base_pipeline_element"
    ).BasePipelineElement

    class Passthrough(base_element):
        def query(self, query, runtime, env, messages=(), extra_args=None):
            return query, runtime, env, messages, extra_args or {}

    module.register_defense(DEFENSE_NAME, lambda config: Passthrough())

    original_get_llm = module.get_llm

    def get_llm(model: str):
        if not model.startswith(NIM_PREFIX):
            return original_get_llm(model)
        model_id = model.removeprefix(NIM_PREFIX)
        key = os.environ.get("NVIDIA_API_KEY")
        if not key:
            raise AdapterError("NVIDIA_API_KEY is required for nim: target models")
        return OpenAICompatibleLLM(
            model=model_id,
            base_url=os.environ.get("NVIDIA_BASE_URL", NVIDIA_BASE_URL),
            api_key=key,
            temperature=float(os.environ.get("TRIPWIRE_TARGET_TEMPERATURE", "0")),
            max_tokens=int(os.environ.get("TRIPWIRE_TARGET_MAX_TOKENS", "2048")),
            disable_thinking=os.environ.get("TRIPWIRE_DISABLE_THINKING", "1") == "1",
            timeout=float(os.environ.get("TRIPWIRE_TARGET_TIMEOUT", "300")),
        )

    module.get_llm = get_llm

    task_suite_module = importlib.import_module("agentdojo.task_suite.task_suite")
    task_suite_type = task_suite_module.TaskSuite
    original_run = task_suite_type.run_task_with_pipeline

    def run_task_with_pipeline(
        self,
        agent_pipeline,
        user_task,
        injection_task,
        injections,
        runtime_class=None,
        environment=None,
        verbose=False,
        prompt_override=None,
    ):
        if not _is_tripwire_pipeline(agent_pipeline):
            kwargs = {
                "environment": environment,
                "verbose": verbose,
            }
            if runtime_class is not None:
                kwargs["runtime_class"] = runtime_class
            if prompt_override is not None:
                kwargs["prompt_override"] = prompt_override
            return original_run(
                self,
                agent_pipeline,
                user_task,
                injection_task,
                injections,
                **kwargs,
            )

        gate = os.environ.get("TRIPWIRE_GATE", "deny")
        if gate not in {"approve", "deny"}:
            raise AdapterError("TRIPWIRE_GATE must be approve or deny")
        suite_name = str(getattr(self, "name", "")).split("/")[-1]
        policy_path = _tripwire_policy_path(suite_name)
        protected = protect_suite(self, _policy(str(policy_path.resolve())), gate)
        return protected.run_task_with_pipeline(
            agent_pipeline,
            user_task,
            injection_task,
            injections,
            environment=environment,
            verbose=verbose,
            prompt_override=prompt_override,
        )

    task_suite_type.run_task_with_pipeline = run_task_with_pipeline
    module._tripwire_plugin_installed = True


if _enabled_as_plugin():
    install()
