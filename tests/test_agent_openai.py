"""The OpenAI-compatible agent, against a real HTTP server.

There is no NVIDIA key or ollama on CI, and mocking the SDK would only
prove the mock works. So this stands up a tiny server that speaks the
chat-completions wire format, points the real SDK at it, and checks the
loop end to end: tools advertised in OpenAI shape, tool_calls parsed,
results fed back as role="tool", conversation terminated when the model
stops asking.

If NVIDIA, ollama or anyone else changes their models, these still pass —
what's pinned here is the protocol, which is the part we implement.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tripwire_gym.agent import OpenAICompatAgent, ToolCallRecord


class FakeToolBox:
    def __init__(self, answers=None):
        self.calls = []
        self.answers = answers or {}

    async def list_tools(self):
        return [
            {
                "name": "read_email",
                "description": "Read the inbox.",
                "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}},
            },
            {"name": "send_email", "description": "Send mail.", "inputSchema": {}},
        ]

    async def call(self, name, args):
        self.calls.append((name, args))
        return self.answers.get(name, f"{name} ok"), False


def turn(*tool_calls):
    """One assistant reply, in chat-completions shape."""
    if not tool_calls:
        return {"choices": [{"message": {"role": "assistant", "content": "all done"}}]}
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": f"call_{i}",
                            "type": "function",
                            "function": {"name": name, "arguments": args},
                        }
                        for i, (name, args) in enumerate(tool_calls)
                    ],
                }
            }
        ]
    }


@pytest.fixture
def server():
    """A chat-completions endpoint that plays a scripted list of turns."""
    state = {"turns": [], "seen": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["seen"].append(body)
            reply = state["turns"].pop(0) if state["turns"] else turn()
            payload = json.dumps(
                {
                    **reply,
                    "model": body.get("model", "x"),
                    "id": "1",
                    "object": "chat.completion",
                    "created": 0,
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    state["url"] = f"http://127.0.0.1:{httpd.server_address[1]}/v1"
    yield state
    httpd.shutdown()
    httpd.server_close()


def agent(server, **kw):
    return OpenAICompatAgent(model="test-model", base_url=server["url"], api_key="k", **kw)


async def test_a_tool_call_reaches_the_toolbox(server):
    server["turns"] = [turn(("read_email", '{"folder": "inbox"}'))]
    box, made = FakeToolBox(), []

    await agent(server).run("read my mail", box, made)

    assert box.calls == [("read_email", {"folder": "inbox"})]
    assert made == [
        ToolCallRecord(
            tool="read_email", args={"folder": "inbox"}, result_text="read_email ok", is_error=False
        )
    ]


async def test_tools_are_advertised_in_openai_shape(server):
    server["turns"] = [turn()]
    await agent(server).run("hello", FakeToolBox(), [])

    tools = server["seen"][0]["tools"]
    assert [t["function"]["name"] for t in tools] == ["read_email", "send_email"]
    assert tools[0]["type"] == "function"
    assert tools[0]["function"]["parameters"]["properties"]["folder"]["type"] == "string"


async def test_the_task_and_system_prompt_are_sent(server):
    server["turns"] = [turn()]
    await agent(server).run("summarise my inbox", FakeToolBox(), [])

    messages = server["seen"][0]["messages"]
    assert messages[0]["role"] == "system"
    assert messages[1] == {"role": "user", "content": "summarise my inbox"}


async def test_results_go_back_as_tool_messages(server):
    server["turns"] = [turn(("read_email", "{}")), turn()]
    await agent(server).run("read", FakeToolBox({"read_email": "you have mail"}), [])

    second = server["seen"][1]["messages"]
    assert second[-2]["role"] == "assistant"
    assert second[-1] == {"role": "tool", "tool_call_id": "call_0", "content": "you have mail"}


async def test_it_keeps_going_until_the_model_stops_asking(server):
    server["turns"] = [
        turn(("read_email", "{}")),
        turn(("send_email", '{"to": "a@b.com"}')),
        turn(),
    ]
    box, made = FakeToolBox(), []

    await agent(server).run("read then reply", box, made)

    assert [c[0] for c in box.calls] == ["read_email", "send_email"]
    assert len(made) == 2


async def test_two_calls_in_one_turn_both_run(server):
    server["turns"] = [turn(("read_email", "{}"), ("send_email", "{}")), turn()]
    box, made = FakeToolBox(), []

    await agent(server).run("do both", box, made)

    assert [c[0] for c in box.calls] == ["read_email", "send_email"]
    assert len(made) == 2


async def test_malformed_arguments_still_count_as_an_attempt(server):
    # smaller models emit broken json; that's a call the model made, and
    # dropping it would score a badly-formatted model as a firewall win
    server["turns"] = [turn(("send_email", "{not json at all")), turn()]
    box, made = FakeToolBox(), []

    await agent(server).run("send", box, made)

    assert box.calls == [("send_email", {})]
    assert made[0].tool == "send_email"


async def test_non_object_arguments_become_empty(server):
    server["turns"] = [turn(("send_email", '"just a string"')), turn()]
    box, made = FakeToolBox(), []

    await agent(server).run("send", box, made)

    assert box.calls == [("send_email", {})]


async def test_the_turn_budget_is_respected(server):
    # a model that never stops asking must not run forever
    server["turns"] = [turn(("read_email", "{}")) for _ in range(20)]
    box, made = FakeToolBox(), []

    await agent(server, max_turns=3).run("loop", box, made)

    assert len(box.calls) == 3


async def test_a_refusal_is_passed_back_to_the_model(server):
    class Refusing(FakeToolBox):
        async def call(self, name, args):
            self.calls.append((name, args))
            return "tripwire_blocked: nope (rule: tools.send_email.action)", True

    server["turns"] = [turn(("send_email", "{}")), turn()]
    box, made = Refusing(), []

    await agent(server).run("send", box, made)

    assert made[0].is_error is True
    assert "tripwire_blocked" in server["seen"][1]["messages"][-1]["content"]
