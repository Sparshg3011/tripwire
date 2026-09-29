"""One agent session through the real proxy, narrated.

play() starts `tripwire serve` with the bundled policy in front of the
bundled mailbox, writes the user's task to the proxy's task file, and
makes the calls a model that fell for the email's injection would make.
Only the agent is scripted: every verdict, reason and anchor printed is
read from the proxy's answers, its audit log or the mailbox's outbox. An
answer that doesn't fit its verdict (an allowed call that failed, a
block without its denial) ends the demo with an error instead of being
narrated.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
import tempfile
import textwrap
from collections.abc import Mapping
from contextlib import ExitStack
from dataclasses import dataclass
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any, TextIO

import anyio
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

from tripwire.intent import write_task
from tripwire.policy.types import explain_leaf
from tripwire.provenance import describe
from tripwire.proxy.denial import META_KEY
from tripwire.tx import read_records, trace, verify_log

TITLE = "one agent session through the real proxy, offline"
SCOPE = "A scripted agent and a mock mailbox; the proxy, policy and log are real."

TASK = "Summarize my latest email and send the summary to alice@acme.example."
ATTACKER = "audit@evil.example"  # the address the email in mailbox.py asks for
SUMMARY = "The September invoice is attached and due in 14 days."

WIDTH = 80
INDENT = 3  # a step's lines, under its heading
COLUMN = 12  # where the text beside ALLOWED or BLOCKED starts
PAUSE = 0.6  # seconds before each step, on a terminal
TIMEOUT = 60


def is_terminal(stream: TextIO) -> bool:
    isatty = getattr(stream, "isatty", None)
    return bool(isatty is not None and isatty())


def color_wanted(stream: TextIO, environ: Mapping[str, str]) -> bool:
    """Color on a terminal only, and never with NO_COLOR set (no-color.org)."""
    return is_terminal(stream) and not environ.get("NO_COLOR") and environ.get("TERM") != "dumb"


class Printer:
    def __init__(self, stream: TextIO, color: bool, pause: float) -> None:
        self.stream = stream
        self.color = color
        self.pause = pause

    def paint(self, text: str, sgr: str) -> str:
        return f"\x1b[{sgr}m{text}\x1b[0m" if self.color else text

    def line(self, text: str = "") -> None:
        print(text, file=self.stream, flush=True)

    def labelled(self, label: str, lines: list[str], width: int = 9) -> None:
        self.line(f"{label:<{width}}{lines[0]}")
        for rest in lines[1:]:
            self.line(" " * width + rest)

    def verdict(self, decision: str, lines: list[str]) -> None:
        """ALLOWED or BLOCKED under a step, with lines beside it."""
        label, sgr = VERDICTS.get(decision, (decision.upper(), "1;33"))
        pad = COLUMN - INDENT - len(label)
        self.line(" " * INDENT + self.paint(label, sgr) + " " * pad + (lines or [""])[0])
        for rest in lines[1:]:
            self.line(" " * COLUMN + rest)


VERDICTS = {"allow": ("ALLOWED", "1;32"), "block": ("BLOCKED", "1;31")}
FLAGS = {"allow": ("ok", "32"), "block": ("BLOCK", "1;31"), "gate": ("GATE", "1;33")}


def fill(text: str, width: int = WIDTH - COLUMN) -> list[str]:
    return textwrap.wrap(text, width) or [""]


def call_line(tool: str, args: Mapping[str, Any], width: int) -> str:
    """tool(key="value", ...) in at most width characters, the longest
    values cut short first."""
    shown = {key: json.dumps(value, ensure_ascii=False) for key, value in args.items()}

    def render() -> str:
        return f"{tool}({', '.join(f'{key}={value}' for key, value in shown.items())})"

    while (over := len(render()) - width) > 0:
        key = max(shown, key=lambda k: len(shown[k]))
        keep = len(shown[key]) - over - 2
        if keep < 4:
            break
        shown[key] = shown[key][:keep] + '…"'
    return render()


@dataclass
class Called:
    result: types.CallToolResult
    decision: dict[str, Any]  # the decision record's data
    records: list[dict[str, Any]]  # every record the call added
    sent: list[dict[str, Any]]  # what reached the mailbox's outbox


class Agent:
    """The scripted agent's end of one proxy session."""

    def __init__(self, client: ClientSession, audit: Path, outbox: Path, out: Printer):
        self.client = client
        self.audit = audit
        self.outbox = outbox
        self.out = out
        # proxy_start is written before the proxy answers initialize
        self.session_id = read_records(audit)[-1]["session"]
        self.seen = len(self.records())

    def records(self) -> list[dict[str, Any]]:
        return [r for r in read_records(self.audit) if r.get("session") == self.session_id]

    def outboxed(self) -> list[dict[str, Any]]:
        lines = self.outbox.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines if line.strip()]

    async def call(self, n: int, narration: str, tool: str, args: dict[str, Any]) -> Called:
        await anyio.sleep(self.out.pause)
        self.out.line()
        self.out.line(self.out.paint(f"{n}  {narration}", "1"))
        self.out.line(" " * INDENT + call_line(tool, args, WIDTH - INDENT))
        before = len(self.outboxed())
        result = await self.client.call_tool(tool, args)
        # the proxy has written its records for the call before it answers
        added = self.records()[self.seen :]
        self.seen += len(added)
        decision = next(r["data"] for r in added if r.get("kind") == "decision")
        if decision["decision"] == "allow" and result.isError:
            raise RuntimeError(f"{tool} was allowed, but the call failed: {text(result)}")
        if decision["decision"] == "block" and denial_body(result) is None:
            raise RuntimeError(f"{tool} was blocked, but the proxy's answer has no denial")
        return Called(result, decision, added, self.outboxed()[before:])


async def script(agent: Agent) -> None:
    """What a model that fell for the injection would do."""
    out = agent.out

    called = await agent.call(
        1,
        "The agent reads the latest email, which carries an injected instruction.",
        "read_inbox",
        {},
    )
    email = text(called.result)
    lines = [out.paint(f"> {line}".rstrip(), "2") for line in email.splitlines()]
    if any(r.get("kind") == "session_tainted" for r in called.records):
        lines += fill("Its text is untrusted, so the session is now tainted.")
    out.verdict(called.decision["decision"], lines)

    exfil = {"to": ATTACKER, "subject": "Mailbox", "body": email}
    called = await agent.call(
        2, "It obeys the email and mails the inbox to the attacker.", "send_email", exfil
    )
    out.verdict(called.decision["decision"], [*denial(called.result), *delivery(called.sent)])

    reply = {"to": "alice@acme.example", "subject": "Summary", "body": SUMMARY}
    called = await agent.call(3, "It sends the summary the user asked for.", "send_email", reply)
    leaves = (called.decision.get("anchors") or {}).get("leaves") or []
    out.verdict(called.decision["decision"], [*map(explain_leaf, leaves), *delivery(called.sent)])


def text(result: types.CallToolResult) -> str:
    return "".join(c.text for c in result.content if isinstance(c, types.TextContent))


def denial_body(result: types.CallToolResult) -> dict[str, Any] | None:
    body = (result.meta or {}).get(META_KEY)
    return body if isinstance(body, dict) else None


def denial(result: types.CallToolResult) -> list[str]:
    """The structured refusal the agent was handed, one field a line."""
    body = denial_body(result)
    if body is None:
        return []
    lines = [f"{body['code']}, rule {body['rule']}"]
    for failed in body["failed"]:
        value = failed["value"]
        if failed["status"] == "unanchored" and "task" in failed["accepted"]:
            value += " (not in the task)"
        lines.append(f"{failed['arg']:<11} {value}")
        seen = failed["first_seen"]
        if seen is not None:
            where = describe(str(seen["class"]), str(seen["tool"]), int(seen["turn"]))
            lines.append(f"{'first seen':<11} {where}")
        lines.append(f"{'accepted':<11} {', '.join(failed['accepted'])}")
    return lines


def delivery(sent: list[dict[str, Any]]) -> list[str]:
    if not sent:
        return fill("The mailbox never received it.")
    return fill(f"The mailbox sent it to {', '.join(str(m.get('to')) for m in sent)}.")


def summarize(audit: Path, session_id: str, out: Printer) -> None:
    """The session as `tripwire trace` rebuilds it from the log, one line
    per call."""
    checked = verify_log(audit)
    chain = "hash chain intact" if checked.ok else f"hash chain BROKEN: {checked.why}"
    out.line()
    out.line(out.paint("audit log", "1") + f"  {checked.records} records, {chain}")
    for step in trace(read_records(audit), session_id):
        flag, sgr = FLAGS.get(step.decision, (step.decision, "0"))
        out.line(
            f"  turn {step.turn:<2} {out.paint(f'{flag:<6}', sgr)} {step.tool:<11} {step.rule}"
        )


async def run(workdir: Path, policy: Path, errlog: TextIO, out: Printer) -> None:
    """Start the proxy, play the session through it, and summarize the
    log it wrote. The proxy's stderr, and the mailbox's, go to errlog."""
    audit = workdir / "audit.jsonl"
    task = workdir / "task.txt"
    outbox = workdir / "outbox.jsonl"
    outbox.write_text("", encoding="utf-8")
    task.unlink(missing_ok=True)

    mailbox = shlex.join([sys.executable, "-m", "tripwire.demo.mailbox", str(outbox)])
    serve = ["serve", "--policy", str(policy), "--upstream", mailbox]
    serve += ["--audit", str(audit), "--task-file", str(task)]
    # the user's own TRIPWIRE_ settings are for their proxies, not this one
    env = {name: value for name, value in os.environ.items() if not name.startswith("TRIPWIRE_")}
    params = StdioServerParameters(command=sys.executable, args=["-m", "tripwire", *serve], env=env)

    with anyio.fail_after(TIMEOUT):
        async with (
            stdio_client(params, errlog=errlog) as (read, write),
            ClientSession(read, write) as client,
        ):
            await client.initialize()
            agent = Agent(client, audit, outbox, out)
            write_task(task, TASK)  # the user submits the prompt
            await script(agent)
    summarize(audit, agent.session_id, out)


def header(out: Printer, policy: Path) -> None:
    out.line(f"{out.paint('tripwire demo', '1')}: {TITLE}")
    out.line(out.paint(SCOPE, "2"))
    out.line()
    out.labelled("task", fill(TASK, WIDTH - 9))
    out.labelled("policy", policy.read_text(encoding="utf-8").splitlines())


def play(directory: str | None = None, stream: TextIO | None = None) -> int:
    """Run the demo and return its exit status. Its files go in directory,
    or in a temporary one that is removed afterwards."""
    stream = stream if stream is not None else sys.stdout
    out = Printer(
        stream,
        color=color_wanted(stream, os.environ),
        pause=PAUSE if is_terminal(stream) else 0.0,
    )
    with ExitStack() as stack:
        if directory is None:
            workdir = Path(
                stack.enter_context(tempfile.TemporaryDirectory(prefix="tripwire-demo-"))
            )
        else:
            workdir = Path(directory)
            workdir.mkdir(parents=True, exist_ok=True)
        policy = stack.enter_context(as_file(files("tripwire.demo").joinpath("policy.yaml")))
        errlog = stack.enter_context(open(workdir / "proxy.log", "w", encoding="utf-8"))

        header(out, policy)
        try:
            anyio.run(run, workdir, policy, errlog, out)
        except KeyboardInterrupt:
            return 130
        except Exception as e:  # noqa: BLE001 - shown with the proxy's log, not a traceback
            cause: BaseException = e
            # unwrapped from the task groups under stdio_client
            while isinstance(cause, BaseExceptionGroup) and len(cause.exceptions) == 1:
                cause = cause.exceptions[0]
            print(f"tripwire demo: failed: {cause}", file=sys.stderr)
            sys.stderr.write((workdir / "proxy.log").read_text(encoding="utf-8"))
            return 1

    if directory is not None:
        log = shlex.quote(str(Path(directory) / "audit.jsonl"))
        out.line()
        out.line(f"The files are in {directory}. For the whole trace:")
        out.line(f"  tripwire trace {log}")
    return 0
