"""The quickstart shows what `tripwire report` and `tripwire trace` print
after a first stretch in shadow mode. Replaying those calls through the
interceptor, under the policy the quickstart writes, has to print exactly
what it shows.
"""

import re
from pathlib import Path

import yaml
from mcp import types

from tripwire.policy.schema import Policy
from tripwire.proxy.interceptor import Interceptor
from tripwire.session import SessionState
from tripwire.tx import AuditLog, format_report, format_trace, read_records, report, trace

QUICKSTART = Path(__file__).resolve().parents[1] / "docs" / "quickstart.md"

LIST = ("list_directory", {"path": "/Users/me/work"})
READ = ("read_file", {"path": "/Users/me/work/notes.md"})
WRITE = ("write_file", {"path": "/Users/me/work/out.txt", "content": "..."})

# 23 calls over three sessions, four of them writes; the trace shows the last
SESSIONS = {
    "7f3e9c10": [LIST] * 6 + [READ] * 4 + [WRITE] * 2,
    "5d2a8b77": [LIST] * 5 + [READ] * 3 + [WRITE],
    "a1b2c3d4": [READ, WRITE],
}


class Files:
    async def call(self, name, args):
        return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])


async def test_the_quickstart_shows_what_report_and_trace_print(tmp_path):
    text = QUICKSTART.read_text()
    written = re.search(r"```yaml\n(.*?)```", text, re.DOTALL)[1]
    policy = Policy.model_validate(yaml.safe_load(written))
    audit = tmp_path / "audit.jsonl"
    for session, calls in SESSIONS.items():
        log = AuditLog(audit, session_id=session)
        interceptor = Interceptor(policy, log, Files(), SessionState(policy))
        for name, args in calls:
            await interceptor.handle(name, args)
        log.close()

    records = read_records(audit)
    assert format_report(report(records)) in text
    assert format_trace(trace(records, "a1b2c3d4"), "a1b2c3d4") in text
