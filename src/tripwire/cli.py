from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import anyio

from tripwire import __version__
from tripwire.intent import claude_code_hook
from tripwire.policy import Policy, PolicyError, load_policy
from tripwire.policy.anchoring import accepted
from tripwire.policy.loader import policy_warnings
from tripwire.tx import (
    AuditKeyError,
    AuditWriteError,
    LogError,
    VerifyResult,
    format_report,
    format_trace,
    load_key,
    read_records,
    report,
    sessions,
    trace,
    verify_log,
)

KEY_ENV = "TRIPWIRE_AUDIT_KEY_FILE"
TASK_ENV = "TRIPWIRE_TASK_FILE"


def audit_key(key_file: str | None) -> bytes | None:
    """The key the command was given, if it was given one.

    An empty name is refused rather than read as no key: that's what an
    unset variable in `--audit-key-file "$KEY"` or an empty secret in a
    unit file looks like, and it must not turn keying off without a word.
    """
    if key_file is None:
        return None
    if not key_file:
        raise AuditKeyError(
            f"the audit key file name is empty; to go without a key, unset {KEY_ENV} "
            f"and leave out --audit-key-file"
        )
    return load_key(key_file)


def check_chain(path: str, key_file: str | None) -> None:
    """Say so, loudly, before showing anyone a log as evidence.

    trace, report and replay read a log and tell a story about it. If
    the chain is broken, that story may be the attacker's, so it can't be
    printed without the warning attached — a forensic tool that quietly
    renders tampered input is worse than one that doesn't exist.

    The rules are verify's: a keyed log can't be checked without its key,
    and a key won't vouch for a log that isn't keyed. A log that can't be
    checked is called unverified, not altered, and an intact unkeyed one
    still gets a note, because a rewrite wouldn't show in it.
    """
    key = None
    try:
        key = audit_key(key_file)
        result = verify_log(path, key=key)
    except AuditKeyError as e:
        result = VerifyResult(ok=False, records=0, why=str(e))

    if result.ok and key is not None:
        return
    if result.ok:
        message = (
            f"note: {path} is intact but unkeyed, so anyone who can write it "
            f"could have rewritten it."
        )
    elif result.bad_line is None:
        message = f"WARNING: cannot verify {path} ({result.why}). Everything below is UNVERIFIED."
    else:
        message = (
            f"WARNING: {path} is BROKEN at line {result.bad_line} ({result.why}). "
            f"Everything below is UNVERIFIED and may have been altered."
        )
    print(f"{message} Run `tripwire verify` for detail.\n", file=sys.stderr)


def explain(policy: Policy) -> list[str]:
    """Each tool rule as anchoring reads it: which flows skip the tool's
    anchored calls, each argument's role, and what anchors it."""
    out = [f"known {vtype}: {', '.join(entries)}" for vtype, entries in policy.known.items()]
    for tool, rule in policy.tools.items():
        head: list[str] = [rule.action]
        if rule.destructive:
            head.append("destructive")
        if rule.self_scoped:
            head.append("self_scoped")
        flows = [
            f"flows[{i}]"
            for i, flow in enumerate(policy.flows)
            if flow.unless == "anchored" and tool in flow.tools
        ]
        if rule.args is None:
            head.append("no args contract")  # so no flow skips it
        elif flows:
            verb = "skips" if len(flows) == 1 else "skip"
            head.append(f"{', '.join(flows)} {verb} it when anchored")
        out.append(f"{tool}: {', '.join(head)}")

        outward = any(spec.role == "target" for spec in (rule.args or {}).values())
        for name, spec in (rule.args or {}).items():
            line = f"  {name}: {spec.role}"
            if spec.type != "auto":
                line += f" ({spec.type})"
            sources = ", ".join(accepted(spec.role, rule.destructive, spec.type))
            if spec.role != "content":
                line += f", anchored by {sources}"
            elif outward:
                line += f", links in it anchored by {sources}"
            if spec.match == "under":
                line += ", or by a task or known path above it"
            out.append(line)
    return out


async def listed(command: str) -> bytes:
    """An upstream's tool listing, as `recipe --tools` reads it."""
    from tripwire.proxy import Upstream

    upstream = Upstream(command)
    await upstream.start()
    try:
        tools = [
            t.model_dump(mode="json", by_alias=True, exclude_none=True) for t in upstream.tools
        ]
    finally:
        await upstream.aclose()
    return (json.dumps(tools, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="tripwire", description="MCP firewall for AI agents")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser("serve", help="run the proxy in front of an upstream MCP server")
    p_serve.add_argument("--policy", required=True, help="path to policy yaml")
    p_serve.add_argument(
        "--upstream", required=True, help='upstream command, e.g. "npx some-server"'
    )
    p_serve.add_argument("--audit", default="tripwire-audit.jsonl", help="audit log path")
    p_serve.add_argument(
        "--gate",
        choices=["none", "cli", "web"],
        default="none",
        help="how a human approves gated calls (default: none — gated calls are refused)",
    )
    p_serve.add_argument(
        "--gate-port", type=int, default=8642, help="port for --gate web (127.0.0.1 only)"
    )
    p_serve.add_argument(
        "--tx-db",
        help=(
            "sqlite ledger for idempotency; with it a retried identical call in the "
            "same session returns the first call's result instead of running the tool twice "
            "(shadow mode doesn't use it)"
        ),
    )
    p_serve.add_argument(
        "--audit-key-file",
        default=os.environ.get(KEY_ENV),
        help=(
            "file holding a secret key; the audit log becomes an HMAC chain nobody "
            f"can rewrite without it (default: ${KEY_ENV})"
        ),
    )
    p_serve.add_argument(
        "--task-file",
        default=os.environ.get(TASK_ENV),
        help=(
            "file holding the user's task text, read again whenever it changes; "
            f"what it names anchors (default: ${TASK_ENV})"
        ),
    )

    p_validate = sub.add_parser("validate", help="check a policy file")
    p_validate.add_argument("policy")

    p_explain = sub.add_parser("explain", help="say what anchors each argument of a policy")
    p_explain.add_argument("policy")

    p_recipe = sub.add_parser(
        "recipe", help="draft a policy from an MCP server's tool listing, to stdout"
    )
    listing = p_recipe.add_mutually_exclusive_group(required=True)
    listing.add_argument("--tools", help="a tools/list result saved as JSON")
    listing.add_argument(
        "--upstream", help='an MCP server command to read the listing from, e.g. "npx some-server"'
    )
    p_recipe.add_argument(
        "--strict",
        action="store_true",
        help="make no tool self_scoped, so a write naming nothing anchorable is always gated",
    )

    p_hook = sub.add_parser("hook", help="hand an agent host's prompts to serve --task-file")
    hosts = p_hook.add_subparsers(dest="host", required=True)
    p_claude = hosts.add_parser("claude-code", help="Claude Code's UserPromptSubmit hook")
    p_claude.add_argument("--task-file", required=True, help="the file serve --task-file reads")

    p_verify = sub.add_parser("verify", help="check an audit log's hash chain")
    p_verify.add_argument("log")

    p_trace = sub.add_parser("trace", help="replay one session as a causal chain")
    p_trace.add_argument("log")
    p_trace.add_argument("session", nargs="?", help="session id (default: the only/latest one)")

    p_report = sub.add_parser("report", help="summarise what the policy has been doing")
    p_report.add_argument("log")

    p_replay = sub.add_parser("replay", help="re-judge recorded traffic under a candidate policy")
    p_replay.add_argument("log")
    p_replay.add_argument("--policy", required=True, help="the candidate policy to try")
    p_replay.add_argument("session", nargs="?", help="session id (default: every session)")

    for reader in (p_verify, p_trace, p_report, p_replay):
        reader.add_argument(
            "--audit-key-file",
            default=os.environ.get(KEY_ENV),
            help=f"the key the log was served with; a keyed log needs it (default: ${KEY_ENV})",
        )

    args = parser.parse_args(argv)

    if args.command == "hook":
        # what it prints reaches the model, and the prompt must go through
        # whatever happens here: it says nothing and exits 0
        claude_code_hook(args.task_file)

    elif args.command == "validate":
        try:
            policy = load_policy(args.policy)
        except PolicyError as e:
            print(e, file=sys.stderr)
            sys.exit(1)
        mode = "enforce" if policy.enforce else "shadow (nothing will be blocked)"
        print(f"ok: {args.policy} is valid, mode: {mode}, {len(policy.tools)} tool rules")
        for warning in policy_warnings(policy):
            print(f"warning: {warning}", file=sys.stderr)

    elif args.command == "explain":
        try:
            policy = load_policy(args.policy)
        except PolicyError as e:
            print(e, file=sys.stderr)
            sys.exit(1)
        for line in explain(policy):
            print(line)
        for warning in policy_warnings(policy):
            print(f"warning: {warning}", file=sys.stderr)

    elif args.command == "recipe":
        from tripwire.proxy import UpstreamError
        from tripwire.recipe import recipe

        try:
            if args.tools is not None:
                source = Path(args.tools).read_bytes()
            else:
                source = anyio.run(listed, args.upstream)
            print(recipe(source, arm="strict" if args.strict else "primary"), end="")
        # ValueError: a RecipeError, or a command shlex can't split
        except (OSError, ValueError, UpstreamError) as e:
            print(f"tripwire recipe: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "verify":
        try:
            key = audit_key(args.audit_key_file)
        except AuditKeyError as e:
            print(e, file=sys.stderr)
            sys.exit(1)
        result = verify_log(args.log, key=key)
        if result.ok and key is None:
            print(f"ok: chain intact, {result.records} records (unkeyed)")
            print("  catches: a line edited or deleted in the middle of the log")
            print("  misses:  a rewrite by anyone who can write the file; lines cut from the end,")
            print("           even once a restart carries on past the cut")
            print("  serve and verify with --audit-key-file to catch rewrites")
        elif result.ok:
            print(f"ok: chain intact, {result.records} records (keyed, all authenticated)")
            print("  catches: any edit, insertion or rewrite made without the key, and a line")
            print("           deleted in the middle of the log")
            print("  misses:  lines cut from the end, even once a restart carries on past the cut")
        elif result.bad_line is None:
            print(f"cannot verify {args.log}: {result.why}", file=sys.stderr)
            sys.exit(1)
        else:
            print(
                f"BROKEN at line {result.bad_line}: {result.why} "
                f"({result.records} records verified before that)",
                file=sys.stderr,
            )
            sys.exit(1)

    elif args.command == "trace":
        check_chain(args.log, args.audit_key_file)
        try:
            records = read_records(args.log)
        except LogError as e:
            print(e, file=sys.stderr)
            sys.exit(1)

        known = sessions(records)
        session_id = args.session
        if session_id is None:
            if not known:
                print(f"{args.log} has no records", file=sys.stderr)
                sys.exit(1)
            session_id = known[-1]
        elif session_id not in known:
            print(
                f"no session {session_id!r} in {args.log}; known: {', '.join(known) or 'none'}",
                file=sys.stderr,
            )
            sys.exit(1)

        print(format_trace(trace(records, session_id), session_id))

    elif args.command == "report":
        check_chain(args.log, args.audit_key_file)
        try:
            records = read_records(args.log)
        except LogError as e:
            print(e, file=sys.stderr)
            sys.exit(1)
        print(format_report(report(records)))

    elif args.command == "replay":
        from tripwire.replay import format_replay, replay

        check_chain(args.log, args.audit_key_file)
        try:
            records = read_records(args.log)
            candidate = load_policy(args.policy)
        except (LogError, PolicyError) as e:
            print(e, file=sys.stderr)
            sys.exit(1)

        wanted = [args.session] if args.session else sessions(records)
        for sid in wanted:
            print(format_replay(replay(records, sid, candidate), args.policy))
            print()

    elif args.command == "serve":
        from tripwire.gate import GateUnavailable
        from tripwire.proxy import UpstreamError, serve
        from tripwire.tx.executor import TxError

        if args.task_file == "":
            # an unset variable in `--task-file "$TASK"` looks like this,
            # and it would quietly leave the session without its task
            print(
                f"tripwire: refusing to start: the task file name is empty; to go without "
                f"one, unset {TASK_ENV} and leave out --task-file",
                file=sys.stderr,
            )
            sys.exit(2)
        try:
            key = audit_key(args.audit_key_file)
            anyio.run(
                serve,
                args.policy,
                args.upstream,
                args.audit,
                args.gate,
                args.gate_port,
                args.tx_db,
                key,
                args.task_file,
            )
        except (
            PolicyError,
            UpstreamError,
            AuditWriteError,
            AuditKeyError,
            GateUnavailable,
            TxError,
        ) as e:
            # bad policy, dead upstream, nowhere to write the log, a key
            # we can't use, or a gate that can't run here: we can't do the
            # job, so we don't pretend to
            print(f"tripwire: refusing to start: {e}", file=sys.stderr)
            sys.exit(2)
        except KeyboardInterrupt:
            pass
