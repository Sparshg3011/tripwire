from __future__ import annotations

import argparse
import sys

import anyio

from tripwire.policy import PolicyError, load_policy
from tripwire.tx import (
    AuditWriteError,
    LogError,
    format_report,
    format_trace,
    read_records,
    report,
    sessions,
    trace,
    verify_log,
)


def check_chain(path: str) -> None:
    """Say so, loudly, before showing anyone a log as evidence.

    trace and report read a log and tell a story about it. If the chain
    is broken, that story may be the attacker's, so it can't be printed
    without the warning attached — a forensic tool that quietly renders
    tampered input is worse than one that doesn't exist.
    """
    result = verify_log(path)
    if not result.ok:
        print(
            f"WARNING: {path} fails its integrity check at line {result.bad_line} "
            f"({result.why}). Everything below is UNVERIFIED and may have been "
            f"altered. Run `tripwire verify` for detail.\n",
            file=sys.stderr,
        )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="tripwire", description="MCP firewall for AI agents")
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
            "sqlite ledger for idempotency; with it a retried identical call "
            "returns the first call's result instead of running the tool twice"
        ),
    )

    p_validate = sub.add_parser("validate", help="check a policy file")
    p_validate.add_argument("policy")

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

    args = parser.parse_args(argv)

    if args.command == "validate":
        try:
            policy = load_policy(args.policy)
        except PolicyError as e:
            print(e, file=sys.stderr)
            sys.exit(1)
        mode = "enforce" if policy.enforce else "shadow (nothing will be blocked)"
        print(f"ok: {args.policy} is valid, mode: {mode}, {len(policy.tools)} tool rules")

    elif args.command == "verify":
        result = verify_log(args.log)
        if result.ok:
            print(f"ok: chain intact, {result.records} records")
        else:
            print(
                f"BROKEN at line {result.bad_line}: {result.why} "
                f"({result.records} records verified before that)",
                file=sys.stderr,
            )
            sys.exit(1)

    elif args.command == "trace":
        check_chain(args.log)
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
        check_chain(args.log)
        try:
            records = read_records(args.log)
        except LogError as e:
            print(e, file=sys.stderr)
            sys.exit(1)
        print(format_report(report(records)))

    elif args.command == "replay":
        from tripwire.replay import format_replay, replay

        check_chain(args.log)
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

        try:
            anyio.run(
                serve,
                args.policy,
                args.upstream,
                args.audit,
                args.gate,
                args.gate_port,
                args.tx_db,
            )
        except (PolicyError, UpstreamError, AuditWriteError, GateUnavailable, TxError) as e:
            # bad policy, dead upstream, nowhere to write the log, or a
            # gate that can't run here: we can't do the job, so we don't
            # pretend to
            print(f"tripwire: refusing to start: {e}", file=sys.stderr)
            sys.exit(2)
        except KeyboardInterrupt:
            pass
