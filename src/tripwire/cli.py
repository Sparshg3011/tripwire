from __future__ import annotations

import argparse
import sys

import anyio

from tripwire.policy import PolicyError, load_policy
from tripwire.tx import AuditWriteError, verify_log


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="tripwire", description="MCP firewall for AI agents")
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser("serve", help="run the proxy in front of an upstream MCP server")
    p_serve.add_argument("--policy", required=True, help="path to policy yaml")
    p_serve.add_argument(
        "--upstream", required=True, help='upstream command, e.g. "npx some-server"'
    )
    p_serve.add_argument("--audit", default="tripwire-audit.jsonl", help="audit log path")

    p_validate = sub.add_parser("validate", help="check a policy file")
    p_validate.add_argument("policy")

    p_verify = sub.add_parser("verify", help="check an audit log's hash chain")
    p_verify.add_argument("log")

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

    elif args.command == "serve":
        from tripwire.proxy import UpstreamError, serve

        try:
            anyio.run(serve, args.policy, args.upstream, args.audit)
        except (PolicyError, UpstreamError, AuditWriteError) as e:
            # bad policy, dead upstream, nowhere to write the log: all
            # three mean we can't do the job, so we don't pretend to
            print(f"tripwire: refusing to start: {e}", file=sys.stderr)
            sys.exit(2)
        except KeyboardInterrupt:
            pass
