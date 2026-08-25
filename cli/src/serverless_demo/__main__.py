"""serverless-demo -- seeds, verifies and tears down the security demo.

Exit codes are a contract, because this runs in CI as well as by hand:

    0  what was asked for happened
    1  a usage or configuration error -- nothing was attempted
    2  an account guard refused -- nothing was attempted
    3  the operation ran and did not reach the state it was asked for
"""

from __future__ import annotations

import argparse
import sys

from . import configsync, lifecycle, seed, verify
from .config import ConfigError, load
from .sessions import AccountMismatch, SessionError

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_GUARD = 2
EXIT_INCOMPLETE = 3


def report(message: str) -> None:
    print(message, flush=True)


def cmd_status(config, args) -> int:
    estate = lifecycle.status(config)

    report(f"{'ACCOUNT':<14} {'REGION':<15} {'NAME':<24} {'TYPE':<10} STATE")
    for instance in sorted(estate.instances, key=lambda i: (i.account, i.name)):
        report(f"{instance.account:<14} {instance.region:<15} {instance.name:<24} "
               f"{instance.instance_type:<10} {instance.state}")

    monthly = estate.monthly_cost()
    report("")
    report(f"{len(estate.running)} running, {len(estate.instances) - len(estate.running)} stopped, "
           f"{estate.ebs_gb} GB EBS, {estate.eip_count} elastic IP(s)")
    report(f"approximately ${monthly:.2f}/month at this posture")

    # GuardDuty is excluded from the figure above on purpose: it bills on events
    # analysed rather than on anything visible here, and it is not a lever -- it
    # needs to stay on between demos so its baselines are worth something.
    report("plus GuardDuty (~$1-3/month), which should stay on between demos for baselining")

    if estate.running:
        report("")
        report("`serverless-demo down` returns this to minimum cost.")
    return EXIT_OK


def cmd_up(config, args) -> int:
    report("Bringing the estate up for a demo.")
    if not lifecycle.up(config, report, ssm_timeout=args.ssm_timeout):
        report("")
        report("The egress host is not reachable, so a seed run would fail at the attack step.")
        return EXIT_INCOMPLETE
    report("")
    report("Ready. Seed 20-30 minutes before the demo: CloudTrail lags its own telemetry.")
    return EXIT_OK


def cmd_down(config, args) -> int:
    report("Returning the estate to minimum cost.")
    lifecycle.down(config, report, release_eip=not args.keep_eip)
    report("")
    if args.keep_eip:
        report("Kept the elastic IP. That is $3.65/month for a stable source address.")
    else:
        report("Released the elastic IP. `up` allocates a new one, so the source address "
               "will differ next time -- which is what `--fresh` does deliberately anyway.")
    return EXIT_OK


def cmd_verify(config, args) -> int:
    report(f"Preflight against {config.demo.account_id} ({config.demo.region})")
    report("")

    result = verify.run(config, config.demo.investigator_external_id)

    symbol = {verify.Outcome.OK: "ok  ", verify.Outcome.WARN: "warn", verify.Outcome.FAIL: "FAIL"}
    for check in result.checks:
        report(f"  {symbol[check.outcome]}  {check.name}")
        report(f"        {check.detail}")
        if check.fix and check.outcome is not verify.Outcome.OK:
            report(f"        -> {check.fix}")

    report("")
    if result.failed:
        report(f"{len(result.failed)} check(s) failed. Do not start a demo on this.")
        return EXIT_INCOMPLETE
    if result.warned:
        report(f"{len(result.warned)} warning(s). Readable above; none of them block a demo.")
        return EXIT_OK
    report("All checks passed.")
    return EXIT_OK


def cmd_config_sync(config, args) -> int:
    from .config import repo_root
    from .configsync import SyncError
    try:
        target = configsync.sync(repo_root())
    except SyncError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    report(f"Wrote {target} from the Terraform outputs.")
    report("Commit it: the file is what lets a fresh clone run verify without Terraform.")
    return EXIT_OK


def cmd_seed(config, args) -> int:
    report(f"Seeding {config.demo.account_id} as run {args.run_id}")
    report("")
    result = seed.run(config, args.run_id, report, confirm_timeout=args.confirm_timeout)
    report("")
    if not result.ok:
        report(f"Seed did not complete: {result.reason}")
        return EXIT_INCOMPLETE
    report(f"Seed complete. Source {result.source_ip}, "
           f"orphaned key {result.orphaned_key_id} on {config.demo.persistence_user}.")
    report("The events are confirmed present. Run `soar` next, then `artifacts`.")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="serverless-demo",
        description="Seeds, verifies and tears down the Serverless AI security demo.",
    )
    parser.add_argument("--config", help="Path to demo.toml. Defaults to the repository's.")
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status", help="What is running, and what it costs to leave it.")
    status.set_defaults(handler=cmd_status)

    up = sub.add_parser("up", help="Demo-ready: start the egress host and attach an address.")
    up.add_argument("--ssm-timeout", type=int, default=240,
                    help="Seconds to wait for SSM to register the host. A cold t4g.nano "
                         "usually takes 60-120s.")
    up.set_defaults(handler=cmd_up)

    down = sub.add_parser("down", help="Minimum cost: stop everything, release the address.")
    down.add_argument("--keep-eip", action="store_true",
                      help="Keep the elastic IP so the source address is stable between "
                           "demos. Costs $3.65/month.")
    down.set_defaults(handler=cmd_down)

    verify_cmd = sub.add_parser(
        "verify", help="Read-only preflight. Run before every demo.")
    verify_cmd.set_defaults(handler=cmd_verify)

    seed_cmd = sub.add_parser("seed", help="Mint the key, run the attack, confirm the events.")
    seed_cmd.add_argument("--run-id", required=True, help="Tags everything this run creates.")
    seed_cmd.add_argument("--confirm-timeout", type=int, default=1200,
                          help="Seconds to wait for CloudTrail. Default 20 minutes.")
    seed_cmd.set_defaults(handler=cmd_seed)

    config_cmd = sub.add_parser("config", help="Manage demo.toml.")
    config_sub = config_cmd.add_subparsers(dest="config_command", required=True)
    sync_cmd = config_sub.add_parser("sync", help="Regenerate demo.toml from Terraform.")
    sync_cmd.set_defaults(handler=cmd_config_sync)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        from pathlib import Path
        config = load(Path(args.config) if args.config else None)
    except ConfigError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE

    try:
        return args.handler(config, args)
    except AccountMismatch as error:
        print(f"\n{error}", file=sys.stderr)
        return EXIT_GUARD
    except SessionError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_INCOMPLETE


if __name__ == "__main__":
    sys.exit(main())
