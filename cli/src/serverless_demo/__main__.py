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

from . import bot, configsync, containment, lifecycle, seed, siembot, teardown, verify
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


def cmd_containment_check(config, args) -> int:
    import json
    from pathlib import Path
    from datetime import datetime, timezone, timedelta
    from . import sessions

    artifacts_dir = config_mod_repo_root() / "artifacts" / args.run_id
    alert = json.loads((artifacts_dir / "alert.json").read_text())
    soar_case = json.loads((artifacts_dir / "soar-case.json").read_text())

    # A generous lower bound on the window; the alert's own events fix the real one.
    start = datetime.now(timezone.utc) - timedelta(hours=args.window_hours)

    investigator = sessions.investigator(config, config.demo.investigator_external_id)
    result = containment.verify(investigator, config, alert, soar_case, start)

    report(f"Containment verification for {result.compromised_identity}")
    report("")
    report(f"  SOAR claimed: contained")
    report(f"  quarantine policy present:  {'yes' if result.quarantine_confirmed else 'NO'}")
    report(f"  alerting key disabled:      {'yes' if result.original_key_disabled else 'NO'}")
    report("")
    report("  Keys the compromised identity created:")
    if not result.findings:
        report("    (none found in the window)")
    for finding in result.findings:
        flag = "  <-- UNCONTAINED" if finding.is_orphan else ""
        report(f"    {finding.identity:22} {finding.access_key_id}  {finding.status:9}"
               f"  named in case: {'yes' if finding.named_in_soar else 'NO'}{flag}")
        if finding.is_orphan and finding.reachable:
            report(f"        can reach: {', '.join(finding.reachable)}")
        report(f"        evidence: {finding.evidence_event_id}")

    report("")
    if result.orphans:
        report(f"{len(result.orphans)} uncontained key(s). The automation reported full "
               "containment and missed this.")
        return EXIT_OK
    report("No uncontained keys. Either the SOAR was complete or the seed did not establish "
           "persistence.")
    return EXIT_INCOMPLETE


def config_mod_repo_root():
    from .config import repo_root
    return repo_root()


def cmd_teardown(config, args) -> int:
    report(f"Tearing down {config.demo.account_id}"
           + (f" (run {args.run_id})" if args.run_id else ""))
    report("")
    result = teardown.run(config, args.run_id, report)
    report("")
    if result.clean:
        report(f"Baseline restored. Deleted {len(result.deleted_keys)} key(s).")
        return EXIT_OK
    report("Account does NOT match baseline:")
    for violation in result.baseline_violations:
        report(f"  - {violation}")
    return EXIT_INCOMPLETE


def cmd_alert_post(config, args) -> int:
    import os
    from pathlib import Path
    from .config import repo_root
    from .siembot import AlertPostError, post
    alert_path = repo_root() / "artifacts" / args.run_id / "alert.json"
    try:
        result = post(
            alert_path,
            webhook_url=args.webhook_url or os.environ.get("SLACK_WEBHOOK_URL"),
            bot_token=args.bot_token or os.environ.get("SLACK_BOT_TOKEN"),
            channel=args.channel or os.environ.get("SLACK_CHANNEL"),
        )
    except AlertPostError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    report(result)
    report("The Slack trigger should launch the harness now. Nobody clicked anything.")
    return EXIT_OK


def _bot_config(args):
    """BotConfig from flags-or-env. Missing required values raise a usage error."""
    import os
    from .bot import BotConfig

    def need(flag, env):
        val = getattr(args, flag, None) or os.environ.get(env)
        if not val:
            raise SystemExit(f"error: --{flag.replace('_','-')} or {env} is required")
        return val

    return BotConfig(
        signing_secret=need("signing_secret", "BOT_SIGNING_SECRET"),
        public_url=need("public_url", "BOT_PUBLIC_URL"),
        api_url=need("api_url", "SERVERLESS_API_URL"),
        client_id=need("client_id", "SERVERLESS_CLIENT_ID"),
        client_secret=need("client_secret", "SERVERLESS_CLIENT_SECRET"),
        configuration_id=need("configuration_id", "SOC_TRIAGE_CONFIG_ID"),
        thread_parameter=(getattr(args, "thread_parameter", None)
                          or os.environ.get("SOC_TRIAGE_THREAD_PARAM", "thread")),
    )


def cmd_demo_fire(config, args) -> int:
    import os
    from pathlib import Path
    from .config import repo_root
    from .siembot import AlertPostError, fire
    from .bot import launch_url_for

    bot_cfg = _bot_config(args)
    token = args.bot_token or os.environ.get("SLACK_BOT_TOKEN")
    channel = args.channel or os.environ.get("SLACK_CHANNEL")
    if not token or not channel:
        print("error: --bot-token/SLACK_BOT_TOKEN and --channel/SLACK_CHANNEL are required "
              "(the thread needs a bot token, not a webhook)", file=sys.stderr)
        return EXIT_USAGE

    run_dir = repo_root() / "artifacts" / args.run_id
    try:
        result = fire(run_dir / "alert.json", run_dir / "soar-case.json",
                      bot_token=token, channel=channel,
                      launch_url_for=launch_url_for(bot_cfg), report=report, pace=args.pace)
    except AlertPostError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    report("")
    report(f"Thread is live: {result['channel']}/{result['thread_ts']}")
    report("Click the button in the thread to launch the harness. Make sure `bot serve` is up.")
    return EXIT_OK


def cmd_bot_serve(config, args) -> int:
    from .bot import serve
    bot_cfg = _bot_config(args)
    serve(bot_cfg, args.port, report=report)
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

    cc = sub.add_parser("containment-check",
                        help="Derive uncontained keys from the alert, the trail and the SOAR case.")
    cc.add_argument("--run-id", required=True, help="Which run's artifacts to read.")
    cc.add_argument("--window-hours", type=int, default=2,
                    help="How far back to search the trail. Default 2 hours.")
    cc.set_defaults(handler=cmd_containment_check)

    td = sub.add_parser("teardown", help="Revoke keys, undo containment, assert baseline.")
    td.add_argument("--run-id", help="The run to tear down. Omit to clean whatever is present.")
    td.set_defaults(handler=cmd_teardown)

    alert = sub.add_parser("alert", help="The simulated SIEM bot.")
    alert_sub = alert.add_subparsers(dest="alert_command", required=True)
    ap = alert_sub.add_parser("post", help="Post a run's alert.json to Slack (fires the demo).")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--webhook-url", help="Slack incoming webhook (or SLACK_WEBHOOK_URL).")
    ap.add_argument("--bot-token", help="Slack bot token (or SLACK_BOT_TOKEN).")
    ap.add_argument("--channel", help="Channel id for bot posting (or SLACK_CHANNEL).")
    ap.set_defaults(handler=cmd_alert_post)

    # Shared bot/product flags for demo+bot commands.
    def add_bridge_flags(sp):
        sp.add_argument("--signing-secret", help="or BOT_SIGNING_SECRET")
        sp.add_argument("--public-url", help="the tunnel URL the button points at (or BOT_PUBLIC_URL)")
        sp.add_argument("--api-url", help="product base URL (or SERVERLESS_API_URL)")
        sp.add_argument("--client-id", help="API client id (or SERVERLESS_CLIENT_ID)")
        sp.add_argument("--client-secret", help="API client secret (or SERVERLESS_CLIENT_SECRET)")
        sp.add_argument("--configuration-id", help="soc-triage template id (or SOC_TRIAGE_CONFIG_ID)")
        sp.add_argument("--thread-parameter", help="frame slack-thread param name (or SOC_TRIAGE_THREAD_PARAM, default 'thread')")

    demo = sub.add_parser("demo", help="Drive the Slack demo flow.")
    demo_sub = demo.add_subparsers(dest="demo_command", required=True)
    fire_cmd = demo_sub.add_parser("fire", help="Post the alert, SOAR replies, and launch button to a thread.")
    fire_cmd.add_argument("--run-id", required=True)
    fire_cmd.add_argument("--bot-token", help="Slack bot token (or SLACK_BOT_TOKEN).")
    fire_cmd.add_argument("--channel", help="Channel id (or SLACK_CHANNEL).")
    fire_cmd.add_argument("--pace", type=float, default=1.5, help="Seconds between SOAR replies.")
    add_bridge_flags(fire_cmd)
    fire_cmd.set_defaults(handler=cmd_demo_fire)

    bot_cmd = sub.add_parser("bot", help="The launch bridge for the Slack button.")
    bot_sub = bot_cmd.add_subparsers(dest="bot_command", required=True)
    serve_cmd = bot_sub.add_parser("serve", help="Run the /launch endpoint locally.")
    serve_cmd.add_argument("--port", type=int, default=8787)
    add_bridge_flags(serve_cmd)
    serve_cmd.set_defaults(handler=cmd_bot_serve)

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
