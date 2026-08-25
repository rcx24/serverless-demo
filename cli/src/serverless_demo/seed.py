"""The seed run: mint, attack, confirm.

The orchestration, kept deliberately linear so the demo runbook and this file read
the same way. Each phase reports as it goes, because a seed run is watched -- often
at T-30 with a demo booked -- and silence for two minutes during the CloudTrail
wait reads as a hang.

The phases:

  preflight   the compromised identity is clean, the host is reachable
  mint        a fresh key for the compromised identity, staged to the egress account
  attack      the sequence runs on the host with jittered timing
  confirm     poll CloudTrail until every expected event is present
  record      capture what was minted, for teardown and the answer key

Confirmation is the phase that must not be skipped or shortcut. Everything
downstream -- the SOAR, the artifacts, the harness -- assumes the events are real
and present. A seed that reported success without confirming would push that
assumption onto the demo floor.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import confirm, egress, keys, lifecycle, sessions
from .config import Config


@dataclass
class SeedResult:
    run_id: str
    ok: bool
    started_at: datetime
    access_key_id: str = ""
    orphaned_key_id: str = ""
    source_ip: str = ""
    object_keys: list[str] = field(default_factory=list)
    confirmations: list = field(default_factory=list)
    reason: str = ""


def _pick_object_keys(seed_session, config: Config, count: int = 3) -> list[str]:
    """Which objects the attack reads. The answer key records these, so the
    rehearsal can check the analyst found the right ones."""
    s3 = seed_session.client("s3")
    objects = s3.list_objects_v2(Bucket=config.demo.exports_bucket).get("Contents", [])
    dated = sorted(o["Key"] for o in objects if o["Key"].endswith(".csv"))
    # The most recent months -- the ones an attacker after current financials
    # would take, and the ones that make "they took July and August" a sentence.
    return dated[-count:]


def run(config: Config, run_id: str, report, confirm_timeout: int = 1200) -> SeedResult:
    started_at = datetime.now(timezone.utc)
    result = SeedResult(run_id=run_id, ok=False, started_at=started_at)

    seed_session = sessions.seed_admin(config)
    egress_session = sessions.egress(config)
    admin_session = sessions.admin(config, config.demo.account_id)

    # --- preflight ------------------------------------------------------------
    report("preflight")
    existing = keys.list_keys(seed_session, config.demo.compromised_user)
    if existing:
        result.reason = (f"{config.demo.compromised_user} already has a key; a previous run "
                         "did not tear down. Run teardown first.")
        report(f"  {result.reason}")
        return result

    report("  bringing the egress host up")
    if not lifecycle.up(config, lambda m: report(f"  {m.strip()}")):
        result.reason = "the egress host is not reachable"
        return result

    # The source address the alert will report. Captured now, from the host.
    result.source_ip = _host_public_ip(egress_session, config)
    report(f"  source address {result.source_ip}")

    object_keys = _pick_object_keys(seed_session, config)
    result.object_keys = object_keys

    # --- mint -----------------------------------------------------------------
    report("mint")
    minted = keys.mint(seed_session, config)
    result.access_key_id = minted.access_key_id
    report(f"  minted {minted.access_key_id} on {minted.user_name}")

    secret_id = egress.stage_key(egress_session, config, run_id, minted)
    report(f"  staged the key for the host to collect")

    # --- attack ---------------------------------------------------------------
    report("attack")
    attack = egress.run_attack(egress_session, config, secret_id, object_keys, report)
    egress.unstage_key(egress_session, config, run_id)

    if not attack.ok:
        result.reason = f"attack did not complete: {attack.reason}"
        report(f"  {result.reason}")
        return result
    report(f"  {attack.calls_ok} calls made, {attack.calls_failed} failed")

    # Capture the orphaned key the attack minted, from the persistence identity.
    #
    # Checked here rather than trusting confirmation, because a *denied*
    # CreateAccessKey still writes a CreateAccessKey event to CloudTrail -- so the
    # confirm phase would go green on an attack that never established persistence.
    # No orphaned key means no punchline, and that is worth failing on now rather
    # than fifteen minutes into the confirmation wait.
    orphaned = keys.list_keys(seed_session, config.demo.persistence_user)
    if not orphaned:
        result.reason = (f"the attack did not create a key on {config.demo.persistence_user}. "
                         f"The compromised identity may lack iam:CreateAccessKey -- check its policy.")
        report(f"  {result.reason}")
        return result
    result.orphaned_key_id = orphaned[-1]["AccessKeyId"]
    report(f"  persistence key {result.orphaned_key_id} on {config.demo.persistence_user}")

    # --- confirm --------------------------------------------------------------
    report("confirm")
    report("  CloudTrail lags 5-15 minutes; polling until every event is present")

    def progress(confirmations):
        pass

    ok, confirmations = confirm.wait(
        seed_session, admin_session, config, minted.access_key_id, started_at,
        report, timeout=confirm_timeout, on_progress=progress)
    result.confirmations = confirmations

    if not ok:
        missing = [c for c in confirmations if not c.satisfied]
        result.reason = "these events never appeared: " + ", ".join(
            f"{c.expectation.event_name} ({c.found}/{c.expectation.min_count})" for c in missing)
        report(f"  timed out. {result.reason}")
        return result

    report("  every expected event confirmed")
    result.ok = True
    return result


def _host_public_ip(egress_session, config: Config) -> str:
    ec2 = egress_session.client("ec2")
    reservations = ec2.describe_instances(InstanceIds=[config.egress.instance_id])["Reservations"]
    return reservations[0]["Instances"][0].get("PublicIpAddress", "")
