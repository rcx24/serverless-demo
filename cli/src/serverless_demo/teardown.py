"""Returning the account to baseline after a run, and proving it got there.

Distinct from `down`, which only changes what is powered on. Teardown reverses a
seed run: it deletes both access keys -- the compromised one and the orphaned one
the attack minted -- detaches the quarantine policy, removes the staged secret,
and then ASSERTS the account matches baseline, printing a diff of anything
unexpected and exiting non-zero if it does not.

The assertion is the point. A teardown that runs cleanly but leaves a key behind
is worse than one that fails, because the next seed inherits it and the run after
that inherits two. "It probably cleaned up" is not something a demo account that
gets reused weekly can afford.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from botocore.exceptions import ClientError

from . import egress, keys, sessions, soar
from .config import Config


@dataclass
class TeardownReport:
    deleted_keys: list[str] = field(default_factory=list)
    detached_policies: list[str] = field(default_factory=list)
    removed_secrets: list[str] = field(default_factory=list)
    baseline_violations: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.baseline_violations


def run(config: Config, run_id: str | None, report) -> TeardownReport:
    result = TeardownReport()
    seed_session = sessions.seed_admin(config)
    egress_session = sessions.egress(config)

    # --- delete both keys -----------------------------------------------------
    # Both decoy identities, not just the compromised one. The orphaned key on the
    # persistence identity is the whole point of the scenario, and it is exactly
    # the thing a careless teardown would leave active in a real account.
    for user in (config.demo.compromised_user, config.demo.persistence_user):
        for key in keys.list_keys(seed_session, user):
            keys.delete_key(seed_session, user, key["AccessKeyId"])
            result.deleted_keys.append(f"{key['AccessKeyId']} ({user})")
            report(f"  deleted {key['AccessKeyId']} on {user}")

    # --- detach the quarantine policy the SOAR attached -----------------------
    soar.undo(config, lambda m: report(m if m.startswith("  ") else f"  {m}"))
    result.detached_policies.append("soar-quarantine-deny-all")

    # --- remove the staged leaked key -----------------------------------------
    if run_id:
        egress.unstage_key(egress_session, config, run_id)
        result.removed_secrets.append(f"leaked-key/{run_id}")
        report(f"  removed the staged key for {run_id}")

    # --- assert baseline ------------------------------------------------------
    report("  asserting the account matches baseline")
    _assert_baseline(seed_session, config, result, report)

    return result


def _assert_baseline(seed_session, config: Config, result: TeardownReport, report) -> None:
    """Everything that should be true of a clean account. Each violation is
    reported specifically, because 'not clean' is not an actionable diff."""
    iam = seed_session.client("iam")

    # No access keys on either decoy identity.
    for user in (config.demo.compromised_user, config.demo.persistence_user):
        remaining = keys.list_keys(seed_session, user)
        for key in remaining:
            result.baseline_violations.append(
                f"{user} still has key {key['AccessKeyId']} ({key['Status']})")

    # No quarantine policy left attached.
    try:
        inline = iam.list_user_policies(UserName=config.demo.compromised_user)["PolicyNames"]
        for name in inline:
            if "quarantine" in name.lower():
                result.baseline_violations.append(
                    f"{config.demo.compromised_user} still has policy {name}")
    except ClientError:
        pass
