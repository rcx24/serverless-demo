"""Read-only preflight. Run it before every demo.

Everything here answers a question that has a wrong answer somebody would
otherwise discover on stage. Each check is independent, and a failure reports what
to do rather than only what happened -- at T-15 the useful output is the fix, not
the diagnosis.

Nothing in this module writes. It assumes the investigator role and deliberately
tries things that must fail, which is the only way to know a control is real
rather than merely written down.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum

from botocore.exceptions import ClientError

from . import lifecycle, sessions
from .config import Config


class Outcome(Enum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"


@dataclass
class Check:
    name: str
    outcome: Outcome
    detail: str
    fix: str = ""


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)

    def add(self, name, outcome, detail, fix=""):
        self.checks.append(Check(name, outcome, detail, fix))
        return self.checks[-1]

    @property
    def failed(self):
        return [c for c in self.checks if c.outcome is Outcome.FAIL]

    @property
    def warned(self):
        return [c for c in self.checks if c.outcome is Outcome.WARN]


def _check_roles(config: Config, report: Report) -> None:
    """Every role this tool depends on, assumed for real rather than described."""
    for label, factory in (("seed", sessions.seed_admin),
                           ("SOAR", sessions.soar),
                           ("egress operator", sessions.egress)):
        try:
            session = factory(config)
            arn = session.client("sts").get_caller_identity()["Arn"]
            report.add(f"assume the {label} role", Outcome.OK, arn.split("/")[-2])
        except Exception as error:
            report.add(f"assume the {label} role", Outcome.FAIL, str(error),
                       "Has `make apply` been run for both environment roots?")


def _check_external_id_is_enforced(config: Config, report: Report, external_id: str) -> None:
    """The control that has to be real, checked by trying to break it.

    A trust policy that names an external id and does not enforce it looks
    identical from the outside. The only way to know is to assume without one and
    require that it fails -- which is also the demonstration worth doing on screen
    when somebody asks what stops a caller who knows the role ARN.
    """
    base = sessions.management(config)
    sts = base.client("sts")

    try:
        sts.assume_role(RoleArn=config.demo.investigator_role_arn,
                        RoleSessionName="verify-no-external-id")
        report.add("investigator refuses assumption without the external id", Outcome.FAIL,
                   "the role was assumed without one",
                   "The trust policy is not enforcing sts:ExternalId. Re-apply the demo root.")
    except ClientError:
        report.add("investigator refuses assumption without the external id", Outcome.OK,
                   "AccessDenied, as it should be")

    try:
        sessions.investigator(config, external_id)
        report.add("investigator assumes with the external id", Outcome.OK, "assumed")
    except Exception as error:
        report.add("investigator assumes with the external id", Outcome.FAIL, str(error),
                   "The external id in demo.toml disagrees with the trust policy. "
                   "Re-run `serverless-demo config sync`.")


def _check_investigator_cannot_overreach(config: Config, report: Report, external_id: str) -> None:
    """The two guarantees the demo makes out loud, tested against the live role."""
    try:
        session = sessions.investigator(config, external_id)
    except Exception:
        return  # already reported by the check above

    try:
        session.client("s3").get_object(
            Bucket=config.demo.exports_bucket,
            Key="exports/2026/08/cost-allocation-2026-08.csv")
        report.add("investigator cannot read an object", Outcome.FAIL,
                   "GetObject succeeded",
                   "The Deny on s3:GetObject is missing. This is the demo's central claim.")
    except ClientError as error:
        code = error.response["Error"]["Code"]
        report.add("investigator cannot read an object", Outcome.OK, f"{code}, as it should be")

    try:
        session.client("iam").update_access_key(
            UserName=config.demo.compromised_user,
            AccessKeyId="AKIAZZZZZZZZZZZZZZZZ", Status="Inactive")
        report.add("investigator cannot touch a credential", Outcome.FAIL,
                   "UpdateAccessKey was permitted",
                   "The Deny on iam:*AccessKey* is missing. An investigator that can "
                   "disable a key holds the same power as the attacker.")
    except ClientError as error:
        code = error.response["Error"]["Code"]
        outcome = Outcome.OK if code == "AccessDenied" else Outcome.WARN
        report.add("investigator cannot touch a credential", outcome,
                   f"{code}, as it should be" if outcome is Outcome.OK else
                   f"got {code}; expected AccessDenied")


def _check_trail_is_delivering(config: Config, report: Report) -> None:
    """That the trail exists is not the question. Whether events are arriving is.

    A trail can be present, correctly configured and logging nothing -- which is
    exactly the state that produces an empty timeline twenty minutes into a demo.
    """
    session = sessions.seed_admin(config)

    try:
        events = session.client("cloudtrail").lookup_events(MaxResults=1)["Events"]
        if events:
            age = time.time() - events[0]["EventTime"].timestamp()
            report.add("Event History is delivering", Outcome.OK,
                       f"most recent management event {int(age // 60)} min old")
        else:
            report.add("Event History is delivering", Outcome.WARN,
                       "no management events found",
                       "Normal in an account nobody has touched. A seed run will produce them.")
    except ClientError as error:
        report.add("Event History is delivering", Outcome.FAIL, str(error))

    admin = sessions.admin(config, config.demo.account_id)
    try:
        streams = admin.client("logs").describe_log_streams(
            logGroupName=config.demo.log_group_name, limit=1)["logStreams"]
        if streams and "lastEventTimestamp" in streams[0]:
            age = time.time() - streams[0]["lastEventTimestamp"] / 1000
            outcome = Outcome.OK if age < 3600 else Outcome.WARN
            report.add("trail is reaching CloudWatch Logs", outcome,
                       f"last event {int(age // 60)} min old",
                       "" if outcome is Outcome.OK else
                       "The trail may have stopped. Object reads are only visible here.")
        else:
            report.add("trail is reaching CloudWatch Logs", Outcome.WARN,
                       "log group is empty",
                       "It can take ~15 minutes after the trail is created for the first "
                       "events to arrive. Object reads are only visible here.")
    except ClientError as error:
        report.add("trail is reaching CloudWatch Logs", Outcome.FAIL, str(error),
                   "Without this, s3:GetObject is invisible -- data events never reach "
                   "Event History.")


def _check_guardduty(config: Config, report: Report) -> None:
    session = sessions.seed_admin(config)
    try:
        detectors = session.client("guardduty").list_detectors()["DetectorIds"]
        if detectors:
            report.add("GuardDuty is enabled", Outcome.OK, detectors[0])
        else:
            report.add("GuardDuty is enabled", Outcome.WARN, "no detector",
                       "Findings are a bonus, never a scripted beat -- but they need "
                       "weeks of baselining to appear at all.")
    except ClientError as error:
        report.add("GuardDuty is enabled", Outcome.WARN, str(error))


def _check_baseline_posture(config: Config, report: Report) -> None:
    """The decoy identities exist, and nothing is running that should not be."""
    session = sessions.seed_admin(config)
    iam = session.client("iam")

    for label, user in (("compromised", config.demo.compromised_user),
                        ("persistence target", config.demo.persistence_user)):
        try:
            iam.get_user(UserName=user)
            keys = iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
            if keys:
                report.add(f"{label} identity is clean", Outcome.WARN,
                           f"{user} already has {len(keys)} access key(s)",
                           "A previous run did not tear down. Run `serverless-demo teardown`.")
            else:
                report.add(f"{label} identity is clean", Outcome.OK, f"{user}, no keys")
        except ClientError as error:
            report.add(f"{label} identity is clean", Outcome.FAIL, str(error),
                       "Has the demo root been applied?")

    # Terraform creates EC2 instances running, so this drifts on every apply.
    estate = lifecycle.status(config)
    running = [i for i in estate.running if i.account == config.demo.account_id]
    if running:
        names = ", ".join(i.name for i in running)
        report.add("padding estate is stopped", Outcome.WARN,
                   f"{len(running)} running: {names}",
                   "They only need to appear in DescribeInstances, which a stopped "
                   "instance does. `serverless-demo down` stops them (~$3/month each).")
    else:
        report.add("padding estate is stopped", Outcome.OK,
                   f"{len(estate.instances)} instances, none running")


def run(config: Config, external_id: str) -> Report:
    report = Report()
    _check_roles(config, report)
    _check_external_id_is_enforced(config, report, external_id)
    _check_investigator_cannot_overreach(config, report, external_id)
    _check_trail_is_delivering(config, report)
    _check_guardduty(config, report)
    _check_baseline_posture(config, report)
    return report
