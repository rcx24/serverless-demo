"""The simulated SOAR playbook.

The one component other than the SIEM bot that is simulated, and it is simulated
as a thin wrapper around real actions: it genuinely attaches a deny-all policy and
genuinely disables the compromised key, in the real account, recorded by real
CloudTrail. What is "simulated" is only that a person wrote it to look like a
vendor playbook, not that its effects are fake.

It runs at seed time, not demo time, under its own role -- so its actions appear
in the timeline under a principal named after automation, which is what the
analyst reads to work out what was already done.

The whole point is the step that is NOT here. The playbook was written against the
alerting identity, and iam:CreateAccessKey on a *different* principal is outside
its scope. It contains svc-billing-export completely and never looks at
svc-report-runner. That omission is the demo. It is an explicit, commented,
intentional non-line below, and there is a test that fails if a future refactor
"completes" it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from . import sessions
from .config import Config

_QUARANTINE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "Quarantine",
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
    }],
}


@dataclass
class Step:
    step_id: int
    action: str
    target: str
    started_at: str
    completed_at: str
    status: str
    raw_response: dict = field(default_factory=dict)


@dataclass
class SoarResult:
    case_id: str
    steps: list[Step] = field(default_factory=list)
    disposition: str = "contained"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _request_id(response) -> str:
    return response.get("ResponseMetadata", {}).get("RequestId", "")


def run(config: Config, run_id: str, report) -> SoarResult:
    session = sessions.soar(config)
    iam = session.client("iam")
    user = config.demo.compromised_user
    case_id = f"CASE-{datetime.now(timezone.utc):%Y%m%d}-{run_id[-6:]}"
    result = SoarResult(case_id=case_id)

    report(f"playbook aws-compromised-access-key-containment on {user}")

    # Step 1: confirm the identity exists.
    started = _now()
    got = iam.get_user(UserName=user)
    result.steps.append(Step(1, "iam:GetUser", user, started, _now(), "succeeded",
                             {"UserName": got["User"]["UserName"],
                              "Arn": got["User"]["Arn"],
                              "RequestId": _request_id(got)}))
    report("  [1] confirmed the identity")

    # Step 2: attach the deny-all quarantine policy.
    started = _now()
    put = iam.put_user_policy(UserName=user, PolicyName="soar-quarantine-deny-all",
                              PolicyDocument=json.dumps(_QUARANTINE_POLICY))
    result.steps.append(Step(2, "iam:PutUserPolicy", user, started, _now(), "succeeded",
                             {"PolicyName": "soar-quarantine-deny-all",
                              "RequestId": _request_id(put)}))
    report("  [2] attached the deny-all quarantine policy")

    # Step 3: enumerate the alerting identity's keys.
    started = _now()
    listed = iam.list_access_keys(UserName=user)
    keys = listed["AccessKeyMetadata"]
    result.steps.append(Step(3, "iam:ListAccessKeys", user, started, _now(), "succeeded",
                             {"AccessKeyIds": [k["AccessKeyId"] for k in keys],
                              "RequestId": _request_id(listed)}))
    report(f"  [3] enumerated {len(keys)} key(s) on the alerting identity")

    # Step 4: disable each key found ON THE ALERTING IDENTITY.
    for key in keys:
        started = _now()
        updated = iam.update_access_key(UserName=user, AccessKeyId=key["AccessKeyId"],
                                        Status="Inactive")
        result.steps.append(Step(4, "iam:UpdateAccessKey", key["AccessKeyId"], started, _now(),
                                 "succeeded", {"Status": "Inactive",
                                               "RequestId": _request_id(updated)}))
        report(f"  [4] disabled {key['AccessKeyId']}")

    # ------------------------------------------------------------------------
    # There is no step 5.
    #
    # The playbook does not enumerate keys on svc-report-runner, and does not
    # disable the one the attacker minted there. This is not an oversight in the
    # code -- it is the scenario. The automation was written against the identity
    # the alert named, and a CreateAccessKey on a different principal is outside
    # what it was built to handle. The orphaned key stays Active, and finding it
    # is the analyst's job.
    #
    # DO NOT ADD A STEP HERE. A test in cli/tests/test_soar.py asserts the SOAR
    # never touches the persistence identity, and contracts/README.md explains
    # why. Completing the playbook here removes the entire point of the demo.
    # ------------------------------------------------------------------------

    report("  containment reported complete (the persistence key is untouched -- by design)")
    result.disposition = "contained"
    return result


def undo(config: Config, report) -> None:
    """Reverses the containment, for teardown. Detaches the quarantine policy;
    the disabled key is deleted by the key teardown, not re-enabled here."""
    session = sessions.soar(config)
    iam = session.client("iam")
    try:
        iam.delete_user_policy(UserName=config.demo.compromised_user,
                               PolicyName="soar-quarantine-deny-all")
        report("  detached the quarantine policy")
    except ClientError as error:
        if error.response["Error"]["Code"] != "NoSuchEntity":
            raise
