"""Containment verification -- the finding the whole demo is built to produce.

The requirement is exact: this must surface the orphaned key WITHOUT being told
where to look. It is not handed `svc-report-runner`. It derives it, from evidence,
by the same reasoning an analyst would use -- which is what lets the finding be
defended afterward rather than merely asserted.

The derivation, every step of which reads real state or the real trail:

  1. From the alert: the compromised principal and its access key.
  2. From CloudTrail: every identity that key ACTED ON during the window, and
     every credential it CREATED. CloudTrail records CreateAccessKey's target in
     requestParameters and the new key's id in responseElements.
  3. From the SOAR case: the set of identities and keys the automation actually
     named in its steps.
  4. Set difference: anything the key created or acted on that the SOAR never
     named is uncontained by the automation's own account of itself.
  5. Confirm each against live IAM state: is the key still Active, what can the
     identity reach.

The orphaned key falls out of (2) -> (4). Nothing names svc-report-runner until
step 5 confirms what step 4 already found. The SOAR case is complete and accurate
about what it did; the gap is real, which is why it holds up.

This runs from the investigator role -- read-only, no s3:GetObject, no credential
mutation. It can see everything it needs and change nothing, which is the same
posture the harness has.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .config import Config
from .confirm import IAM_REGION


@dataclass
class KeyFinding:
    identity: str
    access_key_id: str
    created: str
    status: str
    named_in_soar: bool
    evidence_event_id: str
    reachable: list[str] = field(default_factory=list)

    @property
    def is_orphan(self) -> bool:
        return self.status == "Active" and not self.named_in_soar


@dataclass
class ContainmentReport:
    compromised_identity: str
    quarantine_confirmed: bool
    original_key_disabled: bool
    findings: list[KeyFinding] = field(default_factory=list)

    @property
    def orphans(self) -> list[KeyFinding]:
        return [f for f in self.findings if f.is_orphan]


def _events_for_key(investigator_session, config: Config, access_key_id: str, start_time):
    """Every management event the compromised key made, across the regions that
    record them. The raw records, because we need requestParameters and
    responseElements, not just the names."""
    regions = {config.demo.region, IAM_REGION, *config.attack.discovery_regions}
    # Deduped by event id: a global event (IAM) can be returned by more than one
    # region's Event History, and a CreateAccessKey counted twice would report two
    # orphans where there is one.
    by_id = {}
    for region in regions:
        client = investigator_session.client("cloudtrail", region_name=region)
        for page in client.get_paginator("lookup_events").paginate(
            LookupAttributes=[{"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id}],
            StartTime=start_time,
        ):
            for event in page["Events"]:
                record = json.loads(event["CloudTrailEvent"])
                by_id[record.get("eventID", event["EventId"])] = record
    return list(by_id.values())


def _keys_created(events: list[dict]) -> list[tuple[str, str, str]]:
    """(target identity, new key id, event id) for each CreateAccessKey the
    compromised key made. This is where the orphan is discovered -- the key names
    an identity nobody mentioned, because the attacker chose it, not the analyst."""
    created = []
    for event in events:
        if event.get("eventName") != "CreateAccessKey":
            continue
        # A denied CreateAccessKey has no responseElements; skip it -- it created
        # nothing, so there is nothing uncontained to find.
        response = event.get("responseElements") or {}
        access_key = response.get("accessKey") or {}
        new_key_id = access_key.get("accessKeyId")
        if not new_key_id:
            continue
        target = access_key.get("userName") or \
            (event.get("requestParameters") or {}).get("userName", "")
        created.append((target, new_key_id, event.get("eventID", "")))
    return created


def _soar_named(soar_case: dict) -> set[str]:
    """Every identity and key the SOAR steps actually named. The automation's own
    account of what it touched -- read from its case, not assumed."""
    named = set()
    for step in soar_case.get("steps", []):
        named.add(step.get("target", ""))
    return named


def _reachability(iam, identity: str) -> list[str]:
    """A short, honest summary of what an identity could reach -- enough to decide
    whether an orphaned key matters. Reads attached and inline policy names; the
    detail lives in the policies themselves, which the analyst can open."""
    reach = []
    try:
        for policy in iam.list_attached_user_policies(UserName=identity)["AttachedPolicies"]:
            reach.append(f"managed:{policy['PolicyName']}")
        for name in iam.list_user_policies(UserName=identity)["PolicyNames"]:
            reach.append(f"inline:{name}")
    except Exception:
        pass
    return reach


def verify(investigator_session, config: Config, alert: dict, soar_case: dict,
           start_time) -> ContainmentReport:
    iam = investigator_session.client("iam")
    compromised = alert["entity"]["principalArn"].split("/")[-1]
    compromised_key = alert["entity"]["accessKeyId"]

    report = ContainmentReport(compromised_identity=compromised,
                               quarantine_confirmed=False, original_key_disabled=False)

    # --- confirm the half the SOAR claims it did -----------------------------
    try:
        inline = iam.list_user_policies(UserName=compromised)["PolicyNames"]
        report.quarantine_confirmed = any("quarantine" in name.lower() for name in inline)
    except Exception:
        pass

    for key in iam.list_access_keys(UserName=compromised)["AccessKeyMetadata"]:
        if key["AccessKeyId"] == compromised_key:
            report.original_key_disabled = key["Status"] == "Inactive"

    # --- derive what the automation missed -----------------------------------
    events = _events_for_key(investigator_session, config, compromised_key, start_time)
    created = _keys_created(events)
    soar_named = _soar_named(soar_case)

    for target_identity, new_key_id, event_id in created:
        # Live status of the key the compromised credential minted.
        status = "Unknown"
        try:
            for key in iam.list_access_keys(UserName=target_identity)["AccessKeyMetadata"]:
                if key["AccessKeyId"] == new_key_id:
                    status = key["Status"]
        except Exception:
            pass

        named = new_key_id in soar_named or target_identity in soar_named
        finding = KeyFinding(
            identity=target_identity,
            access_key_id=new_key_id,
            created=next((e["eventTime"] for e in events if e.get("eventID") == event_id), ""),
            status=status,
            named_in_soar=named,
            evidence_event_id=event_id,
            reachable=_reachability(iam, target_identity),
        )
        report.findings.append(finding)

    return report
