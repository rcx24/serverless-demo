"""Turning a confirmed seed run into the three bundles and the answer key.

Every value in the alert, the SOAR case and the IOC list is read back out of real
CloudTrail after confirmation, not invented. That is the whole discipline: a
security audience checks these against the console, so the samples must be genuine
events, the source IP must be the address the calls actually came from, and the
timestamps must be the ones CloudTrail recorded.

The three bundles go to artifacts/<run-id>/ and are cloned into the harness. The
answer key goes to out/<run-id>/ and is never committed -- it names the orphaned
key, the anomalous regions and the objects read, which is exactly what the analyst
is supposed to discover.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

from .config import Config

_MITRE = [
    {"techniqueId": "T1078.004", "name": "Valid Accounts: Cloud Accounts", "tactic": "Defense Evasion"},
    {"techniqueId": "T1580", "name": "Cloud Infrastructure Discovery", "tactic": "Discovery"},
    {"techniqueId": "T1098", "name": "Account Manipulation", "tactic": "Persistence"},
]


@dataclass
class Bundle:
    alert: dict
    soar_case: dict
    iocs: dict
    answer_key: str


def _slug(run_id: str) -> str:
    # A short, stable suffix for ids, derived from the run id so two bundles from
    # one run agree and two runs differ.
    return "".join(ch for ch in run_id if ch.isalnum())[-6:].lower().rjust(6, "0")


def _collect_events(seed_session, config: Config, access_key_id: str, start_time):
    """Every confirmed management event, pulled back with its full detail.

    Re-queried here rather than threaded through from confirmation because the
    alert needs the raw event records -- source IP, user agent, request parameters
    -- and confirmation only needed the counts.
    """
    from .confirm import IAM_REGION

    regions = {config.demo.region, IAM_REGION, *config.attack.discovery_regions}
    events = []
    for region in regions:
        client = seed_session.client("cloudtrail", region_name=region)
        for page in client.get_paginator("lookup_events").paginate(
            LookupAttributes=[{"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id}],
            StartTime=start_time,
        ):
            for event in page["Events"]:
                events.append(json.loads(event["CloudTrailEvent"]))
    events.sort(key=lambda e: e["eventTime"])
    return events


def _source_from_events(events: list[dict]) -> dict:
    """The source IP and user agent, taken from the events themselves."""
    for event in events:
        ip = event.get("sourceIPAddress", "")
        # Skip AWS-internal service addresses; we want the attacker's address.
        if ip and not ip.endswith(".amazonaws.com"):
            return {"ip": ip, "userAgent": event.get("userAgent", "")}
    return {"ip": "", "userAgent": ""}


def build(config: Config, seed_result, soar_result, seed_session, start_time) -> Bundle:
    events = _collect_events(seed_session, config, seed_result.access_key_id, start_time)
    slug = _slug(seed_result.run_id)
    date = datetime.now(timezone.utc).strftime("%Y%m%d")
    source = _source_from_events(events)
    source["ip"] = source["ip"] or seed_result.source_ip

    detected_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    principal_arn = f"arn:aws:iam::{config.demo.account_id}:user/{config.demo.compromised_user}"

    # Raw event samples, copied rather than summarised. Three to five that show the
    # shape of the activity: the identity check, the discovery, and the persistence.
    wanted = ["GetCallerIdentity", "GetAccountAuthorizationDetails", "DescribeInstances",
              "GetObject", "CreateAccessKey"]
    samples = []
    for name in wanted:
        match = next((e for e in events if e["eventName"] == name), None)
        if match:
            samples.append({
                "eventId": match.get("eventID", ""),
                "eventTime": match["eventTime"],
                "eventName": match["eventName"],
                "eventSource": match["eventSource"],
                "awsRegion": match["awsRegion"],
                "sourceIPAddress": match.get("sourceIPAddress", ""),
                "userAgent": match.get("userAgent", ""),
            })

    alert = {
        "schemaVersion": 1,
        "alertId": f"ALERT-{date}-{slug}",
        "runId": seed_result.run_id,
        "rule": {
            "id": "AWS-IAM-0041",
            "name": "Cloud discovery and credential creation from unrecognised ASN",
            "description": ("A long-lived access key enumerated IAM and EC2 across regions "
                            "with no prior activity, then created a new access key on a "
                            "second identity. Fires on the combination, not any single call."),
        },
        "severity": "high",
        "detectedAt": detected_at,
        "entity": {
            "principalArn": principal_arn,
            "principalType": "IAMUser",
            "accessKeyId": seed_result.access_key_id,
            "accountId": config.demo.account_id,
        },
        "source": {k: v for k, v in {
            "ip": source["ip"],
            "userAgent": source["userAgent"],
        }.items() if v},
        "mitre": _MITRE,
        "samples": samples[:5],
        "dedupeKey": f"AWS-IAM-0041:{config.demo.account_id}:{principal_arn}",
        "siemUrl": f"https://siem.demo.invalid/notable/ALERT-{date}-{slug}",
    }

    soar_case = {
        "schemaVersion": 1,
        "caseId": soar_result.case_id,
        "alertId": alert["alertId"],
        "runId": seed_result.run_id,
        "playbook": {
            "name": "aws-compromised-access-key-containment",
            "version": "2.4.1",
            "trigger": "AWS-IAM-0041",
        },
        "startedAt": soar_result.steps[0].started_at if soar_result.steps else detected_at,
        "completedAt": soar_result.steps[-1].completed_at if soar_result.steps else detected_at,
        "assignedAnalyst": {"name": "Unassigned", "email": "soc-tier1@acme.invalid",
                            "queue": "cloud-tier1"},
        "steps": [
            {
                "stepId": step.step_id,
                "action": step.action,
                "target": step.target,
                "startedAt": step.started_at,
                "completedAt": step.completed_at,
                "status": step.status,
                "rawResponse": step.raw_response,
            }
            for step in soar_result.steps
        ],
        "disposition": soar_result.disposition,
        "notes": ("Quarantine policy attached and the alerting access key deactivated. "
                  "Identity can no longer authenticate. Routed to cloud-tier1 for close-out."),
    }

    iocs = _build_iocs(config, seed_result, events, source, alert["alertId"])
    answer_key = _build_answer_key(config, seed_result, events)

    _validate(alert, soar_case, iocs)
    return Bundle(alert=alert, soar_case=soar_case, iocs=iocs, answer_key=answer_key)


def _ioc(value, first, last, event_ids, confidence, disposition, note=""):
    entry = {"value": value, "firstSeen": first, "lastSeen": last,
             "observedIn": event_ids[:10], "confidence": confidence, "disposition": disposition}
    if note:
        entry["note"] = note
    return entry


def _build_iocs(config, seed_result, events, source, alert_id):
    ids = [e.get("eventID", "") for e in events if e.get("eventID")]
    times = [e["eventTime"] for e in events]
    first, last = (times[0], times[-1]) if times else ("", "")

    # Deliberately omits the minted key. The seeded bundle carries what the
    # detection surfaced; enumerating the blast radius of a CreateAccessKey is an
    # investigation step, and the orphaned key is what the harness adds.
    return {
        "schemaVersion": 1,
        "runId": seed_result.run_id,
        "alertId": alert_id,
        "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "indicators": {
            "ipv4": [_ioc(source["ip"], first, last, ids, "high", "block",
                          "Single source address for the whole sequence.")] if source["ip"] else [],
            "userAgent": [_ioc(source["userAgent"], first, last, ids, "low", "investigate",
                               "Trivially forgeable; a lead, not evidence.")] if source["userAgent"] else [],
            "accessKeyId": [_ioc(seed_result.access_key_id, first, last, ids, "high", "block",
                                 "The credential named in the alert.")],
            "principalArn": [_ioc(f"arn:aws:iam::{config.demo.account_id}:user/{config.demo.compromised_user}",
                                  first, last, ids, "high", "investigate")],
        },
    }


def _build_answer_key(config, seed_result, events):
    regions = sorted({e["awsRegion"] for e in events if e["eventName"] == "DescribeInstances"})
    return f"""# Answer key -- run {seed_result.run_id}

NOT shipped to the harness. This is what the analyst should find, so the demo can
be rehearsed and any regression caught before it reaches a prospect.

## The finding that matters

The SOAR contained `{config.demo.compromised_user}` and missed the persistence.

- Orphaned access key: **{seed_result.orphaned_key_id}**
- On identity: **{config.demo.persistence_user}**
- Status: Active (the automation never touched it)

`containment-verification` must surface this without being told where to look.

## The rest of what a good investigation returns

- Source address: {seed_result.source_ip}
- Anomalous regions (DescribeInstances, org does not operate here): {", ".join(regions)}
- Objects read from {config.demo.exports_bucket}:
{chr(10).join(f"    - {k}" for k in seed_result.object_keys)}

## What the SOAR did do (the half that worked)

- Attached a deny-all quarantine policy to {config.demo.compromised_user}
- Disabled the compromised key {seed_result.access_key_id}
"""


def _validate(alert, soar_case, iocs):
    root = _repo_root()
    for doc, schema_name in ((alert, "alert"), (soar_case, "soar-case"), (iocs, "iocs")):
        schema = json.loads((root / "contracts" / f"{schema_name}.schema.json").read_text())
        errors = sorted(Draft202012Validator(schema).iter_errors(doc), key=lambda e: list(e.path))
        if errors:
            location = "/".join(str(p) for p in errors[0].absolute_path) or "(root)"
            raise ValueError(f"{schema_name} bundle is invalid at {location}: {errors[0].message}")


def _repo_root() -> Path:
    from .config import repo_root
    return repo_root()


def write(bundle: Bundle, run_id: str) -> tuple[Path, Path]:
    """Bundles to artifacts/<run-id>/ (cloned into the harness), answer key to
    out/<run-id>/ (never committed). The split is the whole confidentiality
    boundary of the puzzle."""
    root = _repo_root()
    artifacts_dir = root / "artifacts" / run_id
    out_dir = root / "out" / run_id
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    (artifacts_dir / "alert.json").write_text(json.dumps(bundle.alert, indent=2) + "\n")
    (artifacts_dir / "soar-case.json").write_text(json.dumps(bundle.soar_case, indent=2) + "\n")
    (artifacts_dir / "iocs.json").write_text(json.dumps(bundle.iocs, indent=2) + "\n")
    (out_dir / "answer-key.md").write_text(bundle.answer_key)
    return artifacts_dir, out_dir
