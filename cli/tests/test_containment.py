"""The acceptance guarantee, as unit tests.

The live acceptance test -- run the seed, find the orphan cold -- is the real
proof and cannot be a unit test. These lock in the two properties that make it
work, so a refactor cannot quietly break them:

  1. The finding is DERIVED, never hardcoded. No code path may reference the
     persistence identity by name; it must come out of the CloudTrail evidence.
  2. The derivation is set difference: a key the compromised credential created,
     that the SOAR case never named, still Active. Change any one of those and it
     is not an orphan.
"""

import ast
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from serverless_demo import containment, config as config_mod

CONTAINMENT = Path(containment.__file__)


def test_the_finding_is_never_hardcoded():
    """No executable line may name the persistence identity. It is discovered from
    the trail, not looked up. Docstrings are allowed to explain the principle."""
    tree = ast.parse(CONTAINMENT.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            # A docstring is the first statement of a module/function/class; those
            # are allowed to say svc-report-runner. Other string constants are not.
            continue
        if isinstance(node, ast.Name) and "report_runner" in node.id:
            pytest.fail("containment.py references the persistence identity in code; "
                        "the orphan must be derived from evidence, not named.")
    # Also assert no non-docstring source line mentions it.
    for line in CONTAINMENT.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith(("#", '"', "'", "*")) or "where to look" in line or "falls out" in line:
            continue
        assert "report-runner" not in stripped and "report_runner" not in stripped, (
            f"containment.py names the persistence identity in code: {stripped}")


class _FakeIam:
    def __init__(self, orphan_status="Active"):
        self._orphan_status = orphan_status

    def list_user_policies(self, UserName):
        if UserName == "svc-billing-export":
            return {"PolicyNames": ["soar-quarantine-deny-all"]}
        return {"PolicyNames": ["report-runner"]}

    def list_attached_user_policies(self, UserName):
        return {"AttachedPolicies": []}

    def list_access_keys(self, UserName):
        if UserName == "svc-billing-export":
            return {"AccessKeyMetadata": [{"AccessKeyId": "AKIACOMPROMISED00000", "Status": "Inactive"}]}
        if UserName == "svc-report-runner":
            return {"AccessKeyMetadata": [{"AccessKeyId": "AKIAORPHAN0000000000", "Status": self._orphan_status}]}
        return {"AccessKeyMetadata": []}


class _FakeCloudTrail:
    def __init__(self, events):
        self._events = events

    def get_paginator(self, _):
        return self

    def paginate(self, **_):
        return [{"Events": [{"CloudTrailEvent": json.dumps(e), "EventId": e["eventID"]}
                            for e in self._events]}]


class _FakeSession:
    def __init__(self, events, orphan_status="Active"):
        self._events = events
        self._iam = _FakeIam(orphan_status)

    def client(self, service, region_name=None):
        return self._iam if service == "iam" else _FakeCloudTrail(self._events)


def _create_event(target="svc-report-runner", new_key="AKIAORPHAN0000000000"):
    return {
        "eventName": "CreateAccessKey", "eventID": "evt-create",
        "eventTime": "2026-08-25T02:05:00Z", "awsRegion": "us-east-1",
        "requestParameters": {"userName": target},
        "responseElements": {"accessKey": {"userName": target, "accessKeyId": new_key}},
    }


def _alert():
    return {"entity": {"principalArn": "arn:aws:iam::431662316594:user/svc-billing-export",
                       "accessKeyId": "AKIACOMPROMISED00000"}}


def _soar_case_missing_orphan():
    # The SOAR named only the compromised identity and its key.
    return {"steps": [
        {"target": "svc-billing-export"},
        {"target": "AKIACOMPROMISED00000"},
    ]}


@pytest.fixture
def config():
    return config_mod.load()


def test_the_orphan_is_found(config):
    session = _FakeSession([_create_event()])
    result = containment.verify(session, config, _alert(), _soar_case_missing_orphan(),
                                datetime(2026, 8, 25, tzinfo=timezone.utc))
    assert len(result.orphans) == 1
    orphan = result.orphans[0]
    assert orphan.identity == "svc-report-runner"
    assert orphan.access_key_id == "AKIAORPHAN0000000000"
    assert orphan.status == "Active"
    assert result.quarantine_confirmed and result.original_key_disabled


def test_a_key_the_soar_named_is_not_an_orphan(config):
    """If the SOAR had disabled the minted key, it would appear in the case and
    would not be uncontained. This is the negative that proves it is set difference,
    not just 'any CreateAccessKey'."""
    soar_case = {"steps": [
        {"target": "svc-billing-export"},
        {"target": "AKIACOMPROMISED00000"},
        {"target": "AKIAORPHAN0000000000"},  # the SOAR did name it
    ]}
    session = _FakeSession([_create_event()])
    result = containment.verify(session, config, _alert(), soar_case,
                                datetime(2026, 8, 25, tzinfo=timezone.utc))
    assert result.orphans == []


def test_an_inactive_minted_key_is_not_an_orphan(config):
    """Status is part of the definition: a key that was created and then disabled
    is contained, even if the SOAR case does not mention it."""
    session = _FakeSession([_create_event()], orphan_status="Inactive")
    result = containment.verify(session, config, _alert(), _soar_case_missing_orphan(),
                                datetime(2026, 8, 25, tzinfo=timezone.utc))
    assert result.orphans == []


def test_a_denied_create_access_key_yields_no_orphan(config):
    """A denied CreateAccessKey has no responseElements -- it created nothing, so
    there is nothing uncontained. This is why seed checks the key exists."""
    denied = {"eventName": "CreateAccessKey", "eventID": "evt-denied",
              "eventTime": "2026-08-25T02:05:00Z", "awsRegion": "us-east-1",
              "errorCode": "AccessDenied",
              "requestParameters": {"userName": "svc-report-runner"}}
    session = _FakeSession([denied])
    result = containment.verify(session, config, _alert(), _soar_case_missing_orphan(),
                                datetime(2026, 8, 25, tzinfo=timezone.utc))
    assert result.findings == []
