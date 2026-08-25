"""The bundles validate, and they preserve the deliberate omissions.

These build the bundles from a synthetic SeedResult and SoarResult -- no AWS -- and
check both that they satisfy the schemas and that they still carry the gaps the
demo depends on. The schema validation also runs inside artifacts.build itself, so
a bundle that does not validate is never written; this asserts that guard works.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from serverless_demo import artifacts, config as config_mod, soar


@pytest.fixture
def config():
    return config_mod.load()


@pytest.fixture
def seed_result():
    from serverless_demo.seed import SeedResult
    return SeedResult(
        run_id="unit-test-01", ok=True,
        started_at=datetime(2026, 8, 25, tzinfo=timezone.utc),
        access_key_id="AKIATEST00000000TEST",
        orphaned_key_id="AKIATEST11111111TEST",
        source_ip="46.137.235.57",
        object_keys=["exports/2026/07/cost-allocation-2026-07.csv"],
    )


@pytest.fixture
def soar_result():
    result = soar.SoarResult(case_id="CASE-20260825-abc123")
    result.steps = [
        soar.Step(1, "iam:GetUser", "svc-billing-export", "2026-08-25T02:00:00Z",
                  "2026-08-25T02:00:01Z", "succeeded", {"RequestId": "x"}),
        soar.Step(2, "iam:PutUserPolicy", "svc-billing-export", "2026-08-25T02:00:02Z",
                  "2026-08-25T02:00:03Z", "succeeded", {"RequestId": "y"}),
        soar.Step(4, "iam:UpdateAccessKey", "AKIATEST00000000TEST", "2026-08-25T02:00:04Z",
                  "2026-08-25T02:00:05Z", "succeeded", {"Status": "Inactive"}),
    ]
    return result


def _fake_events(access_key_id):
    """Stands in for CloudTrail. One event per name the alert samples."""
    base = {"sourceIPAddress": "46.137.235.57", "userAgent": "aws-cli/2.33",
            "eventSource": "iam.amazonaws.com", "awsRegion": "us-east-1"}
    names = ["GetCallerIdentity", "GetAccountAuthorizationDetails", "DescribeInstances",
             "GetObject", "CreateAccessKey"]
    regions = {"DescribeInstances": "sa-east-1"}
    return [
        {**base, "eventName": n, "eventID": f"id-{i}",
         "eventTime": f"2026-08-25T02:0{i}:00Z", "awsRegion": regions.get(n, "us-east-1")}
        for i, n in enumerate(names)
    ]


class _FakeSession:
    """Returns fixed events, so artifacts.build can be tested without AWS."""
    def __init__(self, events):
        self._events = events

    def client(self, service, region_name=None):
        return _FakeCloudTrail(self._events)


class _FakeCloudTrail:
    def __init__(self, events):
        self._events = events

    def get_paginator(self, _):
        return self

    def paginate(self, **_):
        return [{"Events": [{"CloudTrailEvent": json.dumps(e), "EventId": e["eventID"]}
                            for e in self._events]}]


def test_the_bundle_validates(config, seed_result, soar_result, monkeypatch):
    session = _FakeSession(_fake_events(seed_result.access_key_id))
    bundle = artifacts.build(config, seed_result, soar_result, session, seed_result.started_at)
    # build() validates internally; reaching here means all three passed.
    assert bundle.alert["entity"]["accessKeyId"] == seed_result.access_key_id
    assert bundle.soar_case["disposition"] == "contained"


def test_the_seeded_iocs_omit_the_orphaned_key(config, seed_result, soar_result):
    session = _FakeSession(_fake_events(seed_result.access_key_id))
    bundle = artifacts.build(config, seed_result, soar_result, session, seed_result.started_at)
    key_iocs = [i["value"] for i in bundle.iocs["indicators"]["accessKeyId"]]
    assert seed_result.access_key_id in key_iocs, "the alerting key must be an indicator"
    assert seed_result.orphaned_key_id not in key_iocs, (
        "the minted key must NOT be in the seeded IOC bundle -- adding it is the "
        "harness's job, and ioc-extraction has nothing to show if it arrives solved."
    )


def test_the_alert_does_not_name_the_persistence_identity(config, seed_result, soar_result):
    session = _FakeSession(_fake_events(seed_result.access_key_id))
    bundle = artifacts.build(config, seed_result, soar_result, session, seed_result.started_at)
    assert config.demo.persistence_user not in json.dumps(bundle.alert), (
        "the analyst reaches the persistence identity by following CreateAccessKey, "
        "not by reading it off the alert."
    )


def test_the_answer_key_names_the_orphaned_key(config, seed_result, soar_result):
    """The answer key is the opposite: it must name exactly what the analyst should
    find, so a rehearsal can check the finding."""
    session = _FakeSession(_fake_events(seed_result.access_key_id))
    bundle = artifacts.build(config, seed_result, soar_result, session, seed_result.started_at)
    assert seed_result.orphaned_key_id in bundle.answer_key
    assert config.demo.persistence_user in bundle.answer_key
