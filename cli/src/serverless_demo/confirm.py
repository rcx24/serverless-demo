"""Confirming the attack's events reached CloudTrail before proceeding.

The rule is: never sleep-and-hope. The seed does not assume the events landed
after a fixed delay -- it polls until every expected event is present, or fails
loudly listing exactly which are still missing. A demo whose timeline has holes is
worse than one that never started, because the hole is discovered on stage.

The confirmation has to be region-aware, and getting this wrong is a subtle trap
that cost a full rehearsal to find. CloudTrail Event History -- what LookupEvents
reads -- is *per region*, and the attack's events are spread across several:

  IAM (global)        us-east-1. ListUsers, ListRoles,
                      GetAccountAuthorizationDetails, CreateAccessKey all log here
                      no matter where the caller is.
  DescribeInstances   each discovery region, since that is where the call was made.
  STS and S3          the home region.
  GetObject           nowhere in Event History -- it is a data event. Only the
                      CloudWatch log group the trail delivers to has it.

Querying only the home region -- the obvious first implementation -- finds the S3
and STS calls and silently misses every IAM event and every cross-region
DescribeInstances, then times out waiting for events that were never going to
appear where it was looking.

CloudTrail Event History lags 5-15 minutes. That lag is real and not hidden: seed
20-30 minutes before a demo, confirm here, and only then is the timeline whole.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from botocore.exceptions import ClientError

from .config import Config

# IAM is a global service; its events are recorded only in us-east-1, regardless
# of the caller's region.
IAM_REGION = "us-east-1"


@dataclass(frozen=True)
class Expectation:
    event_name: str
    # Which regions' Event History to search. Empty for data events, which are not
    # in Event History at all and come from the log group instead.
    regions: tuple[str, ...] = ()
    min_count: int = 1
    source: str = "management"
    describe: str = ""


@dataclass
class Confirmation:
    expectation: Expectation
    found: int
    event_ids: list[str] = field(default_factory=list)

    @property
    def satisfied(self) -> bool:
        return self.found >= self.expectation.min_count


def expectations(config: Config) -> list[Expectation]:
    home = (config.demo.region,)
    discovery = tuple(config.attack.discovery_regions)
    return [
        Expectation("GetCallerIdentity", regions=home),
        Expectation("GetAccountAuthorizationDetails", regions=(IAM_REGION,)),
        Expectation("ListUsers", regions=(IAM_REGION,)),
        Expectation("ListRoles", regions=(IAM_REGION,)),
        # One event per discovery region, each recorded in its own region.
        Expectation("DescribeInstances", regions=discovery, min_count=len(discovery),
                    describe="across the unused discovery regions"),
        Expectation("ListBuckets", regions=home),
        # ListObjectsV2 is an S3 object-level operation, not a management event --
        # it is nowhere in Event History and only in the log group, same as
        # GetObject. This is not obvious: ListBuckets IS a management event and
        # sits one line up, so the two look like they should live in the same
        # place and do not.
        Expectation("ListObjects", source="data"),
        # A data event: nowhere in Event History, only in the log group.
        Expectation("GetObject", source="data", min_count=2,
                    describe="object reads (data events, only in the log group)"),
        Expectation("CreateAccessKey", regions=(IAM_REGION,),
                    describe=f"on {config.demo.persistence_user}"),
    ]


def _lookup(seed_session, region: str, event_name: str, access_key_id: str,
            start_time) -> list[str]:
    """Event ids for one event name made by the key, in one region, since start.

    Filtered on AccessKeyId so a concurrent run against a different key cannot
    satisfy this one's confirmation.
    """
    client = seed_session.client("cloudtrail", region_name=region)
    ids = []
    for page in client.get_paginator("lookup_events").paginate(
        LookupAttributes=[{"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id}],
        StartTime=start_time,
    ):
        for event in page["Events"]:
            if event["EventName"] == event_name:
                ids.append(event["EventId"])
    return ids


def _query_s3_events(admin_session, config: Config, event_name: str, start_time) -> list[str]:
    """One S3 object-level event's ids from the log group, via Logs Insights.

    GetObject and ListObjects are object-level operations that never reach Event
    History; the log group is the only queryable copy. Filtered on the bucket so a
    read of some other bucket cannot satisfy this. The query returns event ids;
    what matters for confirmation is the count.
    """
    logs = admin_session.client("logs")
    query = logs.start_query(
        logGroupName=config.demo.log_group_name,
        startTime=int(start_time.timestamp()),
        endTime=int(time.time()) + 300,
        queryString=(
            "fields eventID, eventName, requestParameters.bucketName as bucket "
            f"| filter eventName = '{event_name}' "
            f"| filter bucket = '{config.demo.exports_bucket}' "
            "| sort @timestamp desc | limit 100"
        ),
    )["queryId"]

    for _ in range(30):
        result = logs.get_query_results(queryId=query)
        if result["status"] == "Complete":
            ids = []
            for row in result["results"]:
                for cell in row:
                    if cell["field"] == "eventID":
                        ids.append(cell["value"])
            return ids
        if result["status"] in ("Failed", "Cancelled", "Timeout"):
            return []
        time.sleep(2)
    return []


def check_once(seed_session, admin_session, config: Config, access_key_id: str,
               start_time) -> list[Confirmation]:
    data_cache: dict[str, list[str]] = {}  # log-group queries, one per event name
    confirmations = []

    for expectation in expectations(config):
        if expectation.source == "data":
            found_ids = data_cache.get(expectation.event_name)
            if found_ids is None:
                found_ids = _query_s3_events(admin_session, config, expectation.event_name, start_time)
                data_cache[expectation.event_name] = found_ids
        else:
            found_ids = []
            for region in expectation.regions:
                found_ids.extend(
                    _lookup(seed_session, region, expectation.event_name,
                            access_key_id, start_time))
        confirmations.append(Confirmation(expectation, len(found_ids), found_ids))

    return confirmations


def wait(seed_session, admin_session, config: Config, access_key_id: str, start_time,
         report, timeout: int = 1200, on_progress=None) -> tuple[bool, list[Confirmation]]:
    """Polls until every expectation is satisfied or the timeout is hit.

    Returns (all_satisfied, confirmations) so the caller can report exactly which
    events are still missing rather than a bare timeout.
    """
    delays = [30, 30, 60, 60, 120]
    deadline = time.monotonic() + timeout
    attempt = 0
    confirmations: list[Confirmation] = []

    while time.monotonic() < deadline:
        confirmations = check_once(seed_session, admin_session, config, access_key_id, start_time)
        satisfied = [c for c in confirmations if c.satisfied]
        if on_progress:
            on_progress(confirmations)

        if len(satisfied) == len(confirmations):
            return True, confirmations

        missing = [c for c in confirmations if not c.satisfied]
        report(f"  {len(satisfied)}/{len(confirmations)} confirmed; "
               f"waiting on {', '.join(c.expectation.event_name for c in missing)}")

        delay = delays[min(attempt, len(delays) - 1)]
        attempt += 1
        if time.monotonic() + delay > deadline:
            break
        time.sleep(delay)

    return False, confirmations
