"""Powering the estate up for a demo and down again afterwards.

Deliberately separate from `teardown`. Teardown reverses a *seed run* -- it
revokes keys, detaches the quarantine policy, and asserts the account matches
baseline. This only changes what is switched on. Conflating them would put the
cheap daily operation on the same code path as the one that deletes IAM state,
which is the wrong thing to do by accident at 8am before a demo.

The estate idles at roughly $8-10/month. The two levers that matter:

  the EIP        $3.65/month, charged for every public IPv4 since Feb 2024 --
                 including one attached to a stopped instance
  the instances  $9/month if left running, and Terraform creates them running

GuardDuty is deliberately *not* a lever. It is $1-3/month and the only idle cost
that buys something: the Discovery: and UnauthorizedAccess:IAMUser/ families need
behavioural baselining, so a detector switched on for the demo produces nothing.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from botocore.exceptions import ClientError

from . import sessions
from .config import Config

# Rough us-west-2 / ap-southeast-1 list prices. Good enough to answer "is this
# costing us anything right now" without pulling Cost Explorer, which lags a day
# and cannot see a change made a minute ago.
_HOURS = 730
_PRICE = {
    "t4g.nano": 0.0042,
    "gp3_gb": 0.08 / _HOURS,
    "eip": 0.005,
}


@dataclass
class InstanceState:
    instance_id: str
    name: str
    state: str
    instance_type: str
    account: str
    region: str


@dataclass
class EstateStatus:
    instances: list[InstanceState]
    ebs_gb: int
    eip_count: int

    @property
    def running(self) -> list[InstanceState]:
        return [i for i in self.instances if i.state in ("running", "pending")]

    def hourly_cost(self) -> float:
        compute = sum(_PRICE.get(i.instance_type, 0.0) for i in self.running)
        return compute + self.ebs_gb * _PRICE["gp3_gb"] + self.eip_count * _PRICE["eip"]

    def monthly_cost(self) -> float:
        return self.hourly_cost() * _HOURS


def _describe(session, account: str, region: str) -> tuple[list[InstanceState], int, int]:
    ec2 = session.client("ec2")
    instances = []
    for reservation in ec2.describe_instances()["Reservations"]:
        for instance in reservation["Instances"]:
            if instance["State"]["Name"] == "terminated":
                continue
            name = next((t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"), "-")
            instances.append(InstanceState(
                instance_id=instance["InstanceId"],
                name=name,
                state=instance["State"]["Name"],
                instance_type=instance["InstanceType"],
                account=account,
                region=region,
            ))
    ebs = sum(v["Size"] for v in ec2.describe_volumes()["Volumes"])
    eips = len(ec2.describe_addresses()["Addresses"])
    return instances, ebs, eips


def status(config: Config) -> EstateStatus:
    instances: list[InstanceState] = []
    ebs = 0
    eips = 0
    for account, region in ((config.demo.account_id, config.demo.region),
                            (config.egress.account_id, config.egress.region)):
        session = sessions.admin(config, account)
        found, gb, ip_count = _describe(session, account, region)
        instances.extend(found)
        ebs += gb
        eips += ip_count
    return EstateStatus(instances=instances, ebs_gb=ebs, eip_count=eips)


def _wait_for_ssm(session, instance_id: str, timeout: int, report) -> bool:
    """Polls until Run Command can reach the host.

    A cold t4g.nano takes 60-120s from StartInstances to SSM Online, occasionally
    longer. Worth waiting for explicitly rather than letting the first SendCommand
    fail with InvalidInstanceId, which reads like a configuration error rather
    than a timing one.
    """
    ssm = session.client("ssm")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            info = ssm.describe_instance_information(
                Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
            )["InstanceInformationList"]
            if info and info[0]["PingStatus"] == "Online":
                return True
        except ClientError:
            pass
        report("  waiting for SSM to register the host...")
        time.sleep(10)
    return False


def up(config: Config, report, ssm_timeout: int = 240) -> bool:
    """Makes the egress host reachable. The same path `seed` uses to prepare it."""
    session = sessions.egress(config)
    ec2 = session.client("ec2")
    instance_id = config.egress.instance_id

    state = ec2.describe_instances(InstanceIds=[instance_id])[
        "Reservations"][0]["Instances"][0]["State"]["Name"]

    if state in ("stopping",):
        report("  host is still stopping; waiting before starting it")
        ec2.get_waiter("instance_stopped").wait(InstanceIds=[instance_id])
        state = "stopped"

    if state == "stopped":
        report(f"  starting {instance_id}")
        ec2.start_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id])
    elif state == "running":
        report(f"  {instance_id} already running")
    else:
        report(f"  {instance_id} is {state}; cannot start from here")
        return False

    # An EIP may have been released by `down`. Reattach or allocate.
    addresses = ec2.describe_addresses()["Addresses"]
    attached = [a for a in addresses if a.get("InstanceId") == instance_id]
    if attached:
        report(f"  source address {attached[0]['PublicIp']}")
    else:
        spare = [a for a in addresses if not a.get("InstanceId")]
        allocation = spare[0] if spare else ec2.allocate_address(Domain="vpc")
        ec2.associate_address(AllocationId=allocation["AllocationId"], InstanceId=instance_id)
        report(f"  source address {allocation['PublicIp']} (attached)")

    if not _wait_for_ssm(session, instance_id, ssm_timeout, report):
        report(f"  SSM did not register {instance_id} within {ssm_timeout}s")
        return False

    report("  host is reachable")
    return True


def down(config: Config, report, release_eip: bool = True) -> None:
    """Back to minimum cost. Stops every instance, and optionally releases the EIP."""
    for account, label in ((config.demo.account_id, "demo"),
                           (config.egress.account_id, "egress")):
        session = sessions.admin(config, account)
        ec2 = session.client("ec2")

        running = [
            instance["InstanceId"]
            for reservation in ec2.describe_instances(
                Filters=[{"Name": "instance-state-name", "Values": ["running", "pending"]}]
            )["Reservations"]
            for instance in reservation["Instances"]
        ]
        if running:
            report(f"  {label}: stopping {len(running)} instance(s)")
            ec2.stop_instances(InstanceIds=running)
        else:
            report(f"  {label}: nothing running")

        # Only the egress account has an EIP, and only it needs one. The demo
        # account's instances are inventory -- they exist to appear in
        # DescribeInstances, which a stopped instance does identically.
        if release_eip and account == config.egress.account_id:
            for address in ec2.describe_addresses()["Addresses"]:
                if address.get("InstanceId"):
                    ec2.disassociate_address(AssociationId=address["AssociationId"])
                ec2.release_address(AllocationId=address["AllocationId"])
                report(f"  {label}: released {address['PublicIp']}")
