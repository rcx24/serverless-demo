"""Cost arithmetic, and the posture the estate should idle at.

No AWS here -- these are about the numbers the `status` command reports, which is
what somebody reads before deciding whether to leave the estate up over a weekend.
"""

from serverless_demo.lifecycle import EstateStatus, InstanceState


def instance(state, name="x", kind="t4g.nano"):
    return InstanceState(instance_id="i-0", name=name, state=state,
                         instance_type=kind, account="1", region="us-west-2")


def test_a_stopped_estate_costs_only_its_disks():
    """Stopped instances are inventory: they appear in DescribeInstances and bill
    nothing but their volumes. That is the whole reason they are stopped."""
    estate = EstateStatus(instances=[instance("stopped") for _ in range(4)],
                          ebs_gb=32, eip_count=0)
    assert estate.running == []
    assert 2.0 < estate.monthly_cost() < 3.0


def test_an_elastic_ip_is_charged_even_with_everything_stopped():
    """The trap that made `down` release it. Since Feb 2024 AWS charges for every
    public IPv4 address, including one attached to a stopped instance -- so an
    estate that looks entirely switched off still bills $3.65/month."""
    without = EstateStatus(instances=[instance("stopped")], ebs_gb=8, eip_count=0)
    with_eip = EstateStatus(instances=[instance("stopped")], ebs_gb=8, eip_count=1)
    assert with_eip.monthly_cost() - without.monthly_cost() > 3.0


def test_running_instances_dominate_the_bill():
    """Terraform creates instances running, and three t4g.nano left running is
    more than the entire rest of the idle estate combined."""
    stopped = EstateStatus(instances=[instance("stopped") for _ in range(3)],
                           ebs_gb=24, eip_count=0)
    running = EstateStatus(instances=[instance("running") for _ in range(3)],
                           ebs_gb=24, eip_count=0)
    assert running.monthly_cost() > stopped.monthly_cost() * 3


def test_pending_counts_as_running():
    """An instance mid-start bills, and `status` run straight after `up` would
    otherwise report a cost the account is already incurring."""
    estate = EstateStatus(instances=[instance("pending")], ebs_gb=8, eip_count=0)
    assert len(estate.running) == 1
