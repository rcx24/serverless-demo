"""demo.toml loading, and the strictness that catches a stale config early."""

import textwrap
from pathlib import Path

import pytest

from serverless_demo import config


def write(tmp_path, body):
    path = tmp_path / "demo.toml"
    path.write_text(textwrap.dedent(body))
    return path


VALID = """
    [demo]
    account_id = "431662316594"
    region = "us-west-2"
    exports_bucket = "acme-finance-exports-431662316594"
    compromised_user = "svc-billing-export"
    persistence_user = "svc-report-runner"
    log_group_name = "/aws/cloudtrail/serverless-demo"
    seed_admin_role_arn = "arn:aws:iam::431662316594:role/serverless-demo-seedadmin"
    soar_role_arn = "arn:aws:iam::431662316594:role/serverless-demo-soar"
    investigator_role_arn = "arn:aws:iam::431662316594:role/serverless-demo-readonly"
    investigator_external_id = "abcdefghijklmnopqrstuvwxyz012345"
    warehouse_secret_arn = "arn:aws:secretsmanager:us-west-2:431662316594:secret:x"
    [egress]
    account_id = "633800810188"
    region = "ap-southeast-1"
    instance_id = "i-0987f1a23f324d7c8"
    operator_role_arn = "arn:aws:iam::633800810188:role/serverless-demo-egress-operator"
    secret_path_prefix = "serverless-demo/leaked-key"
    [management]
    account_id = "429418377902"
    [attack]
    discovery_regions = ["sa-east-1"]
"""


def test_a_complete_config_loads(tmp_path):
    loaded = config.load(write(tmp_path, VALID))
    assert loaded.demo.account_id == "431662316594"
    assert loaded.egress.instance_id == "i-0987f1a23f324d7c8"
    assert loaded.attack.discovery_regions == ["sa-east-1"]


def test_an_unknown_key_is_rejected(tmp_path):
    """A typo must fail loudly here, not fall back to a default and misbehave later."""
    with pytest.raises(config.ConfigError, match="unknown"):
        config.load(write(tmp_path, VALID + '    [demo]\n    typo = "x"\n'))


def test_a_missing_key_is_rejected(tmp_path):
    """A config from an older schema is missing a field this version needs."""
    broken = VALID.replace('    region = "us-west-2"\n', "")
    with pytest.raises(config.ConfigError, match="missing"):
        config.load(write(tmp_path, broken))


def test_a_missing_section_is_named(tmp_path):
    broken = VALID.replace("[attack]", "[nattack]")
    with pytest.raises(config.ConfigError, match=r"\[attack\]"):
        config.load(write(tmp_path, broken))


def test_repo_root_is_found_from_a_subdirectory(tmp_path):
    (tmp_path / "demo.toml").write_text(VALID)
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert config.repo_root(nested) == tmp_path
