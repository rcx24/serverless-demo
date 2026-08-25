"""Every AWS session this tool uses, and the guard on each one.

The only module that may `import boto3`. `tests/test_no_stray_boto3.py` fails the
build if any other one does, which is the Python analogue of `allowed_account_ids`
on a Terraform provider: there is exactly one place where a credential turns into
a client, so there is exactly one place the account check can be forgotten.

That matters more here than it looks. This tool mints IAM access keys, attaches
deny-all policies, and deletes credentials. Pointed at the wrong account it is
indistinguishable from the intrusion it simulates -- so every session verifies
which account it landed in *before* the caller gets it, and raises rather than
returning a client that works on the wrong estate.
"""

from __future__ import annotations

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError, NoCredentialsError

from .config import Config

# Retries on the throttling that IAM and CloudTrail both apply under the burst a
# seed run produces. Standard mode retries throttles and timeouts; the default of
# `legacy` does noticeably less.
_BOTO = BotoConfig(retries={"max_attempts": 8, "mode": "standard"})


class AccountMismatch(Exception):
    """A session landed in an account nobody asked for. Always fatal."""


class SessionError(Exception):
    """A role could not be assumed, or there was no credential to start from."""


def _verify(session: boto3.Session, expected_account: str, description: str) -> boto3.Session:
    """Refuses to hand back a session that is not where the caller thinks it is."""
    try:
        identity = session.client("sts", config=_BOTO).get_caller_identity()
    except NoCredentialsError as error:
        raise SessionError(
            f"No AWS credentials available for {description}. "
            "Is AWS_PROFILE set, and is the session still valid?"
        ) from error
    except ClientError as error:
        raise SessionError(f"Could not verify identity for {description}: {error}") from error

    actual = identity["Account"]
    if actual != expected_account:
        raise AccountMismatch(
            f"Refusing to continue: {description} landed in account {actual}, "
            f"expected {expected_account}.\n"
            f"Caller: {identity['Arn']}\n"
            "This tool mints access keys and attaches deny-all policies. Pointed at "
            "the wrong account it is indistinguishable from the intrusion it simulates."
        )
    return session


def management(config: Config) -> boto3.Session:
    """The operator's own credential. Everything else is assumed from here."""
    session = boto3.Session(region_name=config.demo.region)
    return _verify(session, config.management.account_id, "the management session")


def _assume(config: Config, role_arn: str, expected_account: str, region: str,
            description: str, external_id: str | None = None) -> boto3.Session:
    base = management(config)
    kwargs = {
        "RoleArn": role_arn,
        "RoleSessionName": "serverless-demo-cli",
        # An hour. Long enough for a seed run including the CloudTrail wait, short
        # enough that a session left open on a laptop expires by itself.
        "DurationSeconds": 3600,
    }
    if external_id:
        kwargs["ExternalId"] = external_id

    try:
        credentials = base.client("sts", config=_BOTO).assume_role(**kwargs)["Credentials"]
    except ClientError as error:
        raise SessionError(
            f"Could not assume {role_arn} for {description}: "
            f"{error.response['Error']['Message']}"
        ) from error

    session = boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region,
    )
    return _verify(session, expected_account, description)


def seed_admin(config: Config) -> boto3.Session:
    """Mints and revokes the decoy's access key, and reads the trail."""
    return _assume(config, config.demo.seed_admin_role_arn, config.demo.account_id,
                   config.demo.region, "the seed session")


def soar(config: Config) -> boto3.Session:
    """Runs the simulated containment.

    A distinct role from `seed_admin` on purpose. Both act on the same account and
    both appear in the CloudTrail the analyst reads -- and an account where the
    operator and the automation share one principal is one where the timeline
    cannot be told apart.
    """
    return _assume(config, config.demo.soar_role_arn, config.demo.account_id,
                   config.demo.region, "the SOAR session")


def egress(config: Config) -> boto3.Session:
    """Drives the attacker host: start, stop, Run Command, stage the leaked key."""
    return _assume(config, config.egress.operator_role_arn, config.egress.account_id,
                   config.egress.region, "the egress session")


def investigator(config: Config, external_id: str) -> boto3.Session:
    """What the harness gets. Assumed here only so `verify` can prove it works.

    Deliberately unused by any command that changes anything -- this role cannot
    read an object or touch a credential, and the point of assuming it here is to
    demonstrate that before a demo rather than during one.
    """
    return _assume(config, config.demo.investigator_role_arn, config.demo.account_id,
                   config.demo.region, "the investigator session", external_id=external_id)


def admin(config: Config, account: str) -> boto3.Session:
    """OrganizationAccountAccessRole, for the few things the scoped roles cannot do.

    Used by `up`/`down` to start and stop instances in the demo account, which the
    seed role has no business being able to do -- it mints credentials, and adding
    EC2 control to it would widen the one role that already holds the sharpest
    permissions here.
    """
    if account == config.demo.account_id:
        region = config.demo.region
    elif account == config.egress.account_id:
        region = config.egress.region
    else:
        raise SessionError(f"{account} is not an account this tool manages.")

    return _assume(config, f"arn:aws:iam::{account}:role/OrganizationAccountAccessRole",
                   account, region, f"the admin session for {account}")
