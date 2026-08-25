"""Minting and revoking the decoy's access key.

The key is created here, at run time, and never by Terraform -- a key in
Terraform state is an S3 object that outlives every teardown. It exists for the
few minutes of a seed run and is deleted on teardown, which is also the only way
the demo can honestly claim afterwards that the leaked credential is gone.
"""

from __future__ import annotations

from dataclasses import dataclass

from botocore.exceptions import ClientError

from .config import Config


@dataclass
class MintedKey:
    access_key_id: str
    secret_access_key: str
    user_name: str


def mint(session, config: Config) -> MintedKey:
    """A fresh key for the compromised identity.

    Raises if the identity already has a key: two live keys on one decoy means a
    previous run did not tear down, and minting a third quietly compounds the mess
    rather than surfacing it.
    """
    iam = session.client("iam")
    user = config.demo.compromised_user

    existing = iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
    if existing:
        raise RuntimeError(
            f"{user} already has {len(existing)} access key(s). A previous run did not "
            "tear down. Run `serverless-demo teardown` before seeding again.")

    created = iam.create_access_key(UserName=user)["AccessKey"]
    return MintedKey(
        access_key_id=created["AccessKeyId"],
        secret_access_key=created["SecretAccessKey"],
        user_name=user,
    )


def list_keys(session, user_name: str) -> list[dict]:
    return session.client("iam").list_access_keys(UserName=user_name)["AccessKeyMetadata"]


def delete_key(session, user_name: str, access_key_id: str) -> None:
    try:
        session.client("iam").delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
    except ClientError as error:
        if error.response["Error"]["Code"] != "NoSuchEntity":
            raise
