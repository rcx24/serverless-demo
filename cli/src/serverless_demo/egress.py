"""Driving the attacker host: stage the leaked key, run the attack, collect it.

The leaked key goes into Secrets Manager in the egress account and the host reads
it with its instance role. It is never a SendCommand parameter -- those are
recorded in the caller's CloudTrail, and putting the leaked credential there would
write it into the telemetry the demo is about, as well as spoiling the puzzle.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from importlib import resources

from botocore.exceptions import ClientError

from .config import Config
from .keys import MintedKey


@dataclass
class AttackResult:
    ok: bool
    calls_ok: int
    calls_failed: int
    raw_stdout: str
    reason: str = ""


def _secret_id(config: Config, run_id: str) -> str:
    return f"{config.egress.secret_path_prefix}/{run_id}"


def stage_key(egress_session, config: Config, run_id: str, key: MintedKey) -> str:
    """Puts the leaked key where the host can fetch it, scoped to this run."""
    secrets = egress_session.client("secretsmanager")
    secret_id = _secret_id(config, run_id)
    body = json.dumps({
        "AccessKeyId": key.access_key_id,
        "SecretAccessKey": key.secret_access_key,
    })

    try:
        secrets.create_secret(Name=secret_id, SecretString=body)
    except ClientError as error:
        if error.response["Error"]["Code"] == "ResourceExistsException":
            secrets.put_secret_value(SecretId=secret_id, SecretString=body)
        else:
            raise
    return secret_id


def unstage_key(egress_session, config: Config, run_id: str) -> None:
    """Removes the staged key. Called whether the run succeeded or not -- the
    credential should not outlive the attack that used it."""
    try:
        egress_session.client("secretsmanager").delete_secret(
            SecretId=_secret_id(config, run_id),
            ForceDeleteWithoutRecovery=True)
    except ClientError as error:
        if error.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _render_script(config: Config, secret_id: str, object_keys: list[str]) -> str:
    template = resources.files("serverless_demo.attack").joinpath("run-attack.sh").read_text()
    replacements = {
        "__SECRET_ID__": secret_id,
        "__REGION_HOME__": config.demo.region,
        "__REGION_SECRET__": config.egress.region,
        "__DISCOVERY_REGIONS__": " ".join(config.attack.discovery_regions),
        "__EXPORTS_BUCKET__": config.demo.exports_bucket,
        "__PERSISTENCE_USER__": config.demo.persistence_user,
        "__OBJECT_KEYS__": " ".join(object_keys),
    }
    for marker, value in replacements.items():
        template = template.replace(marker, value)
    return template


def run_attack(egress_session, config: Config, secret_id: str, object_keys: list[str],
               report, timeout: int = 600) -> AttackResult:
    """Sends the rendered script to the host and waits for it to finish.

    The jittered sequence takes a few minutes, so the wait is generous. A missing
    ---SUMMARY--- sentinel means the script died partway, which is a failure rather
    than a partial success -- a seed that produced half a timeline is worse than
    one that produced none.
    """
    ssm = egress_session.client("ssm")
    script = _render_script(config, secret_id, object_keys)

    command = ssm.send_command(
        InstanceIds=[config.egress.instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script]},
        TimeoutSeconds=timeout,
    )["Command"]["CommandId"]

    report(f"  attack running on {config.egress.instance_id} (command {command[:8]})")

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(10)
        try:
            invocation = ssm.get_command_invocation(
                CommandId=command, InstanceId=config.egress.instance_id)
        except ClientError as error:
            if error.response["Error"]["Code"] == "InvocationDoesNotExist":
                continue
            raise

        status = invocation["Status"]
        if status in ("Pending", "InProgress", "Delayed"):
            continue

        stdout = invocation.get("StandardOutputContent", "")
        stderr = invocation.get("StandardErrorContent", "")

        if "---SUMMARY---" not in stdout:
            return AttackResult(ok=False, calls_ok=0, calls_failed=0, raw_stdout=stdout,
                                reason=f"script ended ({status}) with no summary. stderr: {stderr[:300]}")

        summary = json.loads(stdout.split("---SUMMARY---", 1)[1].strip().splitlines()[-1])
        return AttackResult(
            ok=summary.get("ok", False),
            calls_ok=summary.get("calls_ok", 0),
            calls_failed=summary.get("calls_failed", 0),
            raw_stdout=stdout,
            reason=summary.get("reason", ""),
        )

    return AttackResult(ok=False, calls_ok=0, calls_failed=0, raw_stdout="",
                        reason=f"attack did not finish within {timeout}s")
