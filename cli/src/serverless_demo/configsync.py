"""Regenerates demo.toml from the Terraform roots' outputs.

Every command reads demo.toml, so a value edited there and not in Terraform is a
divergence that surfaces three commands later as a confusing failure. This is the
one writer, and `verify` points people at it whenever the file and the account
disagree.

Shells out to `terraform output` rather than reading state directly: state is an
implementation detail that has changed format between Terraform versions, and the
output command is the supported interface to exactly these values.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .config import Config, load


class SyncError(Exception):
    pass


def _outputs(repo_root: Path, root: str) -> dict:
    try:
        result = subprocess.run(
            ["terraform", f"-chdir={repo_root}/terraform/environments/{root}", "output", "-json"],
            capture_output=True, text=True, check=True)
    except FileNotFoundError as error:
        raise SyncError("terraform is not on PATH.") from error
    except subprocess.CalledProcessError as error:
        raise SyncError(
            f"Could not read outputs from the {root} root. Has it been applied?\n"
            f"{error.stderr.strip()}") from error
    return json.loads(result.stdout)


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render(repo_root: Path) -> str:
    demo = _outputs(repo_root, "demo")
    egress = _outputs(repo_root, "egress")

    if "demo_config" not in demo:
        raise SyncError("The demo root has no demo_config output. Re-apply it.")
    cfg = demo["demo_config"]["value"]
    ext = demo["investigator_external_id"]["value"]

    lines = [
        "# Written by `serverless-demo config sync` from the Terraform roots' outputs.",
        "#",
        "# Committed. Nothing here is a secret: account ids and role ARNs appear in every",
        "# error message this tool prints, and the external id is useless without the",
        "# credential it accompanies. Keeping it in the repository is what lets a fresh",
        "# clone run `verify` without first running Terraform.",
        "#",
        "# Regenerate rather than hand-edit. Every command reads this file, so a value",
        "# edited here and not in Terraform is a divergence that surfaces three commands",
        "# later as a confusing failure.",
        "",
        "[demo]",
        f'account_id = {_quote(cfg["account_id"])}',
        f'region = {_quote(cfg["region"])}',
        f'exports_bucket = {_quote(cfg["exports_bucket"])}',
        f'compromised_user = {_quote(cfg["compromised_user"])}',
        f'persistence_user = {_quote(cfg["persistence_user"])}',
        f'log_group_name = {_quote(cfg["log_group_name"])}',
        f'seed_admin_role_arn = {_quote(cfg["seed_admin_role_arn"])}',
        f'soar_role_arn = {_quote(cfg["soar_role_arn"])}',
        "",
        "# Required on every assume of the investigator role. Not a secret in the way a",
        "# credential is -- useless without the credential it accompanies, and shown on",
        "# screen during the demo alongside the trust policy.",
        f'investigator_external_id = {_quote(ext)}',
        f'investigator_role_arn = {_quote(cfg["investigator_role_arn"])}',
        f'warehouse_secret_arn = {_quote(cfg["warehouse_secret_arn"])}',
        "",
        "[egress]",
        f'account_id = {_quote(egress["account_id"]["value"])}',
        f'region = {_quote("ap-southeast-1")}',
        f'instance_id = {_quote(egress["instance_id"]["value"])}',
        f'operator_role_arn = {_quote(egress["operator_role_arn"]["value"])}',
        f'secret_path_prefix = {_quote(egress["secret_path_prefix"]["value"])}',
        "",
        "[management]",
        f'account_id = {_quote(cfg["management_account_id"])}',
        "",
        "# The regions the attack discovers in. Chosen because the organization does not",
        "# operate in any of them, which is what makes the calls anomalous -- and the SCP",
        "# deliberately permits read-only verbs everywhere so they succeed rather than",
        "# returning AccessDenied.",
        "[attack]",
        'discovery_regions = ["ap-northeast-1", "eu-central-1", "sa-east-1", "ap-south-1"]',
    ]
    return "\n".join(lines) + "\n"


def sync(repo_root: Path) -> Path:
    content = render(repo_root)
    target = repo_root / "demo.toml"
    target.write_text(content)
    # Prove the result round-trips through the loader that rejects unknown keys,
    # so a rename in Terraform that this did not account for fails here rather
    # than in the next command.
    load(target)
    return target
