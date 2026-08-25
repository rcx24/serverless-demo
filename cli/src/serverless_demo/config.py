"""The facts every command shares, read from demo.toml.

One file, generated from the Terraform outputs, rather than nine `terraform
output` calls in a shell script -- which is nine chances for one to be renamed
and the script to keep working against a stale value.

Unknown keys are an error rather than ignored. A typo in a hand-edited config is
otherwise a silent fallback to a default, and the failure surfaces three commands
later as something that reads like a bug in the tool.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, fields
from pathlib import Path


class ConfigError(Exception):
    """demo.toml is missing, malformed, or disagrees with this version of the CLI."""


def _build(cls, data, section):
    known = {f.name for f in fields(cls)}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(
            f"[{section}] has unknown keys: {', '.join(sorted(unknown))}. "
            f"Known keys are {', '.join(sorted(known))}. "
            "Regenerate with `serverless-demo config sync` rather than editing by hand."
        )
    missing = known - set(data)
    if missing:
        raise ConfigError(
            f"[{section}] is missing: {', '.join(sorted(missing))}. "
            "Regenerate with `serverless-demo config sync`."
        )
    return cls(**data)


@dataclass(frozen=True)
class DemoAccount:
    account_id: str
    region: str
    exports_bucket: str
    compromised_user: str
    persistence_user: str
    log_group_name: str
    seed_admin_role_arn: str
    soar_role_arn: str
    investigator_role_arn: str
    warehouse_secret_arn: str


@dataclass(frozen=True)
class EgressAccount:
    account_id: str
    region: str
    instance_id: str
    operator_role_arn: str
    secret_path_prefix: str


@dataclass(frozen=True)
class ManagementAccount:
    account_id: str


@dataclass(frozen=True)
class Attack:
    discovery_regions: list[str]


@dataclass(frozen=True)
class Config:
    demo: DemoAccount
    egress: EgressAccount
    management: ManagementAccount
    attack: Attack
    path: Path


def repo_root(start: Path | None = None) -> Path:
    """Walks up looking for demo.toml, so commands work from any subdirectory."""
    current = (start or Path.cwd()).resolve()
    for candidate in [current, *current.parents]:
        if (candidate / "demo.toml").is_file():
            return candidate
    raise ConfigError(
        "Could not find demo.toml in this directory or any parent. "
        "Run from inside the serverless-demo repository."
    )


def load(path: Path | None = None) -> Config:
    config_path = path or (repo_root() / "demo.toml")
    if not config_path.is_file():
        raise ConfigError(f"{config_path} does not exist.")

    try:
        raw = tomllib.loads(config_path.read_text())
    except tomllib.TOMLDecodeError as error:
        raise ConfigError(f"{config_path} is not valid TOML: {error}") from error

    for section in ("demo", "egress", "management", "attack"):
        if section not in raw:
            raise ConfigError(f"{config_path} has no [{section}] section.")

    return Config(
        demo=_build(DemoAccount, raw["demo"], "demo"),
        egress=_build(EgressAccount, raw["egress"], "egress"),
        management=_build(ManagementAccount, raw["management"], "management"),
        attack=_build(Attack, raw["attack"], "attack"),
        path=config_path,
    )
