"""Properties of the Terraform source that HCL cannot assert about itself.

`terraform test` can assert things about a plan. It cannot assert that a resource
type is *absent* -- referencing an undeclared resource is a hard error rather than
something `can()` swallows -- and absence is exactly what matters here. So these
read the source.

Cheap, fast, and they run in the same `make test` as everything else.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TERRAFORM = ROOT / "terraform"

TF_FILES = sorted(TERRAFORM.rglob("*.tf"))


def resources_of_type(kind):
    """Every declaration of a given resource type, as (path, block name)."""
    pattern = re.compile(rf'^resource\s+"{re.escape(kind)}"\s+"([^"]+)"', re.MULTILINE)
    found = []
    for path in TF_FILES:
        if ".terraform" in path.parts:
            continue
        for match in pattern.finditer(path.read_text()):
            found.append((path.relative_to(ROOT), match.group(1)))
    return found


def test_there_is_terraform_to_check():
    """Guards the tests below from passing because they found nothing at all."""
    assert TF_FILES, "No .tf files found -- the assertions below would be vacuous."


def test_terraform_never_mints_an_access_key():
    """The decoy's credential is created per run, not by Terraform.

    A key created by Terraform lives in state: an S3 object, readable by anyone
    with state access, surviving every teardown and every `--fresh` run. The seed
    mints one, uses it for a few minutes, and deletes it on teardown -- which is
    also the only way the demo can honestly claim the leaked credential is gone
    afterwards.
    """
    found = resources_of_type("aws_iam_access_key")
    assert not found, (
        "Terraform declares an aws_iam_access_key at "
        + ", ".join(f"{p}:{n}" for p, n in found)
        + ". The secret would be written to state and outlive every teardown. Mint "
        "it in the seed CLI instead."
    )


ALLOW_MARKER = "allow-secret-in-state:"


def test_a_secret_in_state_is_always_justified():
    """Anything assigned to `secret_string` ends up in Terraform state.

    State is an S3 object that outlives every teardown, so a real credential put
    there is a real credential leaked. This does not forbid the pattern outright --
    the demo needs a plausible lateral-movement target, and a secret that exists
    has to have a value -- it forbids doing it *silently*.

    Opt out with a comment in the preceding five lines:

        # allow-secret-in-state: invented value, opens nothing

    The first version of this test matched `secret_string = "..."` and was
    satisfied by writing `secret_string = jsonencode({...})` instead. A test that
    the obvious spelling walks straight past is worse than no test, because it
    implies a guarantee it never had.
    """
    offenders = []
    for path in TF_FILES:
        if ".terraform" in path.parts:
            continue
        lines = path.read_text().splitlines()
        for index, line in enumerate(lines):
            if line.strip().startswith("#"):
                continue
            if not re.match(r"\s*secret_string\s*=", line):
                continue
            window = lines[max(0, index - 5):index]
            if any(ALLOW_MARKER in earlier for earlier in window):
                continue
            offenders.append(f"{path.relative_to(ROOT)}:{index + 1}: {line.strip()}")

    assert not offenders, (
        "A value assigned to secret_string is written to Terraform state:\n  "
        + "\n  ".join(offenders)
        + f"\n\nIf the value is invented and opens nothing, say so with a "
        f"'# {ALLOW_MARKER} <why>' comment above it."
    )


@pytest.mark.parametrize("module_dir", sorted(
    d for d in (TERRAFORM / "modules").iterdir() if d.is_dir()
))
def test_every_module_has_the_full_file_set(module_dir):
    """The convention quiv-iac holds to without exception.

    A module missing `versions.tf` inherits whatever the calling root pinned;
    one missing `README.md` is one the next person has to read in full to use.
    """
    required = {"main.tf", "variables.tf", "outputs.tf", "versions.tf", "README.md"}
    present = {f.name for f in module_dir.iterdir() if f.is_file()}
    missing = required - present
    assert not missing, f"{module_dir.name} is missing {sorted(missing)}"

    tests = module_dir / "tests"
    assert tests.is_dir() and any(tests.glob("*.tftest.hcl")), (
        f"{module_dir.name} has no tests/*.tftest.hcl"
    )


def test_the_padding_estate_is_reachable_by_nobody():
    """No ingress rule anywhere in the decoy estate.

    Terraform reports a security group's `ingress` as a computed set, so it is
    unknown at plan time and `terraform test` cannot assert on it. The property
    still matters: these instances run nothing, exist only to appear in
    `DescribeInstances`, and live in an account that gets screen-shared. An
    ingress rule here is an invitation nobody meant to send.
    """
    main = TERRAFORM / "modules" / "padding-estate" / "main.tf"
    body = "\n".join(
        line for line in main.read_text().splitlines()
        if not line.strip().startswith("#")
    )
    assert not re.search(r"^\s*ingress\s*\{", body, re.MULTILINE), (
        "padding-estate declares an ingress rule. These instances are inventory, "
        "not workloads, and nothing should be able to reach them."
    )
