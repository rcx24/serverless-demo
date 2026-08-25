"""The invariant that makes the account guard reliable.

`sessions.py` is the only module permitted to import boto3, so there is exactly
one place a credential becomes a client -- and therefore exactly one place the
account check can be forgotten. This is the Python analogue of
`allowed_account_ids` on a Terraform provider.

It matters because of what this tool does. It mints IAM access keys, attaches
deny-all policies, and deletes credentials. Pointed at the wrong account it is
indistinguishable from the intrusion it simulates, and a `boto3.client(...)` added
directly to a command module would bypass every guard in the codebase without
looking wrong.
"""

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[1] / "src" / "serverless_demo"
ALLOWED = {"sessions.py"}


def modules():
    return sorted(p for p in PACKAGE.glob("*.py"))


def test_there_are_modules_to_check():
    """Guards the test below from passing because it found nothing."""
    assert modules(), "No modules found; the assertion below would be vacuous."


@pytest.mark.parametrize("module", modules(), ids=lambda p: p.name)
def test_only_the_session_module_imports_boto3(module):
    tree = ast.parse(module.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])

    offending = imports & {"boto3"}
    if module.name in ALLOWED:
        return
    assert not offending, (
        f"{module.name} imports boto3 directly. Every session must come from "
        "sessions.py, which verifies which account it landed in before handing "
        "the caller a client. A client built anywhere else bypasses that check."
    )


def test_the_session_module_verifies_every_session():
    """Each public session factory must route through the verifying helper.

    Checked structurally rather than by calling AWS: a new factory added without
    the check would still work in every test that mocks boto3, and would fail only
    in production, against a real account, doing something irreversible.
    """
    source = (PACKAGE / "sessions.py").read_text()
    tree = ast.parse(source)

    factories = [
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_")
    ]
    assert factories, "No session factories found."

    for factory in factories:
        calls = {
            node.func.id
            for node in ast.walk(factory)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert calls & {"_verify", "_assume", "management"}, (
            f"sessions.{factory.name}() does not verify the account it lands in. "
            "Route it through _verify or _assume."
        )
