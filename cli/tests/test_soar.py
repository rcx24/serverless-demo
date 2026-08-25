"""The SOAR's deliberate gap, guarded structurally.

test_contracts.py protects the gap in the *example fixtures*. This protects it in
the *code that produces the real case*, which is a different place a refactor
could close it -- somebody "finishing" the playbook by adding a step that
enumerates the persistence identity would pass every fixture test and quietly
remove the punchline.
"""

import ast
from pathlib import Path

SOAR = Path(__file__).resolve().parents[1] / "src" / "serverless_demo" / "soar.py"


def test_the_soar_never_references_the_persistence_user():
    """The playbook acts on the compromised user by config, never on the
    persistence user. Checked at the source level: the persistence identity is
    reached through config.demo.persistence_user, and that attribute must not
    appear anywhere in the SOAR."""
    source = SOAR.read_text()
    assert "persistence_user" not in source, (
        "soar.py references config.demo.persistence_user. The playbook is written "
        "against the alerting identity only; touching the persistence user -- even "
        "to read its keys -- is the step whose absence is the entire demo."
    )


def test_the_soar_disposition_is_contained_not_partial():
    """The playbook reports full containment. That the claim is true of what it
    did, and insufficient for the incident, is the point."""
    source = SOAR.read_text()
    tree = ast.parse(source)
    literals = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)}
    assert "contained" in literals
    assert "partially-contained" not in literals, (
        "The SOAR must report 'contained'. An automation that already knew it had "
        "missed something would have escalated instead of closing."
    )


def test_the_soar_still_does_real_containment():
    """The gap is a missing step, not a broken playbook. The actions it does take
    -- quarantine and key disable on the alerting identity -- must be present, or
    containment-verification has nothing to confirm as the half that worked."""
    source = SOAR.read_text()
    assert "put_user_policy" in source
    assert "update_access_key" in source
