"""The shipped artifact examples, and the omissions that make the demo work.

Most of this file asserts that things are *missing*. That is unusual enough to
explain: the scenario depends on the simulated SOAR having done a partially
correct job, and every gap below is one a well-meaning refactor would close. A
test that fails loudly is the only thing standing between "the automation missed
the persistence" and a demo where the analyst has nothing to find.

If one of these fails, read the message before changing the fixture. The fixture
is probably right.
"""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"
EXAMPLES = CONTRACTS / "examples"

PAIRS = [
    ("alert.schema.json", "alert.json"),
    ("soar-case.schema.json", "soar-case.json"),
    ("iocs.schema.json", "iocs.json"),
]

# The identity the attacker mints a key on. Named once, here, because several
# tests below assert it is absent from places it must not appear.
PERSISTENCE_IDENTITY = "svc-report-runner"
ALERTING_IDENTITY = "svc-billing-export"


def load(name):
    return json.loads((EXAMPLES / name).read_text())


@pytest.mark.parametrize("schema_name,example_name", PAIRS)
def test_example_validates_against_its_schema(schema_name, example_name):
    schema = json.loads((CONTRACTS / schema_name).read_text())
    # An invalid schema accepts everything, so a broken one would pass silently.
    Draft202012Validator.check_schema(schema)
    errors = sorted(Draft202012Validator(schema).iter_errors(load(example_name)),
                    key=lambda e: list(e.path))
    assert not errors, "\n".join(
        f"{'/'.join(str(p) for p in e.absolute_path) or '(root)'}: {e.message}"
        for e in errors
    )


def test_the_soar_case_never_touches_the_persistence_identity():
    """The gap the whole demo is built on.

    The playbook was written against the alerting identity. `iam:CreateAccessKey`
    on a *different* principal is outside its scope, so it never enumerates keys
    there and never disables the one it finds. Adding a step for it here would
    contain the incident and leave the analyst nothing to discover.
    """
    case = load("soar-case.json")
    targets = " ".join(f"{s['action']} {s['target']}" for s in case["steps"])
    assert PERSISTENCE_IDENTITY not in targets, (
        f"A SOAR step now names {PERSISTENCE_IDENTITY}. If that was deliberate, the "
        "demo no longer has a punchline: containment-verification exists to find the "
        "orphaned key precisely because the automation never looked at that identity."
    )


def test_the_soar_case_claims_it_contained_the_incident():
    """`contained`, not `partially-contained`.

    Every step the playbook ran did succeed, so the claim is true. It being true
    and insufficient at the same time is the point -- an automation that already
    knew it had missed something would have escalated instead of closing.
    """
    case = load("soar-case.json")
    assert case["disposition"] == "contained", (
        "The SOAR's self-reported disposition is the claim the analyst is meant to "
        "test against the account. Softening it to 'partially-contained' tells them "
        "the answer before they look."
    )


def test_the_soar_case_did_contain_the_alerting_identity():
    """The other half: the automation has to have genuinely done something.

    A playbook that achieved nothing is not a partially correct job, it is a
    broken one, and the demo's claim is specifically that automation does most of
    the work and misses the tail.
    """
    case = load("soar-case.json")
    actions = {s["action"] for s in case["steps"] if s["status"] == "succeeded"}
    assert "iam:AttachUserPolicy" in actions or "iam:PutUserPolicy" in actions
    assert "iam:UpdateAccessKey" in actions, (
        "The alerting identity's key must actually be deactivated. Containment "
        "verification confirms this half succeeded before reporting the half that "
        "did not."
    )
    assert any(ALERTING_IDENTITY in s["target"] for s in case["steps"])


def test_the_seeded_iocs_omit_the_minted_key():
    """The IOC bundle carries what the detection surfaced, and no more.

    The SIEM alerted on a behavioural rule and extracted indicators from the
    events that fired it. Enumerating the blast radius of a CreateAccessKey call
    is an investigation step, not an extraction step -- so the enriched set that
    includes the orphaned key is an *output* of the harness session, and
    ioc-extraction has nothing to demonstrate if it arrives pre-solved.
    """
    iocs = load("iocs.json")
    keys = [entry["value"] for entry in iocs["indicators"].get("accessKeyId", [])]
    assert len(keys) == 1, (
        f"The seeded IOC bundle lists {len(keys)} access keys. It must list exactly "
        "one -- the credential named in the alert. The key minted on "
        f"{PERSISTENCE_IDENTITY} is what the harness is supposed to add."
    )
    principals = " ".join(
        entry["value"] for entry in iocs["indicators"].get("principalArn", [])
    )
    assert PERSISTENCE_IDENTITY not in principals


def test_the_alert_shows_the_persistence_action_without_naming_the_target():
    """The evidence is present; the conclusion is not.

    A `CreateAccessKey` sample has to be in the alert -- it is what makes the
    finding derivable rather than guessable. What must not be there is the
    response, which carries the new key id and the identity it belongs to.
    """
    alert = load("alert.json")
    names = {s["eventName"] for s in alert["samples"]}
    assert "CreateAccessKey" in names, (
        "Without a CreateAccessKey sample the analyst has no thread to pull, and the "
        "finding stops being derivable from what they were given."
    )
    assert PERSISTENCE_IDENTITY not in json.dumps(alert), (
        f"The alert names {PERSISTENCE_IDENTITY}. The analyst is meant to reach that "
        "identity by following the CreateAccessKey event to its target, not by "
        "reading it off the alert."
    )


def test_the_alert_records_cross_region_discovery():
    """The clearest anomaly in the timeline, and the reason the SCP is careful.

    The organization's SCP deliberately does not region-restrict read-only verbs,
    so that these calls succeed rather than returning AccessDenied.
    """
    alert = load("alert.json")
    regions = {s["awsRegion"] for s in alert["samples"]}
    assert len(regions) > 1, (
        "Every sampled event is in one region. Cross-region discovery is most of why "
        "this alert fires; if the samples do not show it, check that the SCP has not "
        "started denying Describe calls outside the demo regions."
    )
