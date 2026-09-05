"""The launch bridge's security properties, and the SOAR rendering.

The token is the only thing standing between the button's public URL and an open
harness-launcher, so its verification is tested hardest: a tampered or expired
token must be refused, and only a token we signed for a specific thread launches
against that thread.
"""

import json
from pathlib import Path

import pytest

from serverless_demo import bot, siembot

CFG = bot.BotConfig(
    signing_secret="test-secret", public_url="https://demo.ngrok.io",
    api_url="https://app.example", client_id="slsc_x", client_secret="y",
    configuration_id="cfg-1", thread_parameter="thread")

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts" / "examples"


def test_a_signed_token_round_trips():
    token = bot.sign_token(CFG, "C0ABCDEF", "1700000000.000100")
    channel, thread = bot.verify_token(CFG, token)
    assert channel == "C0ABCDEF"
    assert thread == "1700000000.000100"


def test_a_tampered_token_is_refused():
    token = bot.sign_token(CFG, "C0ABCDEF", "1700000000.000100")
    # flip the last signature char
    tampered = token[:-1] + ("0" if token[-1] != "0" else "1")
    with pytest.raises(bot.BotError, match="signature"):
        bot.verify_token(CFG, tampered)


def test_a_token_for_a_different_thread_is_refused():
    """Swapping the thread in the token body invalidates the signature -- so a
    token cannot be replayed against a thread it was not signed for."""
    token = bot.sign_token(CFG, "C0ABCDEF", "1700000000.000100")
    channel, thread, expiry, mac = token.split("|")
    forged = f"{channel}|9999999999.999999|{expiry}|{mac}"
    with pytest.raises(bot.BotError):
        bot.verify_token(CFG, forged)


def test_an_expired_token_is_refused():
    token = bot.sign_token(CFG, "C0ABCDEF", "1700000000.000100", ttl_seconds=-1)
    with pytest.raises(bot.BotError, match="expired"):
        bot.verify_token(CFG, token)


def test_a_token_from_a_different_secret_is_refused():
    """The signing secret is what makes the token ours. A bot with a different
    secret cannot mint tokens this one accepts."""
    other = bot.BotConfig(**{**CFG.__dict__, "signing_secret": "different"})
    token = bot.sign_token(other, "C0ABCDEF", "1700000000.000100")
    with pytest.raises(bot.BotError):
        bot.verify_token(CFG, token)


def test_the_launch_url_carries_a_verifiable_token():
    url = bot.launch_url_for(CFG)("C0ABCDEF", "1700000000.000100")
    assert url.startswith("https://demo.ngrok.io/launch?token=")
    token = url.split("token=")[1]
    assert bot.verify_token(CFG, token) == ("C0ABCDEF", "1700000000.000100")


def test_the_soar_thread_renders_every_step():
    case = json.loads((CONTRACTS / "soar-case.json").read_text())
    steps = siembot.format_soar_steps(case)
    assert len(steps) == len(case["steps"])
    # every step is a check-mark line naming its target
    for line, step in zip(steps, case["steps"]):
        assert step["target"] in line


def test_the_soar_thread_never_names_the_persistence_identity():
    """The thread shows what the SOAR did, and the SOAR never touched
    svc-report-runner -- so the thread must not name it either, or the analyst is
    handed the answer instead of finding it."""
    case = json.loads((CONTRACTS / "soar-case.json").read_text())
    rendered = "\n".join([
        siembot.format_soar_intro(case),
        *siembot.format_soar_steps(case),
        siembot.format_soar_disposition(case),
    ])
    assert "svc-report-runner" not in rendered


def test_the_disposition_line_reflects_the_case():
    case = {"disposition": "contained", "steps": [], "playbook": {}}
    assert "CONTAINED" in siembot.format_soar_disposition(case)
    case["disposition"] = "partially-contained"
    assert "PARTIALLY" in siembot.format_soar_disposition(case)
