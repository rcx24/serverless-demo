"""The simulated SIEM bot: posts the alert to Slack at T-0.

The one component besides the SOAR that is simulated -- and, like the SOAR, it is
a thin wrapper around something real. It does not invent an alert; it formats the
`alert.json` that was built from confirmed CloudTrail events (§8) into the shape a
Splunk/Sentinel/Panther notable takes, and posts it to the channel a Slack Events
trigger watches. The trigger then launches the harness. Nobody clicks anything.

Two ways to post, because a workspace may have either set up:

  webhook   an incoming-webhook URL. Simplest; posts to the one channel the webhook
            is bound to. No scopes, no bot user.
  bot       a bot token + channel id, via chat.postMessage. Needed if the same bot
            also has to be in the channel for the Events trigger to read history.

The message carries a marker line the trigger matches on (`contains_text`), and a
`Runbook:` line -- a field real alerts carry -- pointing the harness at where the
investigation starts.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

# The phrase the Slack Events trigger matches to decide this message should launch
# a harness. Distinctive enough not to fire on ordinary chatter.
TRIGGER_MARKER = "SERVERLESS-DEMO-ALERT"


class AlertPostError(Exception):
    pass


def _severity_emoji(severity: str) -> str:
    return {"critical": ":rotating_light:", "high": ":red_circle:",
            "medium": ":large_orange_diamond:", "low": ":large_blue_circle:",
            "informational": ":white_circle:"}.get(severity, ":red_circle:")


def format_message(alert: dict) -> str:
    """The alert as a SOC would see it in Slack. Read off alert.json, nothing added."""
    entity = alert["entity"]
    source = alert.get("source", {})
    rule = alert["rule"]
    mitre = " ".join(m["techniqueId"] for m in alert.get("mitre", []))
    samples = alert.get("samples", [])

    lines = [
        f"{_severity_emoji(alert['severity'])} *{rule['name']}*  "
        f"`{alert['severity'].upper()}`  ({rule['id']})",
        f"{TRIGGER_MARKER}  ·  alert `{alert['alertId']}`",
        "",
        f"*Principal:* `{entity['principalArn']}`",
        f"*Access key:* `{entity['accessKeyId']}`   *Account:* `{entity['accountId']}`",
    ]
    if source.get("ip"):
        place = ", ".join(p for p in (source.get("city"), source.get("country")) if p)
        geo = f" ({place})" if place else ""
        asn = f" · AS{source['asn']} {source.get('asnOrg','')}".rstrip() if source.get("asn") else ""
        lines.append(f"*Source:* `{source['ip']}`{geo}{asn}")
    lines += [
        f"*Detected:* {alert['detectedAt']}",
        f"*MITRE:* {mitre}",
        "",
        "*Sample events:*",
    ]
    for s in samples[:5]:
        lines.append(f"  • `{s['eventTime']}`  {s['eventName']}  ({s['awsRegion']})")
    lines += [
        "",
        f"*Runbook:* runbooks/00-triage.md   ·   *SIEM:* {alert.get('siemUrl','')}",
    ]
    return "\n".join(lines)


def _post_webhook(url: str, text: str) -> None:
    body = json.dumps({"text": text}).encode()
    req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status != 200:
                raise AlertPostError(f"Slack webhook returned HTTP {resp.status}")
    except urllib.error.URLError as error:
        raise AlertPostError(f"could not reach the Slack webhook: {error}") from error


def _post_bot(token: str, channel: str, text: str) -> dict:
    body = json.dumps({"channel": channel, "text": text}).encode()
    req = urllib.request.Request(
        "https://slack.com/api/chat.postMessage", data=body,
        headers={"content-type": "application/json", "authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
    except urllib.error.URLError as error:
        raise AlertPostError(f"could not reach Slack: {error}") from error
    if not result.get("ok"):
        raise AlertPostError(f"Slack rejected the message: {result.get('error')}")
    return result


def post(alert_path: Path, *, webhook_url: str | None = None,
         bot_token: str | None = None, channel: str | None = None) -> str:
    """Posts the alert. Returns a short confirmation string."""
    if not alert_path.is_file():
        raise AlertPostError(f"{alert_path} does not exist. Run `seed` first.")
    alert = json.loads(alert_path.read_text())
    text = format_message(alert)

    if webhook_url:
        _post_webhook(webhook_url, text)
        return f"posted {alert['alertId']} via webhook"
    if bot_token and channel:
        result = _post_bot(bot_token, channel, text)
        return f"posted {alert['alertId']} to {channel} (ts {result.get('ts')})"
    raise AlertPostError(
        "no Slack destination. Pass --webhook-url, or --bot-token with --channel "
        "(or set SLACK_WEBHOOK_URL / SLACK_BOT_TOKEN + SLACK_CHANNEL).")
