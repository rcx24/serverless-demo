"""The simulated SIEM/SOAR bot: posts the incident into a Slack thread.

The one component besides the SOAR itself that is simulated -- and, like the SOAR,
a thin wrapper around something real. It invents nothing: it formats the
`alert.json` and `soar-case.json` built from confirmed CloudTrail events and real
containment actions, and posts them into a Slack thread the way a SOC watches an
incident unfold -- the alert opens the thread, the SOAR reports each step as a
reply, and a launch button lands at the bottom.

`fire()` is the demo entry point: alert -> paced SOAR replies -> button. The button
is a URL button pointing at the launch bridge (see bot.py); clicking it creates a
harness that ingests this thread. `post()` remains for the simpler alert-only path.

Two ways to post a single message:

  webhook   an incoming-webhook URL. Simplest; one channel, no threading, no ts.
  bot       a bot token + channel id, via chat.postMessage. Required for the demo:
            threading needs the alert's ts to reply under, and the harness reads
            the thread with the bot's workspace presence.

The alert carries a `Runbook:` line -- a field real alerts carry -- pointing the
harness at where the investigation starts.
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
        f"*Runbook:* serverless-demo/runbooks/00-triage.md   ·   *SIEM:* {alert.get('siemUrl','')}",
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


def _post_bot(token: str, channel: str, text: str, *, thread_ts: str | None = None,
              blocks: list | None = None) -> dict:
    """chat.postMessage. Returns the result (which carries the message `ts`).

    thread_ts threads this message under an earlier one -- how the SOAR replies and
    the button hang off the alert. blocks carries a Block Kit payload (the button);
    text is kept alongside as the notification fallback.
    """
    payload: dict = {"channel": channel, "text": text}
    if thread_ts:
        payload["thread_ts"] = thread_ts
    if blocks:
        payload["blocks"] = blocks
    body = json.dumps(payload).encode()
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


# --- SOAR rendering ---------------------------------------------------------

_STEP_EMOJI = {"succeeded": ":white_check_mark:", "failed": ":x:",
               "skipped": ":heavy_minus_sign:", "timed-out": ":hourglass:"}

# Human phrasing for the actions the playbook actually takes, so a threaded reply
# reads like an automation reporting in rather than an API log line. Anything not
# here falls back to the raw action string, which is still honest.
_ACTION_PHRASING = {
    "iam:GetUser": "Confirmed the alerting identity",
    "iam:PutUserPolicy": "Attached the deny-all quarantine policy to",
    "iam:ListAccessKeys": "Enumerated access keys on",
    "iam:UpdateAccessKey": "Disabled access key",
    "iam:AttachUserPolicy": "Attached the deny-all quarantine policy to",
    "ticket:Create": "Opened case",
}


def format_soar_intro(soar_case: dict) -> str:
    pb = soar_case.get("playbook", {})
    return (f":robot_face: *SOAR playbook engaged* — `{pb.get('name','')}` "
            f"v{pb.get('version','')}  ·  case `{soar_case.get('caseId','')}`")


def format_soar_steps(soar_case: dict) -> list[str]:
    """One threaded reply per step, in order. Each states what the automation did
    against which target -- the same steps the analyst will later verify. The
    omission (no step against the persistence identity) is invisible here, exactly
    as it is in the case: the thread shows what was done, never what was skipped."""
    lines = []
    for step in soar_case.get("steps", []):
        emoji = _STEP_EMOJI.get(step.get("status"), ":grey_question:")
        phrasing = _ACTION_PHRASING.get(step.get("action"), step.get("action", ""))
        lines.append(f"{emoji} {phrasing} `{step.get('target','')}`")
    return lines


_DISPOSITION_LINE = {
    "contained": ":lock: *Case disposition: CONTAINED* — the identity can no longer "
                 "authenticate. Routing to tier-1 for close-out.",
    "partially-contained": ":warning: *Case disposition: PARTIALLY CONTAINED* — escalating.",
    "not-contained": ":rotating_light: *Case disposition: NOT CONTAINED* — escalating.",
    "false-positive": ":information_source: *Case disposition: FALSE POSITIVE*.",
}


def format_soar_disposition(soar_case: dict) -> str:
    return _DISPOSITION_LINE.get(soar_case.get("disposition"),
                                 f"*Case disposition: {soar_case.get('disposition','?')}*")


def investigate_button_blocks(launch_url: str) -> list:
    """The Block Kit message carrying the launch button. A URL button: clicking
    opens launch_url (the bot's /launch with a signed token), which creates the
    harness and redirects the browser to it."""
    return [
        {"type": "section",
         "text": {"type": "mrkdwn",
                  "text": ":mag: *Validate containment and close the alert.* Opens a "
                          "harness with read-only AWS access, this thread, and the SOC "
                          "runbooks already loaded."}},
        {"type": "actions",
         "elements": [
             {"type": "button",
              "text": {"type": "plain_text", "text": "Investigate in harness", "emoji": True},
              "style": "primary",
              "url": launch_url,
              "action_id": "investigate"}]},
    ]


def post(alert_path: Path, *, webhook_url: str | None = None,
         bot_token: str | None = None, channel: str | None = None) -> str:
    """Posts just the alert. Returns a short confirmation string. Kept for the
    simple `alert post` path; the full demo uses fire()."""
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


def fire(alert_path: Path, soar_path: Path, *, bot_token: str, channel: str,
         launch_url_for, report=lambda _m: None, pace: float = 1.5) -> dict:
    """The whole demo post: the alert starts a thread, the SOAR steps reply into it
    one at a time, and a launch button lands at the bottom.

    Requires a bot token (not a webhook) because it needs the thread ts to reply
    under, and because the harness reads the thread with the bot's workspace
    presence. `launch_url_for(channel, thread_ts)` returns the signed /launch URL
    the button opens -- injected so this module holds no signing logic.

    Returns {channel, thread_ts, alert_id} so the caller can log or re-post.
    """
    import time

    if not alert_path.is_file():
        raise AlertPostError(f"{alert_path} does not exist. Run `seed` first.")
    if not soar_path.is_file():
        raise AlertPostError(f"{soar_path} does not exist. Run `seed` first.")
    alert = json.loads(alert_path.read_text())
    soar_case = json.loads(soar_path.read_text())

    # 1. The alert opens the thread.
    root = _post_bot(bot_token, channel, format_message(alert))
    thread_ts = root["ts"]
    report(f"posted alert {alert['alertId']} (thread {thread_ts})")

    # 2. The SOAR reports in, one threaded reply at a time.
    _post_bot(bot_token, channel, format_soar_intro(soar_case), thread_ts=thread_ts)
    for line in format_soar_steps(soar_case):
        time.sleep(pace)
        _post_bot(bot_token, channel, line, thread_ts=thread_ts)
    time.sleep(pace)
    _post_bot(bot_token, channel, format_soar_disposition(soar_case), thread_ts=thread_ts)
    report(f"posted {len(soar_case.get('steps', []))} SOAR steps")

    # 3. The launch button.
    launch_url = launch_url_for(channel, thread_ts)
    _post_bot(bot_token, channel, "Investigate in a harness",
              thread_ts=thread_ts, blocks=investigate_button_blocks(launch_url))
    report("posted the investigate button")

    return {"channel": channel, "thread_ts": thread_ts, "alert_id": alert["alertId"]}
