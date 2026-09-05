"""The launch bridge: the one endpoint that turns a Slack button click into a harness.

The button in the thread is a URL button pointing at this server's `/launch` with a
signed token carrying the channel and thread. On click the browser opens it, this
server verifies the token, calls the product's `POST /api/harnesses` with a bearer
API-client credential and the thread as a parameter, and 302-redirects the browser
to the new harness.

Why a server at all: a Slack button can only open a URL, and that URL has to reach
something that holds the product credential and can make the authenticated launch
call. The credential cannot live in Slack or the browser, so it lives here. Run it
locally and expose it with a tunnel during the demo; the token is what stops the
open URL being an open harness-launcher.

Standard library only -- http.server, hmac, urllib -- so it drops into the CLI with
no new dependency.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class BotError(Exception):
    pass


@dataclass(frozen=True)
class BotConfig:
    signing_secret: str        # signs/verifies the launch token
    public_url: str            # the tunnel URL the button points at
    api_url: str               # the product base URL
    client_id: str             # API client credential
    client_secret: str
    configuration_id: str      # the soc-triage template id
    thread_parameter: str      # the frame's slack-thread parameter name

    @property
    def bearer(self) -> str:
        return f"{self.client_id}.{self.client_secret}"


# --- token: a signed (channel, thread, expiry) the button carries -------------

def sign_token(config: BotConfig, channel: str, thread_ts: str, ttl_seconds: int = 3600) -> str:
    """A short opaque token binding the button to one thread, with an expiry.

    Not a secret -- it carries no credential -- only proof that *we* posted this
    button for this thread. Without it, anyone who saw the URL shape could launch a
    harness against an arbitrary thread.
    """
    expiry = int(time.time()) + ttl_seconds
    message = f"{channel}|{thread_ts}|{expiry}"
    mac = hmac.new(config.signing_secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    return f"{message}|{mac}"


def verify_token(config: BotConfig, token: str) -> tuple[str, str]:
    """Returns (channel, thread_ts) or raises. Constant-time compare; rejects expiry."""
    try:
        channel, thread_ts, expiry, mac = token.split("|")
    except ValueError as error:
        raise BotError("malformed token") from error
    message = f"{channel}|{thread_ts}|{expiry}"
    expected = hmac.new(config.signing_secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, mac):
        raise BotError("bad token signature")
    if int(expiry) < time.time():
        raise BotError("token expired")
    return channel, thread_ts


def launch_url_for(config: BotConfig):
    """The closure fire() calls to build each button's URL."""
    def build(channel: str, thread_ts: str) -> str:
        token = sign_token(config, channel, thread_ts)
        return f"{config.public_url.rstrip('/')}/launch?token={token}"
    return build


# --- the launch call ----------------------------------------------------------

def create_harness(config: BotConfig, channel: str, thread_ts: str) -> str:
    """POST /api/harnesses with the thread parameter. Returns the harness id.

    The thread value is `channelId/threadTs`, the exact shape the product's
    SLACK_THREAD parameter validates and the Slack processor composes.
    """
    name = f"soc-triage-{thread_ts.replace('.', '')[-12:]}"
    body = json.dumps({
        "name": name,
        "configurationId": config.configuration_id,
        "parameters": {config.thread_parameter: f"{channel}/{thread_ts}"},
    }).encode()
    req = urllib.request.Request(
        f"{config.api_url.rstrip('/')}/api/harnesses", data=body, method="POST",
        headers={"content-type": "application/json",
                 "authorization": f"Bearer {config.bearer}",
                 "idempotency-key": f"slack-button:{channel}:{thread_ts}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            result = json.loads(resp.read())
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")[:300]
        raise BotError(f"harness create failed (HTTP {error.code}): {detail}") from error
    except urllib.error.URLError as error:
        raise BotError(f"could not reach the product API: {error}") from error
    harness_id = result.get("id")
    if not harness_id:
        raise BotError(f"harness create returned no id: {result}")
    return harness_id


def harness_url(config: BotConfig, harness_id: str) -> str:
    return f"{config.api_url.rstrip('/')}/app/harnesses/{harness_id}/terminal"


# --- the server ---------------------------------------------------------------

def _handler(config: BotConfig, report):
    class LaunchHandler(BaseHTTPRequestHandler):
        def log_message(self, *_):  # quiet; we report deliberately
            pass

        def _redirect(self, location: str):
            self.send_response(302)
            self.send_header("Location", location)
            self.end_headers()

        def _error(self, code: int, message: str):
            self.send_response(code)
            self.send_header("content-type", "text/plain")
            self.end_headers()
            self.wfile.write(message.encode())

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/health":
                self.send_response(200); self.end_headers(); self.wfile.write(b"ok"); return
            if parsed.path != "/launch":
                self._error(404, "not found"); return

            token = parse_qs(parsed.query).get("token", [""])[0]
            try:
                channel, thread_ts = verify_token(config, token)
            except BotError as error:
                report(f"rejected launch: {error}")
                self._error(403, f"cannot launch: {error}"); return

            try:
                harness_id = create_harness(config, channel, thread_ts)
            except BotError as error:
                report(f"launch failed: {error}")
                self._error(502, f"launch failed: {error}"); return

            url = harness_url(config, harness_id)
            report(f"launched harness {harness_id} for thread {channel}/{thread_ts}")
            self._redirect(url)

    return LaunchHandler


def serve(config: BotConfig, port: int, report=print) -> None:
    server = ThreadingHTTPServer(("0.0.0.0", port), _handler(config, report))
    report(f"launch bridge listening on :{port}")
    report(f"button will point at {config.public_url}/launch")
    report("expose this with a tunnel (e.g. `ngrok http {}`) and set BOT_PUBLIC_URL".format(port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        report("stopping")
        server.shutdown()
