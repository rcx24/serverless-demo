# Wiring the hands-off Slack demo (Milestone 2)

Everything the live flow needs, in order. The AWS estate and the seed are already
built; this is the Slack presentation layer and the launch bridge.

## 1. Slack app (once)

Create the SIEM bot from `manifest.yaml` (api.slack.com/apps → From a manifest),
install it, and note the **Bot User OAuth Token** (`xoxb-…`).

Use a **public** channel for the demo (e.g. `#soc-alerts`) and invite the bot to
it. Public avoids the `groups:history` scope gap that would leave the harness
unable to read a private thread. Note the channel id (`C…`).

## 2. Product setup (once, in the Serverless UI)

- **Service user + API client.** Create (or pick) a user that holds `harness:create`
  and `configuration:use`. Under that user, mint an API client (Connections →
  Command line, or `/api/api-clients`). Copy the client id and the one-time secret →
  `SERVERLESS_CLIENT_ID` / `SERVERLESS_CLIENT_SECRET`.
- **Connect Slack for that user.** The harness reads the thread with the *launching
  user's* Slack connection, and the launch runs as the API client's owner. So that
  user must have the **Slack** integration connected (Connections → Slack), with
  access to the demo channel. If it is not connected the harness still launches but
  the thread comes through as "could not be read".
- **Template.** Edit the `soc-triage` template: add a parameter named **`thread`**
  of type **Slack thread**, and a **Slack-thread context source** bound to that
  parameter (label `incident`, sync 1m). This mirrors `harness/frame/frame.yaml`.
  Note the template's configuration id → `SOC_TRIAGE_CONFIG_ID`.

## 3. The launch bridge (each demo session)

The bot's `/launch` endpoint must be reachable from your browser, so expose it with
a tunnel:

```
ngrok http 8787            # gives e.g. https://ab12.ngrok.io
```

Set the environment (a `.env` you source, never committed):

```
export SLACK_BOT_TOKEN=xoxb-…
export SLACK_CHANNEL=C…                     # the public demo channel
export SERVERLESS_API_URL=https://app.getserverless.ai
export SERVERLESS_CLIENT_ID=slsc_…
export SERVERLESS_CLIENT_SECRET=…
export SOC_TRIAGE_CONFIG_ID=…               # the template id
export SOC_TRIAGE_THREAD_PARAM=thread       # matches the frame parameter
export BOT_SIGNING_SECRET=$(openssl rand -hex 32)   # any random secret, stable within a session
export BOT_PUBLIC_URL=https://ab12.ngrok.io # the tunnel URL from above
```

Then, in two terminals:

```
serverless-demo bot serve                   # the launch bridge, stays up
serverless-demo demo fire --run-id <id>     # posts alert → SOAR replies → button
```

## 4. The run

```
serverless-demo seed --run-id demo-01       # T-30: real attack + confirmed events
serverless-demo demo fire --run-id demo-01  # T-0: the thread appears in Slack
# → click "Investigate in harness" in the thread
# → the harness launches: reads the thread, clones the runbooks, AWS read-only on
# → ask "did containment work?" → it finds the orphaned svc-report-runner key
serverless-demo teardown --run-id demo-01   # after
```

## What each secret is, and is not

- `BOT_SIGNING_SECRET` signs the button's launch token. It is not a credential —
  it only proves the bot posted the button for a given thread. Any random value;
  keep it stable while `bot serve` is running so tokens it issued stay valid.
- `SERVERLESS_CLIENT_SECRET` is a real credential (the API client). It acts as its
  owner, so scope that owner tightly (`harness:create` + `configuration:use`).
- `SLACK_BOT_TOKEN` posts as the SIEM bot. `chat:write` only — it cannot read.
