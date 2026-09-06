# serverless-demo

A repeatable, live-fire demo of **Serverless AI** for security teams.

The guiding principle is **don't fake the telemetry.** A seed script authenticates as a
decoy IAM user and makes genuinely benign AWS calls that *resemble* an intrusion; real
CloudTrail records them; a harness investigates the real events through a real read-only
role. Only the SIEM alert and the SOAR are simulated — and they're simulated as thin
wrappers around real actions. Security practitioners spot mocked APIs on sight; this design
gives them nothing to catch.

## The scenario

`svc-billing-export` has a leaked access key. An attacker uses it for cloud discovery,
enumerates S3, reads a few objects, then calls `iam:CreateAccessKey` on a *second* identity,
`svc-report-runner`, for persistence. A SOAR playbook auto-contains the alerting identity —
quarantine policy, key disabled — and **misses the persistence**. It reports `contained`.

**The punchline is not "AI summarized an alert."** It's that the automation did a
*partially correct* job, and the harness catches the orphaned key it left behind, before the
alert is closed.

## How it runs

```
seed ──▶ real attack on a real egress host, confirmed in real CloudTrail
  │        (mint key → discovery/S3/CreateAccessKey → poll until every event lands)
  ▼
demo fire ──▶ Slack: the alert opens a thread, the real SOAR steps reply into it,
  │            a button lands at the bottom
  ▼
[click] ──▶ the launch bridge creates a harness that ingests that thread, clones the
  │          runbooks, and has read-only AWS
  ▼
harness ──▶ agent reads the thread, follows the runbook, runs real `aws` commands,
            finds the orphaned svc-report-runner key — cold
```

One command runs all of it and holds it open until you Ctrl-C:

```bash
make demo
```

## Repo layout

| Path | What |
|---|---|
| `terraform/` | The AWS estate: an Organization, a `DemoSecurity` OU + SCP, two vended accounts (victim + attacker), the decoy identities, the finance-exports bucket, a CloudTrail→CloudWatch Logs trail, GuardDuty, the read-only investigator role, and a `$20` budget alarm. Mirrors quiv-iac conventions. |
| `cli/` | The `serverless-demo` CLI (Python + boto3): `seed`, `verify`, `teardown`, the cost lifecycle (`up`/`down`/`status`), the simulated SOAR, artifact generation, the `containment-check` acceptance test, the SIEM bot (`demo fire`), and the launch bridge (`bot serve`). |
| `contracts/` | JSON Schemas for the alert / SOAR case / IOC bundles, with validated examples. |
| `harness/` | What the harness sees: `frame/` (the Template source-of-truth), `runbooks/` + `AGENTS.md` (the investigation method, published to an orphan `harness` branch), `slack/` (the Slack app manifest + setup). |
| `scripts/` | The account guard, the runbooks publisher, `demo-run.sh` (the `make demo` orchestrator), `demo-up.sh` (bridge + tunnel only). |

## The AWS estate

- **Two accounts, deliberately.** The victim account holds the estate the analyst
  investigates; a separate egress account holds the attacker host. `ssm:SendCommand` records
  its command text in the *caller's* CloudTrail — so an attacker host inside the victim
  account would publish the whole attack script to the analyst. Separating them keeps the
  puzzle intact and is true to the scenario.
- **The read-only investigator role** is what the harness assumes (via the AWS connector). It
  carries explicit `Deny` on `s3:GetObject` and on every credential mutation — so the analyst
  can prove *which* objects were read (from the trail) while being unable to read one, and
  can never disable a key. Those two Denies are shown on screen; they're the answer to "what
  can this thing do in our account."
- **The SCP never region-restricts read-only verbs.** The attack discovers across regions the
  org doesn't use, and that cross-region signal is most of why the alert fires; a blanket
  region deny would replace it with `AccessDenied` and change the story.

## Running a demo

**Prerequisites:** AWS access to the management account, Python 3.11+, Terraform, `cloudflared`,
and the product-side wiring in `harness/slack/SETUP.md` (a Slack app, an API client, the
Template, and a Slack connection).

**One-time, per machine:** `cp .env.example .env` and fill it in (see `harness/slack/SETUP.md`).

**Each session:**

```bash
make demo        # preflight → clean slate → bridge up → seed (~15 min) → alert in Slack → hold
```

`make demo` self-heals: it tears down any prior run at the *start* (so the fresh seed can
mint), and on Ctrl-C it stops the bridge and powers the estate down to minimum cost — but
never tears down, so the harness and the finding survive for re-showing. The next run cleans
up.

The pieces are also individual commands if you want to drive them by hand:

```bash
serverless-demo verify                 # read-only preflight — run before every demo
serverless-demo seed --run-id <id>     # generate the telemetry
serverless-demo demo fire --run-id <id># post the alert + SOAR + button to Slack
serverless-demo bot serve              # the launch bridge (or ./scripts/demo-up.sh for bridge+tunnel)
serverless-demo containment-check --run-id <id>   # the acceptance test, from your laptop
serverless-demo teardown --run-id <id> # back to baseline
```

## Cost

The estate idles at about **$2.50/month** with the egress address released, up to ~$9/month
while a demo is live. GuardDuty (~$1–3) stays on between demos — it's the one idle cost that
buys something (its findings need behavioural baselining). `make status` shows what's running
and what it costs; `make down` returns it to minimum.

A `$20/month` budget alarm in the management account is the backstop against a bug leaving
instances running.

## Slack setup — the one thing that bites

The harness reads the alert thread through **your** Slack connection, and this needs a Slack
app configured a specific way. Two gotchas, both documented in `harness/slack/SETUP.md` and
the product's own guide at `app.getserverless.ai/app/docs/tools/slack`:

1. **Token Rotation must be ON** on the Slack app used for the connection — otherwise the
   connect fails with *"Slack returned an incomplete token response."* Creating the app from
   the product's manifest sets this automatically.
2. **The scopes go under *User* Token Scopes**, and the connected account must be a **member
   of the channel** — the agent reads as you, and sees only what you can see.

The SIEM **poster** bot (`harness/slack/manifest.yaml`) is a *separate* app with Token
Rotation *off* and a static bot token — keep the two apart.

## Answers security teams ask (bake these into the pitch)

- **Where do credentials live?** The harness has no AWS identity of its own. It gets a
  short-lived credential, minted on demand from a role you granted and can revoke, scoped to
  exactly the policy you wrote — never a stored key.
- **Is it genuinely read-only?** The role carries an explicit `Deny` on `s3:GetObject` and on
  credential mutation. Shown on screen. The analyst proves what was read without being able to
  read it.
- **What's the audit trail?** With `activityLog` on, every prompt and tool call is recorded.
- **Is this your production environment?** No — a dedicated demo account under a `DemoSecurity`
  OU with an SCP. Here's the SCP.

## Design notes

The full build log, every load-bearing decision, and the reasoning behind the non-obvious
ones live in the module and command docstrings and READMEs throughout the tree. A few worth
knowing up front:

- **The runbooks describe the *method*, never the answer.** `containment-verification.md`
  tells the agent to enumerate every key the compromised credential created and diff against
  what the SOAR named — it never mentions `svc-report-runner`. The finding is *derived*, which
  is what lets it be defended afterward. A test asserts the answer never leaks into the
  harness-facing content.
- **The `harness` branch is isolated from `main`.** The frame clones this repo at
  `revision: harness` (a shallow single-branch clone), and that branch holds only the runbooks
  — never `main`, where the scenario's design and its answer live.
- **`containment-check` is a CI-grade acceptance test.** If the orphan isn't derivable by a
  deterministic script against real CloudTrail, no amount of prompting makes an agent find it
  reliably. It's proven from the laptop before any harness is involved.
