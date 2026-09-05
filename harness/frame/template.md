# Creating the `soc-triage` Template in the product

The frame cannot be applied from git, so recreate it in the Template UI. Values map
one-to-one to `frame.yaml`.

## Templates → New

| Field | Value |
|---|---|
| Name | `soc-triage` |
| Description | Triage a cloud-identity alert against a real read-only AWS role. |
| Runtime | **Pi** |
| Model | Anthropic · `claude-sonnet-4-5` · credential: session-setup |

## Context → Add → Repository

| Field | Value |
|---|---|
| Repository | `rcx24/serverless-demo` |
| Revision | `harness` |
| Destination | `serverless-demo` |

This clones the runbooks branch only. It is a private repo, so the launching user
must have the **GitHub** tool connected (Connections → GitHub).

## AWS (the new toggle)

Turn **AWS on** and select the connected account **serverless-demo (431662316594)**.
That is what gives the harness the `aws` CLI and read-only credentials for the demo
account, via the connection you already verified.

## Options

- **Activity log:** on

## Slack thread (hands-off launch — Milestone 2)

Add a parameter named **`thread`** of type **Slack thread**, and a **Slack-thread
context source** bound to it (label `incident`, sync 1m). This is what lets the
launch button pass the incident thread in; the harness syncs it into `slack/` and
the agent reads the alert + SOAR from there. See `harness/slack/SETUP.md` for the
full wiring (service user, API client, Slack connection, env).

## First test — prove AWS works in the harness (Milestone 1a)

Before wiring the full investigation, launch this template once and confirm the
credential path works end to end inside a real harness. In the terminal, ask the
agent:

```
Run: aws sts get-caller-identity
Then: aws iam list-users --query 'Users[].UserName'
Then try: aws s3api get-object --bucket acme-finance-exports-431662316594 \
          --key exports/2026/07/cost-allocation-2026-07.csv /tmp/x
```

Expected:
- `get-caller-identity` returns `...assumed-role/serverless-demo-readonly/...`
- `list-users` returns the five decoy users
- the `get-object` is **AccessDenied** (the read-only role cannot read objects)

If those three hold, the connector, the CLI install, and the read-only role all
work inside the harness — the core is proven. The full investigation (Milestone 1b)
then just needs the run's artifacts delivered into the workspace, which we wire
next.
