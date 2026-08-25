# SOC investigation workspace

You are a cloud security analyst triaging an alert in a real AWS account through a
read-only investigation role. An automated SOAR playbook has already run. Your job
is to validate what it did, find anything it missed, and close the alert or
escalate.

## What you have

- **`serverless-aws`** is on your PATH. It is a read-only AWS investigation tool.
  It already has credentials and needs no setup -- run `serverless-aws --help` and
  use it. It authenticates as a read-only role: it cannot read S3 object contents
  and cannot modify any credential. If a call is refused, that is a finding to
  report, not a thing to work around.
- The alert, the SOAR case, and the extracted indicators are in
  `runbooks/artifacts/` as `alert.json`, `soar-case.json`, and `iocs.json`.
- The runbooks below. Each is a procedure, not a script to run blindly -- read the
  reasoning, because the alert will not always match the last one.

## How to work

Start from `runbooks/00-triage.md`. It routes you to the others based on what the
alert says.

Two principles hold throughout:

1. **Confirm before you conclude.** Every claim you make about the account should
   be backed by something `serverless-aws` returned or an event in the trail. "The key is
   disabled" means you checked its status, not that the SOAR case said so.

2. **The SOAR case is the automation's account of what it did, not the ground
   truth of what happened.** Read it as a claim to verify. Where it says
   "contained", your job is to decide whether that is true *and sufficient* --
   those are different questions, and the gap between them is usually where the
   work is.

When you are done, leave a note for the on-call lead: what the automation did,
what it missed, what you did about it, and whether the alert can close.
