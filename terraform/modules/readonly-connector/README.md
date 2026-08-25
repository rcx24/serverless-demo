# `readonly-connector`

The role the harness investigates through — and the answer to the first question every
security buyer asks.

Both documents this module produces are meant to be **read aloud from a shared screen**,
and both are deliberately short enough to fit without scrolling. A policy that needs
scrolling is one the audience takes on trust, and taking it on trust is exactly what this
demo exists to make unnecessary.

## The two claims, and how they are enforced

**"It can never read your data."** `s3:GetObject` is in an explicit `Deny`. Not merely
ungranted — denied. That distinction does two things: an audience reading the policy can
*point at* the guarantee rather than infer it from an absence, and an explicit Deny cannot
be overridden by a later Allow, so someone widening the S3 statement to debug a listing
problem cannot accidentally grant object reads.

The analyst still proves **which objects were read**, from CloudTrail Lake. Proving what
was taken while being unable to take it is a stronger demonstration than the original
design's, not a workaround for it.

**"It can never change anything about a credential."** `iam:*AccessKey*`, login profiles,
and user policy attachment are all denied. This one is sharper than it looks: the role
exists to investigate a compromised credential, so if it could disable or delete keys,
the analyst and the attacker would hold the same power — and every containment finding the
harness reported would be a claim about something it could have done itself.

## Why an external ID

A role ARN is not a secret. It turns up in logs, screenshots, support tickets, and on the
screen during this very demo. `sts:ExternalId` requires the caller to also know something
communicated out of band, which is the standard guard against the confused-deputy problem.

It is not a secret in the way a credential is — useless without the credential it
accompanies — which is why it is committed rather than kept in Secrets Manager, and why it
can be shown on screen alongside the trust policy.

## Where the credential lives

The bootstrap IAM user whose key reaches the harness lives in the **management** account,
not the demo account, and its only permission is `sts:AssumeRole` on this one role. So a
credential leaked out of a harness is not even in the account it would be used against,
and the single thing it can do is assume a role that cannot read an object or touch a key.

That is a better answer to "what can this thing do in our account" than a scoped
read-only policy alone, and it is worth saying out loud before someone asks.

## Why `jsonencode` instead of `aws_iam_policy_document`

The data source is nicer to write. But `mock_provider "aws" {}` stubs every data source
the provider owns, so a test asserting on `.json` would be asserting on a mock — and the
policy this module exists to get right would be the one thing never actually checked.

quiv-iac states the rule these modules follow: *an assertion that can only run at apply is
an assertion that never runs in CI.* Building the document as a local keeps it real data
at plan time, which is what lets `terraform test` verify the two Deny statements on every
push.

## Honest caveats

- **The agent can read the credential.** `tools.mjs` says so in its own header: *"there is
  no arrangement of file modes under which a token `gh` can read is a token Pi cannot."*
  What bounds the damage is not secrecy, it is the role — read-only, one account,
  disposable, external ID required, objects explicitly denied. Say this before the
  audience does.
- **`GetQueryResults` cannot be resource-scoped.** It takes a query id, not a store ARN.
  The scoping on `StartQuery` is what bounds it: a query id can only exist for a store this
  role was permitted to query in the first place.
