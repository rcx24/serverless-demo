# `decoy-identities`

The identities the scenario is about, plus enough neighbours that enumerating the account
looks like somebody's real AWS estate.

| Identity | Role in the scenario |
|---|---|
| `svc-billing-export` | The compromised service account. The alert is about this one. |
| `svc-report-runner` | The persistence target. The attacker mints a key here; the SOAR never looks. |
| `svc-backup-agent`, `svc-log-shipper`, `svc-invoice-sync` | Padding |
| `app-deploy` (role) | Padding, so `iam:ListRoles` returns something |

## No access keys here, deliberately

There is no `aws_iam_access_key` in this module, and a test in `cli/tests/` reads the
Terraform source to keep it that way.

A key created by Terraform lives in **state** — an S3 object, readable by anyone with
state access, surviving every teardown and every `--fresh` run. The seed CLI mints the
decoy's key per run, uses it for a few minutes, and deletes it on teardown. That is also
the only way the demo can honestly claim afterwards that the leaked credential is gone.

## Why the padding is not decoration

`iam:ListUsers` and `iam:GetAccountAuthorizationDetails` are two of the calls the attack
makes, and their output goes on screen during `incident-timeline`. An account containing
exactly the two identities the story needs reads as a stage set to anyone who has run
those commands in anger. Three unrelated service accounts with plausible names, owners and
policies is what makes it look real — and it costs nothing.

## Why the two policies are shaped the way they are

**`svc-billing-export`** gets a plausible least-privilege service-account policy: read the
exports bucket, read Cost Explorer, nothing else. `iam-blast-radius` reads this to answer
*"what could they reach"*, and the honest answer has to be interesting but bounded. An
identity with `AdministratorAccess` makes the scenario trivial; one with nothing makes it
pointless.

**`svc-report-runner`** is deliberately more capable — it can write to the exports bucket
and read a warehouse secret. Part of the analyst's job is deciding whether the orphaned
key actually *matters*, and "it can write to finance data and read a credential" is a
finding worth escalating, where "it can do nothing" would be a curiosity.

Nothing in this module encodes which identity is the persistence target. `svc-report-runner`
is an ordinary-looking second service account with an ordinary name — if it were called
`svc-persistence-target`, the analyst would find it by reading the account rather than by
following the evidence, which is a different and much weaker demo.
