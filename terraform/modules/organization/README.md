# `organization`

Creates the AWS Organization, two OUs, one deny-only SCP, and vends the two accounts
the demo runs in.

## Why two accounts

`ssm:SendCommand` records its `commands` parameter in the **caller's** CloudTrail. The
seed script drives the attack sequence on the egress host through Run Command, so if that
host lived in the demo account, the analyst's read-only role would find the entire attack
script — including the deliberate `CreateAccessKey` on `svc-report-runner` — sitting in
`LookupEvents`. The puzzle would survive about one search.

Separating them also happens to be true to the scenario. Attacker infrastructure is not
in your account.

| Account | OU | Holds |
|---|---|---|
| `serverless-demo` | `DemoSecurity` | The victim estate: decoy identities, the exports bucket, padding compute, the trail, the read-only role |
| `serverless-demo-egress` | `DemoEgress` | One small instance in a far region, and the leaked key it fetches from Secrets Manager |

## Read this before applying

**An AWS account root email is permanent.** It is unique across all of AWS, forever, and
closing an account does not release the address. A typo in `demo_account_email` burns that
address for good. Plus-addressing off one mailbox is fine and is what these variables
expect.

**Vending is asynchronous and occasionally slow.** Usually a minute or two; sometimes an
hour; very occasionally it needs a support ticket. Do this a week before anything else
matters, not the morning of a demo.

**Vend once, reuse forever.** `serverless-demo teardown` restores the estate to baseline
and never touches the accounts. Terraform cannot close an AWS account at all — removing
the resource detaches it from state and leaves it running and billing — and AWS caps
closures at 10% of the organization per 30 days. Both accounts carry `prevent_destroy`.

## The SCP, and the two traps in it

`FullAWSAccess` stays attached to both OUs and is deliberately not managed here. SCPs are
deny-by-default, so an OU carrying only this policy would permit nothing at all and the
account would be unreachable except from the management account. This policy is
**deny-only**: it subtracts from `FullAWSAccess` rather than replacing it. A test asserts
that every statement is an `Effect: Deny`.

**Trap one: read-only verbs must never carry a region condition.** The seeded attack calls
`ec2:DescribeInstances` in three or four regions the org does not use, and that
cross-region discovery is the clearest anomaly in the whole timeline — it is most of why
the alert fires. A blanket `aws:RequestedRegion` deny would turn each of those into
`AccessDenied`: still real telemetry, but a different story. The region condition is
scoped to `local.region_scoped_actions`, which holds creation verbs only, and a test fails
if a `Describe`/`List`/`Get` action is ever added to it.

**Trap two: the protective denies exempt `OrganizationAccountAccessRole`.** That is the
role this repository assumes to apply the demo and egress roots, and SCPs apply to it like
any other principal. Without the exemption, the first apply that touches the GuardDuty
detector fails with an error naming the SCP rather than the cause. This does weaken the
guardrail — anyone who can assume that role is exempt — which is an acceptable trade in a
disposable account whose purpose is to be mutated, and would not be in a production OU.

## After applying

```
make org           # plan + apply this root
make accounts      # writes environments/*/account.auto.tfvars, then commit them
```

The demo and egress roots assume `OrganizationAccountAccessRole` in accounts that do not
exist until this root has been applied, so their provider cannot be configured from an
unknown value. The account ids are handed over through committed `.auto.tfvars` files
rather than `terraform_remote_state` — the same reasoning quiv-iac gives for committing
`release.auto.tfvars`: Terraform does not remember variable values between runs, and a
remote-state lookup inside a provider block fails unreadably under `-refresh=false`.
