# `egress-host`

The attacker's infrastructure: one small instance, in its own account, in a region the
fictional organization does not operate in.

## Why a separate account

`ssm:SendCommand` records its `commands` parameter in the **caller's** CloudTrail.

If this host lived in the demo account, the analyst's read-only role would find the entire
attack script — including the deliberate `CreateAccessKey` on `svc-report-runner` — sitting
in `LookupEvents`. The investigation would collapse into a single search, and the demo's
central beat with it.

It is also just true to the scenario. Attacker infrastructure is not in your account.

## Why the leaked key is fetched, not passed

Same reason, sharper consequence. Passing the decoy's secret access key as a `SendCommand`
parameter would write the leaked credential **into the very telemetry this demo is about**
— a real leak and a self-inflicted spoiler in one move.

Instead the seed puts the freshly minted key in Secrets Manager under a per-run prefix, and
the host collects it with its instance role. That also tells a better story: the credential
leaked *to a host*, which is how this actually happens.

The instance role is scoped to that prefix, so it cannot read any other secret in the
account.

## Why SSM instead of SSH

No inbound rules, no key material to manage, and the invocation is itself auditable. An
attacker host with port 22 open to the internet, in a demo shown to security teams, is a
distraction at best.

## Say this before somebody asks

The address is an **Amazon EIP**. The ASN is AS16509 and the geolocation is this region —
so the alert will say `AMAZON-02`, not a residential ISP in a country with a good story.

That is the honest cost of not faking telemetry, and it is a smaller cost than it looks:
*"the attacker used cloud infrastructure in a region you don't operate in"* is both true
and completely realistic. What must not happen is writing `AS-CHOOPA, Moldova` into
`alert.json` — a security audience will check, and being caught fabricating one field
discredits every other claim the demo makes.

Put the sentence in the presenter's script rather than leaving it to be discovered.

## `--fresh`

Releases and re-allocates the EIP so the source address genuinely differs between demos to
the same prospect. It stays inside Amazon's ranges either way.

The instance is created stopped, started by `seed`, and stopped again by `teardown`. There
is no lifecycle block for that: `aws_instance` has no configurable state attribute, so
Terraform has nothing to disagree with the CLI about.
