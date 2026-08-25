# `audit-trail`

What makes the seeded intrusion visible to the analyst: a CloudTrail Lake event data
store, and a GuardDuty detector.

## Why there is no classic trail here

Management events are already in **Event History** for 90 days with nothing configured.
That is what `cloudtrail:LookupEvents` reads, and it is what a real analyst reaches for
first — so the demo gets it for free.

A classic trail would add an S3 bucket full of JSON that nobody queries, and reading it
would require granting the investigator `s3:GetObject`. That is the one permission this
demo promises not to have. Adding a trail would quietly trade away the cleanest claim in
the whole design.

## Why Lake, then

**`s3:GetObject` is a data event, and data events never appear in Event History at any
lag.** Not delayed — absent. Without Lake, the "which objects did they take" half of the
story cannot be told at all, and `LookupEvents` returns nothing no matter how long you
poll.

Lake makes those events queryable through `cloudtrail:StartQuery` / `GetQueryResults`,
which the read-only role can hold while still being unable to read a single object. The
analyst can prove *what was read* without being able to read it themselves — which is a
better demo than the original design, not a workaround for it.

One SQL query also replaces twenty paginated `LookupEvents` calls, which matters when an
agent is the one making them.

## Two things that will bite

**`LookupEvents` is regional.** The seeded attack calls `ec2:DescribeInstances` in three
or four regions the organization does not use, and those events land only in *those*
regions' histories. A query in `us-west-2` returns none of them. Cross-region discovery is
the clearest signal in the timeline, so `multi_region_enabled` is not optional and a test
asserts it. Anything walking Event History directly has to iterate regions itself.

**GuardDuty needs baselining runway.** Findings in the `Discovery:` and
`UnauthorizedAccess:IAMUser/` families depend on behavioural baselines. A detector enabled
the morning of a demo may produce nothing at all. Apply this module weeks before the first
real demo. The seed *reports* which findings fired; nothing in the demo *depends* on any
of them firing, and it should stay that way — treat findings as a strong card to play if a
skeptic pushes, never as a scripted beat.

`finding_publishing_frequency` is fifteen minutes rather than the six-hour default,
because the demo seeds at T-30 and asks its first question at T-0.

## Cost

Lake bills on ingest and retained storage. Retention defaults to 7 days — the AWS
minimum — because a demo run is investigated within the hour and torn down the same day.
Data events are scoped by ARN prefix to the exports bucket alone; account-wide object
logging would bill for every read of every bucket and add nothing to the story.

At demo volume this is a couple of dollars a month.

## Adopting an existing detector

GuardDuty permits exactly one detector per region, and creating a second is an error
rather than a no-op. `enable_guardduty = false` lets this module apply into an account
that already has one.
