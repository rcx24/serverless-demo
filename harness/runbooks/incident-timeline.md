# Incident timeline

Reconstruct what the compromised key did, in order, and flag what is anomalous.

## Procedure

1. From `alert.json`, take the access key id (`entity.accessKeyId`) and a window.
   The events in `samples` bound it; a couple of hours before the first sample is
   a safe start.

2. Pull every event that key made:

   ```
   sdemo timeline --access-key <AKIA...> --since <ISO8601>
   ```

   `sdemo` queries each region the events could be in — this matters, and it is
   the trap a manual investigation falls into. CloudTrail Event History is *per
   region*. IAM is a global service and logs only to us-east-1; calls to other
   regions log in those regions; object reads are data events and are not in Event
   History at all. `sdemo timeline` handles this; if you query one region by hand
   you will see a fraction of the activity and conclude too little happened.

3. Read the sequence for shape, not just contents. A compromised credential
   usually shows:

   - **an identity check first** (`GetCallerIdentity`) — confirming the key works
   - **discovery** — enumerating IAM (`ListUsers`, `ListRoles`,
     `GetAccountAuthorizationDetails`) and infrastructure (`DescribeInstances`)
   - **access** — finding and reading data (`ListBuckets`, `ListObjects`,
     `GetObject`)
   - **something to persist** — this is the one to watch for, and it is covered in
     `containment-verification.md`

## What to flag

- **Cross-region activity.** `sdemo timeline` marks the region of each call. If the
  key called `DescribeInstances` in regions the organization does not operate in,
  that is discovery, and it is one of the clearest signals in the whole timeline.
  Note which regions.
- **The source address.** Every call in this incident came from one IP. `sdemo
  timeline` shows it. Note it for `ioc-extraction.md`.
- **Any call that creates or modifies an identity or credential.**
  `CreateAccessKey`, `CreateUser`, `AttachUserPolicy`, `PutUserPolicy`. These are
  not discovery — they are the attacker changing the account, and they are what
  `containment-verification.md` follows up.

## Output

A short chronology: time, region, event, and a one-line note on anything flagged.
You will reference the `CreateAccessKey` — if there is one — in the next step.
