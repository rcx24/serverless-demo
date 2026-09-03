# Incident timeline

Reconstruct what the compromised key did, in order, and flag what is anomalous.

## Procedure

From `alert.json`, take the access key id (`entity.accessKeyId`) and a window (a
couple of hours before the first event in `samples` is a safe start).

**IAM activity — always `us-east-1`.** IAM is global and logs only there:

```
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<AKIA...> \
  --region us-east-1 --start-time <ISO8601>
```

**Home-region activity** (STS, S3 bucket-level) — repeat the same lookup with
`--region us-west-2`.

**Cross-region discovery** — the attack calls `DescribeInstances` in regions the
org does not operate in, and each logs in its own region. The regions are visible
in `alert.json`'s `samples[].awsRegion`; look those up too, or check the handful of
regions the samples name.

**Object reads** are data events and are **not** in `lookup-events`. Query the
CloudWatch log group instead:

```
aws logs start-query --log-group-name /aws/cloudtrail/serverless-demo \
  --start-time <epoch> --end-time <epoch> \
  --query-string "fields eventTime, eventName, requestParameters.key
                  | filter eventName = 'GetObject'
                  | sort eventTime asc"
# then: aws logs get-query-results --query-id <id>
```

## Read the sequence for shape

A compromised credential usually shows: an identity check first
(`GetCallerIdentity`), then discovery (`ListUsers`, `ListRoles`,
`GetAccountAuthorizationDetails`, `DescribeInstances`), then access
(`ListBuckets`, `ListObjects`, `GetObject`), then something to persist.

## What to flag

- **Cross-region calls** in regions the org does not use — the clearest discovery
  signal. Note which regions.
- **The source address** — every call here came from one IP (`sourceIPAddress` in
  the events). Note it for `ioc-extraction.md`.
- **Any call that creates or modifies an identity or credential** —
  `CreateAccessKey`, `AttachUserPolicy`, `PutUserPolicy`. Not discovery: the
  attacker changing the account. `CreateAccessKey` especially is what
  `containment-verification.md` follows up.

## Output

A short chronology: time, region, event, one-line note on anything flagged. You
will reference the `CreateAccessKey` — if there is one — in the next step.
