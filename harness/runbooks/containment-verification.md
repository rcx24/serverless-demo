# Containment verification

The SOAR reported a disposition. This step decides whether it is true and whether
it is enough. It is the most important thing you will do in this investigation.

## The principle

Automated containment acts on the identity the alert named. But an attacker's
actions are not confined to that identity — the most common thing an attacker does
with a compromised credential is use it to establish a *second* foothold on a
*different* identity, precisely so that containing the first one does not lock them
out.

So the question is not "did the SOAR contain the alerting identity?" It is:

> Did the automation's scope cover **everything the compromised key touched** — or
> only the identity the alert happened to name?

You answer it by enumerating what the key did to *other* identities and checking
each against what the SOAR case says it handled.

## Procedure

### 1. Confirm the half the SOAR claims

From the SOAR replies in the thread, read the steps — the automation typically
claims to have quarantined the
identity and disabled its key. Verify both against the account (IAM, so
`us-east-1` is irrelevant here — these are not lookups, they are live state):

```
aws iam list-attached-user-policies --user-name <compromised-user>
aws iam list-user-policies --user-name <compromised-user>     # look for a quarantine/deny policy
aws iam list-access-keys --user-name <compromised-user>        # the alerting key should be Inactive
```

If either is not true, the automation's own claimed actions did not take effect — a
finding in itself.

### 2. Find what the key did to *other* identities

This is the step that surfaces what automation misses. Pull every `CreateAccessKey`
the compromised key made. **This is an IAM event, so `us-east-1`:**

```
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<compromised-AKIA> \
  --region us-east-1 --start-time <window-start> \
  --query "Events[?EventName=='CreateAccessKey']"
```

For each `CreateAccessKey`, read the event detail — the **target identity and the
new key id are in the event's own `responseElements`**:

```
# CloudTrailEvent is a JSON string; parse it:
... | jq -r '.CloudTrailEvent | fromjson
             | .responseElements.accessKey | "\(.userName)  \(.accessKeyId)"'
```

This is how you learn which identities were touched **without being told** — the
attacker chose them, so no alert or runbook could name them in advance.

### 3. Diff against what the SOAR named

From the SOAR replies in the thread, collect every identity and key the automation
named in its steps. Any identity or key from step 2 that the SOAR **never named**
is outside what the automation handled.

### 4. Confirm each candidate against live state

For anything the SOAR did not name, check the minted key is still usable:

```
aws iam list-access-keys --user-name <target-identity>
```

If that key is **Active**, the automation reported containment while leaving a
working credential in place.

## What to conclude

- **If every minted key was named by the SOAR** and step 1 confirmed the claimed
  actions, the SOAR did its job. Proceed to close-out.
- **If a minted key is Active and unnamed**, the incident is *not* contained
  regardless of what the case says. Establish what that identity can reach
  (`iam-blast-radius.md`), then escalate — do not close. Note the key id, the
  identity, and the evidence event id; you will need all three in the report.

Do not be reassured by a SOAR disposition of "contained." That is the automation's
verdict on the steps it ran — a true statement about a smaller thing than the
question you are answering.
