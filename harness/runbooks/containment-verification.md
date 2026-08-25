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

You answer it by enumerating what the key did to *other* identities, and checking
each against what the SOAR case says it handled.

## Procedure

### 1. Confirm the half the SOAR claims

From `soar-case.json`, read the steps. It typically claims to have quarantined the
identity and disabled its key. Verify both against the account:

```
sdemo identity --name <compromised-user>
```

This shows the identity's attached policies and the status of each of its access
keys. Confirm the quarantine policy is present and the alerting key is `Inactive`.
If either is not true, the automation's own claimed actions did not take effect —
a finding in itself.

### 2. Find what the key did to other identities

This is the step that surfaces what automation misses. The compromised key may
have created credentials on identities the SOAR never looked at.

```
sdemo containment-check --run <run-id>
```

`sdemo containment-check` does the derivation for you, and it is worth
understanding what it does rather than treating it as a black box, because you may
have to defend the finding:

1. It reads every `CreateAccessKey` the compromised key made, from the trail.
2. For each, it takes the **target identity and the new key id from the event's
   own response** — CloudTrail records both. This is how it learns which
   identities were touched *without being told*; the attacker chose them, so no
   alert or runbook could have named them in advance.
3. It reads, from `soar-case.json`, every identity and key the SOAR steps actually
   named.
4. It reports the **difference**: any key the compromised credential created, that
   the SOAR never named, that is **still Active**. That is a credential the
   automation missed and the attacker still holds.

### 3. Confirm each finding against live state

For anything `containment-check` flags, confirm it is real and current:

```
sdemo identity --name <flagged-identity>
```

The flagged key should show as `Active`. If it does, the automation reported
containment while leaving a working credential in place.

## What to conclude

- **If `containment-check` reports nothing uncontained** and step 1 confirmed the
  claimed actions, the SOAR did its job. Proceed to close-out.
- **If it reports an uncontained key**, the incident is *not* contained regardless
  of what the case says. Establish what that identity can reach
  (`iam-blast-radius.md`), then escalate — do not close. Note the key id, the
  identity, and the evidence event id; you will need all three in the report.

Do not be reassured by a SOAR disposition of "contained." That is the automation's
verdict on the steps it ran, which is a true statement about a smaller thing than
the question you are answering.
