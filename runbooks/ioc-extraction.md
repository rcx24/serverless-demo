# IOC extraction

Pull the indicators into a form a blocklist or SIEM can import. Start from what the
detection already gave you and add what the investigation found.

## Procedure

The alert in the thread carries the indicators the detection surfaced — the source
IP, ASN, user agent, the compromised key and principal. Collect those, then add what
*you* found that the detection did not — most importantly, the uncontained credential
from `containment-verification.md`.

The seeded indicators deliberately do not include the orphaned key, because
extracting the blast radius of a `CreateAccessKey` is an investigation step, not
something the detection could have known. Adding it is the point of this step.

## What each indicator needs

- a **value** (IP, ASN, user agent, access key id, principal ARN, object key)
- **provenance** — the event ids it was seen in, so a future analyst can trace why
  it is on the list and decide when to remove it
- a **disposition** — block, monitor, investigate. Not every indicator is a block:
  the source ASN here is a hyperscaler's, and blocking it blocks most of the
  internet's automation along with the attacker.

## Output

An indicator set that includes the orphaned access key id and the identity it
belongs to. That is the indicator the automation's own extraction missed.
