# Artifact schemas

The three documents the harness is handed at T-0, and the shapes they have to hold.
Everything downstream depends on these, which is why they are built first: the seed
script writes them, the runbooks read them, and those two live in different repositories.

| File | What it is |
|---|---|
| `alert.schema.json` | What the simulated SIEM raises. Populated from real CloudTrail events after the seed confirms they landed. |
| `soar-case.schema.json` | What the automation did before anybody looked, including the per-step run log. |
| `iocs.schema.json` | Indicators, structured for import rather than for reading. |

`examples/` holds one validated bundle per schema. They are checked by
`scripts/validate-contracts.sh`, which runs in CI and is worth running by hand after
editing a schema — a schema that no longer accepts its own example is the usual way this
drifts.

## Three omissions that are load-bearing

Everything below looks like an oversight and is not. Each one is what the analyst is
supposed to discover in the harness, and closing any of them removes a beat from the
demo.

**1. `soar-case.json` never calls `ListAccessKeys` on `svc-report-runner`.**

Step 3 enumerates keys on the alerting identity only. There is no step 6. This is the
entire scenario: the playbook contained the identity it was told about and never looked
at the one that identity acted on. If you add a step here, the harness has nothing to
find.

**2. `soar-case.json` reports `disposition: contained`.**

Not `partially-contained`. The playbook's verdict is that every step it ran succeeded,
which is true. That claim being *true and insufficient at the same time* is the point —
an automation that already knew it had missed something would have escalated instead.

**3. `iocs.json` omits the second access key.**

The seeded bundle carries only what the detection itself surfaced: the source address,
the ASN, the user agent, the compromised credential and principal, and the objects read.
The key minted on `svc-report-runner` is absent.

That is faithful rather than convenient. The SIEM alerted on a behavioural rule and
extracted indicators from the events that fired it; enumerating the blast radius of a
`CreateAccessKey` call is an investigation step, not an extraction step. The enriched IOC
set — the one that includes the orphaned key — is an *output* of the harness session, and
`ioc-extraction` has nothing to demonstrate if it arrives pre-solved.

## Conventions

- `schemaVersion` is a `const`, bumped only for a breaking change. It exists because the
  operator repo and the runbooks repo are versioned separately, so a harness cloned at
  one revision can be handed a bundle written by another.
- `additionalProperties: false` everywhere except `samples[]` and `rawResponse`, which
  hold AWS output copied verbatim. Truncating those to a known field list would mean the
  bundle disagrees with the console an analyst checks it against.
- Timestamps are RFC 3339, UTC, `Z`-suffixed. CloudTrail's own format, so no conversion
  happens anywhere between the trail and the bundle.
- `detectedAt` is deliberately later than the events it describes. The gap is the
  CloudTrail delivery lag, and it stays visible: real detections lag their telemetry, and
  a bundle that hid it would put the alert in disagreement with the timeline the analyst
  builds from the same events.
