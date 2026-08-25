# Triage — start here

An alert arrived and the SOAR playbook has already run. Work in this order. Each
step names the runbook that covers it.

## 1. Read what you were given

Open `runbooks/artifacts/alert.json`. Note:

- the **principal** and **access key** the alert is about (`entity`)
- the **detection time** vs the event times in `samples` — the gap is the
  CloudTrail delivery lag, and it is normal
- the **MITRE techniques** — they tell you what kind of activity fired the rule

Open `runbooks/artifacts/soar-case.json`. Note its **disposition** and read its
**steps**. This is what the automation says it did.

## 2. What happened? → `incident-timeline.md`

Build the sequence of what the compromised key actually did, from the trail. You
are looking for the shape of the activity: discovery, access, and anything that
looks like the attacker trying to keep their foothold.

## 3. Did containment actually work? → `containment-verification.md`

**This is the step that matters most.** The SOAR reported a disposition. Verify
it — not by trusting the case, but by checking the account. Two questions:

- Did the actions the case claims actually take effect?
- Did the automation's scope cover *everything the incident touched*, or only the
  identity the alert happened to name?

The second question is where automated containment most often falls short, and
where you earn the close.

## 4. What could they reach? → `iam-blast-radius.md`

For anything still uncontained, establish what it can do. This is what turns "a
key is still active" into "a key that can reach the finance data is still active"
— a sentence someone can act on.

## 5. Package and decide → `ioc-extraction.md`, `close-out-report.md`

Pull the indicators into a blocklist-ready form, write the close-out, and either
close the alert or escalate what remains.

---

Do not skip step 3 because step 2 looked complete. A tidy timeline and a SOAR case
that says "contained" is exactly the situation this scenario is built around.
