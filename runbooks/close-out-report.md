# Close-out report

Write the case summary in a form the on-call lead can act on in thirty seconds,
and make the close-or-escalate decision explicit.

## What the report has to say

1. **What happened.** One paragraph: the compromised identity, the source, the
   discovery, the data touched, and the persistence action — in sequence.

2. **What the automation did.** The steps the SOAR ran and that you *confirmed*
   took effect. Credit the half that worked; it did most of the job.

3. **What the automation missed.** The uncontained credential, the identity it is
   on, its blast radius, and the evidence event id. This is the finding.

4. **The decision.**
   - If nothing was missed and the claimed actions are confirmed: **close**, and
     say what you verified to justify it.
   - If a credential is still active: **escalate**. Name the exact action needed
     (disable key `AKIA...` on `<identity>`), because the reader should not have to
     re-derive it.

## Output

Drop the report as a note for the on-call lead. Then, in the harness, either close
the alert or hand off the escalation. Do not close an alert with a known
uncontained credential — the entire reason this investigation happened is that a
"contained" disposition was not the whole story.
