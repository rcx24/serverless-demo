# `budget-alarm`

The $20/month tripwire from the spec's §2.

## What it is, and is not

An AWS budget **notifies**; it does not **cap**. Nothing here stops spend — it
emails someone. Be clear about that: the real defenses against runaway cost are the
SCP's instance-type restriction (a bug cannot launch something expensive) and
`serverless-demo down` (nothing is left running between demos).

This alarm is the backstop for what those miss: a bug that leaves small instances
running for *days*. At the estate's ~$9/month running cost that would not trip a
naive monthly check until late, so the budget carries a **forecast** threshold as
well as an actual one — it fires when the run rate projects past $20, days before
the actual number gets there. That early warning is the point.

## Applying it

Lives in the management account (budgets are visible there across the consolidated
org). Pass the operators' emails; they are the same people who vended the accounts.
