# IAM blast radius

For an identity that is still uncontained, establish what it can actually reach.
This turns "a key is still active" into a sentence someone can act on.

## Procedure

```
aws iam list-attached-user-policies --user-name <identity>
aws iam list-user-policies --user-name <identity>
# then read each inline policy:
aws iam get-user-policy --user-name <identity> --policy-name <name>
```

Read the permissions for reachability that matters:

- **Data.** Can it read or write S3 buckets? Which ones? A key that can reach the
  finance exports is a different severity from one that cannot.
- **Credentials.** Can it create or modify access keys, users, or policies? Such a
  key can re-establish persistence after you revoke it — which changes how you
  contain it.
- **Secrets.** Can it read Secrets Manager? A reachable warehouse or database
  credential is a lateral-movement path out of the account.
- **Escalation.** Can it attach policies to itself or pass a more privileged role?

## Output

One or two sentences naming the concrete reach — "this key can write to the finance
exports bucket and read the reporting warehouse credential" — not a policy dump.
That sentence is what justifies escalating rather than closing.
