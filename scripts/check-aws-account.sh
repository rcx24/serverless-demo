#!/usr/bin/env bash
# Layer one of three. Refuses to run against an account that is not the expected one.
#
# The other two layers are `allowed_account_ids` on every provider and a
# `check "target_account"` block in every root module. Three layers for one
# question looks excessive until you notice what this repository does: it mints
# IAM access keys, attaches deny-all policies to identities, and runs dozens of
# times. Pointed at the wrong account it is indistinguishable from the intrusion
# it simulates.
#
# This layer answers "who am I locally", which is not the same question the
# `check` block answers. The demo root assumes a role into the vended account, so
# the identity here is the management account and the identity Terraform ends up
# with is not. Both have to be right, and only one of them is visible from here.
set -euo pipefail

expected_account="${1:?expected account id required}"

if ! command -v aws >/dev/null 2>&1; then
  echo "AWS CLI is required." >&2
  exit 1
fi

if ! identity="$(aws sts get-caller-identity --output json 2>&1)"; then
  echo "Could not read the caller identity. Is the session still valid?" >&2
  echo "$identity" >&2
  exit 1
fi

actual_account="$(printf '%s' "$identity" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Account"])')"
caller_arn="$(printf '%s' "$identity" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Arn"])')"

if [[ "$actual_account" != "$expected_account" ]]; then
  echo "Refusing to continue: authenticated to AWS account $actual_account, expected $expected_account." >&2
  echo "Caller: $caller_arn" >&2
  exit 1
fi

echo "AWS account verified: $actual_account"
echo "Caller: $caller_arn"
