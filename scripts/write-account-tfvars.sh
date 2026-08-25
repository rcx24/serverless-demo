#!/usr/bin/env bash
# Hands the vended account ids from the org root to the environment roots.
#
# The environment roots' providers assume OrganizationAccountAccessRole in accounts
# that do not exist when the org root is planned. A provider cannot be configured
# from an unknown value, so this cannot be one apply -- it is two, with a file in
# between.
#
# A file rather than `terraform_remote_state` in the provider block. That works
# right up until somebody runs `-refresh=false` or the state moves, and then it
# fails during provider configuration, which is before Terraform can produce a
# readable error. quiv-iac committed `release.auto.tfvars` for the same class of
# reason: Terraform does not remember variable values between runs, so a value
# that is not in the repository is one the next person to clone does not have.
#
# These files are committed. Neither holds a secret -- an AWS account id is not
# one, and it appears in every ARN this repository prints.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if ! outputs="$(terraform -chdir=terraform/org output -json 2>/dev/null)"; then
  echo "Could not read the org root's outputs. Has 'make org' been applied?" >&2
  exit 1
fi

read_output() {
  printf '%s' "$outputs" | python3 -c "
import json, sys
data = json.load(sys.stdin)
key = '$1'
if key not in data:
    sys.exit('missing output: ' + key)
print(data[key]['value'])
"
}

demo_account_id="$(read_output demo_account_id)"
egress_account_id="$(read_output egress_account_id)"

for pair in "demo:$demo_account_id" "egress:$egress_account_id"; do
  env="${pair%%:*}"
  account_id="${pair##*:}"

  if [[ ! "$account_id" =~ ^[0-9]{12}$ ]]; then
    echo "Refusing to write '$account_id' as the $env account id: not 12 digits." >&2
    echo "Account vending is asynchronous. Check organizations:DescribeCreateAccountStatus." >&2
    exit 1
  fi

  target="terraform/environments/$env/account.auto.tfvars"
  mkdir -p "$(dirname "$target")"
  cat > "$target" <<EOF
# Written by scripts/write-account-tfvars.sh from the org root's outputs.
# Committed on purpose: without it, the next person to clone this cannot plan.
# Not a secret -- this id appears in every ARN this repository prints.
account_id = "$account_id"
EOF
  echo "wrote $target ($account_id)"
done

echo
echo "Commit these:"
echo "  git add terraform/environments/*/account.auto.tfvars"
