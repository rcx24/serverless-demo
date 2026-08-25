# Read by scripts/write-account-tfvars.sh and written into the environment roots'
# committed account.auto.tfvars. That handoff is the whole reason these are here.
output "demo_account_id" {
  value = module.organization.demo_account_id
}

output "egress_account_id" {
  value = module.organization.egress_account_id
}

output "organization_id" {
  value = module.organization.organization_id
}

output "guardrail_policy_id" {
  description = "The SCP to show on screen when asked whether this is your production account."
  value       = module.organization.guardrail_policy_id
}
