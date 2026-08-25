output "organization_id" {
  value = aws_organizations_organization.this.id
}

output "demo_account_id" {
  description = "Written to environments/demo/account.auto.tfvars by scripts/write-account-tfvars.sh. The demo root's provider assumes a role in this account, so it cannot plan until this exists."
  value       = aws_organizations_account.demo.id
}

output "egress_account_id" {
  value = aws_organizations_account.egress.id
}

output "demo_ou_id" {
  value = aws_organizations_organizational_unit.demo_security.id
}

output "egress_ou_id" {
  value = aws_organizations_organizational_unit.demo_egress.id
}

output "guardrail_policy_id" {
  description = "The SCP. Shown on screen when somebody asks whether this is your production account."
  value       = aws_organizations_policy.demo_guardrail.id
}
