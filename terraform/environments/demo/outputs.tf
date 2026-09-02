output "account_id" {
  value = var.account_id
}

output "exports_bucket_name" {
  value = module.finance_exports.bucket_name
}

output "compromised_user_name" {
  description = "The identity the alert is about. The seed mints its key per run."
  value       = module.decoy_identities.compromised_user_name
}

output "persistence_user_name" {
  description = "The identity the attacker mints a key on and the SOAR never inspects. verify asserts exactly one uncontained key here after a seed run."
  value       = module.decoy_identities.persistence_user_name
}

output "investigator_role_arn" {
  value = module.readonly_connector.role_arn
}

output "investigator_external_id" {
  description = "Goes into the tool catalog entry's credential template. Not a secret in the way a credential is -- useless without the credential it accompanies, and shown on screen alongside the trust policy."
  value       = local.investigator_external_id
  sensitive   = true
}

output "log_group_name" {
  description = "Where the analyst queries the trail. CloudWatch Logs Insights rather than CloudTrail Lake, which AWS closed to new customers."
  value       = module.audit_trail.log_group_name
}

output "seed_admin_role_arn" {
  value = aws_iam_role.seed_admin.arn
}

output "soar_role_arn" {
  value = aws_iam_role.soar.arn
}

output "warehouse_secret_arn" {
  value = module.padding_estate.warehouse_secret_arn
}

# Everything the CLI needs, in one place.
#
# The alternative is nine `terraform output` calls in a shell script, which is
# nine chances for one of them to be renamed and the script to keep working
# against a stale value.
output "demo_config" {
  description = "Written to demo.toml by the CLI so that verify, seed and teardown all read the same facts."
  value = {
    account_id            = var.account_id
    management_account_id = var.management_account_id
    region                = var.aws_region
    exports_bucket        = module.finance_exports.bucket_name
    compromised_user      = module.decoy_identities.compromised_user_name
    persistence_user      = module.decoy_identities.persistence_user_name
    investigator_role_arn = module.readonly_connector.role_arn
    seed_admin_role_arn   = aws_iam_role.seed_admin.arn
    soar_role_arn         = aws_iam_role.soar.arn
    log_group_name        = module.audit_trail.log_group_name
    warehouse_secret_arn  = module.padding_estate.warehouse_secret_arn
  }
}
