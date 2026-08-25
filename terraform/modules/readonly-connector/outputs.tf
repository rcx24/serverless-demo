output "role_arn" {
  description = "Named in the tool catalog entry's credential template, which is what puts it in the harness's ~/.aws/config."
  value       = aws_iam_role.investigator.arn
}

output "role_name" {
  value = aws_iam_role.investigator.name
}

output "trust_policy_json" {
  description = "Shown on screen during the demo. Every security buyer's first question is what this thing can do in their account, and a two-line answer defuses it before it is asked."
  value       = jsonencode(local.trust_policy)
}

output "permissions_policy_json" {
  description = "The other half of that answer. Read alongside the trust policy."
  value       = jsonencode(local.investigator_policy)
}
