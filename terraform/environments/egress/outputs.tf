output "account_id" {
  value = var.account_id
}

output "instance_id" {
  value = module.egress_host.instance_id
}

output "public_ip" {
  description = "The alert's source address. Known before the seed runs, which is what lets the answer key be written ahead of time."
  value       = module.egress_host.public_ip
}

output "operator_role_arn" {
  value = aws_iam_role.operator.arn
}

output "secret_path_prefix" {
  value = module.egress_host.secret_path_prefix
}
