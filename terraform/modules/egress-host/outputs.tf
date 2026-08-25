output "instance_id" {
  description = "The seed starts this before the attack and teardown stops it. Named so the CLI does not have to discover it by tag on every run."
  value       = aws_instance.egress.id
}

output "public_ip" {
  description = "The alert's source address. Known before the seed runs, which is what lets the answer key be written ahead of time."
  value       = aws_eip.egress.public_ip
}

output "role_arn" {
  value = aws_iam_role.egress.arn
}

output "secret_path_prefix" {
  description = "Where the seed writes the freshly minted decoy key for this host to collect."
  value       = var.secret_path_prefix
}
