output "instance_ids" {
  description = "Every instance this module owns. Teardown asserts the account matches, so an instance left running by a failed apply shows up as a diff rather than on next month's bill."
  value       = [for instance in aws_instance.workload : instance.id]
}

output "instance_names" {
  value = sort(keys(local.selected))
}

output "warehouse_secret_arn" {
  description = "The lateral-movement target. svc-report-runner is permitted to read this, which is what turns the orphaned key from a loose end into a finding worth escalating."
  value       = aws_secretsmanager_secret.warehouse.arn
}
