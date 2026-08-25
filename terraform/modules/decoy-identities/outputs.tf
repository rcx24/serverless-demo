output "compromised_user_name" {
  description = "The identity the alert is about. The seed mints its access key per run."
  value       = aws_iam_user.billing_export.name
}

output "compromised_user_arn" {
  value = aws_iam_user.billing_export.arn
}

output "persistence_user_name" {
  description = "The identity the attacker mints a key on and the SOAR never inspects. Named here so the CLI's teardown can find and delete that key, and so verify can assert exactly one uncontained key exists after a seed."
  value       = aws_iam_user.report_runner.name
}

output "persistence_user_arn" {
  value = aws_iam_user.report_runner.arn
}

output "all_user_names" {
  description = "Every identity this module owns. Teardown asserts the account matches this set, so a user left behind by a failed run is a diff rather than a surprise."
  value = concat(
    [aws_iam_user.billing_export.name, aws_iam_user.report_runner.name],
    [for user in aws_iam_user.padding : user.name],
  )
}
