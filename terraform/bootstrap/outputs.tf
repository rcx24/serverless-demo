output "state_bucket" {
  description = "Bucket holding every root's state. Named in each backend block."
  value       = aws_s3_bucket.state.id
}

output "state_region" {
  description = "Region the backend blocks have to name."
  value       = var.aws_region
}
