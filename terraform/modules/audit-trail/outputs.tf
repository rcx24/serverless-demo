output "log_group_name" {
  description = "Where the analyst queries. CloudTrail Lake would have been the natural home for this, but AWS closed it to new customers -- see the module README."
  value       = aws_cloudwatch_log_group.trail.name
}

output "log_group_arn" {
  description = "Named in the investigator role's logs:StartQuery grant, so the role cannot query a log group somebody adds later for another purpose."
  value       = aws_cloudwatch_log_group.trail.arn
}

output "trail_arn" {
  value = aws_cloudtrail.this.arn
}

output "trail_bucket_name" {
  description = "Delivery target, read by nobody. The investigator queries the log group instead, which is what keeps s3:GetObject off the role entirely."
  value       = aws_s3_bucket.trail.id
}

output "guardduty_detector_id" {
  description = "Null when the detector was not created here. GuardDuty permits one per region, so an account that already had one is adopted rather than duplicated."
  value       = var.enable_guardduty ? aws_guardduty_detector.this[0].id : null
}
