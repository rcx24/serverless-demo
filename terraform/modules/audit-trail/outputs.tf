output "event_data_store_arn" {
  description = "Named in the read-only role's cloudtrail:StartQuery grant, and by the CLI's confirmation step. The store is how s3:GetObject becomes visible without anyone holding s3:GetObject."
  value       = aws_cloudtrail_event_data_store.this.arn
}

output "event_data_store_id" {
  value = aws_cloudtrail_event_data_store.this.id
}

output "guardduty_detector_id" {
  description = "Null when the detector was not created here. GuardDuty permits one detector per region, so an account that already had one is adopted rather than duplicated."
  value       = var.enable_guardduty ? aws_guardduty_detector.this[0].id : null
}
