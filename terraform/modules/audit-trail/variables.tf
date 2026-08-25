variable "name_prefix" {
  type    = string
  default = "serverless-demo"
}

variable "exports_bucket_name" {
  description = "The bucket whose object reads have to be visible to the analyst. Data events are selected by ARN prefix rather than for the whole account, because every object read anywhere would be billed and only this bucket is part of the story."
  type        = string
}

variable "retention_days" {
  description = <<-EOT
    How long the log group keeps events.

    A demo run is investigated within the hour and torn down the same day, so
    nothing here needs to outlive the week. The number is a cost control: this
    repository runs unattended in CI, and CloudWatch Logs bills on both ingest
    and retained storage.
  EOT
  type        = number
  default     = 7

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365], var.retention_days)
    error_message = "CloudWatch Logs accepts only a fixed set of retention values; 7 is the shortest that outlives a demo day."
  }
}

variable "enable_guardduty" {
  description = "Kept as a switch only so the module can be applied into an account where a detector already exists -- GuardDuty permits exactly one per region, and a second is an error rather than a no-op."
  type        = bool
  default     = true
}

variable "tags" {
  type    = map(string)
  default = {}
}
