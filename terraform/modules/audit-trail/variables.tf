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
    How long the event data store keeps events. Seven is the floor AWS allows.

    A demo run is investigated within the hour and torn down the same day, so
    nothing here needs to outlive the week. The number is a cost control: Lake
    bills on ingest and on retained storage, and this repository is expected to
    run unattended in CI.
  EOT
  type        = number
  default     = 7

  validation {
    condition     = var.retention_days >= 7 && var.retention_days <= 3653
    error_message = "CloudTrail Lake retention is 7 to 3653 days."
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
