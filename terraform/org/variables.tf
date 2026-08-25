variable "aws_account_id" {
  description = "The management account. This root runs here and nowhere else."
  type        = string
  default     = "429418377902"
}

variable "aws_region" {
  type    = string
  default = "us-west-2"
}

variable "demo_account_email" {
  description = "Root email for the vended demo account. Permanent -- see modules/organization/README.md."
  type        = string
}

variable "egress_account_email" {
  description = "Root email for the vended egress account. Permanent -- see modules/organization/README.md."
  type        = string
}

variable "egress_region" {
  description = "Where the attacker host lives. Far from the home region on purpose."
  type        = string
  default     = "ap-southeast-1"
}

variable "organization_id" {
  description = <<-EOT
    The Organization to adopt.

    An Organization already exists on the management account and carries live
    infrastructure, so this repository imports it rather than creating one. The
    import block in main.tf is what makes that happen on the first apply instead
    of as a manual `terraform import` somebody has to be told about.

    Find it with `aws organizations describe-organization`.
  EOT
  type        = string
  default     = "o-7pwyf3tc4m"
}
