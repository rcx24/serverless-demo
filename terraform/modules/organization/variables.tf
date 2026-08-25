variable "name_prefix" {
  description = "Prefixed onto every name this module creates."
  type        = string
  default     = "serverless-demo"
}

variable "demo_account_name" {
  type        = string
  description = "Account holding the simulated victim estate. The one the analyst investigates."
  default     = "serverless-demo"
}

variable "demo_account_email" {
  description = <<-EOT
    Root email for the demo account. Plus-addressing off one mailbox is fine and is
    what this expects.

    Read the warning in the README before choosing: an AWS account root email is
    unique across all of AWS, forever, and a closed account does not release it. A
    typo here burns that address permanently.
  EOT
  type        = string
}

variable "egress_account_name" {
  type        = string
  description = "Account holding the attacker host. Deliberately not the demo account -- see README."
  default     = "serverless-demo-egress"
}

variable "egress_account_email" {
  description = "Root email for the egress account. Same permanence warning as demo_account_email."
  type        = string
}

variable "home_region" {
  description = "The region the fictional org operates in. Baseline resources live here."
  type        = string
  default     = "us-west-2"
}

variable "egress_region" {
  description = "Where the attacker host lives. Far from home_region on purpose -- it is what makes the source IP and geo genuinely foreign rather than annotated as foreign."
  type        = string
  default     = "ap-southeast-1"
}

variable "allowed_instance_types" {
  description = "The only instance types either account may launch. The cost guard: this repository runs unattended in CI, and an SCP is the only control that survives a bug in the seed script."
  type        = list(string)
  default     = ["t4g.nano", "t4g.micro", "t3.micro"]
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "aws_service_access_principals" {
  description = <<-EOT
    Service principals granted organization-wide access.

    Reconciled as a set: anything enabled on the account and missing from this
    list is disabled on the next apply. The default preserves what is already on
    rather than expressing what the demo wants, because the demo wants nothing --
    each account gets its own trail and detector, so no organization-level
    integration is required.

    Run `aws organizations list-aws-service-access-for-organization` and match it
    before changing this.
  EOT
  type        = list(string)
  default     = ["sso.amazonaws.com"]
}
