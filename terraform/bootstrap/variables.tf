variable "aws_account_id" {
  description = "The management account. Layer two of the account guard."
  type        = string
  default     = "429418377902"
}

variable "aws_region" {
  description = "Region for the state bucket. Not the demo's home region by coincidence -- state lives with the operator, not with the scenario."
  type        = string
  default     = "us-west-2"
}

variable "name_prefix" {
  description = "Prefixed onto every resource name, as in quiv-iac."
  type        = string
  default     = "serverless-demo"
}
