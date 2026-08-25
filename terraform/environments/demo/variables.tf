variable "account_id" {
  description = "The vended demo account. Written by scripts/write-account-tfvars.sh into the committed account.auto.tfvars, because a provider cannot be configured from a value the org root only knows after apply."
  type        = string
}

variable "management_account_id" {
  description = "Where Terraform runs from, and where the bootstrap user whose credential reaches the harness lives. A credential leaked out of a harness is therefore not even in the account it would be used against."
  type        = string
  default     = "429418377902"
}

variable "aws_region" {
  description = "The region the fictional organization operates in. The contrast between this and the regions the attack touches is most of what makes the timeline anomalous."
  type        = string
  default     = "us-west-2"
}

variable "name_prefix" {
  type    = string
  default = "serverless-demo"
}
