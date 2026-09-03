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

variable "investigator_external_id" {
  description = <<-EOT
    The external id the AWS connector generated for this connection, if the
    harness reaches this account through the connector.

    Null uses the random one this environment generates, which is what a clone
    with no connection yet wants. Set it to the value shown on the connection's
    page in the product — the connector mints its own and will not accept one,
    so this is the side that adapts.
  EOT
  type        = string
  default     = null

  validation {
    condition     = var.investigator_external_id == null || length(var.investigator_external_id) >= 16
    error_message = "An external id short enough to guess is decoration rather than a control."
  }
}

variable "control_plane_role_arn" {
  description = "The AWS connector's control-plane task role, which assumes the read-only role to deliver credentials to a harness. Null when no connection is wired yet."
  type        = string
  default     = null
}
