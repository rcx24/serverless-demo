variable "name_prefix" {
  type    = string
  default = "serverless-demo"
}

variable "trusted_principal_arns" {
  description = <<-EOT
    The principals allowed to assume this role, gated by the external id below.

    The AWS connector's control-plane task role is the one the product uses to
    reach this account -- it assumes this role and hands the harness temporary
    credentials, so the harness itself holds no standing access. The operator's
    own account is usually included too, so rehearsal and `verify` can assume the
    same role from a laptop; drop it once the demo runs entirely through the
    product.
  EOT
  type        = list(string)
}

variable "external_id" {
  description = <<-EOT
    Required on every assume. Guards against the confused-deputy problem: knowing
    the role ARN is not enough, the caller has to have been told this too.

    Not a secret in the sense a credential is -- it is useless without the
    credential it accompanies -- which is why it is committed rather than kept in
    Secrets Manager. It is shown on screen during the demo along with the trust
    policy.
  EOT
  type        = string

  validation {
    condition     = length(var.external_id) >= 16
    error_message = "An external id short enough to guess is decoration rather than a control."
  }
}

variable "log_group_arn" {
  description = <<-EOT
    The CloudWatch log group the trail delivers to, and the only place this role
    may query.

    This was a CloudTrail Lake event data store until AWS closed Lake to new
    customers. The property that mattered is unchanged: the investigator can
    prove which objects were read without holding s3:GetObject.
  EOT
  type        = string
}

variable "exports_bucket_arn" {
  description = "The exports bucket. The role may list it and read its policy; it may never read an object out of it."
  type        = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
