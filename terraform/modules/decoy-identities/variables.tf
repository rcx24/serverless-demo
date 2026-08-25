variable "name_prefix" {
  type    = string
  default = "serverless-demo"
}

variable "exports_bucket_arn" {
  description = "What the compromised identity is legitimately allowed to read. The decoy's policy has to be a plausible least-privilege service-account policy, because an analyst will read it while working out the blast radius."
  type        = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
