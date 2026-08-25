variable "name_prefix" {
  type    = string
  default = "serverless-demo"
}

variable "instance_type" {
  type    = string
  default = "t4g.nano"
}

variable "secret_path_prefix" {
  description = "Where the seed puts the freshly minted decoy key for this host to collect. A prefix rather than a fixed name so each run gets its own, and so the instance role can be scoped to the prefix instead of to a wildcard."
  type        = string
  default     = "serverless-demo/leaked-key"
}

variable "tags" {
  type    = map(string)
  default = {}
}
