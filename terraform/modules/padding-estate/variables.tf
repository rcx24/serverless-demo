variable "name_prefix" {
  type    = string
  default = "serverless-demo"
}

variable "instance_type" {
  description = "Constrained by the organization's SCP to the small list it permits. t4g.nano is the cheapest thing that still appears in DescribeInstances output looking like a real workload."
  type        = string
  default     = "t4g.nano"
}

variable "instance_count" {
  description = "Enough that DescribeInstances in the home region returns an inventory rather than a single row."
  type        = number
  default     = 3

  validation {
    condition     = var.instance_count >= 2 && var.instance_count <= 5
    error_message = "Between two and five. One reads as a fixture; more than five is paying for scenery."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
