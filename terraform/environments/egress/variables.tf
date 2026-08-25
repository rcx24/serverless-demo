variable "account_id" {
  description = "The vended egress account. Separate from the demo account because ssm:SendCommand records its command text in the caller's CloudTrail."
  type        = string
}

variable "management_account_id" {
  type    = string
  default = "429418377902"
}

variable "aws_region" {
  description = "Far from the demo's home region on purpose. This is what makes the source IP and its geolocation genuinely foreign rather than annotated as foreign."
  type        = string
  default     = "ap-southeast-1"
}

variable "name_prefix" {
  type    = string
  default = "serverless-demo"
}
