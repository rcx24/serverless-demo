variable "name_prefix" {
  type    = string
  default = "serverless-demo"
}

variable "monthly_limit_usd" {
  description = "The dollar ceiling from the spec's §2. Not a billing control -- AWS budgets only notify -- but the tripwire that catches a seed-script bug leaving instances running, which is exactly the failure this repository can produce."
  type        = number
  default     = 20
}

variable "notify_emails" {
  description = "Where budget alerts go. The demo's operators; the same people who vended the accounts."
  type        = list(string)
}

variable "tags" {
  type    = map(string)
  default = {}
}
