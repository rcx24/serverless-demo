variable "bucket_name" {
  description = "Deliberately not prefixed with the demo's name. An analyst reads this bucket name on screen while reconstructing what was taken, and `serverless-demo-exports` would tell them they are looking at a fixture."
  type        = string
  default     = "acme-finance-exports"
}

variable "account_id" {
  description = "Appended to the bucket name if unique_suffix is set. S3 bucket names are globally unique, so a fixed name works exactly once across all of AWS."
  type        = string
}

variable "unique_suffix" {
  description = <<-EOT
    Whether to append the account id to the bucket name.

    On by default because `acme-finance-exports` is almost certainly taken, and a
    BucketAlreadyExists failure two modules into an apply is a bad way to find
    out. Turn it off only if you have secured the bare name.
  EOT
  type        = bool
  default     = true
}

variable "tags" {
  type    = map(string)
  default = {}
}
