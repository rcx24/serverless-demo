# Copied to backend.tf by `make bootstrap-migrate`, after the bucket exists.
#
# `use_lockfile` rather than a DynamoDB table: S3 has native conditional writes now,
# and a lock table is a second resource to create, pay for, and forget to clean up.
terraform {
  backend "s3" {
    bucket       = "serverless-demo-tfstate-429418377902-us-west-2"
    key          = "bootstrap/terraform.tfstate"
    region       = "us-west-2"
    encrypt      = true
    use_lockfile = true
  }
}
