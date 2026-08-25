# The remote state bucket, and nothing else.
#
# Applied once with local state and then migrated into itself -- the chicken-and-egg
# that every S3 backend has. `backend.tf.example` is copied into place by
# `make bootstrap-migrate` after this has been applied, which is the only ordering
# that works.
#
# Kept in its own root rather than folded into `org` because it has a different
# lifecycle from everything else here: the org root is applied once and then
# rarely, and this is applied once and then never.

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.aws_account_id]

  default_tags {
    tags = {
      ManagedBy   = "Terraform"
      Project     = "serverless-demo"
      Repository  = "rcx24/serverless-demo"
      Environment = "bootstrap"
    }
  }
}

data "aws_caller_identity" "current" {}

check "target_account" {
  assert {
    condition     = data.aws_caller_identity.current.account_id == var.aws_account_id
    error_message = "State for a repository that mints IAM credentials must not be written to an account nobody expected it in."
  }
}

locals {
  # A local rather than a resource attribute, for the reason quiv-iac's object-store
  # gives: it is known at plan time, which is what lets a test assert on it.
  bucket_name = "${var.name_prefix}-tfstate-${var.aws_account_id}-${var.aws_region}"
}

resource "aws_s3_bucket" "state" {
  bucket        = local.bucket_name
  force_destroy = false

  lifecycle {
    prevent_destroy = true
  }
}

# Versioning is the recovery path for a corrupted or truncated state file, which is
# the failure this bucket exists to survive. Not belt-and-braces.
resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket = aws_s3_bucket.state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# State for this repository names the vended account, the connector role, and the
# external id. None of those are secrets on their own, and all of them together are
# a map of the demo account -- so the transport is not optional.
resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.state.arn,
        "${aws_s3_bucket.state.arn}/*",
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}
