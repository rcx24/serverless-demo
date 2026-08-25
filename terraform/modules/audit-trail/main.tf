# What makes the seeded intrusion visible to the analyst.
#
# Three things:
#
#   a trail        capturing management events and S3 object reads
#   CloudWatch Logs where the analyst actually queries them
#   GuardDuty      AWS's own opinion about the same behaviour
#
# This module used to use a CloudTrail Lake event data store, which was the
# natural fit. It is gone: AWS closed Lake to new customers, and
# `CreateEventDataStore` now returns "CloudTrail Lake is no longer accepting new
# customers" in any account that did not already have one. Nothing in the AWS
# provider or the documentation says so up front, so the failure arrives forty
# resources into an apply.
#
# The problem Lake was solving has not gone away. `s3:GetObject` is a *data*
# event, and data events never appear in Event History at any lag -- not delayed,
# absent. Without somewhere to put them, the "which objects did they take" half
# of the story cannot be told at all.
#
# CloudWatch Logs solves it and keeps the property that mattered. The trail
# delivers to a log group, the investigator queries it with Logs Insights, and the
# role needs `logs:StartQuery` rather than `s3:GetObject` -- so the analyst can
# still prove which objects were read while being unable to read one. Reading raw
# trail files out of the delivery bucket would have required exactly the
# permission this demo promises not to have.
#
# It is arguably the better tool for the audience anyway: a SOC analyst has
# written a Logs Insights query before, and has probably never written Lake SQL.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  # Known at plan time, which is what lets other modules' IAM policies be
  # asserted in CI rather than at apply.
  trail_bucket_name = "${var.name_prefix}-trail-${data.aws_caller_identity.current.account_id}"
  log_group_name    = "/aws/cloudtrail/${var.name_prefix}"
}

# Required by CloudTrail, and read by nobody.
#
# A trail has to deliver to S3 whether or not anything reads it. The investigator
# role is never granted access here -- it queries the log group instead, which is
# the whole point of the CloudWatch integration below.
resource "aws_s3_bucket" "trail" {
  bucket        = local.trail_bucket_name
  force_destroy = true

  tags = merge(var.tags, { Name = local.trail_bucket_name })
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket = aws_s3_bucket.trail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.trail.arn, "${aws_s3_bucket.trail.arn}/*"]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
    ]
  })
}

# Where the analyst actually looks.
resource "aws_cloudwatch_log_group" "trail" {
  name              = local.log_group_name
  retention_in_days = var.retention_days

  tags = merge(var.tags, { Name = local.log_group_name })
}

resource "aws_iam_role" "trail_to_logs" {
  name = "${var.name_prefix}-trail-to-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "cloudtrail.amazonaws.com" }
    }]
  })

  tags = merge(var.tags, { Name = "${var.name_prefix}-trail-to-logs" })
}

resource "aws_iam_role_policy" "trail_to_logs" {
  name = "deliver"
  role = aws_iam_role.trail_to_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = ["${aws_cloudwatch_log_group.trail.arn}:*"]
    }]
  })
}

resource "aws_cloudtrail" "this" {
  name           = "${var.name_prefix}-trail"
  s3_bucket_name = aws_s3_bucket.trail.id

  # Non-negotiable, and easy to miss: Event History and `LookupEvents` are
  # *regional*. The seeded attack calls `ec2:DescribeInstances` in three or four
  # regions the organization does not use, and those events land only in those
  # regions' histories -- a query in the home region returns none of them.
  # Cross-region discovery is the clearest signal in the whole timeline.
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.trail_to_logs.arn

  advanced_event_selector {
    name = "Management events"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  # The half Event History cannot show.
  #
  # Scoped to one bucket by ARN prefix rather than to `AWS::S3::Object` in
  # general: account-wide object logging bills for every read of every bucket, and
  # only this one is part of the story being reconstructed.
  advanced_event_selector {
    name = "Object reads on the finance exports bucket"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }

    field_selector {
      field       = "resources.ARN"
      starts_with = ["arn:${data.aws_partition.current.partition}:s3:::${var.exports_bucket_name}/"]
    }
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-trail" })

  depends_on = [aws_s3_bucket_policy.trail]
}

# AWS's own detection, running on the same behaviour.
#
# The credibility multiplier, and the part nobody controls: findings in the
# `Discovery:` and `UnauthorizedAccess:IAMUser/` families need behavioural
# baselining, so a detector switched on the morning of a demo may produce nothing
# at all. Enable it weeks early. The seed reports which findings fired; nothing in
# the demo depends on any of them firing, and it should stay that way.
resource "aws_guardduty_detector" "this" {
  count = var.enable_guardduty ? 1 : 0

  enable = true

  # Fifteen minutes rather than six hours: the demo seeds at T-30 and asks its
  # first question at T-0, so the default would put every finding on the wrong
  # side of it.
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = merge(var.tags, { Name = "${var.name_prefix}-detector" })
}

resource "aws_guardduty_detector_feature" "s3_data_events" {
  count = var.enable_guardduty ? 1 : 0

  detector_id = aws_guardduty_detector.this[0].id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}
