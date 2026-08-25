# What makes the intrusion visible to the analyst.
#
# Two things, and the split between them matters:
#
#   CloudTrail Lake  queryable history, including S3 object reads
#   GuardDuty        AWS's own opinion about the same behaviour
#
# There is deliberately no classic trail here. Management events are already in
# Event History for 90 days with nothing configured, which is what
# `cloudtrail:LookupEvents` reads and what a real analyst reaches for first. A
# trail would add an S3 bucket of JSON that nobody queries and that the read-only
# role would need `s3:GetObject` to read -- the exact permission this demo
# promises not to have.
#
# Lake exists here for one reason: `s3:GetObject` is a *data* event, and data
# events never appear in Event History at any lag. Without this, the "which
# objects did they take" half of the story is not merely delayed, it is
# permanently invisible. Lake makes those events queryable through
# `cloudtrail:StartQuery`, which is an API the read-only role can hold without
# ever being able to read an object.

resource "aws_cloudtrail_event_data_store" "this" {
  name             = "${var.name_prefix}-events"
  retention_period = var.retention_days

  # Non-negotiable, and the reason is easy to miss: Event History and
  # `LookupEvents` are *regional*. The seeded attack calls `ec2:DescribeInstances`
  # in three or four regions the organization does not use, and those events land
  # only in those regions' histories -- a query in us-west-2 returns none of them.
  # Cross-region discovery is the clearest signal in the whole timeline, so the
  # one store that can see all of it has to be multi-region.
  multi_region_enabled = true

  # One account. The demo account's own activity is the whole subject, and an
  # organization-wide store would pull in the management account's unrelated
  # production traffic for the analyst to wade through.
  organization_enabled = false

  # Off deliberately. `serverless-demo teardown` has to be able to return the
  # account to baseline without a human clicking through a console confirmation,
  # and this store holds nothing that is not reproducible by re-running the seed.
  termination_protection_enabled = false

  # Management events, everywhere, including the read-only calls the attack makes
  # in regions the organization does not use.
  advanced_event_selector {
    name = "Management events"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  # The half that Event History cannot show.
  #
  # Scoped to one bucket by ARN prefix rather than to `AWS::S3::Object` in
  # general. Account-wide object logging would bill for every read of every
  # bucket, and only this one is part of the story the analyst is reconstructing.
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
      starts_with = ["arn:aws:s3:::${var.exports_bucket_name}/"]
    }
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-events" })
}

# AWS's own detection, running on the same behaviour.
#
# This is the credibility multiplier and it is also the part of the demo nobody
# controls: findings in the `Discovery:` and `UnauthorizedAccess:IAMUser/`
# families need behavioural baselining, so a detector switched on the morning of a
# demo may produce nothing at all. Enable it weeks early. The seed reports which
# findings actually fired; nothing in the demo depends on any of them firing.
resource "aws_guardduty_detector" "this" {
  count = var.enable_guardduty ? 1 : 0

  enable = true

  # Fifteen minutes rather than six hours. The demo seeds at T-30 and asks its
  # first question at T-0, so a six-hour publishing interval would put every
  # finding on the wrong side of the demo.
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = merge(var.tags, { Name = "${var.name_prefix}-detector" })
}

# S3 protection, as its own resource.
#
# The `datasources` block on the detector is deprecated in provider 6.x; the
# feature resources are what it was split into. This one earns its place: the
# seeded attack reads objects out of the exports bucket, and without S3 protection
# GuardDuty never looks at S3 data events at all.
resource "aws_guardduty_detector_feature" "s3_data_events" {
  count = var.enable_guardduty ? 1 : 0

  detector_id = aws_guardduty_detector.this[0].id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}
