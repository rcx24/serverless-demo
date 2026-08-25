mock_provider "aws" {}

variables {
  exports_bucket_name = "acme-finance-exports"
}

run "object_reads_are_captured_or_half_the_intrusion_is_invisible" {
  command = plan

  assert {
    condition = length([
      for selector in aws_cloudtrail.this.advanced_event_selector :
      selector if anytrue([
        for field in selector.field_selector :
        contains(coalesce(field.equals, []), "Data")
      ])
    ]) == 1
    error_message = "s3:GetObject is a data event and never reaches Event History; a trail without a Data selector makes the objects the attacker read permanently invisible rather than merely delayed."
  }
}

run "the_trail_sees_every_region" {
  command = plan

  assert {
    condition     = aws_cloudtrail.this.is_multi_region_trail
    error_message = "LookupEvents is regional and the attack discovers across regions the org does not use; a single-region trail cannot see the clearest signal in the timeline."
  }
}

run "data_events_are_scoped_to_one_bucket" {
  command = plan

  assert {
    condition = anytrue([
      for selector in aws_cloudtrail.this.advanced_event_selector :
      anytrue([
        for field in selector.field_selector :
        field.field == "resources.ARN" && length(coalesce(field.starts_with, [])) > 0
      ])
    ])
    error_message = "Account-wide object logging bills for every read of every bucket; only the exports bucket is part of the story being reconstructed."
  }
}

run "events_reach_a_queryable_place" {
  command = plan

  # The trail's log group ARN is derived from a resource the mocked provider
  # leaves unknown, and an unknown cannot be asserted at plan time. Overriding it
  # keeps this a plan test -- an assertion that only runs at apply is one that
  # never runs in CI.
  override_resource {
    target          = aws_cloudwatch_log_group.trail
    values          = { arn = "arn:aws:logs:us-west-2:431662316594:log-group:/aws/cloudtrail/serverless-demo" }
    override_during = plan
  }

  assert {
    condition     = aws_cloudtrail.this.cloud_watch_logs_group_arn != null && aws_cloudtrail.this.cloud_watch_logs_group_arn != ""
    error_message = "Without the CloudWatch integration the only copy of the data events is trail files in S3, and reading those needs the s3:GetObject this demo promises the investigator does not have."
  }
}

run "findings_arrive_inside_the_demo_window" {
  command = plan

  assert {
    condition     = aws_guardduty_detector.this[0].finding_publishing_frequency == "FIFTEEN_MINUTES"
    error_message = "The demo seeds at T-30 and asks its first question at T-0; the six-hour default puts every finding on the wrong side of that."
  }
}
