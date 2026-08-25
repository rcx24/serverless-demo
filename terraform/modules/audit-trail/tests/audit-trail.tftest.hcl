mock_provider "aws" {}

variables {
  exports_bucket_name = "acme-finance-exports"
}

run "object_reads_are_captured_or_half_the_intrusion_is_invisible" {
  command = plan

  assert {
    condition = length([
      for selector in aws_cloudtrail_event_data_store.this.advanced_event_selector :
      selector if anytrue([
        for field in selector.field_selector :
        contains(coalesce(field.equals, []), "Data")
      ])
    ]) == 1
    error_message = "s3:GetObject is a data event and never reaches Event History; a store without a Data selector makes the objects the attacker read permanently invisible rather than merely delayed."
  }
}

run "the_store_sees_every_region" {
  command = plan

  assert {
    condition     = aws_cloudtrail_event_data_store.this.multi_region_enabled
    error_message = "LookupEvents is regional and the attack discovers across regions the org does not use; a single-region store cannot see the clearest signal in the timeline."
  }
}

run "data_events_are_scoped_to_one_bucket" {
  command = plan

  assert {
    condition = anytrue([
      for selector in aws_cloudtrail_event_data_store.this.advanced_event_selector :
      anytrue([
        for field in selector.field_selector :
        field.field == "resources.ARN" && length(coalesce(field.starts_with, [])) > 0
      ])
    ])
    error_message = "Account-wide object logging bills for every read of every bucket; only the exports bucket is part of the story being reconstructed."
  }
}

run "findings_arrive_inside_the_demo_window" {
  command = plan

  assert {
    condition     = aws_guardduty_detector.this[0].finding_publishing_frequency == "FIFTEEN_MINUTES"
    error_message = "The demo seeds at T-30 and asks its first question at T-0; the six-hour default puts every finding on the wrong side of that."
  }
}
