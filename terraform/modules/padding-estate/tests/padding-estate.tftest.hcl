mock_provider "aws" {}

# A mocked provider returns empty lists for these lookups, and `ids[0]` on an
# empty list is a hard error rather than an unknown -- so without these the plan
# never gets far enough to assert anything. File-level so every run gets them.
override_data {
  target = data.aws_subnets.default
  values = {
    ids = ["subnet-0a1b2c3d4e5f60718"]
  }
}

override_data {
  target = data.aws_vpc.default
  values = {
    id = "vpc-0a1b2c3d4e5f60718"
  }
}

override_data {
  target = data.aws_ami.al2023
  values = {
    id = "ami-0a1b2c3d4e5f60718"
  }
}

run "the_home_region_returns_an_inventory" {
  command = plan

  assert {
    condition     = length(local.selected) >= 2
    error_message = "The attack calls DescribeInstances in four regions; the contrast between real workloads at home and nothing abroad is what makes the cross-region discovery read as anomalous rather than merely unusual."
  }
}

run "the_metadata_service_requires_a_token" {
  command = plan

  assert {
    condition = alltrue([
      for instance in aws_instance.workload : instance.metadata_options[0].http_tokens == "required"
    ])
    error_message = "IMDSv1 is the first thing an auditor looks for and the analyst may well notice it; a demo estate should not fail the check it is demonstrating."
  }
}

run "the_secret_can_be_recreated_the_same_day" {
  command = plan

  assert {
    condition     = aws_secretsmanager_secret.warehouse.recovery_window_in_days == 0
    error_message = "A secret in a recovery window blocks recreation under the same name, so the second demo of the week would fail in a way nobody diagnoses quickly."
  }
}
