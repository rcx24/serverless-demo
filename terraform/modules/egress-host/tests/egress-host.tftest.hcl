mock_provider "aws" {}

override_data {
  target = data.aws_subnets.default
  values = { ids = ["subnet-0a1b2c3d4e5f60718"] }
}

override_data {
  target = data.aws_vpc.default
  values = { id = "vpc-0a1b2c3d4e5f60718" }
}

override_data {
  target = data.aws_ami.al2023
  values = { id = "ami-0a1b2c3d4e5f60718" }
}

run "the_host_reads_its_own_credential_rather_than_being_handed_one" {
  command = plan

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_role_policy.read_leaked_key.policy).Statement :
      contains(statement.Action, "secretsmanager:GetSecretValue")
    ])
    error_message = "SendCommand records its parameters in CloudTrail; passing the decoy's secret key as a command parameter would write the leaked credential into the telemetry the demo is about."
  }
}

run "the_instance_role_cannot_read_every_secret" {
  command = plan

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_role_policy.read_leaked_key.policy).Statement :
      alltrue([for resource in statement.Resource : resource != "*"])
    ])
    error_message = "An attacker host that can read any secret in its account is a bigger blast radius than the scenario needs."
  }
}

run "the_source_address_is_stable_enough_to_write_down_in_advance" {
  command = plan

  assert {
    condition     = aws_eip.egress.domain == "vpc"
    error_message = "The answer key records the alert's source IP before the seed runs; an address that changes on every stop and start cannot be written down ahead of time."
  }
}
