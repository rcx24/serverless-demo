# Error messages state a claim about the design rather than restating the assert,
# following quiv-iac's convention. A test that says "region_scoped_actions should
# not contain DescribeInstances" tells the next reader what broke; one that says
# why tells them whether to fix the test or the code.

mock_provider "aws" {}

variables {
  demo_account_email   = "demo@example.invalid"
  egress_account_email = "egress@example.invalid"
}

run "read_only_verbs_are_never_region_restricted" {
  command = plan

  assert {
    condition = length([
      for action in local.region_scoped_actions :
      action if can(regex("^[a-z0-9]+:(Describe|List|Get)", action))
    ]) == 0
    error_message = "Cross-region discovery is the telemetry this demo exists to produce; a region deny on a read-only verb replaces the story with AccessDenied."
  }
}

run "the_guardrail_only_ever_denies" {
  command = plan

  assert {
    condition = alltrue([
      for statement in local.demo_guardrail.Statement : statement.Effect == "Deny"
    ])
    error_message = "Service control policies are deny-by-default; a custom policy carrying an Allow implies FullAWSAccess was replaced rather than subtracted from, which bricks the account."
  }
}

run "the_evidence_cannot_be_switched_off" {
  command = plan

  assert {
    condition = length([
      for statement in local.demo_guardrail.Statement :
      statement if statement.Sid == "ProtectTheEvidence"
    ]) == 1
    error_message = "An account whose trail can be stopped is one where a bad seed run leaves no record of itself."
  }
}

run "accounts_are_vended_into_separate_organizational_units" {
  command = plan

  # A mocked provider returns unknown ids for the OUs, and an unknown compared
  # against an unknown cannot be asserted at plan time. Overriding both with
  # known values is what lets this run as a plan rather than needing an apply --
  # and an assertion that can only run at apply is one that never runs in CI.
  override_resource {
    target          = aws_organizations_organizational_unit.demo_security
    values          = { id = "ou-a1b2-demosec01" }
    override_during = plan
  }

  override_resource {
    target          = aws_organizations_organizational_unit.demo_egress
    values          = { id = "ou-a1b2-demoegr01" }
    override_during = plan
  }

  assert {
    condition     = aws_organizations_account.demo.parent_id != aws_organizations_account.egress.parent_id
    error_message = "SendCommand records its command text in the caller's trail; an attacker host sharing the demo account publishes the attack script to the analyst."
  }
}

run "vended_accounts_survive_a_destroy" {
  command = plan

  assert {
    condition     = aws_organizations_account.demo.close_on_deletion == false
    error_message = "Terraform cannot close an AWS account and closures are capped at 10% per 30 days; an account lost by accident is not one you can recreate on demand."
  }
}
