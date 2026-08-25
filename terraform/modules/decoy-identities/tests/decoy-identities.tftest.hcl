mock_provider "aws" {}

variables {
  exports_bucket_arn = "arn:aws:s3:::acme-finance-exports"
}

run "the_compromised_identity_can_run_the_attack_but_is_not_admin" {
  command = plan

  # The scenario needs this key to enumerate, read the finance data, and mint a
  # credential on another identity. A pure S3-read key cannot be the subject of
  # this breach, and an admin key makes it trivial. So the assertion is two-sided:
  # the persistence action must be grantable, and full administrative access must
  # not be.
  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_user_policy.billing_export.policy).Statement :
      contains(statement.Action, "iam:CreateAccessKey")
    ])
    error_message = "The attack establishes persistence with iam:CreateAccessKey; without this grant the compromised key cannot, and there is no orphaned key for the harness to find."
  }

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_user_policy.billing_export.policy).Statement :
      !contains(statement.Action, "*") && !contains(statement.Action, "iam:*")
    ])
    error_message = "An identity with AdministratorAccess makes the scenario trivial; the over-permission is specific grants that accumulated, not a wildcard."
  }
}

run "the_persistence_target_is_worth_escalating" {
  command = plan

  assert {
    condition = length([
      for statement in jsondecode(aws_iam_user_policy.report_runner.policy).Statement :
      statement if contains(statement.Action, "secretsmanager:GetSecretValue")
    ]) == 1
    error_message = "Part of the analyst's job is deciding whether the orphaned key matters; a target that can reach nothing turns the finding into a curiosity."
  }
}

run "the_account_does_not_read_as_a_stage_set" {
  command = plan

  assert {
    condition     = length(aws_iam_user.padding) >= 3
    error_message = "ListUsers and GetAccountAuthorizationDetails are two of the calls the attack makes; an account holding only the two identities the story needs is visibly staged."
  }
}
