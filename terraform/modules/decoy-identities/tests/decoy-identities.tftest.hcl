mock_provider "aws" {}

variables {
  exports_bucket_arn = "arn:aws:s3:::acme-finance-exports"
}

run "the_compromised_identity_looks_like_a_real_service_account" {
  command = plan

  assert {
    condition = alltrue([
      for statement in jsondecode(aws_iam_user_policy.billing_export.policy).Statement :
      statement.Resource != ["*"] || statement.Sid == "ReadCostData"
    ])
    error_message = "iam-blast-radius reads this policy to answer what the attacker could reach; an identity with wildcard access makes the scenario trivial and one with nothing makes it pointless."
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
