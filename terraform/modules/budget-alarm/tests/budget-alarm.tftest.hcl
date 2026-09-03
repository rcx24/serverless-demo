mock_provider "aws" {}

variables {
  notify_emails = ["ops@example.invalid"]
}

run "the_limit_is_the_specs_twenty_dollars" {
  command = plan
  assert {
    condition     = aws_budgets_budget.monthly.limit_amount == "20"
    error_message = "The spec sets a $20/month alarm; drifting from it removes the tripwire that catches a seed bug leaving instances running."
  }
}

run "there_is_a_forecast_notification" {
  command = plan
  assert {
    condition = anytrue([
      for n in aws_budgets_budget.monthly.notification : n.notification_type == "FORECASTED"
    ])
    error_message = "A forecast threshold fires days before actual spend crosses the line; without it the warning arrives too late to matter."
  }
}

run "alerts_go_somewhere" {
  command = plan
  assert {
    condition = alltrue([
      for n in aws_budgets_budget.monthly.notification : length(n.subscriber_email_addresses) > 0
    ])
    error_message = "A budget with no subscriber notifies nobody and is decoration."
  }
}
