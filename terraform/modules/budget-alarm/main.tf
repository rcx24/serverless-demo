# The $20/month tripwire from the spec.
#
# A budget notifies; it does not cap. That is worth being clear about: nothing here
# stops spend, it only tells someone. The protection this demo actually relies on
# against runaway cost is the SCP's instance-type restriction and `serverless-demo
# down`. This alarm is the backstop for the case those miss -- a bug that leaves
# instances running for days -- so the failure surfaces as an email, not a bill at
# month end.
#
# Two thresholds: one on actual spend crossing 80%, and one on *forecast* crossing
# 100%. The forecast one is the useful early warning -- it fires when the run rate
# projects past the limit, days before the actual number gets there, which is the
# whole point of catching a stuck instance early.

resource "aws_budgets_budget" "monthly" {
  name         = "${var.name_prefix}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = var.notify_emails
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = var.notify_emails
  }
}
