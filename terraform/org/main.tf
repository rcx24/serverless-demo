# Root 1 of 3. The Organization and the accounts, applied from the management account.
#
# Applied once, then rarely. Everything it creates is either permanent (the accounts)
# or a guardrail that should not need to change between demos (the SCP).

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.aws_account_id]

  default_tags {
    tags = {
      ManagedBy   = "Terraform"
      Project     = "serverless-demo"
      Repository  = "rcx24/serverless-demo"
      Environment = "org"
    }
  }
}

data "aws_caller_identity" "current" {}

check "target_account" {
  assert {
    condition     = data.aws_caller_identity.current.account_id == var.aws_account_id
    error_message = "Creating an Organization changes the billing and control relationship of every account under it; doing that to an account nobody expected is not recoverable by re-running Terraform."
  }
}

# Adopts the existing Organization instead of proposing a new one.
#
# A declarative import block rather than a documented `terraform import` command,
# so that a fresh clone reaches the right state from `make org` alone. The
# alternative is a prerequisite step in a README, which is a step somebody
# eventually skips -- and the failure mode for skipping it is Terraform trying to
# create a second Organization on an account that already has one.
#
# Terraform ignores this block once the resource is in state, so it is safe to
# leave here permanently.
import {
  to = module.organization.aws_organizations_organization.this
  id = var.organization_id
}

module "organization" {
  source = "../modules/organization"

  demo_account_email   = var.demo_account_email
  egress_account_email = var.egress_account_email
  egress_region        = var.egress_region

  tags = { Component = "organization" }
}

# The $20/month tripwire from the spec, in the management account so it sees
# consolidated spend across the vended accounts. Notifies; does not cap -- the SCP
# and `serverless-demo down` are the real cost controls, this is the backstop for a
# bug that leaves instances running for days.
module "budget" {
  source = "../modules/budget-alarm"

  notify_emails = var.budget_notify_emails
  tags          = { Component = "budget" }
}
