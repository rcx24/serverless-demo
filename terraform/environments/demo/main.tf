# The victim estate. Everything the analyst investigates lives here.
#
# Applied from the management account by assuming OrganizationAccountAccessRole,
# which Organizations creates in every vended account. That is why `make identity`
# still checks for the *management* account: the credential Terraform starts with
# is there, and the identity it ends up with is not. The provider's
# allowed_account_ids and the check block below assert the second half.

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.account_id]

  assume_role {
    role_arn     = "arn:aws:iam::${var.account_id}:role/OrganizationAccountAccessRole"
    session_name = "serverless-demo-terraform"
  }

  default_tags {
    tags = {
      ManagedBy   = "Terraform"
      Project     = "serverless-demo"
      Repository  = "rcx24/serverless-demo"
      Environment = "demo"
    }
  }
}

data "aws_caller_identity" "current" {}

check "target_account" {
  assert {
    condition     = data.aws_caller_identity.current.account_id == var.account_id
    error_message = "This root mints nothing but it creates the identities a seed run will mint keys for; applying it to an account nobody expected leaves decoy service accounts in somebody's real estate."
  }
}

# Which external id the investigator role actually requires.
#
# This used to be only the random one above, generated here and read out of the
# Terraform output into demo.toml. That direction is backwards once the harness
# connects through the product's AWS connector rather than a tool-catalog
# credential template: the connector generates an external id with a CSPRNG at
# connection-create time and deliberately never accepts one from a caller, so
# that somebody who already knew a victim's value cannot stand a connection up
# against it. The customer's side is what adapts.
#
# So the connector's value wins when there is one, and the random fallback keeps
# a fresh clone able to plan and apply without a connection existing first.
#
# Changing it updates the role's trust policy in place — no replacement, so the
# role ARN in demo.toml stays valid and the seed CLI keeps working once
# configsync has re-read the outputs.
# A generated fallback external id, used when no AWS connection is wired yet -- a
# fresh clone can still stand up the role and assume it from a laptop. Once the
# product's connector is connected, its own external id is set in
# connector.auto.tfvars and takes precedence via the coalesce below.
resource "random_password" "external_id" {
  length  = 32
  special = false
}

locals {
  investigator_external_id = coalesce(var.investigator_external_id, random_password.external_id.result)
}

module "finance_exports" {
  source = "../../modules/finance-exports"

  account_id = var.account_id
  tags       = { Component = "finance-exports" }
}

module "decoy_identities" {
  source = "../../modules/decoy-identities"

  name_prefix        = var.name_prefix
  exports_bucket_arn = module.finance_exports.bucket_arn
  tags               = { Component = "decoy-identities" }
}

module "padding_estate" {
  source = "../../modules/padding-estate"

  name_prefix = var.name_prefix
  tags        = { Component = "padding-estate" }
}

module "audit_trail" {
  source = "../../modules/audit-trail"

  name_prefix         = var.name_prefix
  exports_bucket_name = module.finance_exports.bucket_name
  tags                = { Component = "audit-trail" }
}

module "readonly_connector" {
  source = "../../modules/readonly-connector"

  name_prefix = var.name_prefix
  # The connector's control-plane task role (present once a connection exists) plus
  # the operator account for rehearsal. compact() drops the control-plane entry
  # when no connection is wired yet, so a fresh clone still trusts the operator.
  trusted_principal_arns = compact([
    var.control_plane_role_arn,
    "arn:aws:iam::${var.management_account_id}:root",
  ])
  external_id        = local.investigator_external_id
  log_group_arn      = module.audit_trail.log_group_arn
  exports_bucket_arn = module.finance_exports.bucket_arn
  tags               = { Component = "readonly-connector" }
}

# What the seed CLI assumes to do its work.
#
# A separate identity from the SOAR role below, and both separate from the
# investigator. The reason is legibility rather than least privilege: every action
# these take lands in the same CloudTrail the analyst reads, and an account where
# the attacker, the automation and the operator all share one principal is one
# where the timeline cannot be told apart.
resource "aws_iam_role" "seed_admin" {
  name        = "${var.name_prefix}-seedadmin"
  description = "Assumed by the seed CLI to mint the decoy key and manage run state."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:aws:iam::${var.management_account_id}:root" }
    }]
  })

  tags = { Component = "operator-roles", Name = "${var.name_prefix}-seedadmin" }
}

resource "aws_iam_role_policy" "seed_admin" {
  name = "seed"
  role = aws_iam_role.seed_admin.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ManageDecoyCredentials"
        Effect = "Allow"
        Action = [
          "iam:CreateAccessKey",
          "iam:DeleteAccessKey",
          "iam:UpdateAccessKey",
          "iam:ListAccessKeys",
          "iam:GetAccessKeyLastUsed",
          "iam:GetUser",
          "iam:ListUsers",
        ]
        Resource = ["*"]
      },
      {
        Sid      = "ReadTheTrail"
        Effect   = "Allow"
        Action   = ["cloudtrail:LookupEvents", "cloudtrail:StartQuery", "cloudtrail:GetQueryResults", "cloudtrail:DescribeQuery"]
        Resource = ["*"]
      },
      {
        Sid      = "ReportFindings"
        Effect   = "Allow"
        Action   = ["guardduty:ListFindings", "guardduty:GetFindings", "guardduty:ListDetectors"]
        Resource = ["*"]
      },
      {
        Sid      = "InspectBaseline"
        Effect   = "Allow"
        Action   = ["ec2:Describe*", "s3:ListBucket", "s3:ListAllMyBuckets", "secretsmanager:ListSecrets", "sts:GetCallerIdentity"]
        Resource = ["*"]
      },
    ]
  })
}

# What the simulated SOAR assumes.
#
# Separate from the seed role so that the containment actions appear in CloudTrail
# under a principal named after automation. The analyst reads that distinction
# while working out what was already done, and it costs one role to make it true
# rather than merely claimed.
resource "aws_iam_role" "soar" {
  name        = "${var.name_prefix}-soar"
  description = "Assumed by the simulated SOAR playbook to contain the alerting identity."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:aws:iam::${var.management_account_id}:root" }
    }]
  })

  tags = { Component = "operator-roles", Name = "${var.name_prefix}-soar" }
}

resource "aws_iam_role_policy" "soar" {
  name = "contain"
  role = aws_iam_role.soar.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ContainAnIdentity"
      Effect = "Allow"
      Action = [
        "iam:PutUserPolicy",
        "iam:DeleteUserPolicy",
        "iam:UpdateAccessKey",
        "iam:ListAccessKeys",
        "iam:GetUser",
      ]
      Resource = ["*"]
    }]
  })
}
