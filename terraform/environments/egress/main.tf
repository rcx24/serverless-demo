# The attacker's account. One host, and the role that lets the seed drive it.
#
# Separate from the demo account for a reason that is easy to miss and expensive
# to discover late: `ssm:SendCommand` records its `commands` parameter in the
# caller's CloudTrail. With this host in the demo account, the analyst's
# read-only role would find the whole attack script -- including the deliberate
# CreateAccessKey on svc-report-runner -- in LookupEvents.

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
      Environment = "egress"
    }
  }
}

data "aws_caller_identity" "current" {}

check "target_account" {
  assert {
    condition     = data.aws_caller_identity.current.account_id == var.account_id
    error_message = "An attacker host applied into the demo account publishes its own script to the analyst through SendCommand's CloudTrail record."
  }
}

module "egress_host" {
  source = "../../modules/egress-host"

  name_prefix = var.name_prefix
  tags        = { Component = "egress-host" }
}

# What the seed CLI assumes to drive the host and stage the leaked key.
resource "aws_iam_role" "operator" {
  name        = "${var.name_prefix}-egress-operator"
  description = "Assumed by the seed CLI to start the host, stage the decoy key, and run the attack sequence."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:aws:iam::${var.management_account_id}:root" }
    }]
  })

  tags = { Component = "egress-host", Name = "${var.name_prefix}-egress-operator" }
}

resource "aws_iam_role_policy" "operator" {
  name = "drive-the-host"
  role = aws_iam_role.operator.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "StartAndStopTheHost"
        Effect   = "Allow"
        Action   = ["ec2:StartInstances", "ec2:StopInstances", "ec2:DescribeInstances", "ec2:DescribeInstanceStatus"]
        Resource = ["*"]
      },
      {
        Sid      = "RunTheAttackSequence"
        Effect   = "Allow"
        Action   = ["ssm:SendCommand", "ssm:GetCommandInvocation", "ssm:ListCommandInvocations", "ssm:DescribeInstanceInformation"]
        Resource = ["*"]
      },
      {
        # The decoy key is staged here for the host to collect, rather than passed
        # as a SendCommand parameter -- see the module README.
        Sid    = "StageTheLeakedKey"
        Effect = "Allow"
        Action = [
          "secretsmanager:CreateSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:DeleteSecret",
          "secretsmanager:DescribeSecret",
          "secretsmanager:ListSecrets",
        ]
        Resource = ["*"]
      },
      {
        Sid      = "VaryTheSourceAddress"
        Effect   = "Allow"
        Action   = ["ec2:AllocateAddress", "ec2:ReleaseAddress", "ec2:AssociateAddress", "ec2:DisassociateAddress", "ec2:DescribeAddresses"]
        Resource = ["*"]
      },
    ]
  })
}
