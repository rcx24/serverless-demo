# The identities the scenario is about, and enough neighbours to make an
# enumeration look like a real organization.
#
# There are no access keys in this module, and that is a deliberate constraint
# rather than an omission. A key created here would live in Terraform state --
# which is an S3 object, readable by anyone with state access, surviving every
# teardown and every `--fresh` run. The decoy's key is minted per run by the seed
# CLI, used for a few minutes, and deleted on teardown. A test asserts no
# `aws_iam_access_key` resource ever appears here.
#
# The padding identities matter more than they look. `iam:ListUsers` and
# `iam:GetAccountAuthorizationDetails` are two of the calls the attack makes, and
# an account containing exactly the two users the story needs reads as a stage
# set. Four unrelated principals with plausible names and plausible policies is
# what makes the enumeration output look like somebody's actual AWS account.

# The compromised identity.
#
# Its policy is written as a real billing-export service account would be: read
# the exports bucket, read Cost Explorer, nothing else. That plausibility is
# load-bearing -- `iam-blast-radius` reads this policy to answer "what could they
# reach", and the honest answer has to be interesting but bounded. An identity
# with AdministratorAccess would make the scenario trivial; one with nothing would
# make it pointless.
resource "aws_iam_user" "billing_export" {
  name = "svc-billing-export"
  path = "/service/"

  tags = merge(var.tags, {
    Name    = "svc-billing-export"
    Purpose = "Nightly finance export to the reporting warehouse"
    Owner   = "finance-platform"
  })
}

resource "aws_iam_user_policy" "billing_export" {
  name = "billing-export"
  user = aws_iam_user.billing_export.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadExports"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [var.exports_bucket_arn, "${var.exports_bucket_arn}/*"]
      },
      {
        Sid      = "ReadCostData"
        Effect   = "Allow"
        Action   = ["ce:Get*", "ce:Describe*", "ce:List*"]
        Resource = ["*"]
      },
    ]
  })
}

# The persistence target.
#
# The attacker calls `iam:CreateAccessKey` against this identity, and the
# simulated SOAR never looks at it. Nothing about this resource encodes that --
# it is an ordinary-looking second service account, which is the point. If it
# were named `svc-persistence-target` the analyst would find it by reading the
# account rather than by following the evidence.
#
# Its policy is deliberately more interesting than the first one. Part of the
# analyst's job is deciding whether the orphaned key matters, and "it can write to
# the exports bucket and read a secret" is a finding worth escalating, where "it
# can do nothing" would not be.
resource "aws_iam_user" "report_runner" {
  name = "svc-report-runner"
  path = "/service/"

  tags = merge(var.tags, {
    Name    = "svc-report-runner"
    Purpose = "Scheduled reporting jobs"
    Owner   = "finance-platform"
  })
}

resource "aws_iam_user_policy" "report_runner" {
  name = "report-runner"
  user = aws_iam_user.report_runner.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteReports"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Resource = [var.exports_bucket_arn, "${var.exports_bucket_arn}/*"]
      },
      {
        Sid      = "ReadWarehouseCredential"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = ["arn:aws:secretsmanager:*:*:secret:${var.name_prefix}/warehouse-*"]
      },
    ]
  })
}

# Neighbours. Present so that enumerating the account returns something that looks
# like an organization rather than a two-prop stage set.
locals {
  padding_users = {
    "svc-backup-agent" = {
      purpose = "Nightly EBS snapshot rotation"
      owner   = "platform-ops"
      actions = ["ec2:CreateSnapshot", "ec2:DescribeSnapshots", "ec2:DeleteSnapshot"]
    }
    "svc-log-shipper" = {
      purpose = "Ships application logs to the SIEM"
      owner   = "security-engineering"
      actions = ["logs:PutLogEvents", "logs:CreateLogStream", "logs:DescribeLogGroups"]
    }
    "svc-invoice-sync" = {
      purpose = "Reconciles invoices with the billing provider"
      owner   = "finance-platform"
      actions = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
    }
  }
}

resource "aws_iam_user" "padding" {
  for_each = local.padding_users

  name = each.key
  path = "/service/"

  tags = merge(var.tags, {
    Name    = each.key
    Purpose = each.value.purpose
    Owner   = each.value.owner
  })
}

resource "aws_iam_user_policy" "padding" {
  for_each = local.padding_users

  name = "inline"
  user = aws_iam_user.padding[each.key].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = each.value.actions
      Resource = ["*"]
    }]
  })
}

# One role as well as users, because a real account has both and because
# `iam:ListRoles` is one of the calls the attack makes. An account whose roles
# list is empty except for AWS service-linked roles is a tell.
resource "aws_iam_role" "deploy" {
  name = "app-deploy"
  path = "/service/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })

  tags = merge(var.tags, {
    Name    = "app-deploy"
    Purpose = "Task role for the reporting application"
    Owner   = "platform-ops"
  })
}
