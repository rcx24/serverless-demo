# The role the harness investigates through, and the answer to the first question
# every security buyer asks.
#
# Two documents, both meant to be read aloud from a shared screen:
#
#   the trust policy   who may assume this, and what else they must know
#   the permissions    exactly what they can do once they have
#
# Both are deliberately short enough to fit on one screen without scrolling. A
# policy that needs scrolling is one the audience takes on trust, and taking it on
# trust is the thing this demo exists to make unnecessary.

data "aws_caller_identity" "current" {}

# Assumable only from the account that holds the bootstrap user, and only by a
# caller that also knows the external id.
#
# The external id is the confused-deputy guard: a role ARN is not a secret and
# turns up in logs, screenshots and support tickets. Requiring a second value that
# was communicated out of band means somebody who learns the ARN still cannot use
# it.
#
# Built with `jsonencode` rather than `aws_iam_policy_document`. The data source
# is nicer to write, but `mock_provider` stubs every data source the provider
# owns -- so a test asserting on `.json` would be asserting on a mock, and the
# policy this module exists to get right would be the one thing never checked.
# quiv-iac states the rule these modules follow: an assertion that can only run
# at apply is an assertion that never runs in CI.
locals {
  trust_policy = {
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AssumeWithExternalId"
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = var.trusted_principal_arns }
      Condition = {
        StringEquals = { "sts:ExternalId" = var.external_id }
      }
    }]
  }
}

locals {
  investigator_policy = {
    Version = "2012-10-17"
    Statement = [
      # Reconstructing what happened.
      #
      # LookupEvents covers management events and is regional, which is why the Lake
      # store below matters: the attack discovers across regions this account does not
      # use, and a single region's Event History sees only its own slice.
      {
        Sid    = "ReadTheTrail"
        Effect = "Allow"
        Action = [
          "cloudtrail:LookupEvents",
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:ListEventDataStores",
          "cloudtrail:GetEventDataStore",
        ]
        Resource = ["*"]
      },

      # Querying object reads without being able to read an object.
      #
      # This is the whole reason the trail delivers to CloudWatch Logs. The
      # objects the attacker read are data events, which never appear in Event
      # History -- and the only other copy is trail files in S3, which would need
      # the `s3:GetObject` denied below to read. Logs Insights closes that gap
      # without opening this one.
      #
      # Scoped to the one log group rather than granted on `*`, so a group
      # somebody adds later for an unrelated purpose is not readable here.
      {
        Sid    = "QueryTheTrail"
        Effect = "Allow"
        Action = [
          "logs:StartQuery",
          "logs:FilterLogEvents",
          "logs:GetLogEvents",
          "logs:DescribeLogStreams",
        ]
        Resource = ["${var.log_group_arn}:*"]
      },

      # GetQueryResults and StopQuery take a query id rather than a log group, so
      # they cannot be resource-scoped. The scoping on StartQuery is what bounds
      # them: a query id can only exist for a group this role was permitted to
      # query in the first place.
      {
        Sid    = "ReadQueryResults"
        Effect = "Allow"
        Action = [
          "logs:GetQueryResults",
          "logs:StopQuery",
          "logs:DescribeQueries",
          "logs:DescribeLogGroups",
        ]
        Resource = ["*"]
      },

      # Enumerating identities. The half of containment verification that finds what
      # the automation missed: every access key on every identity the compromised
      # principal touched, and whether each is still active.
      {
        Sid    = "EnumerateIdentities"
        Effect = "Allow"
        Action = [
          "iam:Get*",
          "iam:List*",
          "iam:GenerateCredentialReport",
          "iam:GenerateServiceLastAccessedDetails",
        ]
        Resource = ["*"]
      },

      # Inventory and posture.
      {
        Sid    = "DescribeTheEstate"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "guardduty:Get*",
          "guardduty:List*",
          "config:Get*",
          "config:Describe*",
          "config:List*",
          "sts:GetCallerIdentity",
          "organizations:DescribeAccount",
          "s3:ListAllMyBuckets",
        ]
        Resource = ["*"]
      },

      # The bucket, but never its contents.
      {
        Sid    = "InspectTheBucketNotTheObjects"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketPolicy",
          "s3:GetBucketAcl",
          "s3:GetBucketLocation",
          "s3:GetBucketVersioning",
          "s3:GetBucketPublicAccessBlock",
        ]
        Resource = [var.exports_bucket_arn]
      },

      # Denied explicitly, not merely unmentioned.
      #
      # `iam:Get*` above already excludes it and no statement grants it, so this Deny
      # changes nothing about what the role can do. It is here to be *visible*: an
      # audience reading a policy cannot see a permission that was never written down,
      # and "we didn't grant it" is a weaker claim than a Deny they can point at.
      #
      # It is also load-bearing against future edits. Someone widening the S3
      # statement to debug a listing problem cannot accidentally grant object reads,
      # because an explicit Deny cannot be overridden by any Allow.
      #
      # The demo's credibility rests on this: the analyst proves which objects were
      # read, from the trail, while being unable to read them.
      {
        Sid    = "NeverReadAnObject"
        Effect = "Deny"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:GetObjectAcl",
        ]
        Resource = ["*"]
      },

      # The other explicit Deny, for the same reason and a sharper one.
      #
      # This role investigates a compromised credential. If it could disable or delete
      # access keys, then the analyst and the attacker would hold the same power, and
      # every containment claim the harness makes would be a claim about something it
      # could have done itself. Read-only about credentials is what keeps the finding
      # trustworthy.
      {
        Sid    = "NeverTouchACredential"
        Effect = "Deny"
        Action = [
          "iam:CreateAccessKey",
          "iam:UpdateAccessKey",
          "iam:DeleteAccessKey",
          "iam:CreateLoginProfile",
          "iam:UpdateLoginProfile",
          "iam:AttachUserPolicy",
          "iam:PutUserPolicy",
          "iam:DeleteUserPolicy",
          "iam:DetachUserPolicy",
        ]
        Resource = ["*"]
      },
    ]
  }
}

resource "aws_iam_role" "investigator" {
  name                 = "${var.name_prefix}-readonly"
  description          = "Read-only investigation role assumed by the Serverless AI harness. Cannot read S3 objects and cannot modify any credential."
  assume_role_policy   = jsonencode(local.trust_policy)
  max_session_duration = 3600

  tags = merge(var.tags, { Name = "${var.name_prefix}-readonly" })
}

resource "aws_iam_role_policy" "investigator" {
  name   = "investigate"
  role   = aws_iam_role.investigator.id
  policy = jsonencode(local.investigator_policy)
}
