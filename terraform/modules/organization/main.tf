# The Organization, the two OUs, their guardrails, and the two vended accounts.
#
# Two accounts rather than one, and the reason is specific rather than tidiness:
# `ssm:SendCommand` records its `commands` parameter in the *caller's* CloudTrail.
# With the attacker host inside the demo account, the analyst's read-only role
# would find the entire attack script sitting in `LookupEvents` -- and the puzzle
# this demo is built around evaporates on the first search. Putting the host in
# its own account is also simply true to the scenario: attacker infrastructure is
# not in your account.

# Adopted, not created.
#
# An Organization already exists on this management account and carries live
# infrastructure. The root module has an `import` block that brings it into state
# rather than proposing a new one, so this resource describes something already
# running -- which is why every attribute below is written to match reality first
# and express intent second.
#
# `aws_service_access_principals` is the attribute to be careful with. Terraform
# reconciles it as a set: anything enabled in the account and absent from this
# list gets *disabled* on the next apply. `sso.amazonaws.com` is not something
# this demo needs; it is here because it is already on, and removing it would
# break sign-in for an organization that was doing fine before this repository
# existed. Check `list-aws-service-access-for-organization` before editing.
#
# Nothing else is added. An organization-wide CloudTrail or GuardDuty would need
# its service principal here, but each account in this demo gets its own trail and
# its own detector -- so the demo needs no organization-level integration at all,
# and asking for one would grant a service the right to create a role in every
# member account for no benefit.
resource "aws_organizations_organization" "this" {
  feature_set = "ALL"

  aws_service_access_principals = var.aws_service_access_principals

  # Not currently enabled at the root -- `list-roots` reports PolicyTypes as
  # empty, which is separate from the organization advertising SCPs as available.
  # Attaching a policy to an OU fails until this is on, and this attribute is the
  # only place Terraform can turn it on.
  enabled_policy_types = ["SERVICE_CONTROL_POLICY"]

  lifecycle {
    # Deleting this would delete the Organization that the management account's
    # existing infrastructure lives under. Terraform is adopting something it did
    # not create; it should not be able to remove it either.
    prevent_destroy = true
  }
}

resource "aws_organizations_organizational_unit" "demo_security" {
  name      = "DemoSecurity"
  parent_id = aws_organizations_organization.this.roots[0].id
  tags      = var.tags
}

resource "aws_organizations_organizational_unit" "demo_egress" {
  name      = "DemoEgress"
  parent_id = aws_organizations_organization.this.roots[0].id
  tags      = var.tags
}

locals {
  allowed_regions = [var.home_region, var.egress_region]

  # Everything below is scoped away from the role Terraform assumes to manage
  # these accounts.
  #
  # SCPs apply to every principal in a member account, and that includes
  # OrganizationAccountAccessRole -- which is how this repository applies the demo
  # and egress roots. Without this exemption the protective denies below would
  # lock Terraform out of the resources it is responsible for creating: the first
  # `terraform apply` that touches the GuardDuty detector would fail, and the
  # error would name the SCP rather than the cause.
  #
  # This does weaken the guardrail, and honestly so: anyone who can assume
  # OrganizationAccountAccessRole is exempt from it. That is an acceptable trade
  # in a disposable demo account whose purpose is to be mutated, and it would not
  # be in a production OU.
  terraform_principal_exemption = {
    ArnNotLike = {
      "aws:PrincipalArn" = "arn:aws:iam::*:role/OrganizationAccountAccessRole"
    }
  }

  # Actions that create something billable. The region condition goes HERE and
  # nowhere else.
  #
  # The trap this avoids: the seeded attack calls `ec2:DescribeInstances` in three
  # or four regions the org does not use, and that cross-region discovery is the
  # single clearest anomaly in the whole timeline -- it is most of why the alert
  # fires at all. A blanket `aws:RequestedRegion` deny across all actions would
  # turn every one of those calls into AccessDenied. Still real telemetry, but a
  # different story: "someone was denied" rather than "someone looked". Read-only
  # verbs must stay permitted in every region, forever. Do not "tighten" this.
  region_scoped_actions = [
    "ec2:RunInstances",
    "ec2:CreateVolume",
    "ec2:AllocateAddress",
    "rds:CreateDBInstance",
    "rds:CreateDBCluster",
    "eks:CreateCluster",
    "elasticache:CreateCacheCluster",
    "sagemaker:CreateNotebookInstance",
    "sagemaker:CreateEndpoint",
    "redshift:CreateCluster",
    "emr:RunJobFlow",
  ]

  # Services with no place in this demo at any size. Denied outright rather than
  # bounded by region, because there is no legitimate call to make.
  forbidden_services = [
    "rds:*",
    "redshift:*",
    "sagemaker:*",
    "bedrock:*",
    "emr:*",
    "eks:*",
    "elasticache:*",
  ]

  demo_guardrail = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DenyLeavingTheOrganization"
        Effect   = "Deny"
        Action   = ["organizations:LeaveOrganization"]
        Resource = "*"
      },
      {
        # The trail and the detector are the demo's evidence. An account that can
        # turn them off is one where a bad seed run leaves no record of itself.
        Sid    = "ProtectTheEvidence"
        Effect = "Deny"
        Action = [
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail",
          "cloudtrail:DeleteEventDataStore",
          "guardduty:DeleteDetector",
          "guardduty:DisassociateFromMasterAccount",
        ]
        Resource  = "*"
        Condition = local.terraform_principal_exemption
      },
      {
        Sid      = "DenyForbiddenServices"
        Effect   = "Deny"
        Action   = local.forbidden_services
        Resource = "*"
      },
      {
        Sid      = "DenyExpensiveCreationOutsideDemoRegions"
        Effect   = "Deny"
        Action   = local.region_scoped_actions
        Resource = "*"
        Condition = {
          StringNotEquals = { "aws:RequestedRegion" = local.allowed_regions }
        }
      },
      {
        Sid      = "DenyOversizedInstances"
        Effect   = "Deny"
        Action   = ["ec2:RunInstances"]
        Resource = "arn:aws:ec2:*:*:instance/*"
        Condition = {
          StringNotEquals = { "ec2:InstanceType" = var.allowed_instance_types }
        }
      },
    ]
  }
}

# FullAWSAccess stays attached to both OUs, and is not managed here.
#
# Service control policies are deny-by-default: an OU carrying only the custom
# policy below would permit nothing at all, and the account would be bricked with
# no way back in except the management account. The custom policy is deny-only for
# exactly this reason -- it subtracts from FullAWSAccess rather than replacing it.
resource "aws_organizations_policy" "demo_guardrail" {
  name        = "${var.name_prefix}-guardrail"
  description = "Cost, region and evidence guardrails for the demo account."
  type        = "SERVICE_CONTROL_POLICY"
  content     = jsonencode(local.demo_guardrail)
  tags        = var.tags
}

resource "aws_organizations_policy_attachment" "demo_security" {
  policy_id = aws_organizations_policy.demo_guardrail.id
  target_id = aws_organizations_organizational_unit.demo_security.id
}

resource "aws_organizations_policy_attachment" "demo_egress" {
  policy_id = aws_organizations_policy.demo_guardrail.id
  target_id = aws_organizations_organizational_unit.demo_egress.id
}

# Vended once, and then reused for the life of the demo.
#
# `prevent_destroy` is not belt-and-braces here. Terraform cannot close an AWS
# account at all: removing this resource detaches it from state and leaves the
# account running and billing. Closure is a console action, and AWS caps it at 10%
# of the organization's accounts per 30 days -- so an account destroyed by
# accident is not something you can simply recreate. `teardown` in the CLI
# restores the estate to baseline; it never touches the account itself.
resource "aws_organizations_account" "demo" {
  name      = var.demo_account_name
  email     = var.demo_account_email
  parent_id = aws_organizations_organizational_unit.demo_security.id

  # The demo account's IAM users are props. None of them should be able to reach
  # billing, and the root user is not used after vending.
  iam_user_access_to_billing = "DENY"
  close_on_deletion          = false

  tags = merge(var.tags, { Name = var.demo_account_name })

  lifecycle {
    prevent_destroy = true
    # The email cannot be changed through this API after creation, and a diff on
    # it would propose a replacement -- which means vending a second account and
    # burning a second address.
    ignore_changes = [email]
  }
}

resource "aws_organizations_account" "egress" {
  name      = var.egress_account_name
  email     = var.egress_account_email
  parent_id = aws_organizations_organizational_unit.demo_egress.id

  iam_user_access_to_billing = "DENY"
  close_on_deletion          = false

  tags = merge(var.tags, { Name = var.egress_account_name })

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [email]
  }
}
