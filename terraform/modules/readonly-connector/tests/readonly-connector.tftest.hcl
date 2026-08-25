# Assertions inline their own jsondecode rather than sharing a local, because a
# .tftest.hcl file cannot declare `locals`. The repetition is the price of the
# assertions living next to the thing they protect.

mock_provider "aws" {}

variables {
  trusted_account_id = "429418377902"
  external_id        = "demo-external-id-long-enough"
  log_group_arn      = "arn:aws:logs:us-west-2:431662316594:log-group:/aws/cloudtrail/serverless-demo"
  exports_bucket_arn = "arn:aws:s3:::acme-finance-exports"
}

run "an_object_can_never_be_read" {
  command = plan

  assert {
    condition = contains(flatten([
      for s in local.investigator_policy.Statement :
      try(tolist(s.Action), [s.Action]) if s.Effect == "Deny"
    ]), "s3:GetObject")
    error_message = "The demo's credibility rests on the analyst proving which objects were read while being unable to read them; an explicit Deny is what survives a later Allow being widened."
  }

  assert {
    condition = !contains(flatten([
      for s in local.investigator_policy.Statement :
      try(tolist(s.Action), [s.Action]) if s.Effect == "Allow"
    ]), "s3:GetObject")
    error_message = "An investigator that can read an object has exfiltrated it a second time."
  }
}

run "a_credential_can_never_be_modified" {
  command = plan

  assert {
    condition = alltrue([
      for action in ["iam:UpdateAccessKey", "iam:DeleteAccessKey", "iam:CreateAccessKey"] :
      contains(flatten([
        for s in local.investigator_policy.Statement :
        try(tolist(s.Action), [s.Action]) if s.Effect == "Deny"
      ]), action)
    ])
    error_message = "An investigator that can disable a key holds the same power as the attacker, and every containment finding becomes a claim about something the harness could have done itself."
  }
}

run "the_trust_requires_an_external_id" {
  command = plan

  assert {
    condition = alltrue([
      for s in local.trust_policy.Statement :
      can(s.Condition.StringEquals["sts:ExternalId"])
    ])
    error_message = "A cross-account trust without an external id is a confused deputy waiting for a caller: a role ARN turns up in logs and screenshots, and on its own it would be enough."
  }
}

run "trail_queries_are_scoped_to_one_log_group" {
  command = plan

  assert {
    condition = alltrue([
      for s in local.investigator_policy.Statement :
      alltrue([for r in s.Resource : r != "*"])
      if s.Effect == "Allow" && contains(try(tolist(s.Action), [s.Action]), "logs:StartQuery")
    ])
    error_message = "StartQuery on * would let this role read a log group somebody adds later for an unrelated purpose."
  }
}

run "the_trail_delivery_bucket_is_not_readable" {
  command = plan

  assert {
    condition = alltrue([
      for s in local.investigator_policy.Statement :
      !contains(try(tolist(s.Action), [s.Action]), "s3:GetObject")
      if s.Effect == "Allow"
    ])
    error_message = "Reading trail files out of the delivery bucket is the shortcut that would trade away this demo's cleanest claim; the log group exists so nobody needs to."
  }
}
