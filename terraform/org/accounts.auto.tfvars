# Root emails for the two vended accounts.
#
# Committed deliberately. These are not secrets, and an AWS account root email is
# permanently consumed by the account it creates -- so the record of which
# addresses were burned has to outlive whoever ran the apply. Terraform also does
# not remember variable values between runs, and `email` carries `ignore_changes`
# because the API cannot change it after creation: a value missing here would
# propose replacing the account, which means vending a second one and burning a
# second address.
#
# Root is break-glass only. Day-to-day access to both accounts is by assuming
# OrganizationAccountAccessRole from the management account.
demo_account_email   = "ryan+serverless-demo@getserverless.ai"
egress_account_email = "alex+serverless-demo@getserverless.ai"
