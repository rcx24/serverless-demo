SHELL := /bin/bash

# The management account. Everything in this repository is planned and applied
# from here: the org root creates resources in it directly, and the demo root
# assumes a role from it into the vended account. So this is the identity the
# local guard checks, for both roots.
MGMT_ACCOUNT_ID ?= 429418377902
AWS_PROFILE ?= quiv-source
AWS_REGION ?= us-west-2
TF_DIR ?= terraform/environments/demo
TF_PLAN := tfplan
VENV := .venv

export AWS_PROFILE
export AWS_REGION
export AWS_DEFAULT_REGION := $(AWS_REGION)

.PHONY: help identity fmt contracts test-cli bootstrap bootstrap-migrate org accounts init validate plan apply test clean

help:
	@echo "Targets:"
	@echo "  identity          Verify the local AWS identity is the management account"
	@echo "  fmt               Format all Terraform files"
	@echo "  contracts         Validate the artifact examples against their schemas"
	@echo "  bootstrap         Create the remote-state bucket using local state"
	@echo "  bootstrap-migrate Migrate bootstrap state into the created bucket"
	@echo "  org               Plan and apply the Organization, OUs, SCP and vended accounts"
	@echo "  accounts          Write the vended account ids into the environment roots"
	@echo "  init              Initialize the selected root"
	@echo "  validate          Validate the selected root"
	@echo "  plan              Save a Terraform plan for the selected root"
	@echo "  apply             Apply the previously saved plan"
	@echo "  test              Run every module's terraform test, then the CLI tests"
	@echo ""
	@echo "Defaults: AWS_PROFILE=$(AWS_PROFILE), TF_DIR=$(TF_DIR)"
	@echo "Select another root with: TF_DIR=terraform/org make plan"

identity:
	@./scripts/check-aws-account.sh $(MGMT_ACCOUNT_ID)

fmt:
	terraform fmt -recursive terraform/

contracts:
	@PATH="$(PWD)/$(VENV)/bin:$$PATH" ./scripts/validate-contracts.sh

bootstrap: identity
	terraform -chdir=terraform/bootstrap init
	terraform -chdir=terraform/bootstrap apply

bootstrap-migrate: identity
	@test -f terraform/bootstrap/backend.tf || cp terraform/bootstrap/backend.tf.example terraform/bootstrap/backend.tf
	terraform -chdir=terraform/bootstrap init -migrate-state

# The org root has to be applied before the demo root can plan at all: it writes
# the vended account id into terraform/environments/demo/account.auto.tfvars, and
# the demo root's provider assumes a role in an account that does not exist until
# this has run. Two applies rather than one, because a provider configured from
# an unknown value fails at plan time rather than waiting.
org:
	@$(MAKE) TF_DIR=terraform/org plan
	@$(MAKE) TF_DIR=terraform/org apply

# Hands the vended account ids from the org root to the environment roots. Run
# once after `make org`, then commit what it writes -- the environment roots
# cannot plan without it, because their providers assume a role in an account
# whose id is not otherwise recorded anywhere in the repository.
accounts:
	@./scripts/write-account-tfvars.sh

init: identity
	terraform -chdir=$(TF_DIR) init

validate: init
	terraform -chdir=$(TF_DIR) validate

plan: validate
	terraform -chdir=$(TF_DIR) plan -out=$(TF_PLAN)

# Applies exactly the saved plan and nothing else. A bare `terraform apply` would
# re-plan against whatever the account looks like now, which in a repository that
# deliberately mutates IAM between runs is not the same thing.
apply: identity
	@test -f $(TF_DIR)/$(TF_PLAN) || (echo "Run 'make plan' first." >&2; exit 1)
	terraform -chdir=$(TF_DIR) apply $(TF_PLAN)

test: contracts
	@set -e; for dir in terraform/modules/*/; do \
		if [ -f "$$dir/main.tf" ] && ls "$$dir"/tests/*.tftest.hcl >/dev/null 2>&1; then \
			echo "--- terraform test $$dir"; \
			terraform -chdir="$$dir" init -backend=false >/dev/null; \
			terraform -chdir="$$dir" test; \
		fi; \
	done
	@$(MAKE) test-cli

test-cli:
	@PATH="$(PWD)/$(VENV)/bin:$$PATH" python -m pytest cli -q

clean:
	rm -f $(TF_DIR)/$(TF_PLAN)
