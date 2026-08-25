# Scenery, and one genuine lateral-movement target.
#
# Two jobs. The instances exist so `ec2:DescribeInstances` in the home region
# returns a real inventory -- the attack calls it in four regions, and the
# contrast between "three workloads here" and "nothing in sa-east-1" is what makes
# the cross-region discovery read as anomalous rather than merely unusual.
#
# The secret is the other job: `iam-blast-radius` needs an honest answer to "what
# could they reach", and a Secrets Manager entry that `svc-report-runner` is
# allowed to read is what makes the orphaned key worth escalating rather than
# worth noting.
#
# The instances are never started. A stopped instance appears in DescribeInstances
# exactly as a running one does, costs only its EBS volume, and cannot be used for
# anything by anybody -- which is the right trade for scenery.

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-arm64"]
  }
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

locals {
  # Named after workloads a finance-platform team would plausibly run, because
  # these names appear in DescribeInstances output on screen.
  workloads = {
    "report-worker-01" = "Nightly reporting batch"
    "report-worker-02" = "Nightly reporting batch"
    "export-scheduler" = "Triggers the finance export job"
    "invoice-poller"   = "Polls the billing provider for invoices"
    "ledger-sync"      = "Reconciles the general ledger"
  }

  selected = { for name, purpose in local.workloads : name => purpose
  if index(keys(local.workloads), name) < var.instance_count }
}

# No inbound rules at all. These instances run nothing and are reachable by
# nobody; the group exists because an instance needs one, and an empty one is the
# honest expression of that.
resource "aws_security_group" "workload" {
  name        = "${var.name_prefix}-workload"
  description = "No ingress. These instances are inventory, not workloads."
  vpc_id      = data.aws_vpc.default.id

  egress {
    description = "Outbound only, so patching would work if these were ever started."
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-workload" })
}

resource "aws_instance" "workload" {
  for_each = local.selected

  ami                    = data.aws_ami.al2023.id
  instance_type          = var.instance_type
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.workload.id]

  # Costs a few cents a month and keeps the instance metadata service off v1,
  # which is the finding an auditor looks for first and the analyst may notice.
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  root_block_device {
    volume_size = 8
    volume_type = "gp3"
    encrypted   = true
  }

  tags = merge(var.tags, {
    Name    = each.key
    Purpose = each.value
    Owner   = "finance-platform"
  })
}

# The lateral-movement target.
#
# `svc-report-runner` -- the identity the attacker mints a key on -- is allowed to
# read this. That connection is what turns the orphaned key from a loose end into
# a finding: the analyst can say what the uncontained credential could still
# reach, which is the sentence that justifies escalating instead of closing.
#
# The value is invented and structurally plausible. It is a real secret in the
# sense that it is stored as one; it opens nothing.
resource "aws_secretsmanager_secret" "warehouse" {
  name        = "${var.name_prefix}/warehouse-credentials"
  description = "Connection details for the reporting warehouse. Read by the scheduled reporting jobs."

  # Zero rather than the default 30 days. Teardown has to be able to return the
  # account to baseline and then re-apply cleanly; a secret in a recovery window
  # blocks recreation under the same name, which would make the second demo of the
  # week fail in a way nobody would diagnose quickly.
  recovery_window_in_days = 0

  tags = merge(var.tags, { Name = "${var.name_prefix}/warehouse-credentials" })
}

resource "aws_secretsmanager_secret_version" "warehouse" {
  secret_id = aws_secretsmanager_secret.warehouse.id

  # allow-secret-in-state: invented value, opens nothing. The host does not
  # resolve (.invalid is reserved by RFC 2606) and the password is a sentence
  # saying so. A secret has to have a value to exist, and this one exists to be
  # something `svc-report-runner` is permitted to read -- which is what makes the
  # orphaned key worth escalating. Nothing is protected by it.
  secret_string = jsonencode({
    engine   = "postgres"
    host     = "warehouse.internal.acme.invalid"
    port     = 5432
    dbname   = "reporting"
    username = "reporting_ro"
    password = "not-a-real-password-this-opens-nothing"
  })
}
