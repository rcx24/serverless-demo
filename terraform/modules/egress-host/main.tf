# The attacker's infrastructure.
#
# In its own account, in a region the fictional organization does not operate in.
# Both of those are load-bearing.
#
# The separate account exists because `ssm:SendCommand` records its `commands`
# parameter in the *caller's* CloudTrail. If this host lived in the demo account,
# the analyst's read-only role would find the entire attack script -- including
# the deliberate CreateAccessKey on svc-report-runner -- sitting in LookupEvents,
# and the investigation would be a single search rather than a reconstruction.
#
# The far region exists because the source IP and its geolocation have to be
# genuinely foreign rather than annotated as foreign. The demo does not fake
# telemetry, so the alert records what this address actually resolves to.
#
# Be honest about what that means on stage: this is an Amazon EIP, so the ASN is
# AS16509 and the geo is wherever this region is. "The attacker used cloud
# infrastructure in a region you don't operate in" is both true and completely
# realistic. Saying it before somebody asks is much better than being asked.

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-arm64"]
  }
}

# No inbound rules. The seed drives this host through SSM Run Command, which is an
# outbound connection from the instance to the SSM service -- so there is nothing
# to open and no key to manage.
#
# That was the reason for choosing Run Command over SSH in the first place: an
# attacker host with port 22 open to the internet, in a demo shown to security
# teams, is a distraction at best.
resource "aws_security_group" "egress" {
  name        = "${var.name_prefix}-egress"
  description = "Outbound only. Driven through SSM, so nothing needs to reach in."
  vpc_id      = data.aws_vpc.default.id

  egress {
    description = "SSM, STS, S3 and IAM endpoints. Everything this host does is outbound."
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${var.name_prefix}-egress" })
}

resource "aws_iam_role" "egress" {
  name = "${var.name_prefix}-egress-host"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = merge(var.tags, { Name = "${var.name_prefix}-egress-host" })
}

# What makes the host reachable by Run Command at all.
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.egress.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# The host collects the leaked key itself rather than being handed it.
#
# `SendCommand` request parameters are recorded in CloudTrail. Passing the decoy's
# secret access key as a command parameter would write the leaked credential into
# the very telemetry this demo is about -- which is both a real leak and a
# self-inflicted spoiler.
#
# Fetching it from Secrets Manager with the instance role also tells a better
# story: the credential leaked *to a host*, which is how this actually happens.
#
# Scoped to the run-id prefix, so this role cannot read any other secret in the
# account.
resource "aws_iam_role_policy" "read_leaked_key" {
  name = "read-leaked-key"
  role = aws_iam_role.egress.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReadThisRunsKey"
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = ["arn:aws:secretsmanager:*:*:secret:${var.secret_path_prefix}/*"]
    }]
  })
}

resource "aws_iam_instance_profile" "egress" {
  name = "${var.name_prefix}-egress-host"
  role = aws_iam_role.egress.name
}

resource "aws_instance" "egress" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.instance_type
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.egress.id]
  iam_instance_profile   = aws_iam_instance_profile.egress.name

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  root_block_device {
    volume_size = 8
    volume_type = "gp3"
    encrypted   = true
  }

  # Terraform brings this into existence; the seed starts it and teardown stops
  # it. There is no lifecycle block for that: `aws_instance` has no configurable
  # state attribute, so a Terraform run between a seed and a teardown has nothing
  # to disagree with the CLI about.

  tags = merge(var.tags, { Name = "${var.name_prefix}-egress" })
}

# A stable address, so the alert's source IP is known before the seed runs and the
# answer key can be written ahead of time.
#
# `--fresh` releases and re-allocates this to vary the source address between
# demos to the same prospect. It stays inside Amazon's ranges either way; see the
# note at the top of this file.
resource "aws_eip" "egress" {
  instance = aws_instance.egress.id
  domain   = "vpc"

  tags = merge(var.tags, { Name = "${var.name_prefix}-egress" })
}
