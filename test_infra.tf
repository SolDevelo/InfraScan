resource "aws_instance" "app_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro" # COST-001: Old generation instance
  monitoring    = true       # COST-008: Detailed monitoring

  # CKV_AWS_79 / CKV_AWS_8: IMDSv2 not enforced
  # CKV_AWS_88: public IP enabled
  associate_public_ip_address = true

  root_block_device {
    volume_type = "gp2"        # COST-009: Old generation storage
    volume_size = 500          # COST-016: Oversized root volume
    encrypted   = false        # COST-003 / CKV_AWS_8: unencrypted
  }

  tags = {
    Name = "ExampleAppServerInstance"
  }
}

resource "aws_instance" "db_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "r5.24xlarge" # COST-002: Very expensive instance
  monitoring    = true           # COST-008

  associate_public_ip_address = true # CKV_AWS_88
}

resource "aws_ebs_volume" "example" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted         = false # COST-003 / CKV_AWS_189
  type              = "io1" # COST-004: Provisioned IOPS
  iops              = 3000
}

# ── Networking ─────────────────────────────────────────────────────────────────

# CKV_AWS_25: security group open to the world
resource "aws_security_group" "wide_open" {
  name        = "wide-open"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# COST-005: NAT Gateway (expensive, $32/mo + data)
resource "aws_nat_gateway" "primary" {
  allocation_id = aws_eip.nat.id
  subnet_id     = "subnet-12345678"
}

# COST-006: Unassociated Elastic IP (not attached to any instance)
resource "aws_eip" "orphan" {
  vpc = true
}

resource "aws_eip" "nat" {
  vpc = true
}

# ── Load balancer ──────────────────────────────────────────────────────────────

# COST-019: Load balancer ($16/mo base even when idle)
resource "aws_lb" "main" {
  name               = "main-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.wide_open.id]
  subnets            = ["subnet-12345678", "subnet-87654321"]

  # CKV_AWS_91: access logs not enabled
  # CKV_AWS_150: deletion protection disabled
}

# ── Database ───────────────────────────────────────────────────────────────────

# COST-020: Old generation RDS instance; multiple Checkov violations
resource "aws_db_instance" "main" {
  identifier        = "prod-db"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.m4.xlarge" # COST-020: Old gen
  allocated_storage = 500
  storage_type      = "gp2"          # old storage type

  username = "admin"
  password = "SuperSecret123!"       # CKV_SECRET_6 / hardcoded credentials

  # CKV_AWS_16: storage not encrypted
  storage_encrypted = false

  # CKV_AWS_129: no deletion protection
  deletion_protection = false

  # CKV_AWS_17: not multi-AZ (single point of failure)
  multi_az = false

  skip_final_snapshot = true         # CKV_AWS_133
  publicly_accessible = true         # CKV_AWS_17
}

# ── S3 ─────────────────────────────────────────────────────────────────────────

# COST-010: No lifecycle policy; multiple Checkov violations
resource "aws_s3_bucket" "data" {
  bucket = "my-company-data-bucket"

  # CKV_AWS_20: public ACL
  acl = "public-read"
}

# CKV2_AWS_6 / CKV_AWS_53: public access block missing entirely
# CKV_AWS_19: no server-side encryption
# CKV_AWS_21: no versioning

# ── DynamoDB ───────────────────────────────────────────────────────────────────

# COST-007 + COST-018: Provisioned mode with very high capacity
resource "aws_dynamodb_table" "events" {
  name         = "events"
  billing_mode = "PROVISIONED" # COST-007
  read_capacity  = 1000        # COST-018: High capacity
  write_capacity = 500         # COST-018

  hash_key = "id"

  attribute {
    name = "id"
    type = "S"
  }

  # CKV_AWS_28: no point-in-time recovery
  # CKV_AWS_119: no encryption at rest (uses default AWS key)
}

# ── Lambda ─────────────────────────────────────────────────────────────────────

# COST-021: Over-provisioned Lambda memory (cargo-cult 3008 MB)
resource "aws_lambda_function" "processor" {
  filename      = "lambda.zip"
  function_name = "data-processor"
  role          = aws_iam_role.lambda_exec.arn
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  memory_size   = 3008           # COST-021: max memory, rarely justified

  # CKV_AWS_50: no X-Ray tracing
  # CKV_AWS_117: not in VPC
  # CKV_AWS_272: no code signing
}

# ── API Gateway ────────────────────────────────────────────────────────────────

# COST-022: REST API costs 3.5× more per request than HTTP API
resource "aws_api_gateway_rest_api" "main" {
  name        = "main-api"
  description = "Main application API"
  # CKV_AWS_76: no access log group
  # CKV2_AWS_29: no WAF association
}

# ── IAM ────────────────────────────────────────────────────────────────────────

# CKV_AWS_49 / CKV_AWS_40: wildcard IAM permissions
resource "aws_iam_role" "lambda_exec" {
  name = "lambda-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_full_access" {
  name = "lambda-full-access"
  role = aws_iam_role.lambda_exec.id

  # CKV_AWS_40: policy allows * on all resources
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# ── KMS ────────────────────────────────────────────────────────────────────────

# CKV_AWS_7: key rotation disabled
resource "aws_kms_key" "main" {
  description             = "Main encryption key"
  enable_key_rotation     = false # CKV_AWS_7: rotation off
  deletion_window_in_days = 7
}

# ── CloudWatch ────────────────────────────────────────────────────────────────

# COST-015: Log group without retention → grows forever
resource "aws_cloudwatch_log_group" "app" {
  name = "/app/logs"
  # no retention_in_days
}

resource "aws_cloudwatch_log_group" "access" {
  name = "/app/access"
  # no retention_in_days
}

# ── Route53 ───────────────────────────────────────────────────────────────────

# COST-014: Route53 health check ($0.50/mo each)
resource "aws_route53_health_check" "app" {
  fqdn              = "example.com"
  port              = 80
  type              = "HTTP"
  resource_path     = "/health"
  failure_threshold = 3
  request_interval  = 30
}

# ── Provider (triggers COST-011 and COST-017 inverse rules) ──────────────────

provider "aws" {
  region = "us-east-1"
}

