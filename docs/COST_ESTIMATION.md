# Cost Estimation

InfraScan estimates monthly AWS infrastructure cost directly from Terraform source files —
no credentials, no network access, no external tools required.

Two things are calculated for each scan:

- **Savings estimate** — how much could be saved by fixing the cost findings InfraScan flagged
- **Total infrastructure cost** — a bottom-up monthly cost for every billable resource in the repo

---

## Savings estimate

Each cost rule (`COST-001`, `COST-004`, etc.) fires on a specific Terraform resource. When it
does, InfraScan calculates what that configuration decision costs versus the recommended
alternative.

The report shows a **range** — `$low – $high / month` — rather than a single number. For
straightforward optimisations the two ends are equal (you know exactly what you'll save). For
uncertain ones, `low = $0` to avoid overstating the benefit.

Rules where `low = $0`:

| Rule | Why savings are uncertain |
|---|---|
| COST-005 — NAT Gateway exists | The gateway may be necessary; eliminating it requires replacing all internet-bound traffic with VPC endpoints, which may not be feasible |
| COST-007 — DynamoDB provisioned capacity | Switching to on-demand billing can cost *more* under sustained load |
| COST-027 — Missing VPC endpoints | The fraction of NAT traffic that goes to S3/DynamoDB is unknown from config alone |

For rules that represent a fleet-wide change (COST-012 — EC2 Spot instances), the saving is
counted once for the entire account, not multiplied per instance.

When multiple rules fire on the same resource, their combined savings are capped at that
resource's estimated monthly cost — so you can never save more than the resource costs.

### Supported cost rules

| Rule | What it detects | Confidence |
|---|---|---|
| COST-001 | EC2 previous-generation instance (upgrade to current gen) | High |
| COST-004 | io1/io2 EBS volume that could use gp3 | High |
| COST-005 | NAT Gateway present (consider VPC endpoints) | Low |
| COST-006 | Unassociated Elastic IP | High |
| COST-007 | DynamoDB provisioned capacity (consider on-demand) | Low |
| COST-008 | EC2 detailed monitoring enabled | High |
| COST-009 | gp2 EBS volume (upgrade to gp3) | High |
| COST-012 | No Spot instances in the fleet | Medium |
| COST-014 | Unnecessary Route53 health checks | High |
| COST-015 | CloudWatch Log group with no retention policy | Medium |
| COST-020 | RDS previous-generation instance | High |
| COST-021 | Lambda function over-provisioned memory | Medium |
| COST-022 | API Gateway REST API (consider HTTP API) | Medium |
| COST-024 | RDS Multi-AZ in what looks like a non-production environment | High |
| COST-025 | ECS task definition with no CPU/memory limits | Low |
| COST-026 | Multiple NAT Gateways in the same VPC | High |
| COST-027 | S3/DynamoDB traffic routed through NAT instead of VPC endpoints | Low |

Rules COST-003, COST-010, COST-011, COST-017, and COST-023 are governance signals with no
direct cost delta — they show `$0` in the savings column.

---

## Total infrastructure cost

Every resource block in the Terraform files is matched against a list of supported resource
types. For each one, InfraScan calculates two figures:

- **Min cost** — fixed charges only, assuming zero traffic. This is the floor: what you pay
  just for the resource existing.
- **Expected cost** — fixed charges plus estimated usage at the detected traffic profile.

For resources that are purely pay-per-use (Lambda, CloudWatch Logs), min cost is `$0`.

### Traffic profiles

Because usage-based charges — data transfer, invocations, storage GB — aren't visible in
Terraform config, InfraScan uses defaults that scale with the apparent size of the
infrastructure.

It auto-detects one of three profiles:

| Profile | Rough signal |
|---|---|
| **Small** | A handful of services, no large instances |
| **Medium** | Dozens of services, a few NAT gateways or load balancers |
| **Large** | Many EC2 instances, large instance types, significant data infrastructure |

The profile sets total environment-level defaults (e.g. total NAT data transfer per day), which
are then divided evenly across the relevant resource count so each instance gets a per-resource
share.

Pricing comes from a static table (`us-east-1`, on-demand Linux, updated per release). Reserved
Instance or Savings Plan discounts are not modelled.

### Supported resource types

| Resource type | What's priced |
|---|---|
| `aws_instance` | On-demand instance + root EBS volume |
| `aws_db_instance` | RDS on-demand (doubled for Multi-AZ) |
| `aws_rds_cluster_instance` | Aurora on-demand |
| `aws_ebs_volume` | Storage GB + provisioned IOPS if io1/io2 |
| `aws_nat_gateway` | Hourly charge + data processing |
| `aws_eip` | Hourly charge when unattached |
| `aws_lb` / `aws_alb` / `aws_elb` | Hourly base + LCU charge from estimated data |
| `aws_lambda_function` | GB-seconds + request count |
| `aws_cloudwatch_log_group` | Ingestion + storage (based on retention setting) |
| `aws_cloudwatch_metric_alarm` | Per-alarm flat rate |
| `aws_cloudwatch_dashboard` | Per-dashboard flat rate |
| `aws_s3_bucket` | Standard storage GB |
| `aws_dynamodb_table` | Provisioned RCU/WCU (on-demand tables show $0 fixed) |
| `aws_ecs_task_definition` | Fargate vCPU + memory |
| `aws_eks_cluster` | Control plane hourly charge |
| `aws_elasticache_cluster` | Node type × node count |
| `aws_elasticache_replication_group` | Node type × node count |
| `aws_msk_cluster` | Broker type × broker count |
| `aws_opensearch_domain` / `aws_elasticsearch_domain` | Instance type × node count |
| `aws_redshift_cluster` | Node type × node count |
| `aws_secretsmanager_secret` | Per-secret monthly fee + API requests |
| `aws_vpc_endpoint` (Interface) | Hourly charge + data processing |
| `aws_vpc_endpoint` (Gateway) | Free |
| `aws_wafv2_web_acl` | Per-ACL flat rate |
| `aws_sfn_state_machine` | State transitions |
| `aws_api_gateway_rest_api` | Per-request pricing |
| `aws_apigatewayv2_api` | Per-request pricing |
| `aws_kinesis_stream` | Per-shard hourly |
| `aws_route53_health_check` | Per-check flat rate |
| `aws_route53_zone` | Per-zone flat rate |
| `aws_kms_key` | Per-key flat rate |
| `aws_efs_file_system` | Standard storage GB |
| `aws_ec2_transit_gateway` | Hourly (per attachment) |
| `aws_ec2_transit_gateway_vpc_attachment` | Hourly + data processing |
| `aws_ecr_repository` | Image storage GB |
| `aws_cloudfront_distribution` | HTTPS requests + transfer out |

Resources that are free or configuration-only (IAM roles and policies, VPCs, subnets, security
groups, route tables, ACM certificates, Route53 records, SSM parameters, and many others) are
counted as covered but contribute $0 to the total.

---

## Block parsing

Terraform files are parsed with **python-hcl2** — the same HCL library used by Checkov.
This replaces the previous regex-based block extractor and gives:

- Correct block boundary detection (no false positives from comments or multi-line strings)
- Structured attribute values (integers, booleans, dicts) rather than raw text
- Reliable `count` and `for_each` extraction

If hcl2 raises a parse error on a file (e.g. unsupported syntax), the file falls back
to the regex extractor so no resources are silently dropped.

---

## Variable resolution

Attribute values that contain `${var.foo}` or `${local.foo}` expressions are resolved
at parse time, before any cost function sees them.  Resolution sources (highest to lowest
precedence):

1. **`terraform.tfvars` and `*.auto.tfvars`** — auto-loaded var files in Terraform's own
   precedence order: `*.auto.tfvars` → `*.auto.tfvars.json` → `terraform.tfvars` →
   `terraform.tfvars.json`.
2. **`variable {}` defaults** — `default` values from every `variable` block in the
   directory's `.tf` files.  tfvars override these (matching real Terraform behaviour).
3. **`locals {}` blocks** — assignments resolved transitively up to depth 5.
   For ternary expressions (`condition ? a : b`), the else branch is used as the
   conservative fallback.
4. **Adjacent JSON data files** — any `*.json` file in the directory.
   For nested structures like `accounts[env].ec2_instance_type`, InfraScan tries the
   account key `production` (or `prod`, `preproduction`) as the environment fallback.

Once an expression is resolved to a concrete string or number, the content seen by the cost
function contains the literal value so existing attribute regex patterns still match.

When a value is found by resolution (not a literal in the source), confidence is `medium`.
When nothing resolves, a floor of **$50/mo** per EC2 instance and **$100/mo** per RDS
instance is used and confidence is `low`.

---

## count and for_each multipliers

Resource cardinality is derived in priority order:

1. **`for_each` literal dict/set** — `for_each = {"a" = …, "b" = …}` → 2 instances.
   `for_each = toset(["dev", "staging", "prod"])` → 3 instances.
   Both are detected from the hcl2-parsed structure with `confidence = "high"`.
2. **`count` integer** — literal `count = 3` from hcl2 attrs → 3 instances, `"high"`.
3. **`count` variable reference** — `count = var.replica_count` → InfraScan resolves
   via tfvars / variable defaults; if resolved, `confidence = "medium"`.
4. **Default** — 1 instance.

The assumption `count=N` is appended to the resource's assumption list whenever `N > 1`.
`for_each` with a variable reference (`for_each = var.environments`) cannot be statically
counted and falls back to 1.

---

## Limitations

- **Complex chained expressions** — attribute values like
  `local.data.accounts[local.env].instance_type` are not resolved. InfraScan
  handles simple `${var.foo}` and `${local.foo}` substitutions only. Resources
  using such expressions fall back to the price floor.
- **`for_each` with variable references** — `for_each = var.environments` cannot
  be counted statically; the resource is costed as a single instance.
- **Root module detection** — cost scanning is restricted to *root modules*: directories
  that contain a `provider "..." { }` block or a `terraform { backend "..." { } }` block.
  Shared module libraries (which only have `terraform { required_providers {} }`) are
  excluded from cost estimation. COST-* security rules are similarly suppressed for
  non-root-module directories to avoid phantom findings.
- **Excluded directories** — the following directories are never scanned for cost:
  `.git`, `.terraform`, `.terragrunt-cache`, `docs`, `doc`, `documentation`,
  `test`, `tests`, `testing`, `examples`, `example`, `fixtures`, `fixture`,
  `scripts`, `node_modules`. Security scanning is unaffected.
- **Variable defaults vs actual values** — `variable {}` defaults are used when no
  tfvars override is present. Production deployments often override defaults with
  larger instance types, so estimates based on defaults may under-count real costs.
- Prices are for `us-east-1` on-demand Linux. Other regions and purchasing options
  are not modelled.
- Inter-AZ and internet egress costs are not included except where they are part of
  a specific resource's charge (NAT gateway data processing, TGW attachment data,
  CloudFront transfer out).
- Remote modules (sourced from a registry or URL) are only included if already
  downloaded into `.terraform/`.
