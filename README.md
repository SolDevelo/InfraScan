# InfraScan

**Open-source infrastructure auditing platform.**

[![Verified by InfraScan](https://img.shields.io/badge/Verified_by-SolDevelo_InfraScan-0052cc?style=flat&logo=security)](https://github.com/soldevelo/infrascan)
[![Docker Pulls](https://img.shields.io/docker/pulls/soldevelo/infrascan.svg?style=flat-square)](https://hub.docker.com/r/soldevelo/infrascan)
[![Docker Image Size](https://img.shields.io/docker/image-size/soldevelo/infrascan/latest?style=flat-square)](https://hub.docker.com/r/soldevelo/infrascan)
[![GitHub stars](https://img.shields.io/github/stars/soldevelo/infrascan?style=flat-square&logo=github)](https://github.com/soldevelo/infrascan/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/soldevelo/infrascan?style=flat-square)](https://github.com/soldevelo/infrascan/issues)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](https://github.com/soldevelo/infrascan/blob/main/LICENSE)

InfraScan helps engineering teams detect cloud cost waste, security risks, and container vulnerabilities directly in CI/CD - before infrastructure reaches production.

✅ Fully open-source and auditable  
✅ Runs locally or inside your pipelines  
✅ No vendor lock-in  
✅ Transparent grading and rules  
✅ Built for Terraform, Kubernetes, Helm, CloudFormation, Ansible, and containers

Unlike closed SaaS scanners, InfraScan executes entirely in your environment, making it suitable for security-conscious and regulated organizations.

## 🚀 Quick Start: GitHub Action

The fastest way to integrate InfraScan into your repository is using our official GitHub Action. Add this to `.github/workflows/infrascan.yml`:

```yaml
name: InfraScan Security Audit
on: [push, pull_request]

permissions:
  pull-requests: write   # enables automatic PR comments

jobs:
  infrascan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run InfraScan
        uses: soldevelo/infrascan@v1.0.10
        with:
          scanner: comprehensive
          format: html
          out: infrascan-report.html
          fail-on: high_critical

      - name: Upload HTML Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: infrascan-report
          path: infrascan-report.html
```

With `permissions: pull-requests: write`, the action automatically:
- Posts a **PR comment** on every PR with the grade table, cost estimate, and new CRITICAL findings
- Writes a **step summary** visible in the workflow run's Summary tab
- Emits **inline annotations** on the changed files in the PR diff
- **Skips the scan** on PRs where no IaC or container files were changed

No extra inputs are required — all new behaviour is on by default. See [docs/GITHUB_ACTION.md](docs/GITHUB_ACTION.md) for all inputs, outputs, the baseline/delta workflow, and upgrade notes for existing workflows.

## 📦 Installation

In order to use InfraScan from the CLI, Docker is required. InfraScan runs as a Docker container that hosts all the necessary scanners it orchestrates.

You can follow these instructions to install Docker: [Installing the Docker engine](https://docs.docker.com/engineinstall/)

Next install InfraScan:

```bash
curl -fsSL https://raw.githubusercontent.com/SolDevelo/InfraScan/main/bin/install.sh | bash
```

## 🛠️ Usage

### 🔍 Scanner Options

InfraScan offers several scanning modes:
- **regex** (Fast): Quick cost optimization scan (27 regex rules)
- **containers**: Container vulnerability scanning (Docker Scout or Grype)
- **checkov**: IaC Security checks only
- **comprehensive**: All scanners combined (Cost + Security + Containers)

**Report Features:**
- **Professional PDF Export**: Generate beautiful, branded security reports with one click — perfect for compliance and auditing.
- **Grade Cards**: Visual A-F grades for Overall, Cost, and Security
- **Risk Assessment**: Low to Critical risk levels
- **Severity Breakdown**: High/Medium/Low issue counts
- **Smart Recommendations**: Actionable next steps based on your findings

### CLI / CI/CD Usage

InfraScan provides a CLI script, which is installed as described above. This script runs the Docker container underneath, which in turn runs the real Python CLI script inside of it.

Because of this, no matter whether you are running the CLI `infrascan` script you installed, or you are inside the InfraScan container in a CI/CD context, the usage is the same. 

No Python installation or dependency management is required.

```bash
# Get help
infrascan --help

# Scan current directory and print results (text)
infrascan

# Generate a standalone interactive HTML report
infrascan --format html --out /scan/report.html

# Generate a JSON artifact
infrascan --format json --out /scan/report.json

# Fail CI if high or critical findings exist
infrascan --scanner comprehensive --fail-on high_critical

# Fail CI if overall grade is C or worse
infrascan --fail-on grade_c

# Fail CI if overall grade is F
infrascan --fail-on grade_f

# Scan a Kubernetes project (auto-detected)
infrascan --scanner comprehensive

# Explicitly specify Kubernetes framework
infrascan --framework kubernetes --scanner comprehensive

# Use a specific infrascan version
INFRASCAN_VERSION=1.0.10 infrascan

# Do not pull for updates
infrascan --no-update
```

**CLI Arguments:**
- (positional): Directory to scan — in Docker use `/scan` (the default); locally use `.` (if no path is given CLI also defaults to current directory).
- `--scanner`: `regex`, `checkov`, `containers`, `comprehensive` (default: `comprehensive`). You can combine multiple scanners using comma (e.g. `--scanner regex,containers`).
- `--format`: `text`, `json`, or `html` — standalone interactive HTML report (default: `text`)
- `--out`: Path where output file is saved (e.g. `/scan/report.html`)
- `--framework`: `smart`, `auto`, `terraform`, `kubernetes`, `cloudformation`, `helm`, `ansible`, `all` (default: `smart`). 
  - **`smart` (default)**: Intelligently detects the framework. If multiple frameworks are found (e.g., Terraform + Ansible + Kubernetes), automatically scans **all of them** for comprehensive coverage. If only one framework is detected, scans just that one for faster results.
  - **`auto`**: Auto-detects the framework but picks only the dominant one. Shows a warning if other frameworks are ignored. Useful for projects that intentionally use one primary IaC tool.
  - **`all`**: Explicitly scans all frameworks (terraform, kubernetes, cloudformation, helm, ansible).
  - **Explicit framework**: Scan only that specific framework (terraform, kubernetes, etc.).
- `-f`, `--include`: Select specific files or directories to scan. Can be used multiple times (e.g., `-f dir1 -f file2.tf`). This is useful in large repositories to avoid scanning redundant or test deployments.
- `--download-external-modules`: Allow Checkov to download external modules (Terraform/etc)
- `--traffic-profile`: `auto`, `small`, `medium`, `large` (default: `auto`). Controls usage-based cost assumptions for NAT transfer, CloudWatch log ingestion, Lambda invocations, S3 storage, and API calls. `auto` detects the profile from infra size (EC2/NAT/Lambda/RDS counts). Profiles are defined in `reporter/traffic_profiles.json` and can be edited without code changes.
- `--fail-on`: Exit code 1 when: `any` findings, `high_critical` findings, specific grade threshold (`grade_a` through `grade_f`), or priority threshold (`priority_critical` through `priority_info`). Fails if the result matches or is worse than the specified criteria.
- `--no-update`: Does not update to the latest InfraScan version (does not pull the latest image)

#### Selective Scanning (Partial Scans)

In larger projects, you might want to scan only specific subdirectories or files to save time or avoid redundant findings:

```bash
# Scan only a specific directory
infrascan -f production/terraform

# Scan multiple specific files
infrascan -f main.tf -f database.tf

# Combine directories and files
infrascan -f modules/network -f app/deployment.yaml
```

#### GitLab CI

```yaml
infrascan:
  image: docker:27
  stage: test
  services:
    - docker:27-dind
  script:
    - docker run --rm
        -v $CI_PROJECT_DIR:/scan
        soldevelo/infrascan:latest
        --scanner comprehensive
        --format html
        --out /scan/infrascan-report.html
        --fail-on high_critical
  artifacts:
    when: always
    paths:
      - infrascan-report.html
    expire_in: 1 week
```

#### Bitbucket Pipelines

```yaml
pipelines:
  default:
    - step:
        name: InfraScan Audit
        script:
          - docker run --rm
              -v $BITBUCKET_CLONE_DIR:/scan
              soldevelo/infrascan:latest
              --scanner comprehensive
              --format html
              --out /scan/infrascan-report.html
              --fail-on high_critical
        artifacts:
          - infrascan-report.html
```

> **Building images locally** (contributors):
> ```bash
> # Build unified image
> docker build -t soldevelo/infrascan .
> ```


## ☸️ Kubernetes Support

InfraScan natively supports **Kubernetes manifest files** (`.yml`/`.yaml`). When Kubernetes manifests are detected (files containing `apiVersion` and `kind`), InfraScan will:

- **Auto-detect the framework**: If your project contains more K8s manifests than Terraform files, InfraScan will automatically switch to Kubernetes mode. You can also force it with `--framework kubernetes`.
- **Security scanning (Checkov)**: Runs Kubernetes-specific Checkov rules (CKV_K8S_*) to detect misconfigurations such as running as root, missing resource limits, missing network policies, missing probes, etc.
- **Container vulnerability scanning**: Extracts all `image:` references from your Kubernetes manifests (Deployments, StatefulSets, DaemonSets, Pods, Jobs, CronJobs — any resource with container specs) and scans them for CVE vulnerabilities using Docker Scout or Grype.
- **Multi-document support**: Files with multiple YAML documents separated by `---` are fully supported.

**Example — scanning a Kubernetes project:**
```bash
# Auto-detected
infrascan --scanner comprehensive

# Explicit framework
infrascan --framework kubernetes --scanner comprehensive

# Security checks only
infrascan --framework kubernetes --scanner checkov

# Container CVE scan only
infrascan --framework kubernetes --scanner containers
```

## � Ansible Support

InfraScan natively supports **Ansible playbooks** (`.yml`/`.yaml`). When Ansible files are detected (files containing `hosts:` and `tasks:` or `roles:` keys), InfraScan will:

- **Auto-detect the framework**: If your project contains more Ansible playbooks than other IaC files, InfraScan will automatically switch to Ansible mode. You can also force it with `--framework ansible`.
- **Security scanning (Checkov)**: Runs Ansible-specific Checkov rules (CKV_ANSIBLE_*) to detect security issues such as disabled certificate validation, hardcoded secrets, unsafe shell operations, and other misconfigurations.
- **Task and handler counting**: InfraScan counts all tasks and handlers in your playbooks to provide comprehensive reporting.
- **Multi-document support**: Files with multiple plays or multiple YAML documents separated by `---` are fully supported.

**Example — scanning Ansible playbooks:**
```bash
# Auto-detected
infrascan --scanner comprehensive

# Explicit framework
infrascan --framework ansible --scanner comprehensive

# Security checks only
infrascan --framework ansible --scanner checkov

# Scan specific Ansible files
infrascan --framework ansible -f playbooks/ -f roles/
```

## �🐳 Advanced Container Scanning

InfraScan supports advanced container scanning features:
- **Image discovery**: Images are automatically extracted from **Docker Compose files** (`docker-compose.yml`, `compose.yaml`) **and Kubernetes manifests** (`Deployment`, `StatefulSet`, `Pod`, etc.).
- **Environment Variables**: You can use variables in your `docker-compose.yml` image names (e.g., `image: ${REGISTRY}/my-app:${TAG}`). Both `$VAR` and `${VAR:-default}` syntax are supported. Variables are expanded using the environment where InfraScan is running (including your `.env` file).
- **Private Registries**:
  - **Docker Hub**: Set `DOCKER_HUB_USERNAME` and `DOCKER_HUB_PASSWORD` in your environment or `.env` file for automatic authentication.
  - **Amazon ECR**: InfraScan automatically detects ECR images and attempts authentication using `aws ecr get-login-password`. This requires the AWS CLI to be installed and configured with appropriate credentials in the environment.
  - **Intelligent Fallback**: If Docker Scout is not authenticated, InfraScan will automatically run a fallback scan using **Grype** so your pipeline never fails due to missing Docker Hub tokens.
  - **Other Registries**: Pre-authenticate manually using `docker login` before running InfraScan, and it will use your existing local Docker credentials.


## � Cost Estimation

InfraScan calculates actual dollar savings for every finding — not just static text like "$10-50/month", but a computed before/after cost derived from real AWS pricing.

### How it works

1. **Pricing table** (`reporter/pricing_table.json`) — static AWS `us-east-1` prices for EC2, RDS, EBS, NAT Gateway, Lambda, API Gateway, CloudWatch, S3, DynamoDB, SQS, Fargate, Kinesis, and more. Updated on each InfraScan release.
2. **Per-rule savings models** — every COST-* rule has a `savings_fn` that reads the actual HCL config (instance type, volume size, RCU/WCU, etc.) and computes a precise before/after cost.
3. **Per-resource total cost** — InfraScan also computes the monthly cost of every resource found, giving a total infrastructure cost estimate and a savings-as-%-of-total headline.
4. **Traffic profile** — usage-based resources (NAT transfer, Lambda invocations, CW log ingestion) use configurable defaults from `reporter/usage_defaults.json`, scaled by the active traffic profile.

### Traffic profiles

| Profile | NAT transfer/day | CW log ingestion/mo | Lambda invocations/function/mo | S3 storage |
|---|---|---|---|---|
| `small` (auto-detected default for small infra) | 10 GB | 5 GB | 1M | 50 GB |
| `medium` | 100 GB | 50 GB | 10M | 500 GB |
| `large` | 1 TB | 500 GB | 100M | 5,000 GB |

The `auto` mode (default) **detects the profile automatically** from the scanned repo: it scores the infra by counting EC2 instances, NAT gateways, load balancers, RDS instances, Lambda functions, and ECS tasks. Large instance types (8xlarge+) add extra weight. No manual flag needed in most cases.

```bash
# Let InfraScan auto-detect the profile (recommended)
infrascan --scanner regex

# Force a profile when auto-detection doesn't match your actual traffic
infrascan --scanner regex --traffic-profile medium
```

### Customising defaults

Edit `reporter/usage_defaults.json` or `reporter/traffic_profiles.json` directly — no Python changes needed. This is useful when you know your actual traffic numbers:

```json
// reporter/usage_defaults.json — Tier 1 baseline assumptions
{
  "nat_gb_per_day": 10.0,
  "lambda_invocations_per_mo": 1000000,
  ...
}
```

### Confidence levels

- 🟢 **high** — derived entirely from config (instance type, volume size, Multi-AZ flag)
- 🟡 **medium** — requires one usage assumption (invocation count, transfer volume)
- ⚪ **low** — governance rules with no direct cost delta, or highly variable resources

### PR comments and step summary

When running via the GitHub Action, InfraScan automatically posts a PR comment and writes a step summary. See [docs/GITHUB_ACTION.md](docs/GITHUB_ACTION.md) for the full reference including alert thresholds, baseline/delta comparison, and upgrade notes.

A PR comment is **always posted** on pull requests. It contains the grade overview table, infrastructure cost (with baseline delta when available), and the new CRITICAL findings table. Full details (savings, MEDIUM findings) are in the step summary only.

## �📊 Grading System

InfraScan provides four separate grades:

1. **Cost Optimization Grade**: Based on regex scanner findings (old instances, expensive resources, etc.)
2. **IaC Security Grade**: Based on Checkov findings (vulnerabilities, misconfigurations)
3. **Container Security Grade**: Based on container scanner findings (Docker Scout or Grype)
4. **Overall Grade**: Weighted average (~33% Cost + ~33% IaC Security + ~33% Container Security)

**Grade Scale:**
- **A (95-100%)**: Excellent - Low risk
- **B (85-94%)**: Good - Medium risk
- **C (70-84%)**: Fair - Medium-High risk
- **D (55-69%)**: Poor - High risk
- **F (<55%)**: Critical - Immediate action needed

**Severity Weights:**
- Critical: 4 points
- High: 3 points
- Medium: 2 points
- Low: 1 point
- Info: 0.5 points

**Grading Formula:**

*Cost Grade:*
- Weighted Score = Σ(severity_weight × count) for all findings
- Max Score = (resource_count + unique_rules) × 4
- Percentage = 100 - (Weighted Score / Max Score × 100)

*Security/Compliance Grade:*
- Only the most severe finding per resource is scored (prevents overweighting)
- Max Score = resource_count × 4
- Percentage calculation same as cost

*Severity Caps:*
- Critical findings cap grade at **C** (prevents misleading high grades)
- High findings cap grade at **B**

The system is designed to be extensible for future enhancements like historical tracking and custom scoring rules.

## 📋 Detection Rules

**27 Cost Optimization Rules** including:
- COST-001: Old generation EC2 instances (t2, m3, c4, r3)
- COST-002: Over-provisioned large instances (8xlarge+)
- COST-003: Unencrypted EBS volumes
- COST-004: Expensive Provisioned IOPS (io1/io2)
- COST-005: Expensive NAT Gateways
- COST-006: Unassociated Elastic IPs
- COST-007: DynamoDB Provisioned billing mode
- COST-008: EC2 detailed monitoring enabled
- COST-009: Old generation storage (gp2 vs gp3)
- COST-010: Missing S3 lifecycle policies
- COST-011: Missing AWS budgets
- COST-012: Missing Spot instance usage
- COST-013: Expensive premium storage (Premium_LRS)
- COST-014: Unnecessary Route53 health checks
- COST-015: CloudWatch log groups without retention period
- COST-016: Oversized root EBS volumes
- COST-017: Missing Cost and Usage Report
- COST-018: High DynamoDB provisioned capacity
- COST-019: Load balancers on single-instance deployments
- COST-020: Old generation RDS instance classes (db.t2, db.m4, db.r3, db.r4)
- COST-021: Lambda over-provisioned memory (≥3008 MB)
- COST-022: API Gateway REST API instead of HTTP API (3.5× cheaper)
- COST-023: SQS queues at maximum 14-day message retention
- COST-024: RDS Multi-AZ enabled in non-production environments
- COST-025: ECS task definitions without CPU/memory limits
- COST-026: Multiple NAT Gateways (potential redundancy)
- COST-027: Missing VPC Endpoints for S3/DynamoDB (NAT data-processing charges)
- Plus Checkov's 100+ security/compliance checks

## 🏅 Badge

Show that your infrastructure is secure and cost-optimized! Add this badge to your repository's `README.md`:

**Markdown:**
```markdown
[![Verified by InfraScan](https://img.shields.io/badge/Verified_by-SolDevelo_InfraScan-0052cc?style=flat&logo=security)](https://github.com/soldevelo/infrascan)
```

**HTML:**
```html
<a href="https://github.com/soldevelo/infrascan">
  <img src="https://img.shields.io/badge/Verified_by-SolDevelo_InfraScan-0052cc?style=flat&logo=security" alt="Verified by InfraScan">
</a>
```

## 🤝 Need Professional Help?

InfraScan catches the "low-hanging fruit" in your code. 
However, the biggest cloud savings often come from architectural changes, reserved instance planning, and traffic analysis.

**SolDevelo** offers comprehensive AWS Cost Optimization audits.
*   **Contact us**: [https://soldevelo.com/contact](https://soldevelo.com/contact)
*   **Special Offer**: Mention **"InfraScan"** for a free initial consultation.

## 🤝 Contributing

Contributions welcome! Focus areas:
- Additional cost optimization patterns
- Kubernetes-specific cost rules
- Support for more IaC frameworks (Pulumi, Crossplane)
- Performance improvements

## 💬 Community

Join our community on Slack to ask questions, share feedback, and get help:

[Click here to join!](https://join.slack.com/t/infrascancommunity/shared_invite/zt-3rcl6w3wg-gCN1AKW1sXjYT080efVmlQ)

## License

Apache 2.0
