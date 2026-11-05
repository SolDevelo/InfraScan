# InfraScan

[![Docker Pulls](https://img.shields.io/docker/pulls/soldevelo/infrascan.svg?style=flat-square)](https://hub.docker.com/r/soldevelo/infrascan)
[![Docker Image Size](https://img.shields.io/docker/image-size/soldevelo/infrascan/latest?style=flat-square)](https://hub.docker.com/r/soldevelo/infrascan)
[![GitHub stars](https://img.shields.io/github/stars/soldevelo/infrascan?style=flat-square&logo=github)](https://github.com/soldevelo/infrascan/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/soldevelo/infrascan?style=flat-square)](https://github.com/soldevelo/infrascan/issues)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](https://github.com/soldevelo/infrascan/blob/main/LICENSE)

InfraScan is an open-source scanner for infrastructure code. It finds cloud cost waste, security misconfigurations and container vulnerabilities in Terraform, Kubernetes, Helm, CloudFormation, Ansible and Docker Compose projects, and reports them in CI/CD before the changes reach production.

- Scans run entirely in your environment, locally or in your pipeline; your code is not uploaded anywhere.
- Open source under Apache 2.0, with documented rules and a transparent grading formula.
- Ships as a single Docker image that bundles all scanners it uses (Checkov, Grype, Docker Scout).
- Native integrations for GitHub Actions and Bitbucket Pipelines (PR comments, inline annotations, baseline deltas); runs in GitLab CI or any other Docker-capable CI as a plain container.

> **InfraScan Cloud (free beta).** The CLI stays free and local. To scan a live AWS account, InfraScan Cloud connects through a read-only role and grades security, reliability and cost, with a monthly price on each piece of waste and a fix for every finding.
> [See the demo](https://infrascan.soldevelo.com/cloud-demo/?utm_source=github&utm_campaign=beta) · [Get started](https://infrascan.soldevelo.com/?utm_source=github&utm_campaign=beta)

## Contents

- [Quick start: GitHub Action](#quick-start-github-action)
- [Installation](#installation)
- [Usage](#usage)
- [CI/CD integration](#cicd-integration)
- [Supported frameworks](#supported-frameworks)
- [Container scanning](#container-scanning)
- [Cost estimation](#cost-estimation)
- [Grading](#grading)
- [Detection rules](#detection-rules)
- [Badge](#badge)
- [Contributing](#contributing)
- [Support and community](#support-and-community)
- [License](#license)

## Quick start: GitHub Action

Add the following workflow as `.github/workflows/infrascan.yml`:

```yaml
name: InfraScan Security Audit
on:
  push:
    branches: [main]   # your default branch
  pull_request:

permissions:
  contents: read
  pull-requests: write   # PR comments

jobs:
  infrascan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run InfraScan
        uses: soldevelo/infrascan@v1
        with:
          scanner: comprehensive
          format: html
          out: infrascan-report.html
          fail-on: new_high_critical

      - name: Upload HTML Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: infrascan-report
          path: infrascan-report.html
```

Besides the report, the action:

- posts a PR comment with the grade table, the cost estimate (with a delta against the default branch when a baseline is available) and the most severe new findings at or above the `alert-on` threshold (requires `pull-requests: write`);
- writes a step summary to the workflow run's Summary tab;
- adds inline annotations to the changed files in the PR diff;
- skips the scan on PRs that do not touch files relevant to the selected scanners.

No extra inputs are required. See [docs/GITHUB_ACTION.md](docs/GITHUB_ACTION.md) for all inputs and outputs, alert thresholds, the baseline/delta workflow and upgrade notes.

## Installation

The CLI requires Docker: InfraScan runs as a container that bundles every scanner it orchestrates, so no Python installation or dependency management is needed. See [Install Docker Engine](https://docs.docker.com/engine/install/) if you do not have it yet.

Then install the `infrascan` wrapper script:

```bash
curl -fsSL https://raw.githubusercontent.com/SolDevelo/InfraScan/main/bin/install.sh | bash
```

To build the image locally (for contributors):

```bash
docker build -t soldevelo/infrascan .
```

A standalone web application for scanning public repositories is also available; see [docs/WEBAPP.md](docs/WEBAPP.md).

## Usage

The `infrascan` script is a thin wrapper that pulls `soldevelo/infrascan:latest` and runs it with the current directory mounted at `/scan`. All options are passed through to the CLI inside the image, so usage is the same as calling the image directly:

```bash
docker run --rm -v "$(pwd)":/scan soldevelo/infrascan:latest [options]
```

The wrapper does not forward environment variables or Docker credentials. To use the [container scanning settings](#container-scanning) or private registries, run the image directly and pass them with `-e`.

```bash
# Show help
infrascan --help

# Scan the current directory and print a text summary
infrascan

# Write a standalone interactive HTML report
infrascan --format html --out /scan/report.html

# Write a JSON report
infrascan --format json --out /scan/report.json

# Fail if high or critical findings exist
infrascan --scanner comprehensive --fail-on high_critical

# Fail if the overall grade is C or worse
infrascan --fail-on grade_c

# Force a specific framework
infrascan --framework kubernetes --scanner comprehensive

# Pin an InfraScan version (wrapper only)
INFRASCAN_VERSION=1.2.5 infrascan

# Skip pulling the latest image (wrapper only)
infrascan --no-update
```

### Scanners

| Scanner | What it checks |
|---|---|
| `regex` | Cost optimization (27 rules); fastest |
| `checkov` | IaC security and compliance |
| `containers` | Container image CVEs (Docker Scout or Grype) |
| `comprehensive` | All of the above (default) |

Scanners can be combined with a comma, e.g. `--scanner regex,containers`.

### Options

| Option | Description |
|---|---|
| *(positional)* | Directory to scan. Defaults to the current directory (`/scan` inside the container). |
| `--scanner` | `regex`, `checkov`, `containers`, `comprehensive` or a comma-separated combination. Default: `comprehensive`. |
| `--format` | `text`, `json` or `html` (standalone interactive report). Default: `text`. |
| `--out` | Output file path, e.g. `/scan/report.html`. Without it, JSON and HTML are printed to stdout. With `--format text`, the file is written as JSON. |
| `--framework` | `smart`, `auto`, `terraform`, `kubernetes`, `cloudformation`, `helm`, `ansible` or `all`. Default: `smart`. See below. |
| `-f`, `--include` | Scan only the given files or directories. Repeatable. |
| `-x`, `--exclude` | Leave files or directories out of the scan, e.g. `-x docs,tests,examples` or `-x modules/legacy`. A name without a slash matches at any depth, like `.gitignore`; a name with a slash is relative to the scanned directory. `*` and `?` are supported. Comma-separated or repeatable; combines with `--include`. |
| `--download-external-modules` | Allow Checkov to download external Terraform modules. |
| `--traffic-profile` | `auto`, `small`, `medium` or `large`. Default: `auto`. See [Traffic profiles](#traffic-profiles). |
| `--fail-on` | Exit with code 1 when the result matches or is worse than the threshold: `any`, `high_critical`, `grade_a` … `grade_f`, `priority_critical` … `priority_info`. `new_any`, `new_high_critical` and `new_critical` count only findings absent from `--baseline` (in CI: those added by the PR) and are skipped without one. Default: `never`. |
| `--baseline` | Path to an earlier InfraScan JSON result to compare against (cost and finding deltas). |
| `--baseline-out` | Write the current result as JSON for use as a future baseline, regardless of `--format`. |
| `--alert-on` | Severity threshold for PR comments and annotations: `critical`, `high`, `medium`, `low`, `any_new` or `none`. Default: `any_new`. |
| `--min-cost-delta` | Minimum cost change ($/month) highlighted in PR comments. Default: `0` (any change). |
| `--max-pr-findings` | Maximum number of findings listed in a PR comment, most severe first. Default: `10`. |
| `--max-annotations-per-image` | Maximum Bitbucket Code Insights annotations per container image. Default: `10`; `0` means no limit. |
| `--pr-comment`, `--step-summary` | `true` or `false`. Enable or disable the PR comment and the GitHub step summary. Default: `true`. |
| `--force-comment` | Post a PR comment even when the posting rules would skip it. |
| `--no-tips` | Omit the InfraScan Cloud note from the console summary, GitHub step summary and HTML report footer. |
| `--version` | Print the version and exit. |
| `--no-update` | Wrapper only: do not pull the latest image. |

**Framework detection modes:**

- `smart` (default) detects which frameworks are present. If more than one is found (e.g. Terraform, Ansible and Kubernetes), all supported frameworks are scanned; if only one is found, only that one is scanned.
- `auto` scans a single framework and warns about the others it ignores. When several are present, the first one in this order wins: Terraform, Kubernetes, CloudFormation, Helm, Ansible.
- `all` always scans every supported framework.
- An explicit framework name scans only that framework.

Detection looks at the first 1 KB of each file.

### Scanning part of a repository

In large repositories you can limit the scan to specific paths:

```bash
infrascan -f production/terraform
infrascan -f main.tf -f database.tf
infrascan -f modules/network -f app/deployment.yaml
```

### Reports

The HTML report is a single file that works offline (fonts and the Markdown renderer are loaded from a CDN when a connection is available). It includes:

- A–F grades for overall, cost and security, with a risk level from Low to Critical;
- finding counts by severity;
- recommended next steps based on the findings;
- export to a print-ready PDF.

## CI/CD integration

For GitHub Actions, see the [quick start](#quick-start-github-action) above. Further examples are in [examples/pipelines](examples/pipelines) and [docs/PIPELINE_INTEGRATION.md](docs/PIPELINE_INTEGRATION.md).

### GitLab CI

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

### Bitbucket Pipelines

The Bitbucket pipe posts a PR comment, a Code Insights report (the Bitbucket equivalent of a GitHub step summary), inline annotations and a cost/security delta against the default branch. The Code Insights report and annotations work without any setup. The PR comment requires a Repository Access Token passed as `BITBUCKET_ACCESS_TOKEN`; see the Authentication section of [docs/BITBUCKET_PIPELINE.md](docs/BITBUCKET_PIPELINE.md) and the full example in [examples/pipelines/bitbucket-pipelines.yml](examples/pipelines/bitbucket-pipelines.yml).

```yaml
definitions:
  caches:
    infrascan-baseline: infrascan-baseline
    infrascan-grype-db: infrascan-grype-db
  steps:
    - step: &infrascan-audit
        name: InfraScan Audit
        caches:
          - infrascan-baseline
          - infrascan-grype-db
        script:
          - mkdir -p infrascan-baseline infrascan-grype-db && chmod -R 777 infrascan-baseline infrascan-grype-db
          - pipe: docker://soldevelo/infrascan:latest
            variables:
              BITBUCKET_ACCESS_TOKEN: $INFRASCAN_TOKEN
              SCANNER: comprehensive
              FORMAT: html
              OUT: infrascan-report.html
              ALERT_ON: any_new
              DEFAULT_BRANCH: main
        artifacts:
          - infrascan-report.html

pipelines:
  branches:
    main:
      - step: *infrascan-audit
  pull-requests:
    '**':
      - step: *infrascan-audit
```

## Supported frameworks

Terraform, CloudFormation and Helm are scanned with Checkov's framework-specific policies; Terraform is additionally cost-scanned (see [Cost estimation](#cost-estimation)). Kubernetes and Ansible support is described in more detail below.

### Kubernetes

Files with `.yml`/`.yaml` extensions containing `apiVersion` and `kind` are treated as Kubernetes manifests. InfraScan:

- runs Checkov's Kubernetes policies (`CKV_K8S_*`), which flag issues such as containers running as root, missing resource limits, network policies or probes;
- extracts every `image:` reference from the manifests (Deployments, StatefulSets, DaemonSets, Pods, Jobs, CronJobs and any other resource) and scans the images for CVEs;
- supports multi-document files separated by `---`.

```bash
infrascan --framework kubernetes --scanner checkov      # security checks only
infrascan --framework kubernetes --scanner containers   # image CVEs only
```

### Ansible

Files with `.yml`/`.yaml` extensions containing `hosts:` together with `tasks:`, `roles:` or `play` are treated as Ansible playbooks. InfraScan:

- runs Checkov's Ansible policies (`CKV_ANSIBLE_*`), which flag issues such as disabled certificate validation, hardcoded secrets and unsafe shell usage;
- counts tasks and handlers for the report;
- supports multiple plays per file and multi-document files separated by `---`.

```bash
infrascan --framework ansible --scanner checkov
infrascan --framework ansible -f playbooks/ -f roles/
```

## Container scanning

**Image discovery.** Images are extracted from Docker Compose files (`docker-compose.yml`, `compose.yaml`) and Kubernetes manifests.

**Variables in image names.** Compose-style variables in image names (`$VAR`, `${VAR}`, `${VAR:-default}`, `${VAR-default}`, `${VAR:?error}`, `${VAR:+alt}`) are expanded, e.g. `image: ${REGISTRY}/my-app:${TAG}`. As with Compose, values are read from the environment and from a `.env` file next to the compose file or in a parent directory up to the scanned directory. Because `.env` is usually gitignored, InfraScan falls back to the committed `.env.example` and `.env.sample`. `CONTAINER_ENV_FILES` (comma-separated, highest priority first) overrides this list; an entry containing `/` is a fixed path relative to the scanned directory. The values are used only to expand image names and are never exported. An image with an unresolved variable is reported as not scanned, with the variable named.

**Scanner selection.** Docker Scout (fewer false positives) is used when Docker Hub credentials are available, since it requires a Docker login. Otherwise InfraScan falls back to Grype. Set `CONTAINER_SCANNER=grype` to always use Grype.

**Registry credentials.** These settings are read from the container's environment, so pass them with `docker run -e` (the `infrascan` wrapper does not forward them).

- Docker Hub: set `DOCKER_HUB_USERNAME` and `DOCKER_HUB_PASSWORD`. A Docker Hub entry in the container's Docker config (`$DOCKER_CONFIG/config.json`) also counts.
- Amazon ECR: ECR images are detected and authenticated with `aws ecr get-login-password`, which requires AWS credentials in the container's environment.
- Other registries: the container needs a Docker config with credentials for the registry, e.g. mounted and pointed to with `DOCKER_CONFIG`.

**Unscannable images.** An image that cannot be pulled (unreachable registry, missing credentials, nonexistent tag) is listed with the reason in the console output, PR comment and CI report instead of being counted as clean.

**Tuning.**

- `CONTAINER_SCAN_TIMEOUT` (seconds, default 300) limits pull and analysis time per image. A timed-out image is reported as not scanned.
- `CONTAINER_IGNORE_IMAGES` takes a regex of image references to skip, e.g. `-SNAPSHOT$` for images the repository builds itself and publishes only after merge.
- `CLEANUP_SCANNED_IMAGES` (default `true`) removes images pulled for a Docker Scout scan afterwards.

**Notifications.** Set `SLACK_WEBHOOK_URL` to send a summary of each scan to Slack.

## Cost estimation

For every cost finding, InfraScan computes a before/after monthly cost from AWS pricing rather than quoting a generic range. See [docs/COST_ESTIMATION.md](docs/COST_ESTIMATION.md) for details.

### How it works

1. **Pricing table.** `reporter/pricing_table.json` holds static AWS `us-east-1` prices for EC2, RDS, EBS, NAT Gateway, Lambda, API Gateway, CloudWatch, S3, DynamoDB, SQS, Fargate, Kinesis and other services. It is updated with each release.
2. **HCL parsing.** Each `.tf` file is parsed with python-hcl2, with a regex fallback on parse errors. A directory is cost-scanned if it declares a `provider {}` block, a `terraform { backend {} }` block or at least one `resource`. Directories without resources (e.g. modules that only wrap other modules), hidden directories and directories named `scripts` are skipped.
3. **Variable resolution.** `${var.x}` references are resolved from tfvars files (`*.auto.tfvars`, `*.auto.tfvars.json`, `terraform.tfvars`, `terraform.tfvars.json`, later files winning) and then from `variable {}` defaults; `${local.x}` references are resolved from `locals {}` blocks. Adjacent JSON data files are used as a fallback for numeric values. Instance types, sizes and counts therefore reflect what is actually declared.
4. **Per-rule savings models.** Each `COST-*` rule has a savings function that reads the resource configuration (instance type, volume size, RCU/WCU, etc.) and computes the before/after cost.
5. **Total cost.** The monthly cost of every resource is also computed, giving a total infrastructure estimate and savings as a percentage of it. `count = N` and literal `for_each` maps/sets multiply the per-instance cost.
6. **Usage assumptions.** Usage-based resources (NAT transfer, Lambda invocations, CloudWatch log ingestion, S3 storage, API calls) take their volumes from the active traffic profile; other assumptions come from `reporter/usage_defaults.json`.

### Traffic profiles

| Profile | NAT transfer/day | CloudWatch logs/log group/month | Lambda invocations/month | API calls/month | S3 storage |
|---|---|---|---|---|---|
| `small` | 1 GB | 2 GB | 1M | 1M | 50 GB |
| `medium` | 10 GB | 2 GB | 10M | 10M | 125 GB |
| `large` | 50 GB | 100 GB | 100M | 100M | 5,000 GB |

NAT transfer is a total across all gateways: it is scaled up for larger fleets (one step per five instances or ECS tasks) and then split evenly between gateways. Lambda invocations and S3 storage are totals divided across functions and buckets.

In `auto` mode (the default) the profile is chosen from the size of the scanned infrastructure, based on the number of EC2 instances, NAT gateways, load balancers, RDS instances, Lambda functions and ECS tasks; large instance types (8xlarge and above) add extra weight. Use `--traffic-profile` to override it when the detected profile does not match your real traffic:

```bash
infrascan --scanner regex --traffic-profile medium
```

To change the assumptions, edit `reporter/traffic_profiles.json` (traffic volumes per profile) or `reporter/usage_defaults.json` (all other usage assumptions); no code changes are needed. Values set in a profile take precedence over the same keys in `usage_defaults.json`.

### Confidence levels

Each estimate carries a confidence level:

| Level | Meaning |
|---|---|
| High | Derived entirely from configuration (instance type, volume size, Multi-AZ flag). |
| Medium | Depends on one usage assumption (invocation count, transfer volume). |
| Low | Governance rules with no direct cost delta, or highly variable resources. |

## Grading

InfraScan reports four grades:

1. **Cost optimization**, based on `regex` scanner findings.
2. **IaC security**, based on Checkov findings.
3. **Container security**, based on Docker Scout or Grype findings.
4. **Overall**, a weighted average of the three (34% cost, 33% IaC security, 33% container security).

| Grade | Score | Meaning |
|---|---|---|
| A | 95–100% | Excellent, low risk |
| B | 85–94% | Good, medium risk |
| C | 70–84% | Fair, medium-high risk |
| D | 55–69% | Poor, high risk |
| F | < 55% | Critical, immediate action needed |

**Severity weights:** Critical 4, High 3, Medium 2, Low 1, Info 0.5.

**Cost grade**

- Weighted score = Σ(severity weight × count) over all findings
- Max score = (resource count + unique rules) × 4
- Percentage = 100 − (weighted score / max score × 100)

**IaC security grade**

- Only the most severe finding per resource is scored, to avoid overweighting.
- Max score = resource count × 4; the percentage is computed as for cost.

**Container security grade**

- Only the most severe finding per image is scored.
- Max score = number of scanned images (including clean ones) × 4.
- Medium and Low weigh less, since nearly every image carries some (often unfixable) CVEs: Critical 4, High 3, Medium 0.5, Low 0.1, Info 0. An image set whose worst findings are Medium grades about B; Low only, about A. High and Critical still lower the grade sharply.
- CVEs with no available fix are graded one level lower (Critical as High, High as Medium, and so on). The report and `--fail-on` keep their real severity.

**Severity caps.** A Critical finding caps the grade at C and a High finding caps it at B. Caps apply to each category and to the overall grade, and the report states when a cap lowered a grade.

**Not applicable categories.** A category with nothing to check (no Terraform for cost, no IaC resources, no container images) is shown as N/A and excluded from the overall grade rather than counted as an A.

## Detection rules

27 cost optimization rules, in addition to Checkov's built-in security and compliance policies:

| Rule | Description |
|---|---|
| COST-001 | Old generation EC2 instances (t2, m3, c4, r3) |
| COST-002 | Very large instance sizes (8xlarge, 12xlarge, 16xlarge, 24xlarge, metal) |
| COST-003 | Unencrypted EBS volumes |
| COST-004 | Expensive Provisioned IOPS (io1/io2) |
| COST-005 | Expensive NAT Gateways |
| COST-006 | Unassociated Elastic IPs |
| COST-007 | DynamoDB provisioned billing mode |
| COST-008 | EC2 detailed monitoring enabled |
| COST-009 | Old generation storage (gp2 instead of gp3) |
| COST-010 | Missing S3 lifecycle policies |
| COST-011 | Missing AWS budgets |
| COST-012 | No Spot instance usage |
| COST-013 | Expensive premium storage (Premium_LRS) |
| COST-014 | Unnecessary Route 53 health checks |
| COST-015 | CloudWatch log groups without a retention period |
| COST-016 | Large EBS volumes (50 GB and above) |
| COST-017 | Missing Cost and Usage Report |
| COST-018 | High DynamoDB provisioned capacity |
| COST-019 | Load balancers (review whether one is needed) |
| COST-020 | Old generation RDS instance classes (db.t2, db.m3, db.m4, db.r3, db.r4) |
| COST-021 | Lambda functions with high memory allocation (3008 MB or 4000 MB and above) |
| COST-022 | API Gateway REST API instead of HTTP API (about 3.5× cheaper) |
| COST-023 | SQS queues at the maximum 14-day message retention |
| COST-024 | RDS Multi-AZ enabled in non-production environments |
| COST-025 | ECS task definitions without a CPU limit |
| COST-026 | Multiple NAT Gateways in one file (potential redundancy) |
| COST-027 | Missing VPC endpoints for S3/DynamoDB (NAT data processing charges) |

## Badge

If your repository is scanned with InfraScan, you can add this badge to its README:

[![Verified by InfraScan](https://img.shields.io/badge/Verified_by-SolDevelo_InfraScan-0052cc?style=flat&logo=security)](https://github.com/soldevelo/infrascan)

```markdown
[![Verified by InfraScan](https://img.shields.io/badge/Verified_by-SolDevelo_InfraScan-0052cc?style=flat&logo=security)](https://github.com/soldevelo/infrascan)
```

```html
<a href="https://github.com/soldevelo/infrascan">
  <img src="https://img.shields.io/badge/Verified_by-SolDevelo_InfraScan-0052cc?style=flat&logo=security" alt="Verified by InfraScan">
</a>
```

## Contributing

Contributions are welcome, particularly in these areas:

- additional cost optimization rules;
- Kubernetes-specific cost rules;
- support for more IaC frameworks (Pulumi, Crossplane);
- performance improvements.

Please open an issue to discuss larger changes before submitting a pull request.

## Support and community

Questions and feedback are welcome in the [InfraScan Slack community](https://join.slack.com/t/infrascancommunity/shared_invite/zt-3rcl6w3wg-gCN1AKW1sXjYT080efVmlQ) or on [GitHub Issues](https://github.com/soldevelo/infrascan/issues).

InfraScan covers what can be detected in code. Larger savings often come from architectural changes, reserved capacity planning and traffic analysis. [SolDevelo](https://soldevelo.com/contact) offers AWS cost optimization audits; mention InfraScan for a free initial consultation.

## License

InfraScan is licensed under the [Apache License 2.0](LICENSE).
