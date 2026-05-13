# InfraScan

**Open Source IaC Cost & Security Scanner**

[![Verified by InfraScan](https://img.shields.io/badge/Verified_by-SolDevelo_InfraScan-0052cc?style=flat&logo=security)](https://github.com/soldevelo/infrascan)
[![Docker Pulls](https://img.shields.io/docker/pulls/soldevelo/infrascan.svg?style=flat-square)](https://hub.docker.com/r/soldevelo/infrascan)
[![Docker Image Size](https://img.shields.io/docker/image-size/soldevelo/infrascan/latest?style=flat-square)](https://hub.docker.com/r/soldevelo/infrascan)
[![GitHub stars](https://img.shields.io/github/stars/soldevelo/infrascan?style=flat-square&logo=github)](https://github.com/soldevelo/infrascan/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/soldevelo/infrascan?style=flat-square)](https://github.com/soldevelo/infrascan/issues)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square)](https://github.com/soldevelo/infrascan/blob/main/LICENSE)

InfraScan analyzes Infrastructure as Code to identify cost antipatterns and security issues before deployment. It supports **Terraform**, **Kubernetes manifests**, **CloudFormation**, **Helm**, and **Dockerfiles**. It can be used via a friendly web UI, a standalone Python CLI or as an all‑in‑one Docker image that also exposes a simple `infrascan` executable for pipeline usage.

## 🚀 Quick Start: GitHub Action

The fastest way to integrate InfraScan into your repository is using our official GitHub Action. Add this to `.github/workflows/infrascan.yml`:

```yaml
name: InfraScan Security Audit
on: [push, pull_request]

jobs:
  infrascan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run InfraScan
        uses: soldevelo/infrascan@v1.0.5
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

## 📦 Installation

Requires Python 3.8+

```bash
git clone <repo-url>
cd InfraScan

# Create virtual environment
python3 -m venv venv
source venv/bin/activate 

# Install Python dependencies
pip install -r requirements.txt

# Install security scanners (optional but recommended)
chmod +x install_scanners.sh
./install_scanners.sh
```

**Configuration**: Copy and edit the `.env` file (see `.env.example`) to choose container scanner:
```bash
# Copy the example file
cp .env.example .env

# Edit to select container scanner: docker-scout (default) or grype
CONTAINER_SCANNER=docker-scout
```

**Note**: The app works without container scanning - it will be skipped if not installed. Docker must be installed for Docker Scout to work.

## 🛠️ Usage

### 🔍 Scanner Options

InfraScan offers several scanning modes:
- **regex** (Fast): Quick cost optimization scan (19 regex rules)
- **containers**: Container vulnerability scanning (Docker Scout or Grype)
- **checkov**: IaC Security checks only
- **comprehensive**: All scanners combined (Cost + Security + Containers)

**Report Features:**
- **Professional PDF Export**: Generate beautiful, branded security reports with one click — perfect for compliance and auditing.
- **Grade Cards**: Visual A-F grades for Overall, Cost, and Security
- **Risk Assessment**: Low to Critical risk levels
- **Severity Breakdown**: High/Medium/Low issue counts
- **Smart Recommendations**: Actionable next steps based on your findings

### Web Application

```bash
python3 app.py
```
Open browser at `http://localhost:5000`

### CLI / CI/CD Usage

InfraScan provides two modes for command‑line operation:

* **Standalone Python script** (after cloning the repo or installing dependencies). Run `python3 cli.py [options]` from the project root or install a virtual environment.
* **Docker image** – the preferred way for CI/CD; the official image `soldevelo/infrascan` bundles all dependencies and scanners. **New in v1.0.4**: The CLI now provides a beautiful, colored findings summary directly in your CI/CD logs, even when generating HTML or JSON reports, so you can see results immediately without downloading artifacts.
* **Detailed Guide**: See [docs/PIPELINE_INTEGRATION.md](./docs/PIPELINE_INTEGRATION.md) for best practices and a gradual rollout strategy.

> **Pro Tip:** The official Docker image includes a helper binary called `infrascan`. When using the image directly as your pipeline execution environment (e.g., in Bitbucket or GitLab), you can invoke the scanner directly:
> ```bash
> infrascan --scanner comprehensive --format html --out report.html
> ```

No Python installation or dependency management is required when using the Docker image.

```bash
# Pull the image
docker pull soldevelo/infrascan:latest

# Scan current directory and print results (text)
docker run --rm -v $(pwd):/scan soldevelo/infrascan

# Generate a standalone interactive HTML report
docker run --rm -v $(pwd):/scan soldevelo/infrascan --format html --out /scan/report.html

# Generate a JSON artifact
docker run --rm -v $(pwd):/scan soldevelo/infrascan --format json --out /scan/report.json

# Fail CI if high or critical findings exist
docker run --rm -v $(pwd):/scan soldevelo/infrascan --scanner comprehensive --fail-on high_critical

# Fail CI if overall grade is C or worse
docker run --rm -v $(pwd):/scan soldevelo/infrascan --fail-on grade_c

# Fail CI if overall grade is F
docker run --rm -v $(pwd):/scan soldevelo/infrascan --fail-on grade_f

# Scan a Kubernetes project (auto-detected)
docker run --rm -v $(pwd):/scan soldevelo/infrascan --scanner comprehensive

# Explicitly specify Kubernetes framework
docker run --rm -v $(pwd):/scan soldevelo/infrascan --framework kubernetes --scanner comprehensive
```

**CLI Arguments:**
- (positional): Directory to scan — in Docker use `/scan` (the default); locally use `.` (if no path is given CLI also defaults to current directory).
- `--scanner`: `regex`, `checkov`, `containers`, `comprehensive` (default: `comprehensive`). You can combine multiple scanners using comma (e.g. `--scanner regex,containers`).
- `--format`: `text`, `json`, or `html` — standalone interactive HTML report (default: `text`)
- `--out`: Path where output file is saved (e.g. `/scan/report.html`)
- `--framework`: `auto`, `terraform`, `kubernetes`, `cloudformation`, `helm` (default: `auto`). When set to `auto`, InfraScan detects the framework automatically based on file contents.
- `--download-external-modules`: Allow Checkov to download external modules (Terraform/etc)
- `--fail-on`: Exit code 1 when: `any` findings, `high_critical` findings, specific grade threshold (`grade_a` through `grade_f`), or priority threshold (`priority_critical` through `priority_info`). Fails if the result matches or is worse than the specified criteria.

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
docker run --rm -v $(pwd):/scan soldevelo/infrascan --scanner comprehensive

# Explicit framework
docker run --rm -v $(pwd):/scan soldevelo/infrascan --framework kubernetes --scanner comprehensive

# Security checks only
docker run --rm -v $(pwd):/scan soldevelo/infrascan --framework kubernetes --scanner checkov

# Container CVE scan only
docker run --rm -v $(pwd):/scan soldevelo/infrascan --framework kubernetes --scanner containers
```

## 🐳 Advanced Container Scanning

InfraScan supports advanced container scanning features:
- **Image discovery**: Images are automatically extracted from **Docker Compose files** (`docker-compose.yml`, `compose.yaml`) **and Kubernetes manifests** (`Deployment`, `StatefulSet`, `Pod`, etc.).
- **Environment Variables**: You can use variables in your `docker-compose.yml` image names (e.g., `image: ${REGISTRY}/my-app:${TAG}`). Both `$VAR` and `${VAR:-default}` syntax are supported. Variables are expanded using the environment where InfraScan is running (including your `.env` file).
- **Private Registries**:
  - **Docker Hub**: Set `DOCKER_HUB_USERNAME` and `DOCKER_HUB_PASSWORD` in your environment or `.env` file for automatic authentication.
  - **Amazon ECR**: InfraScan automatically detects ECR images and attempts authentication using `aws ecr get-login-password`. This requires the AWS CLI to be installed and configured with appropriate credentials in the environment.
  - **Intelligent Fallback**: If Docker Scout is not authenticated, InfraScan will automatically run a fallback scan using **Grype** so your pipeline never fails due to missing Docker Hub tokens.
  - **Other Registries**: Pre-authenticate manually using `docker login` before running InfraScan, and it will use your existing local Docker credentials.


## 📊 Grading System

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

**19 Cost Optimization Rules** including:
- COST-001: Old generation instances (t2, m3, c4, r3)
- COST-002: Over-provisioned large instances
- COST-004: Expensive Provisioned IOPS (io1/io2)
- COST-005: Expensive NAT Gateways
- COST-009: Old generation storage (gp2 vs gp3)
- COST-010: Missing S3 lifecycle policies
- COST-011: Missing AWS budgets
- COST-012: Missing Spot instance usage
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
