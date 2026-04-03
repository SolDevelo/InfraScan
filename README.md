# InfraScan

**Open Source IaC Cost & Security Scanner**

InfraScan analyzes Infrastructure as Code to identify cost antipatterns and security issues before deployment. It can be used via a friendly web UI, a standalone Python CLI or as an all‑in‑one Docker image that also exposes a simple `infrascan` executable for pipeline usage.

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

### Web Application

```bash
python3 app.py
```
Open browser at `http://localhost:5000`

**Scanner Options:**
- **regex** (Fast): Quick cost optimization scan (19 regex rules)
- **containers**: Container vulnerability scanning (Docker Scout or Grype)
- **checkov**: IaC Security checks only
- **comprehensive**: All scanners combined (Cost + Security + Containers)

**Report Features:**
- **Grade Cards**: Visual A-F grades for Overall, Cost, and Security
- **Risk Assessment**: Low to Critical risk levels
- **Severity Breakdown**: High/Medium/Low issue counts
- **Smart Recommendations**: Actionable next steps based on your findings

### CLI / CI/CD Usage

InfraScan provides two modes for command‑line operation:

* **Standalone Python script** (after cloning the repo or installing dependencies). Run `python3 cli.py [options]` from the project root or install a virtual environment.
* **Docker image** – the preferred way for CI/CD; the official image `soldevelo/infrascan` bundles all dependencies and scanners.

> The container also installs a helper binary called `infrascan`, so if you use the image directly as your pipeline container (e.g. Bitbucket/GitLab), you can invoke the scanner without wrapping it in `docker run`.

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
```

**CLI Arguments:**
- (positional): Directory to scan — in Docker use `/scan` (the default); locally use `.` (if no path is given CLI also defaults to current directory).
- `--scanner`: `regex`, `checkov`, `containers`, `comprehensive` (default: `comprehensive`). You can combine multiple scanners using comma (e.g. `--scanner regex,containers`).
- `--format`: `text`, `json`, or `html` — standalone interactive HTML report (default: `text`)
- `--out`: Path where output file is saved (e.g. `/scan/report.html`)
- `--download-external-modules`: Allow Checkov to download external modules (Terraform/etc)
- `--fail-on`: Exit code 1 when: `any` findings, `high_critical` findings, specific grade threshold (`grade_a` through `grade_f`), or priority threshold (`priority_critical` through `priority_info`). Fails if the result matches or is worse than the specified criteria.

#### GitHub Actions

> **Note:** when the container image is used directly as the execution environment (e.g. in Bitbucket or GitLab pipelines), you can call the CLI binary included in `PATH` instead of invoking `docker run`:
>
> ```bash
> infrascan --scanner comprehensive --format html --out infrascan-report.html
> ```

```yaml
name: InfraScan Security Audit
on: [push, pull_request]

jobs:
  infrascan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run InfraScan
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/scan \
            soldevelo/infrascan:latest \
            --scanner comprehensive \
            --format html \
            --out /scan/infrascan-report.html \
            --fail-on high_critical

      - name: Upload HTML Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: infrascan-report
          path: infrascan-report.html
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


## 🐳 Advanced Container Scanning

InfraScan supports advanced container scanning features:
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

## 🤝 Need Professional Help?

InfraScan catches the "low-hanging fruit" in your code. 
However, the biggest cloud savings often come from architectural changes, reserved instance planning, and traffic analysis.

**SolDevelo** offers comprehensive AWS Cost Optimization audits.
*   **Contact us**: [https://soldevelo.com/contact](https://soldevelo.com/contact)
*   **Special Offer**: Mention **"InfraScan"** for a free initial consultation.

## 🤝 Contributing

Contributions welcome! Focus areas:
- Additional cost optimization patterns
- Support for more IaC frameworks
- Performance improvements

## 💬 Community

Join our community on Slack to ask questions, share feedback, and get help:

[Click here to join!](https://join.slack.com/t/infrascancommunity/shared_invite/zt-3rcl6w3wg-gCN1AKW1sXjYT080efVmlQ)

## License

Apache 2.0
