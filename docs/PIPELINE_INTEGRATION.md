# CI/CD Pipeline Integration Guide

This guide covers adding InfraScan to a CI/CD pipeline. InfraScan scans **Terraform**, **Kubernetes**, **CloudFormation**, **Helm** and **Ansible** for security issues, Terraform (AWS) for cost, and container images referenced in Dockerfiles, docker-compose and Kubernetes files for CVEs.

Ready-to-use pipeline files are in [examples/pipelines](../examples/pipelines).

## Integration modes

### 1. Monitoring (non-blocking)

Suited to an initial rollout, or when InfraScan should report without stopping the pipeline.

In this mode InfraScan:
*   Scans the code and prints a summary to the console log.
*   Writes an HTML or JSON report.
*   Exits with code 0 regardless of findings (`--fail-on` defaults to `never`). A scan error still exits with code 1.

**CLI command:**
```bash
infrascan --scanner comprehensive --format html --out infrascan-report.html
```

---

### 2. Enforcement (blocking)

Suited to teams with established security standards. You set a threshold; if the scan results reach it, InfraScan exits with code 1 and the pipeline fails.

**Common thresholds:**
*   `--fail-on new_high_critical`: fail a PR only for High or Critical findings it adds; existing findings do not block it. Needs a baseline (automatic in the GitHub Action and the Bitbucket pipe); without one the check is skipped.
*   `--fail-on high_critical`: fail on any High or Critical finding (security, cost or container).
*   `--fail-on grade_c`: fail if the overall grade is C or worse (only A and B pass).
*   `--fail-on priority_medium`: fail on any Medium, High or Critical finding.

**CLI command example:**
```bash
infrascan --fail-on high_critical --format html --out report.html
```

---

## Suggested rollout

To avoid alert fatigue, introduce enforcement gradually:

1.  **Weeks 1-2: observation.**
    Run InfraScan in monitoring mode. Review the reports to understand the current state without requiring changes.
2.  **Week 3: worst cases only.**
    Switch to enforcement with `--fail-on grade_f`, so the pipeline fails only when the overall grade is F.
3.  **Ongoing: tighten the gate.**
    As the infrastructure improves, move to `--fail-on grade_d` or `--fail-on high_critical`. On pull requests, `--fail-on new_high_critical` blocks only regressions.

---

## Pipeline examples

### Bitbucket Pipelines

Use the InfraScan pipe and declare the report as an artifact so it can be downloaded from the pipeline run. This minimal version has no baseline cache; the full setup with caches is in [BITBUCKET_PIPELINE.md](BITBUCKET_PIPELINE.md).

```yaml
pipelines:
  branches:
    main:
      - step:
          name: InfraScan Audit
          script:
            - pipe: docker://soldevelo/infrascan:latest
              variables:
                SCANNER: comprehensive
                FORMAT: html
                OUT: infrascan-report.html
                # FAIL_ON: new_high_critical   # when ready to enforce
          artifacts:
            - infrascan-report.html
```

### GitHub Actions

The step summary, PR comments, automatic baseline and skipping of PRs with no relevant changes are on by default.

```yaml
name: InfraScan
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

      - uses: soldevelo/infrascan@v1
        with:
          scanner: comprehensive
          format: html
          out: infrascan-report.html
          # Optional: fail-on: new_high_critical

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: infrascan-report
          path: infrascan-report.html
```

**Enabled by default:**
- **Step summary**: scan results in the workflow run's Summary tab
- **PR comment**: grade table, cost estimate and new findings on every PR
- **Cost delta**: automatic baseline management shows infrastructure cost changes
- **PR skipping**: the scan is skipped on PRs that change no matching files
- **Inline annotations**: `::error`, `::warning` and `::notice` annotations in the PR diff view

See [GITHUB_ACTION.md](GITHUB_ACTION.md) for all inputs and features.

---

## Tips
*   **Console output:** InfraScan prints a colored summary to the log, so the HTML report is not always needed to see what is wrong.
*   **Selective scanning:** in large monorepos, use `-f` / `--include` to scan only specific files or directories, or `-x` / `--exclude` (the Action's `exclude` input, the pipe's `EXCLUDE` variable) to leave paths out.
*   **Selecting scanners:** for cost only, use `--scanner regex`; for IaC security only, `--scanner checkov`; for container images only, `--scanner containers`. Several can be combined with commas, e.g. `--scanner regex,containers`.
*   **Kubernetes projects:** the default `--framework smart` detects Kubernetes manifests and scans every framework it finds. To restrict the security scan to Kubernetes in a repository that also contains Terraform, use `--framework kubernetes`.
*   **Suppressing false positives:** use Checkov inline comments (e.g. `#checkov:skip=CKV_AWS_1:Reason`) to skip specific security checks that are intentional in your environment.

---

## Kubernetes projects

For projects using **Kubernetes manifests** (Deployments, StatefulSets, Services, etc.) rather than Docker Compose.

### What InfraScan scans
1. **Security misconfigurations** (Checkov): containers running as root, missing resource limits, missing probes, network policies, etc.
2. **Container vulnerabilities** (Docker Scout or Grype): every `image:` reference in the manifests is extracted and scanned for CVEs.

### Example: Bitbucket Pipelines
```yaml
pipelines:
  branches:
    main:
      - step:
          name: InfraScan K8s Audit
          script:
            - pipe: docker://soldevelo/infrascan:latest
              variables:
                FRAMEWORK: kubernetes
                SCANNER: comprehensive
                FORMAT: html
                OUT: infrascan-report.html
          artifacts:
            - infrascan-report.html
```

### Example: GitHub Actions
```yaml
name: InfraScan K8s Audit
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

      - uses: soldevelo/infrascan@v1
        with:
          framework: kubernetes
          scanner: comprehensive
          format: html
          out: infrascan-report.html

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: infrascan-k8s-report
          path: infrascan-report.html
```
