# CI/CD Pipeline Integration Guide

This guide explains how to integrate InfraScan into your CI/CD pipelines to improve your infrastructure's cost efficiency and security without disrupting your development workflow. InfraScan supports **Terraform**, **Kubernetes**, **CloudFormation**, and **Helm** projects.

> 💡 **Ready-to-use Templates**: You can find pre-configured pipeline files in the [examples/pipelines](../examples/pipelines) directory. You can copy these directly into your project to get started in seconds.

## 🚀 Integration Strategies

InfraScan is designed to be flexible. You can choose between two primary integration modes depending on your project's maturity.

### 1. Monitoring Mode (Advisory / Non-blocking)
**Use Case:** Best for initial rollout or when you want InfraScan to act as a "second pair of eyes" without stopping the pipeline.

In this mode, InfraScan will:
*   Scan your code and print a summary to the console logs.
*   Generate detailed HTML/JSON reports.
*   **Always exit with code 0**, ensuring the pipeline continues even if issues are found.

**CLI Command:**
```bash
infrascan --scanner comprehensive --format html --out infrascan-report.html
```

---

### 2. Enforcement Mode (Gatekeeper / Blocking)
**Use Case:** Best for production environments or teams with established security standards.

In this mode, you define a "quality gate". If the scan results are worse than your threshold, the pipeline will **fail (exit code 1)**, preventing the deployment of problematic infrastructure.

**Common Thresholds:**
*   `--fail-on high_critical`: Stop the build only for High or Critical security vulnerabilities.
*   `--fail-on grade_c`: Fail if the overall grade is C or worse (allows only A and B).
*   `--fail-on priority_medium`: Fail if any Medium, High, or Critical issues are detected.

**CLI Command Example:**
```bash
infrascan --fail-on high_critical --format html --out report.html
```

---

## 📈 Recommended Rollout (The "Soft Intro")

To avoid "alert fatigue" and developer frustration, we recommend this 3-step rollout:

1.  **Week 1-2: Observation**
    Integrate InfraScan in **Monitoring Mode**. Review the reports to understand your baseline. Don't force any changes yet.
2.  **Week 3: Critical Only**
    Switch to **Enforcement Mode** with `--fail-on grade_f`. This ensures that only the most severely broken configurations (Critical risks) block the pipeline.
3.  **Ongoing: Continuous Improvement**
    As your infrastructure improves, tighten the gate to `--fail-on grade_d` or `--fail-on high_critical`.

---

## 🛠️ Pipeline Examples

### Bitbucket Pipelines
Always use `artifacts` and `when: always` to ensure you can see the results even when the scan fails.

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
              # Add --fail-on here when ready to enforce
        artifacts:
          - infrascan-report.html
```

### GitHub Actions
Use `if: always()` for the report upload step.

```yaml
jobs:
  infrascan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Scan
        uses: soldevelo/infrascan@v1.0.5
        with:
          format: html
          out: report.html
      - name: Upload Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: infrascan-report
          path: report.html
```

## 💡 Pro Tips
*   **Console Visibility:** InfraScan v1.0.4+ prints a colored summary directly to the terminal. You don't always need to download the HTML report to see what's wrong.
*   **Selective Scanning:** For large monorepos, use `-f` or `--include` to scan only the modified directories or files. This speeds up the scan and reduces noise from unrelated projects.
*   **Selective Scanners:** If you only care about costs, use `--scanner regex`. If you only care about security, use `--scanner checkov`.
*   **Kubernetes Projects:** InfraScan auto-detects Kubernetes manifests. If your repo contains K8s YAML files alongside Terraform, you can force the framework with `--framework kubernetes`.
*   **Ignore False Positives:** Use standard Checkov inline comments (e.g., `#checkov:skip=CKV_AWS_1:Reason`) to skip specific security checks that are intentional in your environment.

---

## ☸️ Kubernetes-Specific Integration

For projects using **Kubernetes manifests** (Deployments, StatefulSets, Services, etc.) instead of Docker Compose:

### What InfraScan scans in K8s projects:
1. **Security misconfigurations** (via Checkov): running as root, missing resource limits, missing probes, network policies, etc.
2. **Container vulnerabilities** (via Docker Scout/Grype): all `image:` references from your manifests are extracted and scanned for CVEs.

### Example — Bitbucket Pipeline for Kubernetes project
```yaml
pipelines:
  default:
    - step:
        name: InfraScan K8s Audit
        services:
          - docker
        script:
          - mkdir -p infrascan-reports && chmod 777 infrascan-reports
          - docker run --rm
              -v $(pwd):/scan
              soldevelo/infrascan:latest
              --framework kubernetes
              --scanner comprehensive
              --format html
              --out /scan/infrascan-reports/report.html
        artifacts:
          - infrascan-reports/**
```

### Example — GitHub Actions for Kubernetes project
```yaml
jobs:
  infrascan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run K8s Scan
        uses: soldevelo/infrascan@v1.0.5
        with:
          framework: kubernetes
          scanner: comprehensive
          format: html
          out: report.html
      - name: Upload Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: infrascan-report
          path: report.html
```
