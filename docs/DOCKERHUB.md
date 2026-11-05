# InfraScan

<p>
    <a href="https://hub.docker.com/r/soldevelo/infrascan"><img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/soldevelo/infrascan.svg?style=flat-square"></a>
    <a href="https://hub.docker.com/r/soldevelo/infrascan"><img alt="Docker Image Size" src="https://img.shields.io/docker/image-size/soldevelo/infrascan/latest?style=flat-square"></a>
    <a href="https://github.com/soldevelo/infrascan/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/soldevelo/infrascan?style=flat-square&logo=github"></a>
    <a href="https://github.com/soldevelo/infrascan/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=flat-square"></a>
</p>

Open-source scanner for infrastructure code: cost, security and container vulnerabilities, in your terminal or CI.

InfraScan checks Terraform, CloudFormation, Kubernetes, Helm and Ansible code and the container images it references. It grades the result from A to F, estimates the monthly cost of each cost finding, and runs entirely on your machine or CI runner.

> **InfraScan Cloud (free beta).** This image stays free and runs locally. To scan a live AWS account, InfraScan Cloud connects through a read-only role and grades security, reliability and cost, with a monthly price on each piece of waste and a fix for every finding.
> [See the demo](https://infrascan.soldevelo.com/cloud-demo/?utm_source=dockerhub&utm_campaign=beta) · [Get started](https://infrascan.soldevelo.com/?utm_source=dockerhub&utm_campaign=beta)

## Quick start

```bash
docker run --rm -v $(pwd):/scan soldevelo/infrascan:latest
```

This scans the current directory with all scanners and prints the results to the terminal.

## What it checks

| Area | Details |
|---|---|
| Cost | 27 Terraform rules (old instance generations, gp2 instead of gp3, NAT Gateways, missing S3 lifecycle rules, missing budgets, oversized Lambda memory and more), each with an estimated monthly saving. |
| IaC security | Checkov policies for Terraform, CloudFormation, Kubernetes, Helm and Ansible. |
| Containers | CVEs in images referenced by Docker Compose files and Kubernetes manifests, scanned with Grype, or Docker Scout when Docker Hub credentials are set. Supports `${VAR}` in image names and Amazon ECR. |
| Grades and deltas | An A–F grade per category; with a baseline, only the findings and cost changes introduced by a pull request. |

## Options

```bash
docker run --rm -v $(pwd):/scan soldevelo/infrascan:latest [options]
```

| Option | Description |
|---|---|
| `--scanner` | `comprehensive` (default), `regex`, `checkov`, `containers`, or a comma-separated combination. |
| `--format` | `text` (default), `json` or `html`. |
| `--out` | Report file path, e.g. `/scan/report.html`. |
| `--framework` | `smart` (default), `auto`, `terraform`, `kubernetes`, `cloudformation`, `helm`, `ansible`, `all`. |
| `-f`, `--include` | Scan only the given files or directories. |
| `-x`, `--exclude` | Leave paths out, e.g. `-x docs,tests,examples`. Names without a slash match at any depth, as in `.gitignore`. |
| `--fail-on` | Exit with code 1 on `any`, `high_critical`, a grade (`grade_a`–`grade_f`), a priority, or only on findings a PR adds (`new_any`, `new_high_critical`, `new_critical`). |
| `--no-tips` | Omit the one-line InfraScan Cloud note. |

## CI/CD

**GitHub Actions** (PR comment, step summary, inline annotations, per-branch baseline):

```yaml
- uses: actions/checkout@v4
- uses: soldevelo/infrascan@v1
  with:
    format: html
    out: infrascan-report.html
    fail-on: new_high_critical
```

**Bitbucket Pipelines** (PR comment, Code Insights report, annotations):

```yaml
- pipe: docker://soldevelo/infrascan:latest
  variables:
    FORMAT: html
    OUT: infrascan-report.html
```

**GitLab CI** and other Docker-based CI systems: use the `docker run` command above.

Full documentation: [GitHub Action](https://github.com/SolDevelo/InfraScan/blob/main/docs/GITHUB_ACTION.md) · [Bitbucket pipe](https://github.com/SolDevelo/InfraScan/blob/main/pipe/README.md) · [README](https://github.com/SolDevelo/InfraScan#readme)

## Tags

| Tag | Description |
|---|---|
| `latest` | The newest release. |
| `1.2.5`, `1.2.4`, … | A specific release. Pin one for reproducible results. Since 1.2.5, the GitHub Action runs the image matching its own version. |

## Links

- Source code and issues: [github.com/SolDevelo/InfraScan](https://github.com/SolDevelo/InfraScan)
- Community: [InfraScan Slack](https://join.slack.com/t/infrascancommunity/shared_invite/zt-3rcl6w3wg-gCN1AKW1sXjYT080efVmlQ)
- Contact: [soldevelo.com/contact](https://soldevelo.com/contact)
