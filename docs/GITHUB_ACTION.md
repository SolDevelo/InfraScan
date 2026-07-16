# InfraScan GitHub Action Reference

The `soldevelo/infrascan` composite action runs InfraScan inside Docker and surfaces findings directly in the GitHub UI — no artifact download required.

- **Step summary** — full scan results in the workflow run's Summary tab (always written)
- **PR comment** — compact critical-findings summary posted on the pull request (posted when actionable; updated on re-runs)
- **Inline annotations** — `::error` / `::warning` annotations appear in the PR diff view
- **HTML report** — full interactive report uploaded as a workflow artifact (optional but recommended)

---

## Minimal workflow

```yaml
name: InfraScan
on: [push, pull_request]

permissions:
  pull-requests: write   # needed only for PR comments; remove if not wanted

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: soldevelo/infrascan@v1
        with:
          scanner: comprehensive
          format: html
          out: infrascan-report.html
          fail-on: high_critical

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: infrascan-report
          path: infrascan-report.html
```

`permissions: pull-requests: write` is the only addition vs. the original Quick Start.  
All other new behaviour (step summary, skip-on-no-match, annotations) is on by default and needs no extra params.

---

## All inputs

| Input | Default | Description |
|---|---|---|
| `directory` | `.` | Directory to scan (relative to repo root) |
| `scanner` | `comprehensive` | `regex`, `checkov`, `containers`, or `comprehensive` |
| `format` | `text` | `text`, `json`, or `html` |
| `out` | _(auto)_ | Output file path. Auto-set to `infrascan-report.html` / `.json` when `format` is `html`/`json` |
| `framework` | `auto` | `smart`, `auto`, `terraform`, `kubernetes`, `cloudformation`, `helm`, `ansible`, `all` |
| `fail-on` | _(off)_ | Exit-code-1 threshold: `any`, `high_critical`, `grade_a`–`grade_f`, `priority_critical`–`priority_info` |
| `github-token` | `github.token` | Token for PR comments and annotations. Defaults to the built-in token — no need to pass `secrets.GITHUB_TOKEN` explicitly |
| `pr-comment` | `true` | Post/update a PR comment when actionable findings exist |
| `step-summary` | `true` | Write scan results to the Actions step summary |
| `alert-on` | `critical` | Severity threshold for PR comments and annotations: `critical`, `critical_high`, or `none` |
| `baseline` | _(none)_ | Path to a baseline JSON for cost/finding delta. Set automatically when using the baseline cache pattern below |
| `skip-if-no-match` | `true` | Skip the scan on PRs when no files matching the scanner's trigger patterns were changed |
| `slack-webhook-url` | _(none)_ | Slack Incoming Webhook URL for scan notifications |
| `download-external-modules` | `false` | Allow Checkov to download external Terraform modules |

## Outputs

| Output | Description |
|---|---|
| `triggered-by-paths` | Newline-separated list of changed files that triggered the scan. Empty when the scan was skipped |

Use `triggered-by-paths` to drive your workflow's `on.pull_request.paths` filter for workflow-level skipping (before a runner is provisioned):

```yaml
on:
  pull_request:
    paths:
      - '**/*.tf'
      - '**/*.tfvars'
      - '**/Dockerfile'
      - '**/docker-compose*.yml'
```

---

## PR comments

A PR comment is posted or updated **only when there is something actionable**:

1. At least one **CRITICAL** finding is present (or new vs baseline), **or**
2. `alert-on: critical_high` and at least one **HIGH** finding, **or**
3. A baseline is available and **cost increased** by more than $5/mo or 10%.

On pushes to the default branch (no open PR) no comment is attempted.

The comment is compact — just the grade, cost delta, and the CRITICAL/HIGH findings table. Full details (savings opportunities, MEDIUM findings) are in the step summary, not the comment.

**Example comment:**
```
## 🔍 InfraScan — B (78%)

|               | main    | This PR  | Delta       |
|---------------|---------|----------|-------------|
| Infra cost    | $89/mo  | $104/mo  | +$15/mo ⚠️ |

### 🔴 New CRITICAL findings (1)
| Rule      | File       | Description                   |
|-----------|------------|-------------------------------|
| CKV_AWS_7 | iam.tf:263 | KMS key rotation not enabled  |

→ Full report in [Actions summary](…)
```

### Permissions

| Feature | Required permission |
|---|---|
| Step summary | _(none — uses file system)_ |
| PR comment | `pull-requests: write` |
| Inline annotations | _(none — uses workflow commands)_ |

Without `pull-requests: write` the comment attempt produces a 403 in the logs but does **not** fail the scan.

### `alert-on` values

| Value | PR comment triggers on | Annotations emitted |
|---|---|---|
| `critical` (default) | CRITICAL findings | CRITICAL as `::error` |
| `critical_high` | CRITICAL or HIGH findings | CRITICAL `::error`, HIGH `::warning` |
| `none` | Never | Never |

---

## Baseline / cost delta

Comparing this PR's scan to the base-branch baseline gives a cost delta and highlights *new* vs *resolved* findings.

```yaml
name: InfraScan
on: pull_request

permissions:
  pull-requests: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      # Try to restore a previously saved baseline
      - name: Restore baseline cache
        id: baseline-cache
        uses: actions/cache/restore@v4
        with:
          path: /tmp/infrascan-baseline.json
          key: infrascan-${{ github.base_ref }}-${{ hashFiles('**/*.tf', '**/Chart.yaml', '**/Dockerfile') }}
          restore-keys: |
            infrascan-${{ github.base_ref }}-

      # Cold-cache fallback: scan the base branch to produce a baseline
      - name: Scan base branch (baseline fallback)
        if: steps.baseline-cache.outputs.cache-hit != 'true'
        run: |
          git checkout ${{ github.base_ref }}
          docker run --rm \
            -v ${{ github.workspace }}:/scan \
            soldevelo/infrascan:latest \
            cli /scan --scanner comprehensive --format json --out /scan/infrascan-baseline.json
          cp infrascan-baseline.json /tmp/infrascan-baseline.json
          git checkout -

      # Save baseline for next run
      - name: Save baseline cache
        uses: actions/cache/save@v4
        with:
          path: /tmp/infrascan-baseline.json
          key: infrascan-${{ github.base_ref }}-${{ hashFiles('**/*.tf', '**/Chart.yaml', '**/Dockerfile') }}

      # Main scan with delta
      - uses: soldevelo/infrascan@v1
        with:
          scanner: comprehensive
          format: html
          out: infrascan-report.html
          fail-on: high_critical
          baseline: /tmp/infrascan-baseline.json

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: infrascan-report
          path: infrascan-report.html
          retention-days: 14
```

On first run (cold cache) this scans twice — once for the baseline, once for the PR. On subsequent runs only the PR branch is scanned and the cached baseline is used for the delta.

---

## Scan skipping

When `skip-if-no-match: true` (default) and the event is a `pull_request`, the action checks whether any files in the PR diff match the scanner's trigger patterns before starting the Docker container. If nothing matches, the scan is skipped with a neutral notice:

```
::notice::InfraScan skipped — no supported files changed.
```

Trigger patterns per scanner:

| Scanner | Triggers on |
|---|---|
| `regex` | `**/*.tf`, `**/*.tfvars`, `**/*.hcl` |
| `checkov` | `**/*.tf`, `**/*.tfvars`, `**/*.hcl`, `**/*.yaml`, `**/*.yml`, `**/*.json`, `**/*.template` |
| `containers` | `**/Dockerfile`, `**/Dockerfile.*`, `**/docker-compose*.yml`, `**/docker-compose*.yaml`, `**/compose.yml`, `**/compose.yaml` |
| `comprehensive` | Union of all the above |

For `push` events the check is skipped and the scan always runs.

---

## Upgrading from an earlier version

If your workflow uses `soldevelo/infrascan@v1.0.x`:

| Feature | Action needed |
|---|---|
| Step summary | None — automatic |
| Skip unchanged PRs | None — automatic (`skip-if-no-match: true` default) |
| Inline annotations | None — automatic |
| PR comments | Add `permissions: pull-requests: write` to the job |
| Cost delta | Add the baseline cache steps above |

Without `pull-requests: write` the scan result is unchanged — the comment just won't be posted.
