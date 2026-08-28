# InfraScan GitHub Action Reference

The `soldevelo/infrascan` composite action runs InfraScan inside Docker and surfaces findings directly in the GitHub UI — no artifact download required.

- **Step summary** — full scan results in the workflow run's Summary tab (always written)
- **PR comment** — grade table, cost estimate, and new CRITICAL/HIGH findings posted on every pull request (updated on re-runs)
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
| `pr-comment` | `true` | Post/update a PR comment on every pull request |
| `step-summary` | `true` | Write scan results to the Actions step summary |
| `alert-on` | `any_new` | Severity threshold for PR comments and annotations: `critical`, `high`, `medium`, `low`, `any_new`, or `none`. `any_new` shows all new findings sorted by severity |
| `min-cost-delta` | `0` | Minimum cost delta ($/month) to highlight in PR comments. Default 0 = show any cost change |
| `max-pr-findings` | `10` | Maximum total findings to show in PR comments (sorted by severity, most important first). Additional findings are aggregated |
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

A PR comment is **always posted** on every pull request — even when there is nothing new — so the team can confirm the scan ran. The comment contains:

1. **Grade overview table** — Category / Grade / Findings for Overall, Security, Cost, and Containers
2. **Grade changes** — Highlighted in title when overall grade drops (e.g. B→C ⚠️)
3. **Infrastructure cost** — current estimate; when a baseline exists, shown as a Baseline / This PR / Delta table (any cost change shown by default)
4. **Top N new IaC findings** — most important findings sorted by severity (CRITICAL → HIGH → MEDIUM → LOW), shown in one unified table, limited to `max-pr-findings` total (default: 10)
5. **Container findings** — aggregated summary table showing total and new CVE counts per severity, not individual CVE listings

On pushes to the default branch (no open PR) no comment is attempted.

Full details (all findings, savings opportunities) are in the step summary.

**Example comment (mixed severities, top 10 shown):**
```
## 🔍 InfraScan: C (71%) B→C ⚠️

| Category   | Grade       | Findings                         |
|------------|-------------|----------------------------------|
| Overall    | **C** (71%) | 🔴 3 critical, 8 high, 22 medium |
| Security   | **D** (58%) | 2 high, 22 medium                |
| Cost       | **C** (70%) | 6 high, 16 medium                |
| Containers | **A** (91%) | 🔴 1 critical, 2 high            |

|            | Baseline  | This PR   | Delta           |
|------------|-----------|-----------|-----------------|
| Infra cost | $4,625/mo | $5,623/mo | **+$998/mo ⚠️** (+21.6%) |

### New IaC findings (28)
| Severity | Rule       | File        | Description                      |
|----------|------------|-------------|----------------------------------|
| 🔴 CRITICAL | CKV_AWS_7  | main.tf:263 | KMS key rotation not enabled     |
| 🔴 CRITICAL | COST-006   | eip.tf:12   | Unassociated Elastic IP          |
| 🔴 CRITICAL | CKV_AWS_20 | s3.tf:5     | S3 bucket not encrypted          |
| 🟠 HIGH | CKV_AWS_79 | vpc.tf:45   | Security group ingress 0.0.0.0/0 |
| 🟠 HIGH | CKV_K8S_8  | deploy.yaml:12 | Container runs as root        |
| 🟠 HIGH | COST-005   | nat.tf:8    | NAT Gateway removable            |
| 🟠 HIGH | CKV_AWS_18 | lb.tf:23    | ALB access logging not enabled   |
| 🟠 HIGH | CKV_AWS_33 | rds.tf:15   | RDS encryption not enabled       |
| 🟡 MEDIUM | CKV_AWS_33 | kms.tf:22   | KMS key no rotation policy       |
| 🟡 MEDIUM | CKV_K8S_11 | pod.yaml:15 | CPU limits not set               |

_… and 18 more findings — see full report_

### 🐳 Container Findings
| Severity | Total | New    |
|----------|-------|--------|
| HIGH     | 15    | +3 ⚠️  |
| MEDIUM   | 32    | +8 ⚠️  |

_→ View all CVEs in full HTML report_

→ [Full report in Actions summary](…)
```

**Example comment (clean, no actionable changes):**
```
## 🔍 InfraScan: B (84%)

| Category | Grade       | Findings      |
|----------|-------------|---------------|
| Overall  | **B** (84%) | 2 high        |
| …        | …           | …             |

**Infrastructure cost:** $1,200/mo

✅ No new findings above threshold.

→ [Full report in Actions summary](…)
```

### Permissions

| Feature | Required permission |
|---|---|
| Step summary | _(none — uses file system)_ |
| PR comment | `pull-requests: write` |
| Inline annotations | _(none — uses workflow commands)_ |

Without `pull-requests: write` the comment attempt produces a 403 in the logs but does **not** fail the scan.

### `alert-on` values

Controls which findings appear in PR comments and inline annotations. Shows the top `max-pr-findings` (default: 10) most important new findings across **all severity levels**, sorted by severity (CRITICAL first).

| Value | Shown in PR comments | Annotations |
|---|---|---|
| `any_new` (default) | Top N new findings across all severities | CRITICAL `::error`, HIGH `::warning`, others `::notice` |
| `low` | Top N new findings (LOW/MEDIUM/HIGH/CRITICAL) | CRITICAL `::error`, HIGH `::warning`, MEDIUM/LOW `::notice` |
| `medium` | Top N new findings (MEDIUM/HIGH/CRITICAL) | CRITICAL `::error`, HIGH `::warning`, MEDIUM `::notice` |
| `high` | Top N new findings (HIGH/CRITICAL) | CRITICAL `::error`, HIGH `::warning` |
| `critical` | Top N new CRITICAL only | CRITICAL `::error` |
| `none` | Never (summary only) | Never |

**Container findings** are aggregated by severity in a summary table instead of listing individual CVEs.

**Cost changes** are always shown when any delta exists (configurable via `min-cost-delta`, default: 0).

**Grade changes** (drops) are highlighted in the comment title.

---

## Baseline / cost delta

The action automatically manages the baseline — no extra steps needed. On every PR it:
1. Restores a cached baseline JSON keyed by **base branch name + base commit SHA** (`infrascan-<base_ref>-<base.sha>`)
2. If the cache is cold (first run, or the base branch has advanced), scans the base branch once to create the baseline
3. Runs the main scan with `--baseline` pointing at the cached result
4. Saves the base-branch scan to cache for future PRs targeting the same base commit

The cache key is intentionally based on the **base branch SHA**, not the PR branch files — this ensures the baseline is always a scan of what you are merging *into*, and it is refreshed automatically whenever the base branch gets new commits.

This is all on by default (`auto-baseline: true`). Your workflow stays minimal:

```yaml
name: InfraScan
on: [push, pull_request]

permissions:
  pull-requests: write
  contents: read

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

To disable automatic baseline management (e.g. you manage it yourself):

```yaml
- uses: soldevelo/infrascan@v1
  with:
    auto-baseline: 'false'
    baseline: /path/to/your/baseline.json
```

---

## Scan skipping

When `skip-if-no-match: true` (default) and the event is a `pull_request`, the action checks whether any files in the PR diff match the scanner's trigger patterns before starting the Docker container. If nothing matches, the scan is skipped with a neutral notice:

```
::notice::InfraScan skipped — no supported files changed.
```

Trigger patterns per scanner (extended regex, matched against `git diff --name-only`):

| Scanner | Triggers on |
|---|---|
| `regex` | `\.tf$`, `\.tfvars$`, `\.hcl$` |
| `checkov` | `\.tf$`, `\.tfvars$`, `\.hcl$`, `\.ya?ml$`, `\.json$`, `\.template$` |
| `containers` | `(^|/)Dockerfile(\.[^/]+)?$`, `(^|/)docker-compose[^/]*\.ya?ml$`, `(^|/)compose\.ya?ml$` |
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
| Cost delta / baseline | None — automatic (`auto-baseline: true` default) |

Without `pull-requests: write` the scan result is unchanged — the comment just won't be posted.
