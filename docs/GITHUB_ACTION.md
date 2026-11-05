# InfraScan GitHub Action Reference

The `soldevelo/infrascan` composite action runs InfraScan in Docker and reports the results in the GitHub UI:

- **Step summary**: scan results in the workflow run's Summary tab (on by default, `step-summary`)
- **PR comment**: grade table, cost estimate and new findings, posted on every pull request and updated in place on re-runs (on by default, `pr-comment`)
- **Inline annotations**: `::error` / `::warning` / `::notice` workflow commands, shown in the PR diff view
- **HTML report**: the full report, uploaded as a workflow artifact by an `actions/upload-artifact` step in your workflow

---

## Minimal workflow

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
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: soldevelo/infrascan@v1
        with:
          scanner: comprehensive
          format: html
          out: infrascan-report.html
          fail-on: new_high_critical

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: infrascan-report
          path: infrascan-report.html
```

`pull-requests: write` is needed only for the PR comment. The step summary, annotations, baseline management and skipping of PRs with no relevant changes are on by default and need no extra inputs. The `push` trigger on the default branch lets every PR reuse that branch's scan as its baseline (see [Baseline / cost delta](#baseline--cost-delta)).

---

## Inputs

| Input | Default | Description |
|---|---|---|
| `directory` | `.` | Directory to scan, relative to the repository root |
| `exclude` | _(none)_ | Comma-separated paths to leave out, e.g. `docs,tests,examples`. A name without a slash matches at any depth (like `.gitignore`), one with a slash is relative to `directory`; `*` and `?` work. Also applied to the base-branch baseline scan, so the delta compares like with like |
| `scanner` | `comprehensive` | `regex`, `checkov`, `containers`, or `comprehensive` |
| `format` | `text` | `text`, `json`, or `html` |
| `out` | _(auto)_ | Output file path, relative to the repository root. When empty, set to `infrascan-report.html` / `infrascan-report.json` if `format` is `html` / `json` |
| `framework` | `smart` | `smart`, `auto`, `terraform`, `kubernetes`, `cloudformation`, `helm`, `ansible`, `all` |
| `fail-on` | `never` | Exit-code-1 threshold: `never`, `any`, `high_critical`, `grade_a`–`grade_f`, `priority_critical`–`priority_info`, `new_any`, `new_high_critical`, `new_critical`. `new_*` count only findings not in the baseline (i.e. added by the PR) and are skipped when there is no baseline, e.g. on the default branch |
| `github-token` | `github.token` | Token for PR comments. Defaults to the built-in token, so there is no need to pass `secrets.GITHUB_TOKEN` |
| `pr-comment` | `true` | Post or update a PR comment on pull requests |
| `step-summary` | `true` | Write scan results to the step summary |
| `alert-on` | `any_new` | Severity threshold for PR comments and annotations: `critical`, `high`, `medium`, `low`, `any_new`, or `none`. See [`alert-on` values](#alert-on-values) |
| `min-cost-delta` | `0` | Minimum cost delta ($/month) to highlight in the PR comment. `0` shows any cost change |
| `max-pr-findings` | `10` | Maximum number of findings listed in the PR comment, most severe first. The rest are counted in an "… and N more findings" line |
| `baseline` | _(none)_ | Path to an explicit baseline JSON for the cost/finding delta. Overrides the automatic baseline |
| `auto-baseline` | `true` | Cache the default branch's scan and compare PRs against it. See [Baseline / cost delta](#baseline--cost-delta) |
| `skip-if-no-match` | `true` | On pull requests, skip the scan when no changed file matches the scanner's trigger patterns. See [Scan skipping](#scan-skipping) |
| `image` | _(released image)_ | InfraScan image to run. Defaults to the image released with this version of the action (`soldevelo/infrascan:<version>`), so pinning the action to a tag or SHA pins the scanner too. Set it for a mirror or a private registry |
| `slack-webhook-url` | _(none)_ | Slack Incoming Webhook URL for scan notifications |
| `docker-hub-username` / `docker-hub-password` | _(none)_ | Docker Hub login (pass the password or access token as a secret). With it, container images are scanned with Docker Scout (fewer false positives); without it, with Grype |
| `container-ignore-images` | _(none)_ | Regex of container images to skip, e.g. `-SNAPSHOT$` for images this repository builds itself and publishes only after merge |
| `container-scan-timeout` | `300` | Per-image scan timeout in seconds, covering pull and analysis. Raise it for very large images; an image that times out is reported as not scanned |
| `container-env-files` | `.env,.env.example,.env.sample` | Env files used to expand `${VAR}` in compose image names, highest priority first. A bare name is looked up next to each compose file and in its parent directories; a path with `/` is relative to `directory` |
| `download-external-modules` | `false` | Allow Checkov to download external Terraform modules |
| `tips` | `true` | One line about InfraScan Cloud at the end of the log, in the step summary and in the HTML report footer (never in PR comments). `false` turns it off |

Grype's vulnerability database is cached with `actions/cache` under a key that changes daily. The first run of a day restores the previous day's database and Grype updates it; later runs that day reuse it without a download (about 2.5 minutes otherwise). There is nothing to configure.

## Outputs

| Output | Description |
|---|---|
| `triggered-by-paths` | Newline-separated list of changed files that triggered the scan. Empty when the scan was skipped |

To skip the whole workflow before a runner starts, use a `paths` filter on the workflow trigger instead of `skip-if-no-match`:

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

With `pr-comment: true` (the default), a comment is posted on every pull request, including when nothing new was found, so the team can confirm the scan ran. Later runs update the same comment. It contains:

1. **Grade table**: grade and finding counts for Overall, Security, Cost and Containers.
2. **Grade change**: when the overall grade drops against the baseline, the title shows it (e.g. `B→C ⚠️`).
3. **Unscanned images**: a warning line when some container images could not be scanned.
4. **Infrastructure cost**: the current estimate; with a baseline, a Baseline / This PR / Delta table.
5. **New findings**: IaC findings and container CVEs in one table, sorted by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO; IaC before containers within a severity), limited to `max-pr-findings` entries.

On push events there is no pull request, so no comment is posted. All findings and savings opportunities are in the step summary.

**Example comment (mixed severities, IaC and container findings, first 10 shown):**
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

### New findings (28)
| Severity | Rule       | File        | Description                      |
|----------|------------|-------------|----------------------------------|
| 🔴 CRITICAL | CKV_AWS_7  | main.tf:263 | KMS key rotation not enabled     |
| 🔴 CRITICAL | COST-006   | eip.tf:12   | Unassociated Elastic IP          |
| 🔴 CRITICAL | CVE-2024-9821 | Dockerfile | Critical libc vulnerability   |
| 🟠 HIGH | CKV_AWS_79 | vpc.tf:45   | Security group ingress 0.0.0.0/0 |
| 🟠 HIGH | CKV_K8S_8  | deploy.yaml:12 | Container runs as root        |
| 🟠 HIGH | COST-005   | nat.tf:8    | NAT Gateway removable            |
| 🟠 HIGH | CVE-2024-1122 | Dockerfile | openssl HIGH vulnerability     |
| 🟡 MEDIUM | CKV_AWS_33 | kms.tf:22   | KMS key no rotation policy       |
| 🟡 MEDIUM | CKV_K8S_11 | pod.yaml:15 | CPU limits not set               |
| 🟡 MEDIUM | CVE-2024-3301 | Dockerfile | openssl MEDIUM vulnerability  |

_… and 18 more findings — see full report_

→ [Full report in Actions summary](…)
```

With the default `alert-on: any_new`, MEDIUM, LOW and INFO findings are listed too, as above. Set `alert-on: high` or `alert-on: critical` to list only the more severe ones.

**Example comment (no actionable changes):**
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
| Step summary | _(none, written to a file)_ |
| PR comment | `pull-requests: write` |
| Inline annotations | _(none, workflow commands)_ |

Without `pull-requests: write` the comment is not posted, and the scan result and exit code are unaffected.

### `alert-on` values

Controls which findings appear in the PR comment and as inline annotations. The PR comment lists up to `max-pr-findings` new findings across the selected severities, most severe first.

| Value | Listed in the PR comment | Annotations |
|---|---|---|
| `any_new` (default) | New findings of any severity | CRITICAL `::error`, HIGH `::warning`, others `::notice` |
| `low` | New LOW, MEDIUM, HIGH and CRITICAL findings | CRITICAL `::error`, HIGH `::warning`, MEDIUM/LOW `::notice` |
| `medium` | New MEDIUM, HIGH and CRITICAL findings | CRITICAL `::error`, HIGH `::warning`, MEDIUM `::notice` |
| `high` | New HIGH and CRITICAL findings | CRITICAL `::error`, HIGH `::warning` |
| `critical` | New CRITICAL findings | CRITICAL `::error` |
| `none` | None (the comment still shows grades and cost) | None |

Annotations are limited to 10 per level (error, warning, notice), GitHub's own per-step limit; the most severe findings are kept. With a baseline, resources whose estimated cost rose by more than $1/month also get a `COST-DELTA` warning annotation.

**Cost changes** are shown whenever the delta reaches `min-cost-delta` (default `0`, i.e. any change).

**Grade drops** are shown in the comment title.

---

## Baseline / cost delta

The action manages the baseline itself (`auto-baseline: true`). On every push to the default branch it saves that scan as the baseline for its commit (cache key `infrascan-<branch>-<sha>`). On every PR it:

1. Restores a cached baseline JSON keyed by base branch name and base commit SHA (`infrascan-<base_ref>-<base.sha>`).
2. If there is no cache entry (the default branch was not scanned at that commit, e.g. because the workflow does not run on `push`), scans the base branch once to create the baseline. If that is not possible (`directory` does not exist on the base branch, e.g. because an earlier step generates it, or the scan fails), the action logs a warning and scans the PR without a baseline instead of failing the job.
3. Runs the main scan with `--baseline` pointing at that result.
4. Caches a base-branch scan from step 2 for later runs of the same PR. GitHub lets a PR read only caches saved by the default branch or by that PR, so running the workflow on `push` to the default branch is what lets every PR skip step 2.

The cache key is based on the base branch commit, not on the PR's files, so the baseline is always a scan of the branch being merged into and is refreshed whenever that branch gets new commits.

The [minimal workflow](#minimal-workflow) above already uses this. To manage the baseline yourself, pass `baseline` (which takes precedence over the automatic one) and, optionally, turn the automatic one off:

```yaml
- uses: soldevelo/infrascan@v1
  with:
    auto-baseline: 'false'
    baseline: /path/to/your/baseline.json
```

---

## Scan skipping

With `skip-if-no-match: true` (default) on a `pull_request` event, the action checks whether any file changed by the PR matches the scanner's trigger patterns before starting the scan. If none does, the scan and the following steps are skipped. If the list of changed files cannot be determined, the scan runs.

Trigger patterns per scanner (extended regex, matched against `git diff --name-only`):

| Scanner | Triggers on |
|---|---|
| `regex` | `\.tf$`, `\.tfvars$`, `\.hcl$` |
| `checkov` | `\.tf$`, `\.tfvars$`, `\.hcl$`, `\.ya?ml$`, `\.json$`, `\.template$` |
| `containers` | `(^|/)Dockerfile(\.[^/]+)?$`, `(^|/)docker-compose[^/]*\.ya?ml$`, `(^|/)compose\.ya?ml$` |
| `comprehensive` | All of the above |

On `push` events the check is not run and the scan always runs.

---

## Upgrading from v1.0.x

| Feature | Action needed |
|---|---|
| Step summary | None (on by default) |
| Skipping PRs with no relevant changes | None (`skip-if-no-match: true` by default) |
| Inline annotations | None (on by default) |
| PR comments | Add `permissions: pull-requests: write` to the workflow or job |
| Cost delta / baseline | None (`auto-baseline: true` by default) |

Without `pull-requests: write` the scan result is unchanged; only the comment is not posted.
