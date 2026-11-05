# InfraScan Bitbucket Pipelines Reference

Run as a Bitbucket **pipe**, InfraScan reports its results in the Bitbucket UI:

- **PR comment**: grade table, cost estimate and new findings, posted on every pull request and updated in place on re-runs
- **Code Insights report**: Bitbucket's counterpart of a step summary, shown in the pull request's Insights / Reports panel
- **Inline annotations**: Code Insights annotations anchored to files and lines in the PR diff view (Bitbucket has no `::error` / `::warning` workflow commands)
- **Baseline / cost delta**: automatic, no per-trigger configuration (see below)
- **HTML report**: the full report, saved as a pipeline artifact

---

## Setup

The pipe is the `soldevelo/infrascan` image, the same image the GitHub Action runs, referenced with Bitbucket's `docker://` pipe syntax; there is no separate pipe image. `:latest` follows every release; use a version tag such as `docker://soldevelo/infrascan:1.2.5` to pin it.

One step definition is shared, through a YAML anchor, by default-branch pushes and pull requests. The pipe decides at runtime what to do from Bitbucket's environment variables, not from which pipeline invoked it (see [Baseline / cost delta](#baseline--cost-delta)):

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

`branches: main` is used instead of `default:` on purpose: `default:` runs on every branch push, which would scan and post a Code Insights report on every feature-branch push, while only a push to `DEFAULT_BRANCH` writes the shared baseline. If your default branch is not `main`, change both the branch pattern and the `DEFAULT_BRANCH` variable; they are not linked.

`BITBUCKET_ACCESS_TOKEN` is needed only for the PR comment (see [Authentication](#authentication-pr-comment-only)). The `chmod` line is required whenever the caches are declared (see [Write permissions](#write-permissions)). See [examples/pipelines/bitbucket-pipelines.yml](../examples/pipelines/bitbucket-pipelines.yml) for a commented version of this file and [pipe/README.md](../pipe/README.md) for every variable.

A plain `docker run` step (with `services: docker` and explicit `-e` variables) also works, since it runs the same `cli.py` with the same flags, but it is not documented here; the pipe is the recommended setup.

### Write permissions

Bitbucket creates every directory declared under `caches:` before the step starts. A pipe container runs in its own user namespace, separate from the one the step's own commands run in, so inside the pipe that directory is owned by an unmapped identity the pipe has no rights to. Even `uid=0` inside the pipe cannot `chmod` it, because namespaced root has privileges only within its own namespace's mapped UID range. Running the pipe as root therefore does not help.

`chmod -R 777` on the cache directories, as the first command of the step (before the pipe container starts), solves this because mode bits, unlike UID/GID, apply the same way in every namespace. Use `-R`: a file restored from the cache keeps the mode bits the previous run gave it, and a `chmod` on the directory alone does not reopen access to it.

---

## CLI flags

The pipe maps its variables (see [pipe/README.md](../pipe/README.md)) onto these `cli.py` flags, which behave the same on GitHub and Bitbucket:

| Flag | Default | Description |
|---|---|---|
| `--scanner` | `comprehensive` | `regex`, `checkov`, `containers`, or `comprehensive` |
| `--format` | `text` | `text`, `json`, or `html` |
| `--out` | _(none)_ | Output file path |
| `--framework` | `smart` | `smart`, `auto`, `terraform`, `kubernetes`, `cloudformation`, `helm`, `ansible`, `all` |
| `--exclude` | _(none)_ | Comma-separated paths to leave out of the scan. A name without a slash matches at any depth, like `.gitignore` |
| `--fail-on` | `never` | Exit-code-1 threshold: `never`, `any`, `high_critical`, `grade_a`–`grade_f`, `priority_critical`–`priority_info`, `new_any`, `new_high_critical`, `new_critical`. `new_*` count only findings not in the baseline (i.e. added by the PR) and are skipped when there is no baseline, e.g. on the default branch |
| `--pr-comment` | `true` | Post or update a PR comment |
| `--step-summary` | `true` | On Bitbucket, controls the Code Insights report |
| `--alert-on` | `any_new` | Severity threshold for PR comments and annotations: `critical`, `high`, `medium`, `low`, `any_new`, or `none` |
| `--min-cost-delta` | `0` | Minimum cost delta ($/month) to highlight |
| `--max-pr-findings` | `10` | Maximum number of findings listed in the PR comment |
| `--max-annotations-per-image` | `10` | Maximum Code Insights annotations per container image, most severe first (`0` = no limit). Keeps one image's CVE list from crowding out every other finding; does not affect grading, the PR comment or the report |
| `--baseline` | _(none)_ | Path to a baseline JSON for the cost/finding delta. The pipe sets it automatically, see [Baseline / cost delta](#baseline--cost-delta) |
| `--baseline-out` | _(none)_ | Path to write this scan's result as JSON for use as a future baseline, regardless of `--format` / `--out`. The pipe sets it automatically, only on default-branch runs |
| `--download-external-modules` | off | Allow Checkov to download external Terraform modules |
| `--no-tips` | off | Leave out the line about InfraScan Cloud |

The pipe does not expose `--pr-comment` or `--step-summary`; both stay at `true`.

---

## Authentication (PR comment only)

The Code Insights report and annotations need no token: they go through a local proxy that Bitbucket Pipelines runs alongside every step and that authenticates those requests. The PR comment uses an API the proxy does not cover, so it needs a token. Without one, the scan, HTML report, Code Insights report and annotations work, and the PR comment is skipped with a `[warn]` line in the build log that repeats these steps:

1. Repository settings → Access tokens → create a repository access token with the `pullrequest:write` scope.
2. Repository settings → Pipelines → Repository variables → add a secured variable (e.g. `INFRASCAN_TOKEN`) holding the token.
3. Pass it to the pipe:
   ```yaml
   variables:
     BITBUCKET_ACCESS_TOKEN: $INFRASCAN_TOKEN
   ```

---

## PR comments

A PR comment is posted or updated on every pull-request pipeline run, including when nothing new was found, so the team can confirm the scan ran. As on GitHub, a marker identifies the comment so later runs update it. Bitbucket does not hide HTML comments, so the marker is a labelled footer line at the bottom of the comment rather than an invisible one at the top.

**Example** (grade table, cost delta and findings table are built by the same `format_pr_comment_md()` as on GitHub; the closing link and the footer are Bitbucket-specific):

```
## 🔍 InfraScan: B (78%) A→B ⚠️

| Category   | Grade       | Findings                |
|------------|-------------|--------------------------|
| Overall    | **B** (78%) | 🔴 1 critical, 2 high, 3 medium |
| Security   | **C** (60%) | 🔴 1 critical, 1 high   |
| Cost       | **A** (95%) | clean                   |
| Containers | **B** (80%) | 1 high, 3 medium        |

|            | Baseline | This PR | Delta                    |
|------------|----------|---------|---------------------------|
| Infra cost | $89/mo   | $104/mo | **+$15/mo ⚠️** (+16.9%) |

### New findings (4)
| Severity    | Rule       | File        | Description              |
|-------------|------------|-------------|---------------------------|
| 🔴 CRITICAL | CKV_AWS_7  | iam.tf:263  | KMS key rotation not enabled |
| 🟠 HIGH     | CKV_AWS_8  | ec2.tf:10   | IMDSv1 enabled            |
| 🟠 HIGH     | CVE-2024-1 | Dockerfile  | libc vuln                 |
| 🟡 MEDIUM   | CVE-2024-2 | Dockerfile  | openssl vuln              |

→ [Full report: see the Code Insights report, or download the HTML artifact](https://bitbucket.org/…/pipelines/results/42)

---
_InfraScan · updates this comment in place (infrascan-report)_
```

On runs without a pull request (`BITBUCKET_PR_ID` unset) no comment is posted, as on GitHub. Without a token the whole comment is skipped (see [Authentication](#authentication-pr-comment-only)).

---

## Code Insights report

Bitbucket has no step-summary file. Instead, InfraScan creates or updates a Code Insights report with the id `infrascan-report` on the current commit, shown in the pull request's Insights / Reports panel. Re-running the pipeline updates the same report.

The report contains:
- Data fields Grade, Monthly cost, Critical findings and High findings, rendered by Code Insights as native fields.
- `details`: a short plain-text summary (grade per category and cost trend). Code Insights does not render Markdown in this field, so it is built as plain text rather than reusing the GitHub step summary. Per-finding detail is in the annotations and the HTML artifact.
- `result`: `FAILED` when any CRITICAL finding exists, `PASSED` otherwise, shown as a pass/fail badge.
- `link`: the pipeline run.

No token is needed (see [Authentication](#authentication-pr-comment-only)).

---

## Inline annotations

Findings at or above the `--alert-on` threshold are posted as Code Insights annotations anchored to `file` / `line`, shown in the PR diff view. They are the Bitbucket counterpart of GitHub's workflow-command annotations and are sent through the REST API in batches of up to 100. No token is needed.

| Finding type | `annotation_type` | `severity` |
|---|---|---|
| Security finding / container CVE | `VULNERABILITY` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` (InfraScan's `info` maps to `LOW`; Bitbucket has no INFO level) |
| Cost increase against the baseline | `CODE_SMELL` | `MEDIUM` |

Cost-increase annotations appear only with a baseline, as on GitHub. A container CVE is anchored to the line that declares the vulnerable image in its compose or Kubernetes file. If several files reference the same image, the CVE is anchored in each of them, while the grade, the PR comment and the report's data fields still count it once. `MAX_ANNOTATIONS_PER_IMAGE` (default 10) limits the annotations per image.

---

## Baseline / cost delta

The baseline is handled automatically; beyond declaring the cache, the same step definition both writes and reads it.

[pipe/pipe.sh](../pipe/pipe.sh) checks `$BITBUCKET_BRANCH` and `$BITBUCKET_PR_ID` on each run:
- **Every run** passes `--baseline infrascan-baseline/infrascan-baseline.json` when that file exists, is readable and is not empty (on a PR, it may be replaced as described below).
- **Only a push to `DEFAULT_BRANCH`** that is not a PR also passes `--baseline-out` with the same path, refreshing the shared baseline from the scan already run for the report, so no second scan is needed. PR runs never write the shared baseline.
- **On a PR**, the cached baseline is used only if it still matches the PR's destination branch (see below). Otherwise the pipe extracts the destination branch into a temporary directory and scans it to build a baseline. If that fails (e.g. no network access), the scan continues without a baseline; this never fails the pipeline.

This is why the one step definition above works unchanged under both `branches` and `pull-requests`, with the `infrascan-baseline` cache declared once and shared by both.

### How a stale cache is detected

Bitbucket's cache is repository-wide, not per branch, so every branch and PR reads the same entry. Bitbucket uploads a cache only when none exists yet ("Skipping upload for existing cache" in the build teardown) and keeps it for up to a week, so a default-branch run that refreshes the baseline file does not replace the cached copy. The cached baseline can therefore be many merges old.

To avoid comparing a PR against an outdated baseline, every baseline records a **fingerprint** of the files the scanners read: a hash of their paths and blob IDs from `git ls-tree`, with no checkout needed. On a PR the pipe computes the same fingerprint for the destination branch as it is now:

- **Match**: no scanned file changed since the cache was saved (for example, only application code changed). The cached baseline is what a fresh scan would produce, so it is used without an extra scan.
- **Mismatch**, no cache, or a cache saved by an older version without a fingerprint: the destination branch is scanned directly, which costs one extra scan.

After an infrastructure change lands on `DEFAULT_BRANCH`, PRs keep scanning the destination branch until the cache expires or is cleared (Pipelines → Caches). Clearing it after such a merge lets the next default-branch run save a current baseline. The build log states which path each run took.

---

## Container scanning

Images are read from docker-compose and Kubernetes files and pulled from their registries by the pipe.

- **Variables in image names** (`prom/prometheus:${PROMETHEUS_VERSION}`) are expanded as docker compose does, from the environment and a `.env` file, with the committed `.env.example` / `.env.sample` as fallbacks, since `.env` is rarely committed. These files are looked up next to the compose file and in its parent directories; use `CONTAINER_ENV_FILES` for other names or a fixed path (e.g. `deploy/versions.env`). An image whose variable cannot be resolved is reported as not scanned.
- **Large images**: each image gets `CONTAINER_SCAN_TIMEOUT` seconds (default 300) for pull and analysis. Analysis dominates for images with large binaries (e.g. Grafana: about 40 s pull, about 3 min analysis). An image that times out is reported as not scanned.
- **Scanner**: Docker Scout when `DOCKER_HUB_USERNAME` and `DOCKER_HUB_PASSWORD` (a password or access token, as a secured variable) are set, since it reports fewer false positives; Grype otherwise, because Scout requires a Docker login even on a free account. Force one with `CONTAINER_SCANNER: grype` or `CONTAINER_SCANNER: docker-scout`.
- **Images that cannot be pulled** (a private registry unreachable from Bitbucket's cloud runners, missing credentials, a tag that does not exist) are never counted as clean. Each is logged with its reason, and the PR comment and the Code Insights report state how many images could not be scanned, since the container grade does not cover them. After the first unreachable or unauthorized registry, its remaining images are skipped instead of each waiting for a timeout. (Docker Hub answers "unauthorized" for repositories that do not exist, so for Docker Hub the pipe continues with the next image.)
- **Images this repository builds itself** and publishes only after merge (e.g. `-SNAPSHOT` tags): on a PR the registry holds only the previous build, so scanning it reports stale results or nothing. Skip them in the PR pipeline with `CONTAINER_IGNORE_IMAGES` (a regex matched against the image reference), and scan them in the default-branch pipeline after the step that builds and pushes them:

  ```yaml
  pull-requests:
    '**':
      - step:
          <<: *infrascan-audit
          script:
            - mkdir -p infrascan-baseline infrascan-grype-db && chmod -R 777 infrascan-baseline infrascan-grype-db
            - pipe: docker://soldevelo/infrascan:latest
              variables:
                CONTAINER_IGNORE_IMAGES: '-SNAPSHOT$'
                # ...same variables as the shared step
  ```

### Grype DB cache

Grype downloads its vulnerability database (about 175 MB, about 3 GB unpacked) on every run, which takes about 2.5 minutes. The setup above caches it in a second cache, `infrascan-grype-db`, next to the baseline cache. The cache is optional: remove it from `caches:` and from the `mkdir` / `chmod` line, and the pipe downloads the database on each run.

Scans always use a current database: when the cached one is older than Anchore's latest (published daily), Grype downloads the new one before scanning. The cache only decides whether that download is needed. Because Bitbucket never replaces an existing cache, on the first run after a new database is published the pipe deletes only the `infrascan-grype-db` cache (`DELETE .../pipelines-config/caches?name=infrascan-grype-db`), so the new database is saved in its place and later runs that day skip the download. The delete goes through the same local auth proxy as the Code Insights report, so no token is needed; `BITBUCKET_ACCESS_TOKEN` is used only as a fallback. If neither can delete the cache, the build log says so, and until Bitbucket expires the old cache (up to 7 days) each run downloads the database, as without a cache. The cache is about 550 MB compressed, within Bitbucket's 1 GB limit.

If the cache directory exists but is not writable by the pipe (the `chmod` line is missing), the pipe ignores it and downloads the database.

---

## Scan skipping (opt-in)

Not part of the default setup. It only saves time: it skips the scan, and the PR comment, on PRs that change no IaC or container files. It is worth adding if most of your PRs change no infrastructure files. Querying `cli.py --list-patterns` at runtime would need its own `docker run` (and Docker-in-Docker), so the snippet uses a static pattern list; keep it in sync with the scanner's trigger patterns if you change `SCANNER`.

Add it as the first `script:` item, before the `pipe:` entry. A step's `script:` list runs in one shell session, so an early `exit 0` skips everything after it in the same step, including the pipe:

```yaml
- |
  git fetch origin "$BITBUCKET_PR_DESTINATION_BRANCH" --depth=50 2>/dev/null || true
  CHANGED=$(git diff --name-only "origin/$BITBUCKET_PR_DESTINATION_BRANCH...HEAD" 2>/dev/null || true)
  PATTERN='\.tf$|\.tfvars$|\.hcl$|\.ya?ml$|\.json$|\.template$|(^|/)Dockerfile(\.[^/]+)?$|(^|/)docker-compose[^/]*\.ya?ml$|(^|/)compose\.ya?ml$'
  if [ -n "$CHANGED" ] && ! echo "$CHANGED" | grep -qE "$PATTERN"; then
    echo "InfraScan skipped -- no supported files changed."
    exit 0
  fi
```

This only takes effect in PR pipelines: on a branch push `$BITBUCKET_PR_DESTINATION_BRANCH` is unset, `$CHANGED` stays empty and the scan runs. That is intended, since runs on `DEFAULT_BRANCH` must run to refresh the baseline.

---

## Differences from the GitHub Action

| | GitHub Actions | Bitbucket Pipelines |
|---|---|---|
| Setup | `uses: soldevelo/infrascan@v1` | `pipe: docker://soldevelo/infrascan:latest` |
| Token | `github.token`, provided automatically | Report and annotations authenticate through the local proxy; the PR comment needs a repository access token passed as `BITBUCKET_ACCESS_TOKEN` |
| PR number / context | Read from the `GITHUB_EVENT_PATH` JSON | Read from the `BITBUCKET_PR_ID` variable |
| Step summary | `GITHUB_STEP_SUMMARY` file | Code Insights report (`PUT .../reports/infrascan-report`) |
| Inline findings | `::error` / `::warning` / `::notice` workflow commands | Code Insights annotations (REST) |
| Comment marker | Invisible `<!-- -->` marker | Visible footer line (Bitbucket does not render raw HTML) |
| Baseline caching | Automatic, keyed by base branch commit SHA (`actions/cache`), so it is invalidated when the base branch advances | Automatic, detected at runtime from `BITBUCKET_BRANCH` / `BITBUCKET_PR_ID`. One repository-wide cache entry that Bitbucket does not re-upload while it exists (kept up to a week); a fingerprint of the scanned files decides per PR whether the cache matches the base branch or the base branch is scanned directly |
| Skipping unchanged PRs | On by default (`skip-if-no-match`) | Opt-in, see [Scan skipping](#scan-skipping-opt-in); an early `exit 0` in the step's script has the same effect |
