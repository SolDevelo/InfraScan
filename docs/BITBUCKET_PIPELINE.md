# InfraScan Bitbucket Pipelines Reference

Running InfraScan as a Bitbucket **Pipe** surfaces findings directly in the
Bitbucket UI — no artifact download required:

- **PR comment** — grade table, cost estimate, and new findings, posted on every pull request (updated on re-runs, same comment)
- **Code Insights report** — Bitbucket's equivalent of a step summary: full scan results shown in the PR's "Insights" tab
- **Inline annotations** — findings appear anchored to the changed lines in the PR diff view (Code Insights annotations — Bitbucket has no `::error`/`::warning` workflow-command mechanism)
- **Baseline / cost delta** — automatic, no per-trigger config (see below)
- **HTML report** — full interactive report saved as a pipeline artifact

---

## Setup

This uses `soldevelo/infrascan:latest`, the same image the GitHub Action
uses, referenced via Bitbucket's `docker://` pipe syntax — no separate pipe
image. One shared step definition, reused via a YAML anchor for both branch
pushes and PRs — the pipe figures out which behavior applies at runtime from
Bitbucket's own env vars, not from which pipeline definition invoked it (see
"Baseline / cost delta" below):

```yaml
definitions:
  caches:
    infrascan-baseline: infrascan-baseline
  steps:
    - step: &infrascan-audit
        name: InfraScan Audit
        caches:
          - infrascan-baseline
        script:
          - mkdir -p infrascan-baseline && chmod -R 777 infrascan-baseline
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

`branches: main` (not `default:`) is deliberate — `default:` runs on every
branch push, not just the default branch, which would scan and post a
Code Insights report on every feature-branch push for no benefit, since
only a push to `DEFAULT_BRANCH` ever writes the shared baseline anyway. If
your default branch isn't `main`, update both this branch pattern and the
`DEFAULT_BRANCH` variable — they aren't linked automatically.

`BITBUCKET_ACCESS_TOKEN` is required — see "Authentication" below. The
`chmod` line is required too — see "Write permissions" below. Set
`DEFAULT_BRANCH` if yours isn't `main`. See
[examples/pipelines/bitbucket-pipelines.yml](../examples/pipelines/bitbucket-pipelines.yml)
for the full copy-pasteable version with comments, and
[pipe/README.md](../pipe/README.md) for every variable.

A manual `docker run`-based setup (no pipe, explicit `-e` env forwarding) is
possible too if you want more control — `cli.py`'s flags are the same either
way — but it's not documented here; the pipe is the recommended path.

### Write permissions

Bitbucket pre-provisions any `caches:`-declared path before the step
starts. A `pipe:` container runs in its own isolated user namespace,
separate from the one this step's own commands run in — a directory this
step's `root` has full access to shows up inside the pipe owned by an
unmapped foreign identity it has no rights to (not even `uid=0` inside the
pipe can `chmod` it — namespaced root only bypasses permission checks
within its *own* namespace's mapped UID range, not outside it). Running the
pipe as root doesn't fix this; it's a namespace boundary, not a
permission-bits problem.

`chmod -R 777 infrascan-baseline`, run as the first line of the step (before
the pipe container starts), works because mode bits — unlike UID/GID —
apply the same way in every namespace. Opening the "other" bits there is
what actually bridges the two. Use `-R`, not a plain `chmod` on the
directory alone: once a baseline file has been cached from a previous run,
it carries that run's own mode bits, and a non-recursive `chmod` on the
directory won't reopen access to the file itself for a later run.

---

## CLI flags (same ones the GitHub Action exposes)

These are plain `cli.py` arguments — platform-agnostic, so they behave
identically on GitHub and Bitbucket. The pipe maps its own `variables:` onto
these (see [pipe/README.md](../pipe/README.md)):

| Flag | Default | Description |
|---|---|---|
| `--scanner` | `comprehensive` | `regex`, `checkov`, `containers`, or `comprehensive` |
| `--format` | `text` | `text`, `json`, or `html` |
| `--out` | _(none)_ | Output file path |
| `--framework` | `smart` | `smart`, `auto`, `terraform`, `kubernetes`, `cloudformation`, `helm`, `ansible`, `all` |
| `--fail-on` | _(off)_ | Exit-code-1 threshold: `any`, `high_critical`, `grade_a`–`grade_f`, `priority_critical`–`priority_info` |
| `--pr-comment` | `true` | Post/update a PR comment |
| `--step-summary` | `true` | On Bitbucket this controls the Code Insights report (there's no literal "step summary" file) |
| `--alert-on` | `any_new` | Severity threshold for PR comments and annotations: `critical`, `high`, `medium`, `low`, `any_new`, or `none` |
| `--min-cost-delta` | `0` | Minimum cost delta ($/month) to highlight |
| `--max-pr-findings` | `10` | Maximum total findings shown in the PR comment |
| `--max-annotations-per-image` | `10` | Maximum Code Insights annotations per container image, sorted by severity (`0` = no cap) — keeps one noisy image's CVE list from drowning out every other finding; doesn't affect grading, the PR comment, or the report |
| `--baseline` | _(none)_ | Path to a baseline JSON for cost/finding delta. The pipe passes this automatically — see "Baseline / cost delta" below |
| `--baseline-out` | _(none)_ | Path to write this scan's result as JSON, for a future baseline — written regardless of `--format`/`--out`. The pipe passes this automatically, only on default-branch runs |
| `--download-external-modules` | `false` | Allow Checkov to download external Terraform modules |

---

## Authentication (only required for the PR comment)

The Code Insights report and annotations need **no token at all** — they go
through a local proxy Bitbucket Pipelines runs alongside every step, which
authenticates those requests automatically. The PR comment uses a different,
more general API that proxy doesn't cover, so it still needs a token —
without one, the scan, HTML report, Code Insights report, and annotations
all work, but the PR comment silently does nothing (a `[warn]` line in the
build log says so, with these same steps).

1. Repository settings → Access tokens → Create repository access token, with
   `pullrequest:write` scope.
2. Repository settings → Pipelines → Repository variables → add a secured
   variable (e.g. `INFRASCAN_TOKEN`) with that token's value.
3. Pass it through to the pipe explicitly:
   ```yaml
   variables:
     BITBUCKET_ACCESS_TOKEN: $INFRASCAN_TOKEN
   ```

---

## PR comments

A PR comment is **always posted/updated** on every pull-request pipeline run
— even when there's nothing new — so the team can confirm the scan ran. Same
marker-based update-in-place behavior as GitHub, but since Bitbucket's
renderer doesn't hide HTML comments the way GitHub's does, the marker here
is a small, plainly-labeled footer line at the *bottom* of the comment
instead of an invisible one at the top.

**Example** (the grade table, cost delta, and findings table come from the
same `format_pr_comment_md()` GitHub uses; the closing link and the footer
marker are Bitbucket-specific):

```
## 🔍 InfraScan: B (78%) A→B ⚠️

| Category   | Grade       | Findings                |
|------------|-------------|--------------------------|
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

On pushes without an open PR (`BITBUCKET_PR_ID` unset), no comment is
attempted — same rule as GitHub. Requires a token; see "Authentication"
above — without one this whole comment is skipped, not just the link.

---

## Code Insights report

Bitbucket has no literal step-summary file. InfraScan instead upserts a
**Code Insights report** (id `infrascan-report`) on the current commit,
visible in the PR's "Insights"/"Details" tab. Re-running the pipeline updates
the same report in place — no marker/dedup trick needed, unlike the comment.

The report includes:
- A small structured data grid (Grade, Monthly cost, Critical findings, High
  findings) — Code Insights renders these as native fields, not a Markdown
  table.
- `details`: a short **plain-text** summary (per-category grade + cost
  trend) — Code Insights' `details` field doesn't render Markdown at all
  (confirmed live: headers, bold, and tables all came through as literal
  `##`/`**`/`|` characters), so this is a dedicated plain-text builder, not
  the GitHub step summary's Markdown reused. Per-finding detail lives in the
  annotations and the full HTML artifact instead, not here.
- `result`: `FAILED` when any CRITICAL finding exists, `PASSED` otherwise —
  shown as a pass/fail badge on the report.
- `link`: back to the pipeline run.
- No token needed — see "Authentication" above.

---

## Inline annotations

Findings at or above the `--alert-on` threshold are posted as Code Insights
**annotations** — anchored to `file`/`line`, shown directly in the PR diff
view. This is the structural equivalent of GitHub's `::error`/`::warning`
workflow commands, since Bitbucket has no such mechanism; annotations are
posted via REST (bulk, up to 100 per call) instead of printed to the log. No
token needed — see "Authentication" above.

| Finding type | `annotation_type` | `severity` |
|---|---|---|
| Security / container CVE | `VULNERABILITY` | `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` (InfraScan's `info` findings map to `LOW` — Bitbucket has no INFO level) |
| Cost increase vs. baseline | `CODE_SMELL` | `MEDIUM` |

Cost-increase annotations only appear when `--baseline` is supplied (same
rule as GitHub). A container CVE is anchored to the line that declares the
vulnerable image in its compose/Kubernetes file; if the same image is
referenced by more than one such file, it's anchored in each of them
without inflating the finding count anywhere else (grade, PR comment,
report data grid all still count it once).

---

## Baseline / cost delta

Automatic, with no per-trigger config beyond declaring the cache — the exact
same step definition handles both writing and reading the baseline.

[pipe/pipe.sh](../pipe/pipe.sh) checks `$BITBUCKET_BRANCH` and
`$BITBUCKET_PR_ID` at runtime and decides, per run:
- **Every run** passes `--baseline infrascan-baseline/infrascan-baseline.json`
  when that file exists, is readable, and is non-empty.
- **Only** a push to `DEFAULT_BRANCH` that is *not* a PR also passes
  `--baseline-out` at the same path, refreshing the shared baseline —
  reusing the scan already run for the report, so this never costs a second
  scan. PR runs never write to the shared baseline.
- **On a PR**, if the cached baseline is missing, empty, or unreadable (cold
  cache, first-ever run, or a stale-permission cache entry), the pipe falls
  back to scanning the PR's own base branch directly — fetched into a
  throwaway worktree — to build a baseline on the spot, instead of showing
  every finding as new. If that fallback itself fails (e.g. no network
  access), the scan still proceeds with no baseline; this never fails the
  pipeline.

That's why the one step definition in the setup above works unchanged for
both `pipelines.default` and `pipelines.pull-requests`, with the cache
(`infrascan-baseline`) declared once and shared by both.

Bitbucket's cache mechanism is repo-wide, not branch-scoped — every branch
and PR in the repo reads and writes the same cache slot, so a PR does
compare against `DEFAULT_BRANCH`'s baseline by design. What Bitbucket's
cache lacks, unlike the GitHub Action's cache (keyed per **base-branch
commit SHA** via `actions/cache`, so a stale cache is automatically
bypassed the moment the base branch advances), is native invalidation: its
key can only be derived from **file contents** (`key.files`), not branch
names or commit SHAs. In practice that means the cached baseline can lag by
up to one default-branch pipeline run behind the latest commit on
`DEFAULT_BRANCH`, which is normally the last commit merged before your PR.
The PR-side fallback above covers the *empty*-cache case (first run, or an
evicted/corrupted cache); it does not eliminate this one-run lag on an
otherwise warm cache.

---

## Scan skipping (opt-in)

Not in the default example — it's a pure optimization (skip the scan, and
the "no actionable findings" comment, on PRs that touch no IaC/container
files), not a correctness requirement. Worth adding if most of your PRs
touch no infra files at all; not worth it otherwise, since `cli.py
--list-patterns` would need its own `docker run` to query dynamically
(reintroducing Docker-in-Docker), so this uses a static pattern list
instead — keep it in sync with the scanner's real trigger patterns if you
change `SCANNER`.

Add this as the first `script:` item, before the `pipe:` entry (a step's
`script:` list runs as one continuous shell session — an early `exit 0`
here skips everything after it in the same step, including a later `pipe:`
reference):

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

Only fires on PR pipelines (`$BITBUCKET_PR_DESTINATION_BRANCH` is unset on a
plain branch push, so `$CHANGED` stays empty and the check is skipped there)
— fine, since `default`-triggered runs against `DEFAULT_BRANCH` need to run
anyway to refresh the baseline.

---

## What's different from the GitHub Action

| | GitHub Actions | Bitbucket Pipelines |
|---|---|---|
| Setup | `uses: soldevelo/infrascan@v1` | `pipe: docker://soldevelo/infrascan:latest` |
| Token | `github.token`, auto-injected | Auto-authenticated via a local proxy for the report/annotations; the PR comment (a different API) still needs a manually created Repository Access Token passed as `BITBUCKET_ACCESS_TOKEN` |
| PR number / context | Parsed from `GITHUB_EVENT_PATH` JSON | Read directly from `BITBUCKET_PR_ID` env var — no event file |
| Step summary | `GITHUB_STEP_SUMMARY` file | Code Insights report (`PUT .../reports/infrascan-report`) |
| Inline findings | `::error`/`::warning` workflow commands | Code Insights annotations (REST) |
| Comment dedup | Invisible `<!-- --> ` marker | Visible footer line (Bitbucket doesn't render raw HTML) |
| Baseline caching | Automatic, base-branch-**commit-SHA** keyed (`actions/cache`) — self-invalidates when the base branch advances, hidden inside the Action | Automatic, auto-detected at runtime from `BITBUCKET_BRANCH`/`BITBUCKET_PR_ID` — a single unkeyed cache slot shared repo-wide, can lag by up to one default-branch pipeline run; falls back to scanning the PR's base branch directly when the cache is cold |
| Skip unchanged PRs | On by default, declarative `if:` on a separate step (`skip-if-no-match`) | **Opt-in** — not in the default example (see "Scan skipping" above); when added, an early `exit 0` inside the step's script has the same effect |
