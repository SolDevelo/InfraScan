# InfraScan Pipe for Bitbucket Pipelines

Scan Terraform, Kubernetes and Docker for cost inefficiencies and security
issues, with results posted as a PR comment, a Code Insights report, and
inline annotations. Base-branch cost/security baseline delta is automatic
too, with zero per-trigger config (see "Baseline tracking" below).

`entrypoint.sh` detects a bare, zero-argument invocation running inside
Bitbucket Pipelines (that's exactly how Bitbucket runs a `pipe:
docker://...` reference — it feeds the variables below as env vars, never
argv) and routes to `pipe.sh`, which maps them onto the equivalent `cli.py`
flags.

## YAML Definition

The **same** step works for both branch pushes and PRs — define it once and
reference it from both, via a YAML anchor:

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
branch push, not just the default branch, which would scan for no benefit
since only a push to `DEFAULT_BRANCH` ever writes the shared baseline
anyway. Update both this pattern and `DEFAULT_BRANCH` together if yours
isn't `main` — they aren't linked automatically.

`BITBUCKET_ACCESS_TOKEN` is only needed for the PR comment — see
"Authentication" below. The `chmod` line is required regardless — see "Why
the chmod line is needed" below.

See [examples/pipelines/bitbucket-pipelines.yml](../examples/pipelines/bitbucket-pipelines.yml)
for the full copy-pasteable version with comments.

## Variables

| Variable | Usage | Default |
|---|---|---|
| BITBUCKET_ACCESS_TOKEN | Needed only for the PR comment — the report and annotations work without it. See "Authentication" below | _(none)_ |
| DIRECTORY | Directory to scan, relative to the repo root | `.` |
| SCANNER | `regex`, `checkov`, `containers`, or `comprehensive` | `comprehensive` |
| FORMAT | `text`, `json`, or `html` | `html` |
| OUT | Output file path, relative to the repo root | `infrascan-report.html` |
| FRAMEWORK | `smart`, `auto`, `terraform`, `kubernetes`, `cloudformation`, `helm`, `ansible`, `all` | `smart` |
| ALERT_ON | `critical`, `high`, `medium`, `low`, `any_new`, `none` | `any_new` |
| MIN_COST_DELTA | Minimum cost delta ($/month) to highlight in the PR comment | `0` |
| MAX_PR_FINDINGS | Maximum findings shown in the PR comment | `10` |
| MAX_ANNOTATIONS_PER_IMAGE | Maximum Code Insights annotations per container image, sorted by severity (`0` = no cap) — one noisy image's CVE list can't drown out other findings; doesn't affect grading/PR comment/report | `10` |
| FAIL_ON | (optional) Exit-code-1 threshold | _(none)_ |
| BASELINE | Path read for cost/finding delta, if present. Missing file = "no baseline", safe by default | `infrascan-baseline/infrascan-baseline.json` |
| BASELINE_OUT | Path this scan's result is written to as JSON — but only when this run is a push to `DEFAULT_BRANCH` that isn't a PR, auto-detected (see below) | `infrascan-baseline/infrascan-baseline.json` |
| DEFAULT_BRANCH | Branch whose runs refresh the shared baseline | `main` |
| DOWNLOAD_EXTERNAL_MODULES | Allow Checkov to download external Terraform modules | `false` |

## What you get automatically

Repository context (`BITBUCKET_WORKSPACE`, `BITBUCKET_REPO_SLUG`,
`BITBUCKET_PR_ID`, `BITBUCKET_COMMIT`, `BITBUCKET_BRANCH`, and more) is
injected into every pipe automatically — no `-e` forwarding needed for any
of it, unlike a plain `docker run` step. Authentication is the exception —
see below.

## Authentication (only required for the PR comment)

The Code Insights report and annotations need **no token at all** — they go
through a local proxy Bitbucket Pipelines runs alongside every step, which
authenticates those requests automatically (`host.docker.internal:29418`
from inside a pipe's own container). The PR comment uses a different, more
general API that proxy doesn't cover, so it still needs a token — without
one, everything else works but the PR comment silently does nothing (a
`[warn]` line in the build log says so).

1. Repository settings → Access tokens → create a Repository Access Token
   with `pullrequest:write` scope.
2. Repository settings → Pipelines → Repository variables → add it as a
   **secured** variable (e.g. `INFRASCAN_TOKEN`).
3. Reference it in the pipe's `variables:` block:
   ```yaml
   variables:
     BITBUCKET_ACCESS_TOKEN: $INFRASCAN_TOKEN
   ```

See [docs/BITBUCKET_PIPELINE.md](../docs/BITBUCKET_PIPELINE.md) for what
each channel (PR comment / Code Insights report / annotations) shows once
this is set up.

## Why the chmod line is needed

Bitbucket pre-provisions any `caches:`-declared path before the step
starts. A `pipe:` container runs in its own isolated user namespace,
separate from the one this step's own commands run in — a directory this
step's `root` can access fully shows up inside the pipe as owned by an
unmapped foreign identity it has no rights to (not even `uid=0` there can
`chmod` it — namespaced root only has its usual privilege bypass within its
*own* namespace's mapped UID range, not outside it). Running the pipe
itself as root doesn't help — it's a namespace boundary, not a
permission-bits problem.

`chmod -R 777 infrascan-baseline`, run as the first line in *this* step
(before the pipe container starts), works because mode bits — unlike
UID/GID — apply the same way in every namespace. Opening the "other" bits
here is what actually bridges the two. Use `-R`, not a plain `chmod` on the
directory alone: once a baseline file has been cached from a previous run,
it carries that run's own mode bits, and a non-recursive `chmod` on the
directory won't reopen access to the file itself for a later run.

## Baseline tracking (automatic)

`pipe.sh` checks `$BITBUCKET_BRANCH` and `$BITBUCKET_PR_ID` at runtime to
decide, per run:
- **Every run** reads `BASELINE` if the file is present, readable and
  non-empty.
- **Only** a push to `DEFAULT_BRANCH` that is *not* a PR also writes
  `BASELINE_OUT` — reusing the same scan already run for the report, so this
  never costs a second scan. PR runs never overwrite the shared baseline
  with PR-branch results.
- **On a PR**, the pipe falls back to scanning the PR's own base branch
  directly — `git fetch`-ing it into a throwaway worktree and running a
  second, internal scan to build a baseline on the spot — whenever either:
  `BASELINE` is missing, empty, or unreadable (cold cache, first-ever run,
  or a permission issue), or the PR targets a branch other than
  `DEFAULT_BRANCH` (the cache only ever holds `DEFAULT_BRANCH`'s baseline,
  so it's the wrong one to use for a PR into anywhere else even if it's
  readable). This costs one extra scan only when the fallback actually
  triggers; a same-branch warm cache never does. If the fallback itself
  fails (e.g. no network access to fetch), the pipe just proceeds with no
  baseline, same as it always has — this never fails the pipeline. Every
  outcome here is logged (cache found/not found, fallback triggered or not,
  fallback succeeded/failed) so it's visible in the build log which path a
  given run took.

This is why the exact same step definition (see the YAML above) works
unchanged for both `pipelines.default` and `pipelines.pull-requests` — the
pipe figures out which behavior applies from Bitbucket's own env vars, not
from which pipeline definition invoked it.

## What this pipe does *not* do

**Skip-if-no-match** isn't included — the dynamic pattern query
(`cli.py --list-patterns`) needs its own `docker run`, which would
reintroduce the Docker-in-Docker overhead this pipe avoids everywhere else.
See "Scan skipping" in [docs/BITBUCKET_PIPELINE.md](../docs/BITBUCKET_PIPELINE.md)
for an opt-in snippet if you want it anyway.

## Support

Issues: https://github.com/soldevelo/infrascan/issues
