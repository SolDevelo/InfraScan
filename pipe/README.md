# InfraScan Pipe for Bitbucket Pipelines

Scans Terraform, Kubernetes, Docker and other IaC for cost and security issues and posts the results as a PR comment, a Code Insights report and inline annotations. The cost/security delta against the base branch is computed automatically, with no per-trigger configuration (see [Baseline tracking](#baseline-tracking)).

Bitbucket runs a `pipe: docker://...` reference without arguments and passes the variables below as environment variables. `entrypoint.sh` detects such a call inside Bitbucket Pipelines and runs `pipe.sh`, which maps the variables onto the equivalent `cli.py` flags.

## YAML definition

The same step works for default-branch pushes and pull requests. Define it once and reference it from both with a YAML anchor:

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

`branches: main` is used instead of `default:` on purpose: `default:` runs on every branch push, and only a push to `DEFAULT_BRANCH` writes the shared baseline. If your default branch is not `main`, change both this pattern and `DEFAULT_BRANCH`; they are not linked.

`:latest` follows every release; use a version tag such as `docker://soldevelo/infrascan:1.2.5` to pin it.

`BITBUCKET_ACCESS_TOKEN` is needed only for the PR comment (see [Authentication](#authentication-pr-comment-only)). The `chmod` line is required when the caches are declared (see [Why the chmod line is needed](#why-the-chmod-line-is-needed)).

See [examples/pipelines/bitbucket-pipelines.yml](../examples/pipelines/bitbucket-pipelines.yml) for a commented version of this file.

## Variables

| Variable | Description | Default |
|---|---|---|
| `BITBUCKET_ACCESS_TOKEN` | Needed only for the PR comment; the report and annotations work without it. See [Authentication](#authentication-pr-comment-only) | _(none)_ |
| `DIRECTORY` | Directory to scan, relative to the repository root | `.` |
| `EXCLUDE` | Comma-separated paths to leave out, e.g. `docs,tests,examples`. A name without a slash matches at any depth (like `.gitignore`), one with a slash is relative to `DIRECTORY`; `*` and `?` work | _(none)_ |
| `SCANNER` | `regex`, `checkov`, `containers`, or `comprehensive` | `comprehensive` |
| `FORMAT` | `text`, `json`, or `html` | `html` |
| `OUT` | Output file path, relative to the repository root | `infrascan-report.html` |
| `FRAMEWORK` | `smart`, `auto`, `terraform`, `kubernetes`, `cloudformation`, `helm`, `ansible`, `all` | `smart` |
| `ALERT_ON` | Severity threshold for the PR comment and annotations: `critical`, `high`, `medium`, `low`, `any_new`, `none` | `any_new` |
| `MIN_COST_DELTA` | Minimum cost delta ($/month) to highlight in the PR comment | `0` |
| `MAX_PR_FINDINGS` | Maximum number of findings listed in the PR comment | `10` |
| `DOCKER_HUB_USERNAME` / `DOCKER_HUB_PASSWORD` | Docker Hub login (password or access token, as a secured variable). With it, container images are scanned with Docker Scout (fewer false positives); without it, with Grype | _(none)_ |
| `CONTAINER_SCANNER` | Force `grype` or `docker-scout`. By default Scout is used when Docker Hub credentials are set, Grype otherwise | _(automatic)_ |
| `CONTAINER_IGNORE_IMAGES` | Regex of images to skip, e.g. `-SNAPSHOT$`. See [Container scanning](#container-scanning) | _(none)_ |
| `CONTAINER_SCAN_TIMEOUT` | Per-image scan timeout in seconds, covering pull and analysis | `300` |
| `CONTAINER_ENV_FILES` | Env files used to expand `${VAR}` in compose image names, highest priority first | `.env,.env.example,.env.sample` |
| `GRYPE_DB_CACHE` | Directory and cache name for Grype's database; used only if that cache is declared | `infrascan-grype-db` |
| `MAX_ANNOTATIONS_PER_IMAGE` | Maximum Code Insights annotations per container image, most severe first (`0` = no limit). Keeps one image's CVE list from crowding out other findings; does not affect grading, the PR comment or the report | `10` |
| `FAIL_ON` | Exit-code-1 threshold: `never`, `any`, `high_critical`, `grade_a`–`grade_f`, `priority_critical`–`priority_info`, `new_any`, `new_high_critical`, `new_critical`. `new_*` count only findings the PR adds and are skipped without a baseline (e.g. on the default branch) | `never` |
| `BASELINE` | Path read for the cost/finding delta, if the file exists. A missing file means no baseline | `infrascan-baseline/infrascan-baseline.json` |
| `BASELINE_OUT` | Path this scan's result is written to as JSON, only on a push to `DEFAULT_BRANCH` that is not a PR (see [Baseline tracking](#baseline-tracking)) | `infrascan-baseline/infrascan-baseline.json` |
| `DEFAULT_BRANCH` | Branch whose runs refresh the shared baseline | `main` |
| `DOWNLOAD_EXTERNAL_MODULES` | Allow Checkov to download external Terraform modules | `false` |
| `TIPS` | One line about InfraScan Cloud at the end of the log and in the HTML report footer (never in the PR comment or Code Insights report); `false` turns it off | `true` |

## Repository context

Bitbucket passes its build variables (`BITBUCKET_WORKSPACE`, `BITBUCKET_REPO_SLUG`, `BITBUCKET_PR_ID`, `BITBUCKET_COMMIT`, `BITBUCKET_BRANCH` and others) to every pipe, so they do not need to be forwarded as they would with a plain `docker run`. The access token for the PR comment is the exception; see below.

## Authentication (PR comment only)

The Code Insights report and annotations need no token: they go through a local proxy that Bitbucket Pipelines runs alongside every step and that authenticates those requests (reachable at `host.docker.internal:29418` from a pipe's container). The PR comment uses an API the proxy does not cover, so it needs a token. Without one, everything else works and the PR comment is skipped with a `[warn]` line in the build log.

1. Repository settings → Access tokens → create a repository access token with the `pullrequest:write` scope.
2. Repository settings → Pipelines → Repository variables → add it as a **secured** variable (e.g. `INFRASCAN_TOKEN`).
3. Reference it in the pipe's `variables:` block:
   ```yaml
   variables:
     BITBUCKET_ACCESS_TOKEN: $INFRASCAN_TOKEN
   ```

See [docs/BITBUCKET_PIPELINE.md](../docs/BITBUCKET_PIPELINE.md) for what the PR comment, Code Insights report and annotations contain.

## Why the chmod line is needed

Bitbucket creates every directory declared under `caches:` before the step starts. A pipe container runs in its own user namespace, separate from the one the step's own commands run in, so inside the pipe that directory is owned by an unmapped identity the pipe has no rights to. Even `uid=0` inside the pipe cannot `chmod` it, because namespaced root has privileges only within its own namespace's mapped UID range. Running the pipe as root therefore does not help.

`chmod -R 777` on the cache directories, as the first command of the step (before the pipe container starts), solves this because mode bits, unlike UID/GID, apply the same way in every namespace. Use `-R`: a file restored from the cache keeps the mode bits the previous run gave it, and a `chmod` on the directory alone does not reopen access to it.

## Baseline tracking

`pipe.sh` checks `$BITBUCKET_BRANCH` and `$BITBUCKET_PR_ID` on each run:
- **Every run** reads `BASELINE` if the file exists, is readable and is not empty.
- **Only a push to `DEFAULT_BRANCH`** that is not a PR also writes `BASELINE_OUT`, from the scan already run for the report, so no second scan is needed. PR runs never overwrite the shared baseline.
- **On a PR**, the cached baseline is used only if it still matches the PR's destination branch. Bitbucket uploads a cache only when none exists yet and keeps it for up to a week, so the cached baseline can be many merges old. Each baseline therefore stores a fingerprint of the files the scanners read (from `git ls-tree`, no checkout), and the pipe compares it with the destination branch as it is now. If they match, including when only non-infrastructure code changed, the cache is used as is. If not (scanned files changed, no cache, or a cache saved by an older version), the pipe extracts the destination branch into a temporary directory and scans it to build a baseline, which costs one extra scan. A failure here never fails the pipeline; at worst the scan runs without a baseline. The build log shows which path each run took.

Because the pipe decides this from Bitbucket's variables rather than from the pipeline that invoked it, the same step definition works unchanged under both `branches` and `pull-requests`.

## Container scanning

Images are read from docker-compose and Kubernetes files and pulled from their registries by the pipe:

- **Scanner**: Docker Scout when `DOCKER_HUB_USERNAME` / `DOCKER_HUB_PASSWORD` are set, Grype otherwise.
- **Variables in image names** (`${PROMETHEUS_VERSION}`) are expanded as docker compose does, from the environment, `.env`, or the committed `.env.example` / `.env.sample` next to the compose file or in a parent directory. For other files, set `CONTAINER_ENV_FILES`.
- **Images that cannot be pulled** (a private registry unreachable from Bitbucket's runners, no credentials, a tag that does not exist) are listed in the build log, the PR comment and the Code Insights report, and are never counted as clean. After the first unreachable or unauthorized registry, its remaining images are skipped instead of each waiting for a timeout.
- **Grype's vulnerability database** (about 2.5 minutes to download) can be cached; see "Grype DB cache" in [docs/BITBUCKET_PIPELINE.md](../docs/BITBUCKET_PIPELINE.md).
- **Images this repository builds itself** (e.g. `-SNAPSHOT` tags published only after merge) cannot be scanned meaningfully on a PR, because the registry has only the previous build. Skip them in the PR pipeline with `CONTAINER_IGNORE_IMAGES`, and scan them on the default branch after the build step pushes them.

## Not included

**Skipping PRs with no relevant changes** is not built in: querying the trigger patterns (`cli.py --list-patterns`) would need its own `docker run`, which the pipe avoids. See "Scan skipping" in [docs/BITBUCKET_PIPELINE.md](../docs/BITBUCKET_PIPELINE.md) for an opt-in snippet.

## Support

Issues: https://github.com/soldevelo/infrascan/issues
