# InfraScan 1.2.2 Release Notes

This release contains all changes since `v1.2.1`.

## Highlights

- **New `fail-on` thresholds that only count what a PR adds: `new_high_critical`, `new_critical`, `new_any`.** The existing thresholds count every finding in the repository, so in a repo with even one existing HIGH finding `fail-on: high_critical` fails every PR, including ones that don't touch infrastructure. The `new_*` thresholds compare against the baseline (the same comparison the PR comment's "New findings" uses) and fail only on findings the PR introduces. With no baseline — a push to the default branch, or a PR whose base branch couldn't be scanned — they're skipped with a notice in the log instead of treating every existing finding as new. The examples now use `new_high_critical`.
- **`fail-on` defaults to an explicit `never`** in the GitHub Action and the Bitbucket pipe (same behaviour as before: no threshold, no failure).
- **Variables in compose image names are expanded the way `docker compose` does.** `image: prom/prometheus:${PROMETHEUS_VERSION}` used to be resolved only from the scanner's own environment, so in CI such images were reported as unscannable. InfraScan now reads the environment, then `.env`, then the committed `.env.example` / `.env.sample` (since `.env` is usually gitignored), looked for next to the compose file and in parent directories. Supports `$VAR`, `${VAR}`, `${VAR:-default}`, `${VAR-default}`. Values are only used to expand image names and are never exported — a placeholder like `SLACK_WEBHOOK_URL` in `.env.example` has no effect. An image with a variable that still can't be resolved is reported as not scanned, naming the variable. The file list is configurable with `CONTAINER_ENV_FILES` / `container-env-files` (e.g. `deploy/versions.env,.env.sample`).
- **Configurable per-image container scan timeout: `CONTAINER_SCAN_TIMEOUT` / `container-scan-timeout`, default 300 s** (previously a fixed 240 s for Grype and 120 s for Docker Scout). The limit covers the pull and the analysis, and for large images the analysis dominates — e.g. `grafana/grafana`: ~40 s to pull, ~3 min in Syft's binary cataloger, so it didn't fit in 240 s. A timed-out image is reported as not scanned, with a hint to raise the limit.

## Fixes

- **GitHub Action: `skip-if-no-match` never skipped a scan.** It diffed against `origin/<base>`, which `actions/checkout`'s default shallow clone doesn't fetch, so the diff was always empty and the scan always ran. The action now fetches the PR's base commit (depth 1) and diffs against it. If that fetch fails, the scan still runs.
- **Grype: one image timing out skipped the rest of Docker Hub.** 1.2.1 skips the remaining images of a registry after it proves unreachable, but its own per-image timeout counted as "unreachable" — so one slow, large image on Docker Hub caused every later Docker Hub image to be skipped, even after earlier ones had been scanned. A registry that has already served an image in the run is no longer blocked, and the per-image timeout never blocks Docker Hub.
- **Workflow examples** (README, `docs/GITHUB_ACTION.md`, `docs/PIPELINE_INTEGRATION.md`): `push` runs only on the default branch (that run saves the baseline PRs compare against; on every branch it duplicated each PR's scan), and `contents: read` is included — once a workflow sets `permissions:`, everything unlisted is `none`, and `actions/checkout` then fails on private repositories.

## Notes

- The application version has been updated to `1.2.2`.
- Workflows that generated an env file before the scan just to expand compose image versions can drop that step — `.env.example` / `.env.sample` are picked up automatically. See "Container scanning" in [docs/BITBUCKET_PIPELINE.md](https://github.com/SolDevelo/InfraScan/blob/main/docs/BITBUCKET_PIPELINE.md#container-scanning) and the inputs table in [docs/GITHUB_ACTION.md](https://github.com/SolDevelo/InfraScan/blob/main/docs/GITHUB_ACTION.md).
