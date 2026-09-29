# InfraScan 1.2.1 Release Notes

This release contains all changes since `v1.2.0`.

## Highlights

- **Images that can't be scanned are now reported, not counted as clean.** Previously, if Grype couldn't pull an image (private registry unreachable from the CI runner, missing credentials, tag that doesn't exist), the image silently contributed zero findings. Now each one is listed with its reason in the build log, the PR comment and the step summary / Code Insights report ("K of M container images could not be scanned"). After the first unreachable or unauthorized registry, its remaining images are skipped instead of each one waiting out a timeout.
- **Grype is picked automatically when there are no Docker Hub credentials.** Docker Scout needs a Docker login even on a free account, so without one every image first failed with Scout before falling back to Grype. Pass credentials to keep using Scout (fewer false positives): `docker-hub-username` / `docker-hub-password` inputs (GitHub Action) or `DOCKER_HUB_USERNAME` / `DOCKER_HUB_PASSWORD` (Bitbucket pipe). The pipe also gets `CONTAINER_SCANNER` to force either scanner.
- **New `container-ignore-images` / `CONTAINER_IGNORE_IMAGES`**: a regex of images to skip, e.g. `-SNAPSHOT$` for images the repo builds itself and only publishes after merge — on a PR the registry only has the previous build, so scanning it is misleading.
- **Grype vulnerability DB cache** (saves a ~2.5 min download per run). GitHub Action: automatic, keyed on the date, so the DB is refreshed once a day. Bitbucket: opt-in `infrascan-grype-db` cache (added to all examples); when Anchore publishes a newer DB, the pipe replaces the cache through the step's local auth proxy, with `BITBUCKET_ACCESS_TOKEN` as a fallback. Scans always use a current DB either way — the cache only decides whether a download is needed.

## Fixes

- **Bitbucket: stale baseline gave wrong PR deltas.** Bitbucket never overwrites an existing cache, so the baseline saved on the first default-branch run was reused for up to a week while the branch kept changing. The baseline now carries a fingerprint of the scanned files; when a PR's target branch has changed since, the pipe scans the target branch directly for that PR's delta.
- **Bitbucket: the no-cache baseline fallback didn't work inside the pipe container** (git "dubious ownership", the clone's origin proxy unreachable from the pipe, no write access to `.git`). It now reads and fetches the target branch without touching the clone.
- **Bitbucket: a declared Grype DB cache without the `chmod` line scanned no images at all.** The pipe now ignores a cache directory it can't write to (with a hint in the log) and downloads the DB as if no cache were declared. Pipelines without any caches work out of the box, just slower.
- **GitHub Action: the baseline was rescanned on every PR.** It was only ever saved by PR runs, and GitHub scopes a cache saved by a PR to that PR alone — no other PR could restore it. Pushes to the default branch now save their scan as the baseline for that commit, so PRs targeting it restore it instead of scanning the base branch again. A PR scan failing via `fail-on` also no longer skips saving the baseline or the step summary.
- **GitHub Action: the baseline scan ignored `directory`, `scanner` and `framework`**, so a PR scan with non-default settings was compared against a differently-scanned baseline and reported false "new" findings. Both scans now use the same settings.
- **Findings tables showed only the file's basename**, not its path — in a repo with many services each having their own `docker-compose.yml`/`Dockerfile` (common in a monorepo), every entry looked identical (e.g. `docker-compose.yml:7`) with no way to tell which service a finding actually belonged to. The step summary's findings/cost-savings tables and the PR comment's "New findings" table now show the full relative path.
- **GitHub Actions inline annotations could be dropped non-deterministically.** GitHub Actions caps annotations at 10 errors / 10 warnings / 10 notices per step, and silently keeps only "a random subset" beyond that with no indication anything was cut. A repo with more than 10 CRITICAL (or HIGH, or cost-delta) findings would get an arbitrary subset shown as inline annotations from run to run. Findings are already severity-sorted, so InfraScan now stops at 10 per level itself — the ones that do show up are deterministically the most severe, not whatever GitHub happened to keep. Doesn't affect grading, the PR comment, or the step summary, which already show the full set.

## Notes

- The application version has been updated to `1.2.1`.
- Bitbucket users can add the Grype DB cache to their pipeline — see "Grype DB cache" in [docs/BITBUCKET_PIPELINE.md](BITBUCKET_PIPELINE.md). No token permission changes are needed.
