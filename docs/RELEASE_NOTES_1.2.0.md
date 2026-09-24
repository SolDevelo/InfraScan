# InfraScan 1.2.0 Release Notes

This release contains all changes since `v1.1.1`.

## Highlights

- **New: Bitbucket Pipelines integration** — InfraScan is now available as a Bitbucket Pipe (`pipe: docker://soldevelo/infrascan:latest`), at parity with the GitHub Action: PR comments, a Code Insights report (step-summary equivalent), inline annotations anchored to file/line, an HTML report artifact, and automatic cost/security baseline tracking against the default branch. See [docs/BITBUCKET_PIPELINE.md](BITBUCKET_PIPELINE.md).
- The Code Insights report and annotations authenticate with **no token required** — only the PR comment (a different, more general API) needs a manually created Repository Access Token.
- New `MAX_ANNOTATIONS_PER_IMAGE` variable (default `10`) caps how many Code Insights annotations a single noisy container image can post, so one image's long CVE list can't drown out every other finding — doesn't affect grading, the PR comment, or the report.

## Fixes (apply to both GitHub and Bitbucket)

- Checkov findings could report garbage file paths (e.g. `../../../../../test_infra.tf`) — was relpath-ing Checkov's own synthetic `file_path` instead of its real `file_abs_path`.
- A container CVE for an image referenced by more than one compose/Kubernetes file was silently dropped for every file but the first one encountered — every referencing file now gets the finding, without double-counting it in grading or the PR comment.
- Container CVE annotations now carry a real line number (the image's declaring line in its compose/Kubernetes file), instead of always being line-less.

## Notes

- The application version has been updated to `1.2.0`.
