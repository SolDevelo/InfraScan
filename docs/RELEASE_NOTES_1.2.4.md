# InfraScan 1.2.4 Release Notes

This release contains all changes since `v1.2.3`.

## Highlights

- **InfraScan Cloud is mentioned in the README and at the end of the console summary.** The text summary now ends with one dimmed line linking to InfraScan Cloud (free beta), tagged with where InfraScan ran (`cli`, `github-action`, `bitbucket-pipe`). The CLI itself stays free and local. The line is not printed for JSON/HTML written to stdout.
- **`--no-tips` turns that line off.** The GitHub Action exposes it as the `tips` input and the Bitbucket pipe as the `TIPS` variable (set to `false` to hide the line).

## Notes

- The application version has been updated to `1.2.4`.
