# InfraScan 1.1.1 Release Notes

This release contains all changes since `v1.1.0`.

## Highlights

- `fix: prevent stored/reflected XSS via repository_url and add nginx rate limits`
- `fix: raise grype per-image timeout to cover large image pulls`
- `fix: container scanning silently failing under non-default uid`
- `fix: show container CVEs in PR comment findings`
- `feat: improve PR comments: display all new findings by default`

## Other changes

- CRON for cert renew
- ci: build a local image to test the changes
- Switch action to @v1
- The GitHub Action's `framework` input now defaults to `smart` (was `auto`), matching the CLI and web UI. `smart` scans **all** detected frameworks in a multi-framework repo instead of silently picking one and ignoring the rest — existing workflows that don't set `framework:` explicitly may see additional findings after this update.
- `action.yml`'s description and `framework` input docs updated to reflect Helm/CloudFormation/Ansible security-scanning support (cost estimation remains Terraform-only).

## Notes

- The application version has been updated to `1.1.1`.
- The Marketplace quick-start example now pins the rolling `@v1` tag instead of a specific patch version.
