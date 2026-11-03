# InfraScan 1.2.5 Release Notes

This release contains all changes since `v1.2.4`.

## Highlights

- **`--exclude` leaves paths out of a scan.** `-x docs,tests,examples` or `-x modules/legacy`: a name without a slash matches at any depth, like `.gitignore`; one with a slash is relative to the scanned directory; `*` and `?` work. It applies to every part of the scan (Terraform rules, Checkov, container discovery, resource count, cost estimation). The GitHub Action has an `exclude` input and the Bitbucket pipe an `EXCLUDE` variable, and both pass it to the base-branch baseline scan too, so the delta compares like with like. No more copying the repository to drop docs or tests before scanning.
- **The GitHub Action no longer fails when the base branch can't be scanned for a baseline.** Since 1.2.2 the baseline fallback scanned `directory` on the base branch, and a directory that only exists after an earlier workflow step (or is added by the PR) failed the whole job. Now it logs a warning and the PR is scanned without a baseline.
- **The GitHub Action runs the image released with it.** Every earlier version pulled `soldevelo/infrascan:latest`, so pinning the action to a tag or SHA didn't pin the scanner. From 1.2.5 the action runs `soldevelo/infrascan:<its version>`; the new `image` input overrides it (mirror, private registry).
- **InfraScan Cloud is also mentioned in the HTML report footer and at the end of the GitHub step summary**, next to the console line from 1.2.4. Never in PR comments or the Bitbucket Code Insights report. `--no-tips` / `tips: false` / `TIPS: "false"` turn all of them off.

## Notes

- Workflows pinned to an action version before 1.2.5 still pull `latest`, so they run the 1.2.5 scanner. Versions before 1.2.4 also have no `tips` input. Upgrading the action to 1.2.5 fixes both.
- `docs/COST_ESTIMATION.md` no longer claims `docs`, `tests` and `examples` are skipped for cost; they're scanned unless excluded.
- The application version has been updated to `1.2.5`.
