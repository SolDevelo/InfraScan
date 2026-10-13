# InfraScan 1.2.3 Release Notes

This release contains all changes since `v1.2.2`.

## Highlights

- **Grading recalibrated.** Grades will shift compared with 1.2.2, mostly upward for repositories with many clean images and downward where a Critical/High finding used to be diluted by good scores elsewhere.
  - **Container score is based on scanned images.** The maximum score now uses the number of images that were scanned (clean ones included) instead of the IaC resource count, so one vulnerable image among many clean ones is no longer judged against an unrelated denominator.
  - **Container severity weights:** Medium 0.5, Low 0.1, Info 0 (Critical and High unchanged).
  - **CVEs with no fix available are graded one severity level lower.** The report and `--fail-on` still use the real severity.
  - **Categories with nothing to check are graded N/A** and left out of the overall grade — no Terraform, no IaC resources, or no images no longer produce a misleading "A".
  - **Critical/High severity caps now apply to the overall grade too**, not only to the category. When a cap lowers a grade, `GradeInfo.cap_reason` says why.

## Fixes

- **"Address N images with …" recommendation counts images**, not findings.
- **Grype remediation picks the lowest fix above the installed version.** The first fix listed could be a downgrade.

## Notes

- The application version has been updated to `1.2.3`.
