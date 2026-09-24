#!/bin/bash
# Bitbucket Pipe entrypoint: translates the Pipe's declared variables (plain
# env vars, per pipe.yml's `variables:` list -- Bitbucket's own convention,
# not an InfraScan one) into a cli.py invocation.
#
# Bitbucket mounts the pipeline's checked-out repository at
# $BITBUCKET_CLONE_DIR (and sets it as the container's working directory) for
# every step, pipes included -- so paths here are relative to that, not to
# /scan the way the plain `docker run -v $(pwd):/scan soldevelo/infrascan`
# examples use.
set -e

CLONE_DIR="${BITBUCKET_CLONE_DIR:-.}"
DIRECTORY="${DIRECTORY:-.}"
SCANNER="${SCANNER:-comprehensive}"
FORMAT="${FORMAT:-html}"
OUT="${OUT:-infrascan-report.html}"
FRAMEWORK="${FRAMEWORK:-smart}"
ALERT_ON="${ALERT_ON:-any_new}"
MIN_COST_DELTA="${MIN_COST_DELTA:-0}"
MAX_PR_FINDINGS="${MAX_PR_FINDINGS:-10}"
MAX_ANNOTATIONS_PER_IMAGE="${MAX_ANNOTATIONS_PER_IMAGE:-10}"
# Fixed default path so baseline tracking works with zero YAML config beyond
# declaring the cache -- same path used to read (BASELINE) and, on a default-
# branch push, to write (BASELINE_OUT). Override either if you need to.
BASELINE="${BASELINE:-infrascan-baseline/infrascan-baseline.json}"
BASELINE_OUT="${BASELINE_OUT:-infrascan-baseline/infrascan-baseline.json}"
DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"

CMD=(python /opt/infrascan/cli.py "${CLONE_DIR}/${DIRECTORY}"
  --scanner "${SCANNER}"
  --format "${FORMAT}"
  --out "${CLONE_DIR}/${OUT}"
  --framework "${FRAMEWORK}"
  --alert-on "${ALERT_ON}"
  --min-cost-delta "${MIN_COST_DELTA}"
  --max-pr-findings "${MAX_PR_FINDINGS}"
  --max-annotations-per-image "${MAX_ANNOTATIONS_PER_IMAGE}")

[ -n "${FAIL_ON}" ] && CMD+=(--fail-on "${FAIL_ON}")

# Resolve the baseline to compare against. Normally this is the cached
# file from the last default-branch run -- but that cache only ever holds
# DEFAULT_BRANCH's own baseline, so it's only valid for a PR that actually
# targets DEFAULT_BRANCH. On a PR, fall back to scanning the PR's *actual*
# base branch directly in a throwaway worktree whenever either:
#   - the cache is cold, empty, or unreadable (missing cache, first-ever
#     run, or a permission issue), or
#   - the PR targets some other branch entirely, in which case the cached
#     DEFAULT_BRANCH baseline would silently compare against the wrong
#     branch even though it's perfectly readable.
# Best-effort either way: any failure along the way just leaves
# BASELINE_PATH unusable and the main scan proceeds with no baseline, same
# as it always has.
BASELINE_PATH="${CLONE_DIR}/${BASELINE}"
FALLBACK_BRANCH="${BITBUCKET_PR_DESTINATION_BRANCH:-${DEFAULT_BRANCH}}"

if [ -r "${BASELINE_PATH}" ] && [ -s "${BASELINE_PATH}" ]; then
    echo "Baseline cache found at ${BASELINE_PATH} (${DEFAULT_BRANCH})."
else
    echo "No usable baseline cache at ${BASELINE_PATH} (missing, empty, or unreadable)."
fi

if [ -n "${BITBUCKET_PR_ID}" ] && [ -n "${BASELINE}" ] \
    && { [ "${FALLBACK_BRANCH}" != "${DEFAULT_BRANCH}" ] || [ ! -r "${BASELINE_PATH}" ] || [ ! -s "${BASELINE_PATH}" ]; }; then
    echo "Running a baseline scan against ${FALLBACK_BRANCH} directly (cache unusable or this PR targets a non-default branch)."
    FALLBACK_WORKTREE="$(mktemp -d)"
    FALLBACK_OUT="$(mktemp -t infrascan-fallback-baseline.XXXXXX)"
    if git -C "${CLONE_DIR}" fetch --depth 1 origin "${FALLBACK_BRANCH}" 2>/dev/null \
        && git -C "${CLONE_DIR}" worktree add --detach "${FALLBACK_WORKTREE}" FETCH_HEAD 2>/dev/null; then
        if python /opt/infrascan/cli.py "${FALLBACK_WORKTREE}/${DIRECTORY}" \
            --scanner "${SCANNER}" --framework "${FRAMEWORK}" --format text \
            --baseline-out "${FALLBACK_OUT}" --pr-comment false --step-summary false \
            >/dev/null 2>&1; then
            BASELINE_PATH="${FALLBACK_OUT}"
            echo "Baseline scan of ${FALLBACK_BRANCH} succeeded -- using it for this PR's delta."
        else
            echo "[warn] Fallback scan of ${FALLBACK_BRANCH} failed -- continuing without a baseline." >&2
        fi
        git -C "${CLONE_DIR}" worktree remove --force "${FALLBACK_WORKTREE}" 2>/dev/null || true
    else
        echo "[warn] Could not fetch/checkout ${FALLBACK_BRANCH} for baseline fallback -- continuing without a baseline." >&2
        rm -rf "${FALLBACK_WORKTREE}"
    fi
fi

if [ -r "${BASELINE_PATH}" ] && [ -s "${BASELINE_PATH}" ]; then
    echo "Comparing against baseline: ${BASELINE_PATH}"
    CMD+=(--baseline "${BASELINE_PATH}")
else
    echo "No baseline available -- this scan will report all findings as new, with no delta."
fi

# Only *write* the baseline when this run is a push to the default branch,
# not a PR -- auto-detected from Bitbucket's own env vars, so the same
# step/variables work unchanged for both `pipelines.default` and
# `pipelines.pull-requests`: no separate step per trigger needed, and PR
# runs never overwrite the shared baseline with PR-branch scan results.
# --baseline-out writes the result as JSON regardless of FORMAT/OUT, so this
# reuses the same scan already run for the report -- no second scan.
if [ -n "${BASELINE_OUT}" ] && [ -z "${BITBUCKET_PR_ID}" ] && [ "${BITBUCKET_BRANCH}" = "${DEFAULT_BRANCH}" ]; then
    mkdir -p "$(dirname "${CLONE_DIR}/${BASELINE_OUT}")" 2>/dev/null || true
    CMD+=(--baseline-out "${CLONE_DIR}/${BASELINE_OUT}")
fi

[ "${DOWNLOAD_EXTERNAL_MODULES}" = "true" ] && CMD+=(--download-external-modules)

echo "Running: ${CMD[*]}"
exec "${CMD[@]}"
