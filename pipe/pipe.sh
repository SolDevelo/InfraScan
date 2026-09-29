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

# Optional Grype DB cache (~2.5 min download otherwise). A pipe can't declare
# caches itself, so it's opt-in: declare a cache named infrascan-grype-db at
# this path in bitbucket-pipelines.yml. Grype always downloads a newer DB when
# the cached one is stale, so scan results never depend on the cache -- but
# Bitbucket never replaces an existing cache, so to get today's DB saved, this
# cache alone (the baseline cache is left alone) has to be deleted first.
# Tried through the step's local auth proxy (no token needed, like Code
# Insights), then with BITBUCKET_ACCESS_TOKEN if one is set.
clear_grype_db_cache() {
    local path="repositories/${BITBUCKET_WORKSPACE}/${BITBUCKET_REPO_SLUG}/pipelines-config/caches?name=${GRYPE_DB_CACHE}"
    local code
    code=$(curl -s -o /dev/null -w 'HTTP %{http_code}' --max-time 15 -X DELETE \
        --proxy http://host.docker.internal:29418 "http://api.bitbucket.org/2.0/${path}") || code="unreachable"
    case "${code}" in "HTTP 200"|"HTTP 204") CLEAR_VIA="local proxy"; return 0 ;; esac
    CLEAR_ERR="proxy: ${code}"
    if [ -n "${BITBUCKET_ACCESS_TOKEN}" ]; then
        code=$(curl -s -o /dev/null -w 'HTTP %{http_code}' --max-time 15 -X DELETE \
            -H "Authorization: Bearer ${BITBUCKET_ACCESS_TOKEN}" \
            "https://api.bitbucket.org/2.0/${path}") || code="unreachable"
        case "${code}" in "HTTP 200"|"HTTP 204") CLEAR_VIA="access token"; return 0 ;; esac
        CLEAR_ERR="${CLEAR_ERR}, token: ${code}"
    fi
    return 1
}

GRYPE_DB_CACHE="${GRYPE_DB_CACHE:-infrascan-grype-db}"
# A declared cache the pipe can't write to (the mkdir/chmod line missing) is
# ignored rather than used: Grype would fail to store the DB there and scan
# no images at all.
writable_dir() {
    local probe
    probe=$(mktemp -p "$1" 2>/dev/null) && rm -f "${probe}"
}

if [ -z "${GRYPE_DB_CACHE_DIR}" ] && [ -d "${CLONE_DIR}/${GRYPE_DB_CACHE}" ] \
        && ! writable_dir "${CLONE_DIR}/${GRYPE_DB_CACHE}"; then
    echo "Grype DB cache '${GRYPE_DB_CACHE}' isn't writable by the pipe (missing 'chmod -R 777 ${GRYPE_DB_CACHE}' before the pipe?) -- ignoring it, this run downloads the DB."
elif [ -z "${GRYPE_DB_CACHE_DIR}" ] && [ -d "${CLONE_DIR}/${GRYPE_DB_CACHE}" ]; then
    export GRYPE_DB_CACHE_DIR="${CLONE_DIR}/${GRYPE_DB_CACHE}"
    if grype db check >/dev/null 2>&1; then
        echo "Grype DB cache is current -- no download needed."
    elif [ -z "$(ls -A "${GRYPE_DB_CACHE_DIR}" 2>/dev/null)" ]; then
        echo "Grype DB cache is empty -- this run downloads the DB and Bitbucket saves it as the cache."
    elif clear_grype_db_cache; then
        echo "Grype DB cache is out of date -- this run downloads today's DB; cleared the '${GRYPE_DB_CACHE}' cache (via ${CLEAR_VIA}) so Bitbucket saves it."
    else
        echo "Grype DB cache is out of date -- this run downloads today's DB, but the old cache couldn't be cleared (${CLEAR_ERR}), so Bitbucket keeps it until it expires (up to 7 days)."
    fi
fi

# Fingerprint of the scan input at a given revision: a hash of the
# (path, blob) list of every file the selected scanners read under
# DIRECTORY, straight from `git ls-tree` (no checkout). Two revisions with the
# same fingerprint give the scanners identical input, so a baseline scanned
# from one is valid for the other. Prints nothing if it can't be computed.
SCAN_PATTERNS=""

# The clone is owned by a different user than the one this pipe container
# runs as (see the chmod line in the docs), and git refuses to touch a repo
# owned by someone else ("dubious ownership") unless told otherwise.
git_at() { local dir="$1"; shift; git -c safe.directory='*' -C "${dir}" "$@"; }
git_repo() { git_at "${CLONE_DIR}" "$@"; }

# fingerprint REPO_DIR REV
fingerprint() {
    local listing
    if [ -z "${SCAN_PATTERNS}" ]; then
        SCAN_PATTERNS=$(python /opt/infrascan/cli.py --list-patterns --scanner "${SCANNER}" 2>/dev/null \
            | python -c 'import json,sys; print("|".join(json.load(sys.stdin)["patterns"]))' 2>/dev/null) || true
    fi
    [ -n "${SCAN_PATTERNS}" ] || return 0
    listing=$(git_at "$1" ls-tree -r "$2" -- "${DIRECTORY}" 2>/dev/null) || return 0
    # Field 2 is the path; awk (not grep) so root-level files match `(^|/)`.
    printf '%s\n' "${listing}" \
        | INFRASCAN_RE="${SCAN_PATTERNS}" awk -F'\t' '$2 ~ ENVIRON["INFRASCAN_RE"]' \
        | sha256sum | cut -c1-64
}

# Sets DEST_REPO/DEST_REV to the PR destination branch's current commit.
# A PR build normally already has it (BITBUCKET_PR_DESTINATION_COMMIT) --
# no network, and nothing written to the clone. Otherwise it's fetched into a
# separate scratch repo, since this pipe may not be allowed to write to the
# clone's .git. Bitbucket routes git over HTTPS through its auth proxy,
# configured for the build container as localhost:29418 -- which a pipe's own
# container can't reach; from inside a pipe the proxy is at
# host.docker.internal:29418.
DEST_REPO=""
DEST_REV=""
DEST_ERR=""
resolve_dest() {
    if [ -n "${BITBUCKET_PR_DESTINATION_COMMIT}" ] \
        && git_repo rev-parse --verify -q "${BITBUCKET_PR_DESTINATION_COMMIT}^{commit}" >/dev/null 2>&1; then
        DEST_REPO="${CLONE_DIR}"
        DEST_REV="${BITBUCKET_PR_DESTINATION_COMMIT}"
        echo "Using ${FALLBACK_BRANCH} at ${DEST_REV} (already in the clone)."
        return 0
    fi
    local url scratch proxy=()
    if ! url=$(git_repo remote get-url origin 2>/dev/null); then
        DEST_ERR="the clone has no origin remote"
        return 1
    fi
    scratch=$(mktemp -d)
    git -C "${scratch}" init -q
    [ -n "${BITBUCKET_GIT_HTTP_ORIGIN}" ] \
        && proxy=(-c "http.${BITBUCKET_GIT_HTTP_ORIGIN}.proxy=http://host.docker.internal:29418/")
    if DEST_ERR=$(git "${proxy[@]}" -C "${scratch}" fetch -q --depth 1 "${url}" "${FALLBACK_BRANCH}" 2>&1) \
        || DEST_ERR=$(git -C "${scratch}" fetch -q --depth 1 "${url}" "${FALLBACK_BRANCH}" 2>&1); then
        DEST_REPO="${scratch}"
        DEST_REV=FETCH_HEAD
        echo "Using ${FALLBACK_BRANCH} at $(git -C "${scratch}" rev-parse --short FETCH_HEAD) (fetched)."
        return 0
    fi
    rm -rf "${scratch}"
    # First "fatal:"/"error:" line says what went wrong; the last one is
    # usually boilerplate ("...and the repository exists.").
    DEST_ERR=$(printf '%s\n' "${DEST_ERR}" | grep -m1 -iE '^(fatal|error):' || printf '%s\n' "${DEST_ERR}" | tail -1)
    return 1
}

baseline_fingerprint_of() {
    python -c 'import json,sys; print(json.load(open(sys.argv[1])).get("metadata", {}).get("baseline_fingerprint", ""))' \
        "$1" 2>/dev/null || true
}

# Resolve the baseline to compare against. The cache holds the baseline the
# last default-branch run saved -- but Bitbucket only *uploads* a cache when
# none exists yet, then keeps it for up to a week, so the cached baseline
# can be many merges old. On a PR it's therefore only used when its
# fingerprint matches the PR's destination branch as it is now; otherwise
# the destination branch is scanned directly from a throwaway copy. Any
# failure along the way is non-fatal: the scan continues, at worst without
# a baseline.
BASELINE_PATH="${CLONE_DIR}/${BASELINE}"
FALLBACK_BRANCH="${BITBUCKET_PR_DESTINATION_BRANCH:-${DEFAULT_BRANCH}}"
CACHE_USABLE=false

if [ -r "${BASELINE_PATH}" ] && [ -s "${BASELINE_PATH}" ]; then
    CACHE_USABLE=true
    echo "Baseline cache found at ${BASELINE_PATH}."
else
    echo "No usable baseline cache at ${BASELINE_PATH} (missing, empty, or unreadable)."
fi

if [ -n "${BITBUCKET_PR_ID}" ] && [ -n "${BASELINE}" ]; then
    DEST_FETCHED=false
    resolve_dest && DEST_FETCHED=true
    NEED_SCAN=true
    if [ "${CACHE_USABLE}" = true ] && [ "${DEST_FETCHED}" = true ]; then
        CACHED_FP=$(baseline_fingerprint_of "${BASELINE_PATH}")
        DEST_FP=$(fingerprint "${DEST_REPO}" "${DEST_REV}")
        if [ -n "${CACHED_FP}" ] && [ "${CACHED_FP}" = "${DEST_FP}" ]; then
            echo "Baseline cache matches ${FALLBACK_BRANCH} (same scanned files) -- using it."
            NEED_SCAN=false
        elif [ -z "${CACHED_FP}" ]; then
            echo "Baseline cache has no fingerprint (saved by an older version) -- can't confirm it matches ${FALLBACK_BRANCH}."
        else
            echo "Baseline cache is stale: ${FALLBACK_BRANCH} has changed since it was saved."
        fi
    elif [ "${CACHE_USABLE}" = true ]; then
        echo "[warn] Could not get ${FALLBACK_BRANCH} to check the baseline cache is current (${DEST_ERR}) -- using it as-is." >&2
        NEED_SCAN=false
    fi

    if [ "${NEED_SCAN}" = true ] && [ "${DEST_FETCHED}" = true ]; then
        echo "Running a baseline scan against ${FALLBACK_BRANCH} directly."
        FALLBACK_WORKTREE="$(mktemp -d)"
        FALLBACK_OUT="$(mktemp -t infrascan-fallback-baseline.XXXXXX)"
        # git archive only reads the repo -- worktree add would write under .git
        if git_at "${DEST_REPO}" archive --format=tar "${DEST_REV}" 2>/dev/null | tar -x -C "${FALLBACK_WORKTREE}" 2>/dev/null \
            && python /opt/infrascan/cli.py "${FALLBACK_WORKTREE}/${DIRECTORY}" \
                --scanner "${SCANNER}" --framework "${FRAMEWORK}" --format text \
                --baseline-out "${FALLBACK_OUT}" --pr-comment false --step-summary false \
                >/dev/null 2>&1; then
            BASELINE_PATH="${FALLBACK_OUT}"
            echo "Baseline scan of ${FALLBACK_BRANCH} succeeded -- using it for this PR's delta."
        elif [ "${CACHE_USABLE}" = true ]; then
            echo "[warn] Baseline scan of ${FALLBACK_BRANCH} failed -- falling back to the older cached baseline; changes merged since it was saved may show as new." >&2
        else
            echo "[warn] Baseline scan of ${FALLBACK_BRANCH} failed -- continuing without a baseline." >&2
        fi
        rm -rf "${FALLBACK_WORKTREE}"
    elif [ "${NEED_SCAN}" = true ]; then
        echo "[warn] Could not get ${FALLBACK_BRANCH} for a baseline scan (${DEST_ERR}) -- continuing without a baseline." >&2
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
# reuses the same scan already run for the report -- no second scan. The
# fingerprint is stored inside that JSON, so baseline and fingerprint can
# never disagree.
if [ -n "${BASELINE_OUT}" ] && [ -z "${BITBUCKET_PR_ID}" ] && [ "${BITBUCKET_BRANCH}" = "${DEFAULT_BRANCH}" ]; then
    mkdir -p "$(dirname "${CLONE_DIR}/${BASELINE_OUT}")" 2>/dev/null || true
    CMD+=(--baseline-out "${CLONE_DIR}/${BASELINE_OUT}")
    HEAD_FP=$(fingerprint "${CLONE_DIR}" HEAD)
    [ -n "${HEAD_FP}" ] && CMD+=(--baseline-fingerprint "${HEAD_FP}")
    if [ "${CACHE_USABLE}" = true ]; then
        echo "Note: a baseline cache already exists, and Bitbucket won't re-upload it until it expires (up to 7 days) or is cleared under Pipelines -> Caches. PRs detect this and scan ${DEFAULT_BRANCH} directly in the meantime."
    fi
fi

[ "${DOWNLOAD_EXTERNAL_MODULES}" = "true" ] && CMD+=(--download-external-modules)

echo "Running: ${CMD[*]}"
exec "${CMD[@]}"
