"""GitHub Actions adapter: PR comments, step summary, inline annotations.

Moved out of cli.py unchanged (see docs/bitbucket-integration-plan.md) so the
GitHub and Bitbucket adapters sit side by side behind the same call shape.
"""
import json
import os
import sys

import requests


def emit_annotations(report_dict: dict, baseline: dict, alert_on: str) -> None:
    """Emit GitHub Actions workflow commands for inline PR annotations.

    Security findings at or above alert_on threshold -> ::error/::warning.
    Resources that became more expensive vs baseline -> ::warning.
    """
    if not os.getenv('GITHUB_ACTIONS'):
        return

    findings = report_dict.get('findings', {})
    all_findings = (
        list(findings.get('security', [])) +
        list(findings.get('container', [])) +
        list(findings.get('cost', []))
    )

    # Map alert_on to severity levels
    alert_sevs = set()
    if alert_on == 'critical':
        alert_sevs = {'critical'}
    elif alert_on in ('critical_high', 'high'):  # critical_high is deprecated alias
        alert_sevs = {'critical', 'high'}
    elif alert_on == 'medium':
        alert_sevs = {'critical', 'high', 'medium'}
    elif alert_on == 'low':
        alert_sevs = {'critical', 'high', 'medium', 'low'}
    elif alert_on == 'any_new':
        alert_sevs = {'critical', 'high', 'medium', 'low', 'info'}
    # alert_on == 'none' -> alert_sevs stays empty

    # Create set of container findings for fast lookup
    container_findings = set(id(f) for f in findings.get('container', []))

    # Helper to identify container findings
    def _is_container(f: dict) -> bool:
        return id(f) in container_findings

    # Sort findings: by severity (critical first), then by type (IaC before containers)
    severity_order = ['critical', 'high', 'medium', 'low', 'info']
    def _sort_key(f: dict) -> tuple:
        sev = f.get('severity', '').lower()
        try:
            sev_idx = severity_order.index(sev)
        except ValueError:
            sev_idx = 999
        type_idx = 1 if _is_container(f) else 0
        return (sev_idx, type_idx)
    all_findings.sort(key=_sort_key)

    for f in all_findings:
        sev = f.get('severity', '').lower()
        if sev not in alert_sevs:
            continue
        rid   = f.get('rule_id') or f.get('check_id', 'FINDING')
        fpath = f.get('file', '')
        line  = f.get('line', '')
        desc  = f.get('description', f.get('name', rid))
        # Critical = error, High = warning, others = notice
        if sev == 'critical':
            level = 'error'
        elif sev == 'high':
            level = 'warning'
        else:
            level = 'notice'
        loc   = f"file={fpath}" + (f",line={line}" if line else "")
        print(f"::{level} {loc},title={rid}::{desc}")

    # Cost-increase annotations only when a baseline is present
    if not baseline:
        return
    base_costs = {
        rc['resource_name']: rc['total_usd_month']
        for rc in baseline.get('metrics', {}).get('resource_costs', [])
    }
    for rc in report_dict.get('metrics', {}).get('resource_costs', []):
        base = base_costs.get(rc['resource_name'])
        if base is None:
            continue
        delta = round(rc['total_usd_month'] - base, 2)
        if delta > 1.0:
            fpath = rc.get('file', '')
            line  = rc.get('line', '')
            loc   = f"file={fpath}" + (f",line={line}" if line else "")
            print(f"::warning {loc},title=COST-DELTA::"
                  f"{rc['resource_name']} cost increased: "
                  f"${base:.2f}/mo → ${rc['total_usd_month']:.2f}/mo "
                  f"(+${delta:.2f}/mo)")


def post_pr_comment(body: str) -> None:
    """Post (or update) a PR comment via the GitHub REST API."""
    token      = os.getenv('GITHUB_TOKEN', '').strip()
    event_path = os.getenv('GITHUB_EVENT_PATH', '').strip()
    repo       = os.getenv('GITHUB_REPOSITORY', '').strip()
    if not (token and event_path and repo):
        return
    try:
        with open(event_path, 'r', encoding='utf-8') as f:
            event = json.load(f)
        pr_number = (
            event.get('pull_request', {}).get('number')
            or event.get('issue', {}).get('number')
        )
        if not pr_number:
            return
        marker   = '<!-- infrascan-cost-report -->'
        full_body = f"{marker}\n{body}"
        api_url  = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
        headers  = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
        }
        # Check for an existing comment with the marker to update rather than post duplicate.
        existing_resp = requests.get(api_url, headers=headers, timeout=10)
        if existing_resp.status_code == 200:
            for comment in existing_resp.json():
                if marker in comment.get('body', ''):
                    patch_url = comment['url']
                    requests.patch(patch_url, json={'body': full_body}, headers=headers, timeout=10)
                    return
        requests.post(api_url, json={'body': full_body}, headers=headers, timeout=10)
    except Exception as e:
        print(f"PR comment error: {e}", file=sys.stderr)


_REVIEW_COMMENT_MARKER = '<!-- infrascan-review-comment -->'


def _review_severity_set(review_comment_on: str) -> set:
    if review_comment_on == 'critical':
        return {'critical'}
    if review_comment_on in ('critical_high', 'high'):
        return {'critical', 'high'}
    if review_comment_on == 'medium':
        return {'critical', 'high', 'medium'}
    if review_comment_on == 'low':
        return {'critical', 'high', 'medium', 'low'}
    if review_comment_on == 'any_new':
        return {'critical', 'high', 'medium', 'low', 'info'}
    return set()  # 'none' or unrecognized


def post_pr_review_comments(report_dict: dict, review_comment_on: str = 'critical') -> None:
    """Post real inline PR review comments -- the same threaded, resolvable
    kind a human reviewer leaves -- for findings at/above review_comment_on.

    A different, much more prominent mechanism than emit_annotations()'s
    ::error/::warning workflow-command markers (those just print to the log
    and show as a lightweight gutter marker at best). Defaults to
    critical-only since a real comment thread per finding is far more
    intrusive than the existing annotations.

    Idempotent across re-runs: deletes InfraScan's own previously-posted
    review comments (marked via _REVIEW_COMMENT_MARKER -- a real invisible
    HTML comment; unlike Bitbucket, GitHub does hide these properly) before
    posting the current set, so re-running the workflow doesn't pile up
    duplicates. Findings are grouped by (file, line) into a single combined
    comment -- several findings often land on the same line (multiple
    Checkov checks on one resource, several CVEs for one package), and that
    should be one thread, not one piling up per finding. Each (file, line)
    group is posted individually rather than batched into one review, so
    one group whose line isn't part of the diff hunk (GitHub rejects those)
    can't take the rest down with it.
    """
    token      = os.getenv('GITHUB_TOKEN', '').strip()
    event_path = os.getenv('GITHUB_EVENT_PATH', '').strip()
    repo       = os.getenv('GITHUB_REPOSITORY', '').strip()
    if not (token and event_path and repo):
        return

    alert_sevs = _review_severity_set(review_comment_on)
    if not alert_sevs:
        return

    try:
        with open(event_path, 'r', encoding='utf-8') as f:
            event = json.load(f)
        pr = event.get('pull_request', {})
        pr_number  = pr.get('number')
        commit_sha = pr.get('head', {}).get('sha')
        if not (pr_number and commit_sha):
            return

        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
        }
        base_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"

        # A review comment's line has to be part of the diff, and
        # commenting on a file the PR never touched always fails -- filter
        # to files actually in the diff so we don't waste calls on
        # findings that could never be anchored.
        diff_files = set()
        page = 1
        while True:
            resp = requests.get(f"{base_url}/files", headers=headers,
                                 params={'per_page': 100, 'page': page}, timeout=15)
            if resp.status_code != 200:
                break
            batch = resp.json()
            diff_files.update(item['filename'] for item in batch)
            if len(batch) < 100:
                break
            page += 1

        # Delete InfraScan's own previous review comments so re-running the
        # workflow doesn't pile up duplicates.
        existing_resp = requests.get(f"{base_url}/comments", headers=headers,
                                      params={'per_page': 100}, timeout=15)
        if existing_resp.status_code == 200:
            for c in existing_resp.json():
                if _REVIEW_COMMENT_MARKER in c.get('body', ''):
                    requests.delete(
                        f"https://api.github.com/repos/{repo}/pulls/comments/{c['id']}",
                        headers=headers, timeout=15,
                    )

        findings = report_dict.get('findings', {})
        all_findings = (
            list(findings.get('security', [])) +
            list(findings.get('container', [])) +
            list(findings.get('cost', []))
        )
        candidates = [
            f for f in all_findings
            if f.get('severity', '').lower() in alert_sevs
            and f.get('file') in diff_files
            and f.get('line')
        ]

        # Group by (file, line) -- multiple findings often land on the same
        # line (several Checkov checks on one resource block, several CVEs
        # for one package) and should be one comment thread, not one per
        # finding piling up at the same spot.
        severity_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        by_location = {}
        for f in candidates:
            by_location.setdefault((f['file'], f['line']), []).append(f)
        for group in by_location.values():
            group.sort(key=lambda f: severity_rank.get(f.get('severity', '').lower(), 99))

        posted, skipped = 0, 0
        for (path, line), group in by_location.items():
            if len(group) == 1:
                f = group[0]
                rid  = f.get('rule_id') or f.get('check_id', 'FINDING')
                desc = f.get('description', f.get('name', rid))
                body = f"**{rid}**: {desc}\n\n{_REVIEW_COMMENT_MARKER}"
            else:
                lines = [f"**{len(group)} findings on this line:**", ""]
                for f in group:
                    rid  = f.get('rule_id') or f.get('check_id', 'FINDING')
                    desc = f.get('description', f.get('name', rid))
                    lines.append(f"- **{rid}**: {desc}")
                lines += ["", _REVIEW_COMMENT_MARKER]
                body = "\n".join(lines)
            resp = requests.post(
                f"{base_url}/comments", headers=headers,
                json={
                    'body': body, 'commit_id': commit_sha,
                    'path': path, 'line': line, 'side': 'RIGHT',
                },
                timeout=15,
            )
            if resp.status_code in (200, 201):
                posted += 1
            else:
                skipped += 1
        if skipped:
            print(
                f"[info] Posted {posted} PR review comment(s), skipped {skipped} "
                f"(likely a line outside the diff hunk)", file=sys.stderr,
            )
    except Exception as e:
        print(f"GitHub PR review comment error: {e}", file=sys.stderr)


def write_gh_step_summary(content: str) -> None:
    """Append *content* to the GitHub Actions step summary file."""
    summary_path = os.getenv('GITHUB_STEP_SUMMARY', '').strip()
    if not summary_path:
        return
    try:
        with open(summary_path, 'a', encoding='utf-8') as f:
            f.write(content + '\n')
    except Exception as e:
        print(f"Step summary write error: {e}", file=sys.stderr)


def build_gh_actions_context() -> dict:
    """Extract GitHub Actions context from environment variables."""
    repo = os.getenv('GITHUB_REPOSITORY', '')
    server = os.getenv('GITHUB_SERVER_URL', 'https://github.com').rstrip('/')
    run_id = os.getenv('GITHUB_RUN_ID', '')
    workflow = os.getenv('GITHUB_WORKFLOW', '')
    ref_name = os.getenv('GITHUB_REF_NAME', '')
    actor = os.getenv('GITHUB_ACTOR', '')
    run_url = f"{server}/{repo}/actions/runs/{run_id}" if repo and run_id else ''
    return {
        'repo': repo,
        'workflow': workflow,
        'branch': ref_name,
        'actor': actor,
        'run_url': run_url,
    }
