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
