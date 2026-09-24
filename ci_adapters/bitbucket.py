"""Bitbucket Cloud adapter: PR comments, Code Insights report, annotations.

Mirrors ci_adapters/github.py's call shape (see docs/bitbucket-integration-plan.md)
so cli.py can treat both platforms symmetrically. Differences from the GitHub
side are dictated by what Bitbucket Cloud actually offers:

- No GITHUB_STEP_SUMMARY equivalent -> a Code Insights *report* fills that role
  (upsert_bb_report). Because the report id is fixed, PUT is an idempotent
  update -> no marker/dedup hack needed, unlike the PR comment.
- No `::error`/`::warning` workflow commands -> Code Insights *annotations*
  fill that role (emit_bb_annotations), posted via REST instead of printed.
- No GITHUB_EVENT_PATH JSON to parse -> Bitbucket Pipelines exposes the PR id,
  repo, workspace and commit directly as env vars.
"""
import json
import os
import re
import sys
from typing import Optional

import requests

API_BASE = "https://api.bitbucket.org/2.0"
COMMENT_MARKER = "infrascan-report"
REPORT_ID = "infrascan-report"

_SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']
# Code Insights annotation severity has no INFO level; fold it into LOW.
_BB_SEVERITY_MAP = {
    'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM',
    'low': 'LOW', 'info': 'LOW',
}


def _auth_headers() -> Optional[dict]:
    """Bearer token for the general Bitbucket REST API (PR comments).

    Required for post_bb_pr_comment() -- the Reports API's local-proxy
    zero-token path (_reports_api_call()) doesn't cover the PR comments
    endpoint. Prefers a user-supplied Repository Access Token
    (BITBUCKET_ACCESS_TOKEN); falls back to the auto-injected, repo-scoped
    Pipelines step token (BITBUCKET_STEP_OAUTH_TOKEN) if present -- whether
    a `pipe:` step's own container actually receives that one has been
    unconfirmed and contradicted by both prior testing and Atlassian's own
    docs on the subject, so this logs which source it actually used (never
    the value) to settle it empirically rather than by assumption.
    """
    access_token = os.getenv('BITBUCKET_ACCESS_TOKEN', '').strip()
    step_token   = os.getenv('BITBUCKET_STEP_OAUTH_TOKEN', '').strip()
    token = access_token or step_token
    if token:
        source = 'BITBUCKET_ACCESS_TOKEN' if access_token else 'BITBUCKET_STEP_OAUTH_TOKEN'
        print(f"[info] Bitbucket API auth: using {source}", file=sys.stderr)
    if not token:
        return None
    return {'Authorization': f'Bearer {token}'}


def _repo_context() -> Optional[dict]:
    workspace = os.getenv('BITBUCKET_WORKSPACE', '').strip()
    repo_slug = os.getenv('BITBUCKET_REPO_SLUG', '').strip()
    if not (workspace and repo_slug):
        return None
    return {'workspace': workspace, 'repo_slug': repo_slug}


# Every Bitbucket Pipelines step runs alongside a local proxy that
# auto-authenticates requests to the Reports API (Code Insights reports and
# annotations specifically -- not the general REST API, so this doesn't
# cover PR comments) with zero token setup:
# https://support.atlassian.com/bitbucket-cloud/docs/code-insights/
# A `pipe:` step runs in its own Docker container, separate from the host
# step's own network namespace (the same isolation this integration has run
# into before -- see docs/BITBUCKET_PIPELINE.md "Write permissions"), so it
# reaches the proxy at `host.docker.internal:29418`, not `localhost:29418`.
_REPORTS_PROXY = {
    'http': 'http://host.docker.internal:29418',
    'https': 'http://host.docker.internal:29418',
}
_REPORTS_API_VIA_PROXY = "http://api.bitbucket.org/2.0"


def _reports_api_call(method: str, path: str, json_body: Optional[dict] = None, timeout: int = 15):
    """Call the Bitbucket Reports API, preferring the zero-token local proxy.

    Falls back to a direct HTTPS call with an explicit token
    (BITBUCKET_ACCESS_TOKEN / BITBUCKET_STEP_OAUTH_TOKEN) if the proxy isn't
    reachable -- e.g. running outside Bitbucket Pipelines entirely, or a
    self-hosted runner without it. Returns None if neither path is usable.
    """
    try:
        return requests.request(
            method, f"{_REPORTS_API_VIA_PROXY}/{path}",
            proxies=_REPORTS_PROXY, json=json_body, timeout=timeout,
        )
    except requests.exceptions.RequestException:
        pass

    headers = _auth_headers()
    if not headers:
        return None
    return requests.request(
        method, f"{API_BASE}/{path}",
        headers={**headers, 'Content-Type': 'application/json'},
        json=json_body, timeout=timeout,
    )


def build_bb_pipelines_context() -> dict:
    """Extract Bitbucket Pipelines context from environment variables.

    Returned shape matches build_gh_actions_context() so platform-agnostic
    callers (Slack notification, report metadata) don't need to branch.
    """
    repo = os.getenv('BITBUCKET_REPO_FULL_NAME', '')
    build_number = os.getenv('BITBUCKET_BUILD_NUMBER', '')
    branch = os.getenv('BITBUCKET_BRANCH', '')
    run_url = (
        f"https://bitbucket.org/{repo}/pipelines/results/{build_number}"
        if repo and build_number else ''
    )
    return {
        'repo': repo,
        'workflow': 'Bitbucket Pipelines',
        'branch': branch,
        'actor': os.getenv('BITBUCKET_STEP_TRIGGERER_UUID', ''),
        'run_url': run_url,
    }


def _check_response(resp, what: str) -> None:
    """Log a Bitbucket API call that came back with a non-2xx status.

    requests.post/put/get never raise on their own for a 4xx/5xx response --
    without this, a bad token, wrong scope, or wrong workspace/repo just
    fails silently with zero trace in the pipeline log.
    """
    if not (200 <= resp.status_code < 300):
        print(
            f"[warn] Bitbucket {what} failed: HTTP {resp.status_code} {resp.text[:300]}",
            file=sys.stderr,
        )


def post_bb_pr_comment(body: str) -> None:
    """Post (or update) a PR comment via the Bitbucket REST API.

    Bitbucket's comment renderer does not pass through raw HTML, so the
    dedup marker (unlike GitHub's invisible <!-- --> comment) is always
    visible as plain text. An HTML-comment-*styled* marker specifically
    (`<!-- ... -->`) reads as a rendering bug rather than an intentional
    label, so this uses a plain footer line instead, placed after the
    content rather than before it.
    """
    headers = _auth_headers()
    ctx     = _repo_context()
    pr_id   = os.getenv('BITBUCKET_PR_ID', '').strip()
    if not headers:
        print(
            "[warn] Skipping Bitbucket PR comment: no BITBUCKET_ACCESS_TOKEN set. "
            "To enable it: Repository settings -> Access tokens -> create one with "
            "pullrequest:write scope, add it as a secured Pipelines repository "
            "variable, then pass it to the pipe as BITBUCKET_ACCESS_TOKEN "
            "(see docs/BITBUCKET_PIPELINE.md Authentication).",
            file=sys.stderr,
        )
        return
    if not (ctx and pr_id):
        missing = [n for n, v in (('BITBUCKET_WORKSPACE/BITBUCKET_REPO_SLUG', ctx),
                                   ('BITBUCKET_PR_ID', pr_id)) if not v]
        print(f"[warn] Skipping Bitbucket PR comment: missing {', '.join(missing)}", file=sys.stderr)
        return
    try:
        full_body = f"{body}\n\n---\n_InfraScan · updates this comment in place ({COMMENT_MARKER})_"
        base_url = (
            f"{API_BASE}/repositories/{ctx['workspace']}/{ctx['repo_slug']}"
            f"/pullrequests/{pr_id}/comments"
        )
        # Server-side filter finds an existing marked comment to update in place,
        # instead of listing every comment and searching client-side.
        list_url = f'{base_url}?q=content.raw~"{COMMENT_MARKER}"'
        existing_resp = requests.get(list_url, headers=headers, timeout=10)
        _check_response(existing_resp, "PR comment lookup")
        if existing_resp.status_code == 200:
            values = existing_resp.json().get('values', [])
            if values:
                comment_id = values[0]['id']
                put_resp = requests.put(
                    f"{base_url}/{comment_id}",
                    json={'content': {'raw': full_body}},
                    headers=headers, timeout=10,
                )
                _check_response(put_resp, "PR comment update")
                return
        post_resp = requests.post(
            base_url, json={'content': {'raw': full_body}},
            headers=headers, timeout=10,
        )
        _check_response(post_resp, "PR comment create")
    except Exception as e:
        print(f"Bitbucket PR comment error: {e}", file=sys.stderr)


def _report_data_fields(report_dict: dict) -> list:
    """Small structured grid Code Insights renders natively on the report.

    A richer surface than GitHub's plain step-summary table -- Bitbucket's
    report schema has typed fields, so use them instead of another Markdown
    table for the headline numbers.
    """
    overall = report_dict.get('overall', {})
    metrics = report_dict.get('metrics', {})
    savings = metrics.get('savings_estimate', {})
    bd = overall.get('severity_breakdown', {})

    fields = [{'title': 'Grade', 'type': 'TEXT',
               'value': f"{overall.get('letter', '?')} ({overall.get('percentage', 0)}%)"}]
    total_cost = savings.get('total_infra_cost_usd_month')
    if total_cost:
        fields.append({'title': 'Monthly cost', 'type': 'TEXT', 'value': f"${total_cost:,.2f}"})
    fields.append({'title': 'Critical findings', 'type': 'NUMBER', 'value': bd.get('critical', 0)})
    fields.append({'title': 'High findings', 'type': 'NUMBER', 'value': bd.get('high', 0)})
    return fields


def _report_details_text(report_dict: dict, baseline: Optional[dict] = None) -> str:
    """Plain-text summary for Code Insights' `details` field.

    Code Insights reports do not render Markdown at all -- confirmed live,
    a GFM table sent here showed up as a literal wall of `|`-separated text,
    headers kept their `##`, and `**bold**` stayed as literal asterisks. So
    this builds plain text directly from report_dict rather than reusing
    format_ci_summary_md()'s GitHub-flavored Markdown. Per-finding detail
    belongs in the annotations (emit_bb_annotations) and the `data` grid
    (_report_data_fields) already covers the headline numbers -- this is
    just a short category breakdown plus the cost trend.
    """
    overall = report_dict.get('overall', {})
    metrics = report_dict.get('metrics', {})
    savings = metrics.get('savings_estimate', {})

    def _cat_line(name: str, g: dict) -> Optional[str]:
        if not g or g.get('max_score', 0) == 0:
            return None
        bd = g.get('severity_breakdown', {})
        parts = [f"{bd[s]} {s}" for s in ('critical', 'high', 'medium', 'low') if bd.get(s)]
        return f"{name}: {g.get('letter', '?')} ({g.get('percentage', 0)}%) - {', '.join(parts) or 'clean'}"

    lines = [f"InfraScan: {overall.get('letter', '?')} ({overall.get('percentage', 0)}%)", ""]
    for name, g in (
        ('Security', report_dict.get('security', {})),
        ('Cost', report_dict.get('cost', {})),
        ('Containers', report_dict.get('container', {})),
    ):
        line = _cat_line(name, g)
        if line:
            lines.append(line)

    total_cost = savings.get('total_infra_cost_usd_month')
    if total_cost:
        base_cost = (baseline or {}).get('metrics', {}).get('savings_estimate', {}).get('total_infra_cost_usd_month')
        if base_cost:
            delta = round(total_cost - base_cost, 2)
            trend = (f"+${delta:,.2f}/mo" if delta > 0
                     else f"-${abs(delta):,.2f}/mo" if delta < 0
                     else "no change")
            lines.append(f"Monthly cost: ${total_cost:,.2f} (baseline ${base_cost:,.2f}, {trend})")
        else:
            lines.append(f"Monthly cost: ${total_cost:,.2f}")

    lines.append("")
    lines.append("See this report's annotations for per-finding detail, or the full HTML report artifact.")
    return "\n".join(lines)


_MAX_DETAILS_LEN = 2000  # Code Insights hard limit on the `details` field


def _json_wire_len(s: str) -> int:
    """Length of *s* as it actually goes out on the wire.

    `requests` serializes json= bodies with json.dumps(..., ensure_ascii=True)
    (the stdlib default) -- every non-ASCII character (this report is full of
    emoji) becomes a 6-12 character \\uXXXX escape, not 1. Bitbucket's 2000
    limit is measured against that escaped payload, so truncating against
    len(s) alone still shipped well over 2000 on the wire.
    """
    return len(json.dumps(s)) - 2  # -2 strips the surrounding quotes


def _truncate_details(details_text: str, run_url: str = "") -> str:
    if _json_wire_len(details_text) <= _MAX_DETAILS_LEN:
        return details_text
    suffix = (
        f"\n\n… truncated — see the full report artifact, or {run_url}, for details."
        if run_url else
        "\n\n… truncated — see the full report artifact for details."
    )
    # Binary search the raw-character cutoff since escape overhead varies
    # per character (plain ASCII costs 1, an astral emoji costs up to 12).
    lo, hi = 0, len(details_text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if _json_wire_len(details_text[:mid] + suffix) <= _MAX_DETAILS_LEN:
            lo = mid
        else:
            hi = mid - 1
    return details_text[:lo] + suffix


def upsert_bb_report(report_dict: dict, baseline: Optional[dict] = None, run_url: str = "") -> None:
    """Create or update the Code Insights report for the current commit.

    report_id is fixed (REPORT_ID), so PUT is an idempotent upsert -- re-running
    the pipeline just updates the same report in place. No marker/dedup logic
    needed, unlike post_bb_pr_comment(). Uses _reports_api_call(), so this
    works even with no BITBUCKET_ACCESS_TOKEN set -- see its docstring.

    Deletes the existing report first (Bitbucket cascades that to delete
    its annotations too) before recreating it. Annotations otherwise
    accumulate forever: POST .../annotations only creates/updates by
    external_id, it never removes one that's simply absent from a later
    run's payload -- so a finding that gets fixed, or a run that posts
    fewer annotations after --max-annotations-per-image caps them, would
    otherwise leave every annotation any earlier run ever posted still
    attached, unbounded. A 404 on the delete (nothing to delete yet, e.g.
    the first-ever run) is expected and harmless.
    """
    ctx    = _repo_context()
    commit = os.getenv('BITBUCKET_COMMIT', '').strip()
    if not (ctx and commit):
        missing = [n for n, v in (('BITBUCKET_WORKSPACE/BITBUCKET_REPO_SLUG', ctx),
                                   ('BITBUCKET_COMMIT', commit)) if not v]
        print(f"[warn] Skipping Bitbucket Code Insights report: missing {', '.join(missing)}", file=sys.stderr)
        return
    try:
        overall = report_dict.get('overall', {})
        bd = overall.get('severity_breakdown', {})
        path = f"repositories/{ctx['workspace']}/{ctx['repo_slug']}/commit/{commit}/reports/{REPORT_ID}"
        _reports_api_call('DELETE', path)
        body = {
            'title': f"InfraScan: {overall.get('letter', '?')} ({overall.get('percentage', 0)}%)",
            'details': _truncate_details(_report_details_text(report_dict, baseline), run_url),
            'report_type': 'SECURITY',
            'result': 'FAILED' if bd.get('critical', 0) > 0 else 'PASSED',
            'reporter': 'InfraScan',
            'data': _report_data_fields(report_dict),
        }
        if run_url:
            body['link'] = run_url
        resp = _reports_api_call('PUT', path, json_body=body)
        if resp is None:
            print(
                "[warn] Skipping Bitbucket Code Insights report: no local auth "
                "proxy reachable and no BITBUCKET_ACCESS_TOKEN set", file=sys.stderr,
            )
            return
        _check_response(resp, "Code Insights report upsert")
    except Exception as e:
        print(f"Bitbucket Code Insights report error: {e}", file=sys.stderr)


_EXTERNAL_ID_RE = re.compile(r'[^A-Za-z0-9_.-]+')


def _annotation_external_id(f: dict, is_container: bool, path: str) -> str:
    rid = f.get('rule_id') or f.get('check_id', 'finding')
    line = f.get('line', '')
    prefix = 'container' if is_container else 'iac'
    raw = f"infrascan-{prefix}-{rid}-{path}-{line}"
    return _EXTERNAL_ID_RE.sub('-', raw)[:450]


def emit_bb_annotations(report_dict: dict, baseline: dict, alert_on: str, max_per_image: int = 10) -> None:
    """Post Code Insights annotations for findings at/above the alert_on threshold.

    Structural equivalent of ci_adapters.github.emit_annotations(), posted via
    REST (bulk, chunked to Bitbucket's 100-per-call limit) instead of printed
    as ::error/::warning workflow commands, since Bitbucket has no such
    mechanism. Annotations attach to the report created by upsert_bb_report()
    (same REPORT_ID) -- call this after upsert_bb_report() in the same run.
    Uses _reports_api_call(), so this works even with no BITBUCKET_ACCESS_TOKEN
    set -- see its docstring.

    max_per_image caps how many container-image findings get an annotation
    each (0/None = no cap) -- a single vulnerable image can easily have
    dozens of CVEs, which would otherwise bury every other finding in the
    PR. Doesn't affect IaC findings or anything counted elsewhere (grading,
    PR comment, report data grid all still see every finding).
    """
    ctx    = _repo_context()
    commit = os.getenv('BITBUCKET_COMMIT', '').strip()
    if not (ctx and commit):
        missing = [n for n, v in (('BITBUCKET_WORKSPACE/BITBUCKET_REPO_SLUG', ctx),
                                   ('BITBUCKET_COMMIT', commit)) if not v]
        print(f"[warn] Skipping Bitbucket annotations: missing {', '.join(missing)}", file=sys.stderr)
        return

    findings = report_dict.get('findings', {})
    all_findings = (
        list(findings.get('security', [])) +
        list(findings.get('container', [])) +
        list(findings.get('cost', []))
    )

    alert_sevs = set()
    if alert_on == 'critical':
        alert_sevs = {'critical'}
    elif alert_on in ('critical_high', 'high'):
        alert_sevs = {'critical', 'high'}
    elif alert_on == 'medium':
        alert_sevs = {'critical', 'high', 'medium'}
    elif alert_on == 'low':
        alert_sevs = {'critical', 'high', 'medium', 'low'}
    elif alert_on == 'any_new':
        alert_sevs = {'critical', 'high', 'medium', 'low', 'info'}

    container_ids = set(id(f) for f in findings.get('container', []))

    def _is_container(f: dict) -> bool:
        return id(f) in container_ids

    def _sort_key(f: dict) -> tuple:
        sev = f.get('severity', '').lower()
        try:
            sev_idx = _SEVERITY_ORDER.index(sev)
        except ValueError:
            sev_idx = 999
        return (sev_idx, 1 if _is_container(f) else 0)
    all_findings.sort(key=_sort_key)

    annotations = []
    image_counts = {}  # image -> annotated-finding count so far, container findings only
    skipped_by_image = {}
    for f in all_findings:
        sev = f.get('severity', '').lower()
        if sev not in alert_sevs:
            continue
        is_container = _is_container(f)
        # Cap how many distinct findings from a single container image get
        # annotated -- one noisy image (dozens of CVEs) can otherwise drown
        # out everything else in the PR. findings are already severity-
        # sorted (all_findings.sort above), so this always keeps the most
        # severe ones. IaC findings have no image concept and aren't capped
        # here. A capped finding still counts fully in grading/PR
        # comment/report -- only its annotation is skipped.
        if is_container and max_per_image:
            image = f.get('image', '')
            count = image_counts.get(image, 0)
            if count >= max_per_image:
                skipped_by_image[image] = skipped_by_image.get(image, 0) + 1
                continue
            image_counts[image] = count + 1
        rid  = f.get('rule_id') or f.get('check_id', 'FINDING')
        desc = f.get('description', f.get('name', rid))
        # A finding is one entry in report_dict (so grading/counts never
        # double up), but a container finding from an image shared across
        # multiple compose/k8s files legitimately affects each of them --
        # also_in_files (scanner/grype_scanner.py, docker_scout_scanner.py)
        # carries those extra {file, line} locations. Post one annotation
        # per actual location so each one gets flagged in its own diff view,
        # without touching the finding count itself.
        locations = [{'file': f.get('file', f.get('image', '')), 'line': f.get('line') or None}]
        locations += [
            {'file': loc.get('file', ''), 'line': loc.get('line') or None}
            for loc in f.get('also_in_files', [])
        ]
        for loc in locations:
            annotations.append({
                'external_id': _annotation_external_id(f, is_container, loc['file']),
                'annotation_type': 'VULNERABILITY',
                'severity': _BB_SEVERITY_MAP.get(sev, 'LOW'),
                'path': loc['file'],
                'line': loc['line'],
                'summary': f"{rid}: {desc}"[:450],
            })

    # Cost-increase annotations, only when a baseline is present (mirrors GitHub side)
    if baseline:
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
                annotations.append({
                    'external_id': _EXTERNAL_ID_RE.sub(
                        '-', f"infrascan-cost-{rc['resource_name']}-{rc.get('file', '')}"
                    )[:450],
                    'annotation_type': 'CODE_SMELL',
                    'severity': 'MEDIUM',
                    'path': rc.get('file', ''),
                    'line': rc.get('line') or None,
                    'summary': (
                        f"{rc['resource_name']} cost increased: "
                        f"${base:.2f}/mo → ${rc['total_usd_month']:.2f}/mo (+${delta:.2f}/mo)"
                    )[:450],
                })

    if skipped_by_image:
        details = ', '.join(f"{img}: {n} more" for img, n in skipped_by_image.items())
        print(
            f"[info] Capped container annotations at {max_per_image} per image -- "
            f"skipped ({details}); still counted in grading/PR comment/report.",
            file=sys.stderr,
        )

    if not annotations:
        print(
            f"[warn] No Bitbucket annotations to send: {len(all_findings)} finding(s), "
            f"alert_on={alert_on!r} (severities {sorted(alert_sevs) or 'none'})",
            file=sys.stderr,
        )
        return

    path = (
        f"repositories/{ctx['workspace']}/{ctx['repo_slug']}"
        f"/commit/{commit}/reports/{REPORT_ID}/annotations"
    )
    try:
        for i in range(0, len(annotations), 100):  # Bitbucket bulk limit is 100/call
            chunk = annotations[i:i + 100]
            resp = _reports_api_call('POST', path, json_body=chunk)
            if resp is None:
                print(
                    "[warn] Skipping Bitbucket annotations: no local auth proxy "
                    "reachable and no BITBUCKET_ACCESS_TOKEN set", file=sys.stderr,
                )
                return
            _check_response(resp, "annotations upload")
    except Exception as e:
        print(f"Bitbucket annotations error: {e}", file=sys.stderr)
