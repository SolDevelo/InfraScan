#!/usr/bin/env python3
import os
import sys
import argparse
import json
import logging
import requests
try:
    from colorama import Fore, Style, init
except ImportError:
    # Minimal fallback for environments without colorama
    class MockColor:
        def __getattr__(self, name): return ""
    Fore = Style = MockColor()
    def init(*args, **kwargs): pass

from dotenv import load_dotenv
from scanner.parser import scan_directory
from reporter.grading import ReportGenerator
from reporter.html_generator import generate_standalone_html

__version__ = "1.0.10"

# Setup basic logging
logging.basicConfig(level=logging.ERROR, format='%(levelname)s: %(message)s')

def load_baseline(path: str) -> dict:
    """Load a baseline report JSON; return empty dict if path is blank or missing."""
    if not path:
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"[warn] Could not load baseline {path}: {e}", file=sys.stderr)
        return {}


def collect_ci_limits(scanner_type: str) -> dict:
    """Return CI_SEVERITY_LIMITS per category, read from scanner class attributes."""
    from scanner.checkov_scanner import CheckovScanner
    from scanner.docker_scout_scanner import DockerScoutScanner
    from scanner.grype_scanner import GrypeScanner
    container_cls = DockerScoutScanner
    try:
        from scanner.parser import get_container_scanner
        if get_container_scanner() == 'grype':
            container_cls = GrypeScanner
    except Exception:
        pass
    return {
        'security':  dict(CheckovScanner.CI_SEVERITY_LIMITS),
        'container': dict(container_cls.CI_SEVERITY_LIMITS),
        'cost':      {},  # cost rules use base Scanner defaults
    }


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

    alert_sevs = {'critical'}
    if alert_on == 'critical_high':
        alert_sevs.add('high')

    for f in all_findings:
        sev = f.get('severity', '').lower()
        if sev not in alert_sevs:
            continue
        rid   = f.get('rule_id') or f.get('check_id', 'FINDING')
        fpath = f.get('file', '')
        line  = f.get('line', '')
        desc  = f.get('description', f.get('name', rid))
        level = 'error' if sev == 'critical' else 'warning'
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
                  f"${base:.2f}/mo \u2192 ${rc['total_usd_month']:.2f}/mo "
                  f"(+${delta:.2f}/mo)")


def send_slack_notification(message: str) -> None:
    """Send a Slack notification via webhook URL from environment variable."""
    webhook_url = os.getenv('SLACK_WEBHOOK_URL', '').strip()
    if not webhook_url:
        return
    try:
        response = requests.post(webhook_url, json={'text': message}, timeout=5)
        if response.status_code >= 400:
            print(f"Slack notification failed: {response.status_code} - {response.text}", file=sys.stderr)
    except Exception as e:
        print(f"Slack notification error: {e}", file=sys.stderr)

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

def setup_args():
    parser = argparse.ArgumentParser(
        description="InfraScan CLI - Open Source IaC Cost & Security Scanner"
    )
    
    parser.add_argument(
        "path",
        nargs="?",
        default="/scan",
        help="Path to the directory to scan (default: /scan when using Docker, or '.' for local use)"
    )
    
    parser.add_argument(
        "--scanner",
        default="comprehensive",
        help="Scanner type(s) to run (default: comprehensive). Support multiple scanners separated by comma (e.g., 'regex,containers'). Options: regex, checkov, containers, comprehensive"
    )
    
    parser.add_argument(
        "--format",
        choices=["text", "json", "html"],
        default="text",
        help="Output format (default: text)"
    )
    
    parser.add_argument(
        "--out",
        help="File path to save JSON output explicitly (e.g., infrascan-report.json)"
    )
    
    parser.add_argument(
        "--fail-on",
        choices=["any", "high_critical", "grade_a", "grade_b", "grade_c", "grade_d", "grade_f",
                 "priority_critical", "priority_high", "priority_medium", "priority_low", "priority_info"],
        help="Exit with error code 1 if findings match criteria (any findings, high/critical findings, grade threshold, or priority threshold)"
    )
    
    parser.add_argument(
        "--download-external-modules",
        action="store_true",
        help="Allow Checkov to download external modules (Terraform/etc)"
    )

    parser.add_argument(
        "--framework",
        default="smart",
        choices=["smart", "auto", "terraform", "kubernetes", "cloudformation", "helm", "ansible", "all"],
        help="IaC framework type (default: smart). 'smart' automatically uses 'all' for multi-framework projects"
    )

    parser.add_argument(
        "-f", "--include",
        action="append",
        dest="include",
        help="Select specific files or directories to scan. Can be used multiple times."
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"InfraScan v{__version__}",
        help="Show version information and exit"
    )

    parser.add_argument(
        "--traffic-profile",
        choices=["auto", "small", "medium", "large"],
        default="auto",
        dest="traffic_profile",
        help="Usage-based cost scaling profile (default: auto — detected from infra size). "
             "small=10GB/d NAT, medium=100GB/d, large=1TB/d."
    )

    parser.add_argument(
        "--alert-on",
        choices=["critical", "critical_high", "none"],
        default="critical",
        dest="alert_on",
        help="Severity threshold for PR comments and annotations "
             "(critical | critical_high | none). Default: critical."
    )

    parser.add_argument(
        "--baseline",
        default="",
        help="Path to a baseline InfraScan JSON for cost/finding delta comparison."
    )

    parser.add_argument(
        "--baseline-out",
        default="",
        dest="baseline_out",
        help="Path to write the current scan result as JSON for use as a future baseline "
             "(written regardless of --format)."
    )

    parser.add_argument(
        "--pr-comment",
        default="true",
        dest="pr_comment",
        help="Post/update a PR comment when actionable (true|false)."
    )

    parser.add_argument(
        "--step-summary",
        default="true",
        dest="step_summary",
        help="Write results to the GitHub Actions step summary (true|false)."
    )

    parser.add_argument(
        "--force-comment",
        action="store_true",
        dest="force_comment",
        help="Force a PR comment even when posting rules would normally skip it."
    )

    parser.add_argument(
        "--list-patterns",
        action="store_true",
        dest="list_patterns",
        help="Print trigger patterns for the requested scanner as JSON and exit."
    )

    return parser.parse_args()

def print_text_report(report_dict, resource_count, scanner_type):
    # Initialize colorama
    init(autoreset=True)
    
    overall = report_dict.get('overall', {})
    findings_dict = report_dict.get('findings', {})
    results = findings_dict.get('all', report_dict.get('results', []))
    
    # Header
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'=' * 60}")
    print(f"{Fore.CYAN}{Style.BRIGHT} InfraScan Report - {scanner_type.upper()} SCAN")
    print(f"{Fore.CYAN}{Style.BRIGHT}{'=' * 60}")
    
    # Summary Info
    target_path = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('--') else '.')
    print(f"{Style.BRIGHT}Path Scanned      :{Style.RESET_ALL} {target_path}")
    print(f"{Style.BRIGHT}Resources Found   :{Style.RESET_ALL} {resource_count}")
    print(f"{Style.BRIGHT}Total Findings    :{Style.RESET_ALL} {len(results)}")
    
    # Grades Section
    print(f"\n{Style.BRIGHT}GRADING SUMMARY:")
    print(f"{'-' * 30}")
    
    def get_grade_color(letter):
        if letter == 'A': return Fore.GREEN
        if letter == 'B': return Fore.GREEN
        if letter == 'C': return Fore.YELLOW
        if letter == 'D': return Fore.MAGENTA
        return Fore.RED

    def print_grade_line(name, grade):
        if not grade or (grade.get('max_score', 0) == 0 and grade.get('letter') != 'A'):
            return
        
        letter = grade.get('letter', '?')
        percentage = grade.get('percentage', 0)
        color = get_grade_color(letter)
        
        breakdown = grade.get('severity_breakdown', {})
        counts = [
            f"{Fore.RED}Crit:{breakdown.get('critical', 0)}{Style.RESET_ALL}",
            f"{Fore.LIGHTRED_EX}High:{breakdown.get('high', 0)}{Style.RESET_ALL}",
            f"{Fore.YELLOW}Med:{breakdown.get('medium', 0)}{Style.RESET_ALL}",
            f"{Fore.CYAN}Low:{breakdown.get('low', 0)}{Style.RESET_ALL}"
        ]
        br_str = f" [{' | '.join(counts)}]"
        print(f"{name:18}: {color}{Style.BRIGHT}{letter}{Style.RESET_ALL} ({percentage}%){br_str}")

    print_grade_line("Overall Health", overall)
    
    if scanner_type in ['regex', 'comprehensive']:
        print_grade_line("Cost Efficiency", report_dict.get('cost'))
        
    if scanner_type in ['checkov', 'comprehensive']:
        print_grade_line("IaC Security", report_dict.get('security'))
        
    if scanner_type in ['containers', 'comprehensive']:
        print_grade_line("Container Security", report_dict.get('container'))

    # Recommendations
    recs = report_dict.get('analysis', {}).get('recommendations', [])
    if recs:
        print(f"\n{Fore.GREEN}{Style.BRIGHT}RECOMMENDATIONS:")
        for rec in recs:
            print(f"  {Fore.GREEN}• {Style.BRIGHT}{rec}")
    
    # Findings Details
    if results:
        print(f"\n{Style.BRIGHT}FINDINGS DETAILS:")
        print(f"{'=' * 60}")
        
        # Categorize findings
        categories = []
        if findings_dict.get('cost'):
            categories.append(('Cost Optimization', findings_dict['cost']))
        if findings_dict.get('security'):
            categories.append(('IaC Security', findings_dict['security']))
        if findings_dict.get('container'):
            categories.append(('Container Security', findings_dict['container']))
            
        if not categories:
            categories = [('General Findings', results)]

        for cat_name, cat_findings in categories:
            if not cat_findings:
                continue
            
            print(f"\n{Style.BRIGHT}>>> {cat_name} ({len(cat_findings)})")
            
            # Limit display to 40 findings to avoid overwhelming CI logs
            display_limit = 40
            for i, res in enumerate(cat_findings):
                if i >= display_limit:
                    print(f"\n      {Fore.YELLOW}... and {len(cat_findings) - display_limit} more findings (see full report for details)")
                    break
                    
                severity = res.get('severity', 'UNKNOWN').upper()
                sev_color = Fore.WHITE
                if severity == 'CRITICAL': sev_color = Fore.RED + Style.BRIGHT
                elif severity == 'HIGH': sev_color = Fore.RED
                elif severity == 'MEDIUM': sev_color = Fore.YELLOW
                elif severity == 'LOW': sev_color = Fore.CYAN
                
                rule_id = res.get('rule_id', 'N/A')
                file_path = res.get('file', 'Unknown')
                line_str = f":{res.get('line')}" if res.get('line') else ""
                
                print(f"  {sev_color}[{severity}]{Style.RESET_ALL} {Style.BRIGHT}{rule_id}{Style.RESET_ALL}: {res.get('description', '')}")
                print(f"      {Fore.WHITE}at {file_path}{line_str}{Style.RESET_ALL}")
                if res.get('resource'):
                    print(f"      {Fore.WHITE}resource: {res.get('resource')}{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'=' * 60}\n")


def _print_savings_block(report_dict: dict) -> None:
    """Print the '💰 Estimated Savings' block after the grading summary."""
    init(autoreset=True)
    est = (report_dict.get('metrics') or {}).get('savings_estimate')
    if not est:
        return

    low   = est.get('low_usd_month', 0)
    high  = est.get('high_usd_month', 0)
    total = est.get('total_infra_cost_usd_month')
    pct_lo_det = est.get('savings_pct_of_detectable_low')
    pct_hi_det = est.get('savings_pct_of_detectable_high')
    pct_lo_tot = est.get('savings_pct_of_total_low')
    pct_hi_tot = est.get('savings_pct_of_total_high')
    profile    = (report_dict.get('metrics') or {}).get('traffic_profile', 'small')
    provider   = est.get('cost_provider', 'internal')

    print(f"\n{Fore.GREEN}{Style.BRIGHT}💰 ESTIMATED SAVINGS:")
    print(f"{'-' * 30}")

    if low == high:
        print(f"  Potential saving: {Fore.GREEN}{Style.BRIGHT}${low:,.2f}/month{Style.RESET_ALL}")
    else:
        print(f"  Potential saving: {Fore.GREEN}{Style.BRIGHT}${low:,.2f} – ${high:,.2f}/month{Style.RESET_ALL}")

    if pct_lo_tot is not None and pct_hi_tot is not None:
        print(f"  vs total infra cost: {Fore.YELLOW}{pct_lo_tot}% – {pct_hi_tot}%{Style.RESET_ALL}", end='')
        if total:
            print(f"  (total: ${total:,.0f}/mo)", end='')
        print()
    elif pct_lo_det is not None:
        print(f"  vs detectable resources: {Fore.YELLOW}{pct_lo_det}% – {pct_hi_det}%{Style.RESET_ALL}")

    print(f"  Traffic profile: {profile} | Pricing source: {provider}")

    per = sorted(
        est.get('per_finding', []),
        key=lambda f: f.get('saving_high', 0), reverse=True
    )[:3]
    if per:
        print(f"  {Style.BRIGHT}Top opportunities:{Style.RESET_ALL}")
        for pf in per:
            s_lo = pf.get('saving_low', 0)
            s_hi = pf.get('saving_high', 0)
            saving_str = f"${s_lo:,.2f}" if s_lo == s_hi else f"${s_lo:,.2f}–${s_hi:,.2f}"
            import os as _os
            fname = _os.path.basename(pf.get('file', ''))
            print(f"    • {pf.get('rule_id', '')}: {saving_str}/mo  ({fname}:{pf.get('line', '')})")


def should_fail(args, report_dict, results):
    if not args.fail_on:
        return False
        
    if args.fail_on == 'any' and len(results) > 0:
        print("\n[ERROR] Build failed: Findings detected and --fail-on=any specified.", file=sys.stderr)
        return True
        
    if args.fail_on == 'high_critical':
        critical_high_count = sum(1 for r in results if r.get('severity', '').lower() in ['critical', 'high'])
        if critical_high_count > 0:
            print(f"\n[ERROR] Build failed: {critical_high_count} high/critical findings detected and --fail-on=high_critical specified.", file=sys.stderr)
            return True
            
    if args.fail_on.startswith('grade_'):
        grade_order = ['A', 'B', 'C', 'D', 'F']
        fail_grade = args.fail_on.split('_')[1].upper()
        overall_letter = report_dict.get('overall', {}).get('letter', 'A')
        
        try:
            fail_idx = grade_order.index(fail_grade)
            current_idx = grade_order.index(overall_letter)
            
            if current_idx >= fail_idx:
                print(f"\n[ERROR] Build failed: Overall grade is {overall_letter} and --fail-on={args.fail_on} specified (threshold: {fail_grade} or worse).", file=sys.stderr)
                return True
        except ValueError:
            pass # Should not happen due to argparse choices
            
    if args.fail_on.startswith('priority_'):
        severity_weights = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0.5}
        fail_priority = args.fail_on.split('_')[1]
        threshold_weight = severity_weights.get(fail_priority, 0)
        
        findings_at_or_above = [
            r for r in results 
            if severity_weights.get(r.get('severity', 'info').lower(), 0.5) >= threshold_weight
        ]
        
        if findings_at_or_above:
            print(f"\n[ERROR] Build failed: {len(findings_at_or_above)} findings with priority {fail_priority} or higher detected and --fail-on={args.fail_on} specified.", file=sys.stderr)
            return True
            
    return False

def main():
    load_dotenv()
    args = setup_args()

    # --list-patterns: print trigger patterns as JSON and exit
    if args.list_patterns:
        from scanner.checkov_scanner import CheckovScanner
        from scanner.docker_scout_scanner import DockerScoutScanner
        from scanner.grype_scanner import GrypeScanner
        scanner_map = {
            'checkov': CheckovScanner,
            'containers': DockerScoutScanner,
            'grype': GrypeScanner,
        }
        patterns: list = []
        for name, cls in scanner_map.items():
            if args.scanner in ('comprehensive', name):
                patterns.extend(cls.TRIGGER_PATTERNS)
        # regex / cost rules patterns (not a Scanner subclass)
        if args.scanner in ('comprehensive', 'regex'):
            patterns.extend([r'\.tf$', r'\.tfvars$', r'\.hcl$'])
        print(json.dumps({'scanner': args.scanner, 'patterns': sorted(set(patterns))}))
        sys.exit(0)

    target_path = os.path.abspath(args.path)
    
    if not os.path.exists(target_path):
        print(f"Error: Path '{target_path}' does not exist.", file=sys.stderr)
        sys.exit(1)
        
    try:
        if args.format == 'text':
            print(f"Analyzing {target_path} with '{args.scanner}' scanner...")
            
        # Run Scanners
        results, resource_count, recommendations = scan_directory(
            target_path, 
            scanner_type=args.scanner,
            framework=args.framework,
            download_external_modules=args.download_external_modules,
            included_paths=args.include
        )
        
        # Generate Report
        report_generator = ReportGenerator()
        report = report_generator.generate_report(
            findings=results,
            resource_count=resource_count,
            scanner_type=args.scanner,
            extra_recommendations=recommendations,
            scan_path=target_path,
            traffic_profile=getattr(args, 'traffic_profile', 'auto'),
        )
        
        report_dict = report.to_dict()
        report_dict['results'] = results
        report_dict['summary'] = {
            'total': len(results),
            'scanner_used': args.scanner
        }
        report_dict['metadata'] = report_dict.get('metadata', {})
        gh_ctx = build_gh_actions_context()
        if gh_ctx['repo'] or gh_ctx['workflow'] or gh_ctx['run_url']:
            report_dict['metadata'].update({
                'scan_source': 'github_actions',
                'github_actions': gh_ctx,
            })
            if gh_ctx['repo'] and 'repository_url' not in report_dict['metadata']:
                report_dict['metadata']['repository_url'] = f"https://github.com/{gh_ctx['repo']}"
        
        # Output Results to file/stdout
        if args.out:
            if args.format == 'json':
                with open(args.out, 'w') as f:
                    json.dump(report_dict, f, indent=2)
            elif args.format == 'html':
                html_output = generate_standalone_html(report_dict)
                with open(args.out, 'w', encoding='utf-8') as f:
                    f.write(html_output)
            else: # text format
                # Default behavior for text mode with --out is to save JSON results
                with open(args.out, 'w') as f:
                    json.dump(report_dict, f, indent=2)

        # Write a JSON copy for use as a future baseline (independent of --format)
        if getattr(args, 'baseline_out', ''):
            with open(args.baseline_out, 'w') as f:
                json.dump(report_dict, f, indent=2)

        # Handle console output
        if args.format == 'json' and not args.out:
            print(json.dumps(report_dict, indent=2))
        elif args.format == 'html' and not args.out:
            print(generate_standalone_html(report_dict))
        else:
            # If format is text OR if output is saved to record/html/json
            # always show the text summary in the console
            print_text_report(report_dict, resource_count, args.scanner)
            _print_savings_block(report_dict)
            if args.out:
                 print(f"{Fore.GREEN}[v] Full {args.format.upper()} report saved to: {Fore.WHITE}{args.out}")

        # ── CI output (step summary + PR comment + annotations) ──────────────
        baseline_dict = load_baseline(getattr(args, 'baseline', ''))
        alert_on      = getattr(args, 'alert_on', 'critical')
        do_summary    = getattr(args, 'step_summary', 'true').lower() != 'false'
        do_pr_comment = getattr(args, 'pr_comment', 'true').lower() != 'false'
        force_comment = getattr(args, 'force_comment', False)

        gh_ctx  = build_gh_actions_context()
        run_url = gh_ctx.get('run_url', '')

        if do_summary and os.getenv('GITHUB_STEP_SUMMARY'):
            from reporter.cost_estimator import format_ci_summary_md
            ci_limits = collect_ci_limits(args.scanner)
            summary_md = format_ci_summary_md(
                report_dict,
                ci_limits=ci_limits,
                baseline=baseline_dict or None,
                run_url=run_url,
            )
            write_gh_step_summary(summary_md)

        if do_pr_comment and os.getenv('GITHUB_TOKEN') and os.getenv('GITHUB_EVENT_PATH'):
            from reporter.cost_estimator import format_pr_comment_md
            comment_md = format_pr_comment_md(
                report_dict,
                baseline=baseline_dict or None,
                alert_on=alert_on,
                run_url=run_url,
            )
            if comment_md or force_comment:
                post_pr_comment(comment_md or f"## 🔍 InfraScan\nNo actionable findings.")

        emit_annotations(report_dict, baseline_dict, alert_on)

        # ── Slack notification ────────────────────────────────────────────────
        webhook_url = os.getenv('SLACK_WEBHOOK_URL', '').strip()
        if webhook_url:
            overall = report_dict.get('overall', {})
            cost = report_dict.get('cost', {})
            security = report_dict.get('security', {})
            container = report_dict.get('container', {})

            total_findings = len(results)
            overall_grade = overall.get('letter', '?') if overall else '?'
            overall_pct = overall.get('percentage', 0) if overall else 0

            grades_parts = [f"Overall {overall_grade} ({overall_pct}%)"] 
            if cost and cost.get('max_score', 0) > 0:
                grades_parts.append(f"Cost {cost.get('letter','?')} ({cost.get('percentage',0)}%)")
            if security and security.get('max_score', 0) > 0:
                grades_parts.append(f"Security {security.get('letter','?')} ({security.get('percentage',0)}%)")
            if container and container.get('max_score', 0) > 0:
                grades_parts.append(f"Containers {container.get('letter','?')} ({container.get('percentage',0)}%)")
            grades_summary = " | ".join(grades_parts)

            ctx = build_gh_actions_context()
            lines = ["🤖 InfraScan used in *GitHub Actions*"]
            if ctx['repo']:
                lines.append(f"Repo: *{ctx['repo']}*")
            if ctx['branch']:
                lines.append(f"Branch: `{ctx['branch']}`")
            if ctx['workflow']:
                lines.append(f"Workflow: _{ctx['workflow']}_")
            if ctx['actor']:
                lines.append(f"Triggered by: {ctx['actor']}")
            lines.append(f"Grades: {grades_summary}")
            lines.append(f"Findings: {total_findings} | Scanner: {args.scanner}")

            # Cost savings summary (if available)
            slack_savings = (report_dict.get('metrics') or {}).get('savings_estimate')
            if slack_savings:
                s_lo  = slack_savings.get('low_usd_month', 0)
                s_hi  = slack_savings.get('high_usd_month', 0)
                total_c = slack_savings.get('total_infra_cost_usd_month')
                if total_c:
                    lines.append(f"Infra cost: ~${total_c:,.0f}/mo | Potential savings: ${s_lo:,.0f}–${s_hi:,.0f}/mo")
                else:
                    lines.append(f"Potential savings: ${s_lo:,.0f}–${s_hi:,.0f}/mo")

            if ctx['run_url']:
                lines.append(f"<{ctx['run_url']}|View run>")

            send_slack_notification(" | ".join(lines))

        # Determine Exit Code
        if should_fail(args, report_dict, results):
            sys.exit(1)
            
        sys.exit(0)
        
    except Exception as e:
        print(f"An error occurred during scanning: {e}", file=sys.stderr)
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
