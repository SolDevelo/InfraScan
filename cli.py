#!/usr/bin/env python3
import os
import sys
import argparse
import json
import logging
from dotenv import load_dotenv
from scanner.parser import scan_directory
from reporter.grading import ReportGenerator
from reporter.html_generator import generate_standalone_html

__version__ = "1.0.3"

# Setup basic logging
logging.basicConfig(level=logging.ERROR, format='%(levelname)s: %(message)s')

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
        "--version",
        action="version",
        version=f"InfraScan v{__version__}",
        help="Show version information and exit"
    )
    
    return parser.parse_args()

def print_text_report(report_dict, resource_count, scanner_type):
    overall = report_dict.get('overall', {})
    findings_dict = report_dict.get('findings', {})
    results = findings_dict.get('all', report_dict.get('results', []))
    
    print("=" * 60)
    print(f" InfraScan Report - {scanner_type.upper()} SCAN")
    print("=" * 60)
    print(f"Directory Scanned : {os.path.abspath(sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('--') else '.')}")
    print(f"Resources Found   : {resource_count}")
    print(f"Total Findings    : {len(results)}")
    
    print("-" * 60)
    print(" GRADES & SUMMARY")
    print("-" * 60)
    
    def print_grade(name, grade):
        if not grade or (grade.get('max_score', 0) == 0 and grade.get('letter') != 'A'):
            return
        
        breakdown = grade.get('severity_breakdown', {})
        counts = [
            f"Crit:{breakdown.get('critical', 0)}",
            f"High:{breakdown.get('high', 0)}",
            f"Med:{breakdown.get('medium', 0)}",
            f"Low:{breakdown.get('low', 0)}"
        ]
        br_str = f" [{' | '.join(counts)}]"
        print(f"{name:18}: {grade.get('letter', '?')} ({grade.get('percentage', 0)}%){br_str}")

    print_grade("Overall", overall)
    
    if scanner_type in ['regex', 'comprehensive']:
        print_grade("Cost Optimization", report_dict.get('cost'))
        
    if scanner_type in ['checkov', 'comprehensive']:
        print_grade("Security", report_dict.get('security'))
        
    if scanner_type in ['containers', 'comprehensive']:
        print_grade("Container Security", report_dict.get('container'))

    print("=" * 60)
    
    # Recommendations
    recs = report_dict.get('analysis', {}).get('recommendations', [])
    if recs:
        print("\nRECOMMENDATIONS:")
        for rec in recs:
            print(f"  * {rec}")
        print("=" * 60)
    
    if results:
        print("\nFINDINGS DETAILS:")

        print("-" * 60)
        
        # Categorize findings
        categories = []
        if findings_dict.get('cost'):
            categories.append(('Cost Optimization Findings', findings_dict['cost']))
        if findings_dict.get('security'):
            categories.append(('IaC Security Findings', findings_dict['security']))
        if findings_dict.get('container'):
            categories.append(('Container Security Findings', findings_dict['container']))
            
        # If no categorization available (e.g. older scan structure), use all results
        if not categories:
            categories = [(f"{scanner_type.replace('_',' ').title()} Findings", results)]

        for cat_name, cat_findings in categories:
            if not cat_findings:
                continue
            
            print(f"\n>>> {cat_name} ({len(cat_findings)}) <<<")
            for res in cat_findings:
                severity = res.get('severity', 'UNKNOWN').upper()
                rule_id = res.get('rule_id', 'N/A')
                file_path = res.get('file', 'Unknown')
                line_str = f":{res.get('line')}" if res.get('line') else ""
                
                print(f"[{severity}] {rule_id}: {res.get('description', '')}")
                print(f"           File: {file_path}{line_str}")
                if res.get('resource'):
                    print(f"           Resource: {res.get('resource')}")
                print("-" * 40)


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
            download_external_modules=args.download_external_modules
        )
        
        # Generate Report
        report_generator = ReportGenerator()
        report = report_generator.generate_report(
            findings=results,
            resource_count=resource_count,
            scanner_type=args.scanner,
            extra_recommendations=recommendations
        )
        
        report_dict = report.to_dict()
        report_dict['results'] = results
        report_dict['summary'] = {
            'total': len(results),
            'scanner_used': args.scanner
        }
        
        # Output Results
        if args.out and args.format == 'json':
            with open(args.out, 'w') as f:
                json.dump(report_dict, f, indent=2)
        elif args.out and args.format == 'text':
            # Save a background JSON even in text mode if --out is specified
            with open(args.out, 'w') as f:
                json.dump(report_dict, f, indent=2)
            print(f"Full JSON report saved to {args.out}")
                
        if args.format == 'json':
            print(json.dumps(report_dict, indent=2))
        elif args.format == 'html':
            html_output = generate_standalone_html(report_dict)
            if args.out:
                with open(args.out, 'w', encoding='utf-8') as f:
                    f.write(html_output)
                print(f"Standalone HTML report saved to {args.out}")
            else:
                print(html_output)
        else:
            print_text_report(report_dict, resource_count, args.scanner)
            
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
