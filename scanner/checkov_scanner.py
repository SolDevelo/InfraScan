"""
Checkov integration for deep security and compliance scanning.
This module wraps Checkov to provide comprehensive IaC analysis.
"""

import json
import os
import subprocess
import sys
from typing import List, Dict, Any

try:
    from checkov.main import Checkov
    CHECKOV_AVAILABLE = True
except ImportError:
    CHECKOV_AVAILABLE = False


def is_checkov_available() -> bool:
    """Check if Checkov is installed and available."""
    return CHECKOV_AVAILABLE


def run_checkov_scan(directory_path: str, framework: str = "terraform") -> List[Dict[str, Any]]:
    """
    Run Checkov scan on a directory using subprocess.
    
    Args:
        directory_path: Path to directory containing IaC files
        framework: IaC framework to scan (terraform, cloudformation, kubernetes, etc.)
    
    Returns:
        List of findings in a normalized format
    """
    if not CHECKOV_AVAILABLE:
        raise ImportError(
            "Checkov is not installed. Install it with: pip install checkov"
        )
    
    findings = []
    
    try:
        # Use subprocess to call checkov CLI directly
        cmd = [
            "checkov",
            "-d", directory_path,
            "--framework", framework,
            "-o", "json",
            "--quiet"
        ]
        
        # Run the command and capture output
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=os.path.dirname(directory_path) or "."
        )
        
        # Parse the JSON output
        if result.stdout.strip():
            try:
                # Try to parse the entire output as JSON
                report_data = json.loads(result.stdout)
                findings = parse_checkov_json_output(report_data, directory_path)
            except json.JSONDecodeError:
                # If that fails, try line by line
                for line in result.stdout.strip().split('\n'):
                    if line.strip().startswith('{'):
                        try:
                            report_data = json.loads(line)
                            findings.extend(parse_checkov_json_output(report_data, directory_path))
                            break
                        except json.JSONDecodeError:
                            continue
                
        if result.stderr and "error" in result.stderr.lower():
            print(f"Checkov stderr: {result.stderr}")
                
    except Exception as e:
        print(f"Error running Checkov: {e}")
        import traceback
        traceback.print_exc()
        return []
    
    return findings


def parse_checkov_json_output(report_data: Dict[str, Any], base_path: str) -> List[Dict[str, Any]]:
    """
    Parse Checkov JSON output into normalized format.
    
    Args:
        report_data: Parsed JSON data from Checkov
        base_path: Base path to make file paths relative
    
    Returns:
        List of normalized findings
    """
    findings = []
    
    try:
        # Checkov JSON structure can vary:
        # Option 1: {"check_type": "terraform", "results": {"failed_checks": [...]}}
        # Option 2: {"results": {"terraform": {"failed_checks": [...]}}}
        
        results = report_data.get('results', {})
        
        # Check if failed_checks is directly under results
        if 'failed_checks' in results:
            failed_checks = results.get('failed_checks', [])
            for check in failed_checks:
                findings.append(normalize_checkov_finding(check, base_path))
        else:
            # Handle nested structure (framework -> failed_checks)
            for check_type, check_data in results.items():
                if isinstance(check_data, dict):
                    failed_checks = check_data.get('failed_checks', [])
                    for check in failed_checks:
                        findings.append(normalize_checkov_finding(check, base_path))
                elif isinstance(check_data, list):
                    # Some versions return a list directly
                    for item in check_data:
                        if isinstance(item, dict) and 'failed_checks' in item:
                            for check in item['failed_checks']:
                                findings.append(normalize_checkov_finding(check, base_path))
        
    except Exception as e:
        print(f"Error parsing Checkov JSON output: {e}")
        import traceback
        traceback.print_exc()
    
    return findings


def parse_checkov_output(report_data: Any, base_path: str) -> List[Dict[str, Any]]:
    """
    Legacy function for backward compatibility.
    Parse Checkov output into normalized format.
    
    Args:
        report_data: Checkov report object or JSON data
        base_path: Base path to make file paths relative
    
    Returns:
        List of normalized findings
    """
    if isinstance(report_data, dict):
        return parse_checkov_json_output(report_data, base_path)
    
    findings = []
    
    try:
        # Handle Report object format
        if hasattr(report_data, 'check_type_to_report'):
            # It's a Report object
            for check_type, reports in report_data.check_type_to_report.items():
                for report in reports:
                    if hasattr(report, 'failed_checks'):
                        for check in report.failed_checks:
                            findings.append(normalize_checkov_finding(check, base_path))
        
    except Exception as e:
        print(f"Error parsing Checkov output: {e}")
    
    return findings


def normalize_checkov_finding(check: Any, base_path: str) -> Dict[str, Any]:
    """
    Normalize a Checkov finding to match our internal format.
    
    Args:
        check: Checkov check result (dict or object)
        base_path: Base path for relative file paths
    
    Returns:
        Normalized finding dictionary
    """
    # Handle both dict and object attributes
    def get_attr(obj, key, default=''):
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)
    
    # Extract check details
    check_id = get_attr(check, 'check_id', 'CHECKOV-UNKNOWN')
    check_name = get_attr(check, 'check_name', 'Unknown Check')
    severity = get_attr(check, 'severity', 'MEDIUM') or 'MEDIUM'  # Handle None
    file_path = get_attr(check, 'file_path', '')
    file_line_range = get_attr(check, 'file_line_range', [0, 0])
    resource = get_attr(check, 'resource', '')
    guideline = get_attr(check, 'guideline', '')
    
    # Make file path relative
    if file_path and base_path:
        file_path = os.path.relpath(file_path, base_path)
    
    # Map Checkov severity to our format
    severity_map = {
        'CRITICAL': 'Critical',
        'HIGH': 'High',
        'MEDIUM': 'Medium',
        'LOW': 'Low',
        'INFO': 'Info'
    }
    normalized_severity = severity_map.get(str(severity).upper(), 'Medium')
    
    # Build finding - use check_name as description if description is None
    description = get_attr(check, 'description', None)
    if not description or description == 'null':
        description = check_name
    
    finding = {
        'file': file_path,
        'rule_id': check_id,
        'rule_name': check_name,
        'severity': normalized_severity,
        'description': description,
        'remediation': guideline if guideline else 'See Checkov documentation for remediation guidance.',
        'estimated_savings': 'Varies by issue',
        'line': file_line_range[0] if isinstance(file_line_range, list) else 0,
        'match_content': f"Resource: {resource}" if resource else '',
        'resource': resource,
        'scanner': 'checkov'
    }
    
    return finding


def get_checkov_frameworks() -> List[str]:
    """Return list of supported frameworks by Checkov."""
    return [
        'terraform',
        'cloudformation',
        'kubernetes',
        'helm',
        'dockerfile',
        'secrets',
        'arm',
        'ansible',
        'github_actions',
        'bitbucket_pipelines',
        'gitlab_ci'
    ]


def run_checkov_with_filters(
    directory_path: str,
    framework: str = "terraform",
    checks: List[str] = None,
    skip_checks: List[str] = None,
    check_categories: List[str] = None
) -> List[Dict[str, Any]]:
    """
    Run Checkov with specific filters.
    
    Args:
        directory_path: Path to scan
        framework: IaC framework
        checks: Specific checks to run (e.g., ['CKV_AWS_1', 'CKV_AWS_2'])
        skip_checks: Checks to skip
        check_categories: Categories to include (e.g., ['COST', 'SECURITY'])
    
    Returns:
        List of findings
    """
    if not CHECKOV_AVAILABLE:
        raise ImportError("Checkov is not installed")
    
    try:
        from checkov.main import run
        import sys
        from io import StringIO
        import json
        
        config = [
            "-d", directory_path,
            "--framework", framework,
            "-o", "json",
            "--quiet"
        ]
        
        # Add filters
        if checks:
            config.extend(["--check", ",".join(checks)])
        
        if skip_checks:
            config.extend(["--skip-check", ",".join(skip_checks)])
        
        # Redirect stdout to capture JSON output
        old_stdout = sys.stdout
        sys.stdout = output_buffer = StringIO()
        
        try:
            run(config)
        finally:
            sys.stdout = old_stdout
        
        # Parse output
        output = output_buffer.getvalue()
        if output.strip():
            try:
                report_data = json.loads(output)
                findings = parse_checkov_json_output(report_data, directory_path)
                
                # Post-filter by category if specified
                if check_categories and findings:
                    findings = [
                        f for f in findings
                        if any(cat.upper() in f['rule_id'].upper() for cat in check_categories)
                    ]
                
                return findings
            except json.JSONDecodeError:
                pass
        
        return []
        
    except Exception as e:
        print(f"Error running Checkov with filters: {e}")
        return []
