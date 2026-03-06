import os
import re
from rules.definitions import check_rules
from scanner.checkov_scanner import is_checkov_available, run_checkov_scan
from scanner.docker_scout_scanner import is_docker_scout_available, run_docker_scout_scan
from scanner.grype_scanner import is_grype_available, run_grype_scan

# Get container scanner preference from environment
def get_container_scanner():
    """Get the configured container scanner (docker-scout or grype)."""
    return os.getenv('CONTAINER_SCANNER', 'docker-scout').lower()

def is_container_scanner_available():
    """Check if the configured container scanner is available."""
    scanner = get_container_scanner()
    if scanner == 'grype':
        return is_grype_available()
    else:  # docker-scout (default)
        return is_docker_scout_available()

def count_resources(path, framework='terraform'):
    """
    Count total resources in IaC files.
    
    Args:
        path: Directory path to scan
        framework: IaC framework type
        
    Returns:
        Number of resources found
    """
    resource_count = 0
    
    if framework == 'terraform':
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.endswith('.tf'):
                    try:
                        full_path = os.path.join(root, file)
                        with open(full_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            # Count resource blocks: resource "type" "name" {
                            pattern = r'^\s*resource\s+"[^"]+"\s+"[^"]+"'
                            matches = re.findall(pattern, content, re.MULTILINE)
                            resource_count += len(matches)
                    except Exception:
                        continue
    
    return resource_count

def scan_directory(path, scanner_type='regex', framework='terraform'):
    """
    Scan a directory for IaC issues.
    
    Args:
        path: Directory path to scan
        scanner_type: Scanner selection
            - 'fast' or 'regex': Cost-focused regex scanner only
            - 'containers': Container vulnerability scanning only (Docker Scout or Grype)
            - 'checkov': Checkov IaC security only
            - 'comprehensive': All scanners (regex + Checkov + containers)
        framework: IaC framework type (terraform, cloudformation, etc.)
    
    Returns:
        Tuple of (findings_list, resource_count)
    """
    results = []
    
    # Normalize scanner type names (maintain backward compatibility)
    if scanner_type == 'fast':
        scanner_type = 'regex'
    elif scanner_type == 'both':  # Backwards compatibility for old shared reports
        scanner_type = 'comprehensive'
    # 'comprehensive' is the new standard name
    
    # Count resources for reporting
    resource_count = count_resources(path, framework)
    
    # Run cost-focused regex scanner
    if scanner_type in ['regex', 'comprehensive']:
        # Run regex-based scanner
        all_files = []
        for root, dirs, files in os.walk(path):
            for file in files:
                if file.endswith(".tf"):
                    full_path = os.path.join(root, file)
                    all_files.append(full_path)
        
        # Scan all files and collect results
        for file_path in all_files:
            file_results = scan_file(file_path)
            if file_results:
                results.extend(file_results)
        
        # Run directory-level checks (for InverseRegexRules)
        from rules.definitions import RULES
        results.extend(scan_directory_level(path, all_files, RULES))
    
    # Run IaC security scanner (Checkov)
    if scanner_type in ['checkov', 'comprehensive']:
        if is_checkov_available():
            try:
                checkov_results = run_checkov_scan(path, framework)
                # Add scanner tag to distinguish sources
                for result in checkov_results:
                    result['scanner'] = 'checkov'
                results.extend(checkov_results)
            except Exception as e:
                print(f"Warning: Checkov scan failed: {e}")
        else:
            print("Warning: Checkov is not installed. Install with: pip install checkov")
    
    # Run container security scanner (Docker Scout or Grype based on config)
    extra_recommendations = []  # Track extra recommendations from container scanner
    if scanner_type in ['containers', 'comprehensive']:
        container_scanner = get_container_scanner()
        
        if container_scanner == 'grype':
            if is_grype_available():
                try:
                    from scanner.grype_scanner import run_grype_scan
                    grype_results = run_grype_scan(path)
                    # Add scanner tag
                    for result in grype_results:
                        result['scanner'] = 'grype'
                    results.extend(grype_results)
                except Exception as e:
                    print(f"Warning: Grype scan failed: {e}")
            else:
                print("Warning: Grype is not installed. See https://github.com/anchore/grype for installation")
        else:  # docker-scout (default)
            if is_docker_scout_available():
                try:
                    scout_results, scout_recommendations = run_docker_scout_scan(path)
                    # Add scanner tag
                    for result in scout_results:
                        result['scanner'] = 'docker-scout'
                    results.extend(scout_results)
                    extra_recommendations.extend(scout_recommendations)
                except Exception as e:
                    print(f"Warning: Docker Scout scan failed: {e}")
            else:
                print("Warning: Docker Scout is not installed. See https://docs.docker.com/scout/ for installation")
    
    # Add scanner tag to regex results and normalize paths
    for result in results:
        if 'scanner' not in result:
            result['scanner'] = 'regex'
        
        # Normalize paths to be relative to the scan root
        if 'file' in result and os.path.isabs(result['file']):
            try:
                result['file'] = os.path.relpath(result['file'], path)
            except ValueError:
                # Fallback if path is on a different drive or something
                pass
    
    return results, resource_count, extra_recommendations

def scan_file(filepath):
    """
    Scan a single file using regex-based rules.
    
    Args:
        filepath: Path to the file to scan
    
    Returns:
        List of findings
    """
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # We pass the raw content to the rules engine
        # In a more advanced version, we would parse HCL here
        findings = check_rules(filepath, content)
    except Exception as e:
        print(f"Warning: Could not read file {filepath}: {e}")
    
    return findings

def scan_directory_level(directory, file_paths, rules):
    """
    Run directory-level scans for rules that check across all files.
    This is used for InverseRegexRules that check if something is missing.
    
    Args:
        directory: Directory being scanned
        file_paths: List of all file paths in the directory
        rules: List of all rules to check
    
    Returns:
        List of findings
    """
    from rules.definitions import InverseRegexRule
    findings = []
    
    # Read all files into a dictionary to keep track of content per file
    file_contents = {}
    all_content = ""
    
    for filepath in file_paths:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                file_contents[filepath] = content
                all_content += content + "\n"
        except Exception as e:
            continue
    
    # Only run InverseRegexRules at directory level
    for rule in rules:
        if isinstance(rule, InverseRegexRule):
            # Logic:
            # 1. Check if the required pattern exists GLOBALLY (in all_content)
            # 2. If it exists, then the rule is satisfied.
            # 3. If it does NOT exist, we need to find which files contain the "resource" 
            #    that requires this pattern (e.g., "aws_instance" requires "spot_price")
            
            pattern_found_globally = False
            if rule.pattern:
                pattern_found_globally = re.search(rule.pattern, all_content, re.MULTILINE | re.DOTALL)
            
            if not pattern_found_globally:
                # The required pattern is missing globally.
                # Now find which files contain the resource pattern (trigger).
                if rule.resource_pattern:
                    for filepath, content in file_contents.items():
                        resource_found = re.search(rule.resource_pattern, content, re.MULTILINE | re.DOTALL)
                        if resource_found:
                            # This file has the resource but the required pattern is missing globally.
                            # Find the line number of the resource in this file
                            for i, line in enumerate(content.splitlines()):
                                if re.search(rule.resource_pattern, line):
                                    findings.append({
                                        "file": filepath,
                                        "rule_id": rule.id,
                                        "rule_name": rule.name,
                                        "severity": rule.severity,
                                        "description": rule.description,
                                        "remediation": rule.remediation,
                                        "estimated_savings": rule.estimated_savings,
                                        "line": i + 1,
                                        "match_content": line.strip()
                                    })
                                    break
    
    return findings
