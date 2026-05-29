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

def detect_framework(path: str = None, files: list = None) -> str:
    """
    Detect the IaC framework used in the directory or list of files.
    
    Returns:
    - 'terraform' (default)
    - 'kubernetes'
    - 'cloudformation'
    - 'helm'
    - 'all' (fallback for Docker/secrets/actions/etc.)
    """
    tf_files = 0
    k8s_files = 0
    cfn_files = 0
    helm_files = 0
    
    scan_files = []
    if files:
        scan_files = files
    elif path:
        for root, dirs, f_list in os.walk(path):
            for file in f_list:
                scan_files.append(os.path.join(root, file))
    
    for full_path in scan_files:
        file = os.path.basename(full_path)
        if file.endswith('.tf'):
            tf_files += 1
        elif file == 'Chart.yaml' or file == 'Chart.yml':
            helm_files += 1
        elif file.endswith(('.yml', '.yaml')):
            # Check file content for better detection
            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    head = f.read(1024)
                    if 'apiVersion:' in head and 'kind:' in head:
                        k8s_files += 1
                    elif 'AWSTemplateFormatVersion' in head:
                        cfn_files += 1
            except Exception:
                continue
    
    if k8s_files > tf_files and k8s_files > cfn_files and k8s_files > helm_files:
        return 'kubernetes'
    if cfn_files > tf_files and cfn_files > helm_files:
        return 'cloudformation'
    if helm_files > tf_files:
        return 'helm'
    if tf_files > 0:
        return 'terraform'
    
    return 'all'

def count_resources(path=None, framework='terraform', files=None):
    """
    Count total resources in IaC files.
    
    Args:
        path: Directory path to scan
        framework: IaC framework type
        files: Optional list of specific files to scan
        
    Returns:
        Number of resources found
    """
    resource_count = 0
    
    scan_files = []
    if files:
        scan_files = files
    elif path:
        for root, dirs, f_list in os.walk(path):
            for file in f_list:
                scan_files.append(os.path.join(root, file))

    if framework in ('terraform', 'all'):
        for full_path in scan_files:
            if full_path.endswith('.tf'):
                try:
                    with open(full_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        # Count resource blocks: resource "type" "name" {
                        pattern = r'^\s*resource\s+"[^"]+"\s+"[^"]+"'
                        matches = re.findall(pattern, content, re.MULTILINE)
                        resource_count += len(matches)
                except Exception:
                    continue
                    
    if framework in ('kubernetes', 'all'):
        from scanner.image_utils import find_kubernetes_files
        if files:
            k8s_files = [f for f in files if f.endswith(('.yml', '.yaml'))]
            # Further filter for K8s content if needed, but find_kubernetes_files usually does that
        else:
            k8s_files = find_kubernetes_files(path)
            
        for k8s_file in k8s_files:
            try:
                import yaml
                with open(k8s_file, 'r', encoding='utf-8') as f:
                    docs = yaml.safe_load_all(f)
                    for doc in docs:
                        if doc and isinstance(doc, dict) and 'kind' in doc:
                            resource_count += 1
            except Exception:
                continue
                
    if framework in ('containers', 'all'):
        from scanner.image_utils import find_compose_files
        if files:
            from scanner.image_utils import filter_container_files
            compose_files, _ = filter_container_files(files)
        else:
            compose_files = find_compose_files(path)
            
        for compose_file in compose_files:
            try:
                import yaml
                with open(compose_file, 'r', encoding='utf-8') as f:
                    compose_data = yaml.safe_load(f)
                    if compose_data and isinstance(compose_data, dict) and 'services' in compose_data:
                        services = compose_data['services']
                        if isinstance(services, dict):
                            resource_count += len(services)
            except Exception:
                continue
    
    return resource_count

def resolve_included_paths(base_path, included_paths):
    """
    Resolve a list of files and directories into a list of individual files to scan.
    """
    resolved_files = []
    
    # Valid file extensions/names for scanning
    valid_extensions = ('.tf', '.yml', '.yaml', '.json', 'Dockerfile')
    compose_patterns = ('docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml')
    
    for path_item in included_paths:
        full_path = os.path.join(base_path, path_item) if not os.path.isabs(path_item) else path_item
        
        if not os.path.exists(full_path):
            raise FileNotFoundError(f"Path '{path_item}' does not exist.")
            
        if os.path.isfile(full_path):
            # Check if it's a valid file we can scan
            is_valid = full_path.endswith(valid_extensions) or any(p in os.path.basename(full_path) for p in compose_patterns)
            if not is_valid:
                 raise ValueError(f"File '{path_item}' is not a recognized IaC or container file for scanning.")
            resolved_files.append(full_path)
        elif os.path.isdir(full_path):
            for root, dirs, files in os.walk(full_path):
                for file in files:
                    if file.endswith(valid_extensions) or file.startswith('docker-compose') or file.startswith('compose'):
                        resolved_files.append(os.path.join(root, file))
    
    return list(set(resolved_files))

def scan_directory(path, scanner_type='regex', framework='terraform', download_external_modules=False, included_paths=None):
    """
    Scan a directory for IaC issues.
    
    Args:
        path: Directory path to scan
        scanner_type: Scanner selection
            - 'fast' or 'regex': Cost-focused regex scanner only
            - 'containers': Container vulnerability scanning only (Docker Scout or Grype)
            - 'checkov': Checkov IaC security only
            - 'comprehensive': All scanners (regex + Checkov + containers)
        framework: IaC framework type (terraform, kubernetes, cloudformation, auto)
        download_external_modules: Whether to download external modules
        included_paths: Optional list of specific files or directories to scan
    
    Returns:
        Tuple of (findings_list, resource_count, extra_recommendations)
    """
    results = []
    
    # Handle multiple scanners if provided (e.g. "regex,containers")
    if isinstance(scanner_type, str) and ',' in scanner_type:
        scanners = [s.strip() for s in scanner_type.split(',')]
    elif isinstance(scanner_type, list):
        scanners = scanner_type
    else:
        scanners = [scanner_type]

    # Normalize and expand scanners
    normalized_scanners = []
    for s in scanners:
        if s in ['fast', 'regex']:
            normalized_scanners.append('regex')
        elif s in ['both', 'comprehensive']:
            normalized_scanners.extend(['regex', 'checkov', 'containers'])
        else:
            normalized_scanners.append(s)
    
    # Use set to avoid duplicates
    active_scanners = set(normalized_scanners)
    
    # Resolve included paths if provided
    resolved_files = None
    if included_paths:
        resolved_files = resolve_included_paths(path, included_paths)
        if not resolved_files:
            print(f"Warning: No valid files found in included paths: {included_paths}")
            return [], 0, []

    # Auto-detect framework if needed
    if framework == 'auto' or not framework:
        framework = detect_framework(path, files=resolved_files)
        print(f"Detected framework: {framework}")

    # Count resources for reporting
    resource_count = count_resources(path, framework, files=resolved_files)
    # Log discovered files
    if resolved_files:
        print("Files passed to Checkov:")
        for file in resolved_files:
            print(f"  - {os.path.relpath(file, path)}")
    
    # Run cost-focused regex scanner
    if 'regex' in active_scanners:
        # Run regex-based scanner
        all_files = []
        if resolved_files:
            all_files = [f for f in resolved_files if f.endswith(".tf")]
        else:
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.endswith(".tf"):
                        full_path = os.path.join(root, file)
                        all_files.append(full_path)
        
        # Scan all files and collect results
        for file_path in all_files:
            print(f"[INFO] Scanning Terraform file: {os.path.relpath(file_path, path)}")
            file_results = scan_file(file_path)
            if file_results:
                results.extend(file_results)
        
        # Run directory-level checks (for InverseRegexRules)
        from rules.definitions import RULES
        results.extend(scan_directory_level(path, all_files, RULES))
    
    # Run IaC security scanner (Checkov)
    if 'checkov' in active_scanners:
        if is_checkov_available():
            try:
                if resolved_files:
                    print("[INFO] Files passed to Checkov:")
                    for file in resolved_files:
                        print(f"  - {os.path.relpath(file, path)}")
                checkov_results = run_checkov_scan(
                    path, 
                    framework, 
                    download_external_modules=download_external_modules,
                    files=resolved_files
                )
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
    if 'containers' in active_scanners:
        container_scanner = get_container_scanner()
        
        if container_scanner == 'grype':
            if is_grype_available():
                try:
                    from scanner.grype_scanner import run_grype_scan
                    grype_results = run_grype_scan(path, files=resolved_files)
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
                    scout_results, scout_recommendations, auth_failed = run_docker_scout_scan(path, files=resolved_files)
                    
                    if auth_failed and is_grype_available() and not scout_results:
                        print("\n[i] Falling back to Grype scanner (no Docker Hub login detected)...")
                        try:
                            from scanner.grype_scanner import run_grype_scan
                            grype_results = run_grype_scan(path, files=resolved_files)
                            # Add scanner tag
                            for result in grype_results:
                                result['scanner'] = 'grype'
                            results.extend(grype_results)
                            print(f"    Grype scan completed with {len(grype_results)} findings.")
                        except Exception as grype_e:
                            print(f"    Grype fallback failed: {grype_e}")
                    else:
                        # Add scanner tag
                        for result in scout_results:
                            result['scanner'] = 'docker-scout'
                        results.extend(scout_results)
                        extra_recommendations.extend(scout_recommendations)
                except Exception as e:
                    print(f"Warning: Docker Scout scan failed: {e}")
            elif is_grype_available():
                print("\n[i] Docker Scout is not installed, falling back to Grype scanner...")
                try:
                    from scanner.grype_scanner import run_grype_scan
                    grype_results = run_grype_scan(path, files=resolved_files)
                    for result in grype_results:
                        result['scanner'] = 'grype'
                    results.extend(grype_results)
                    print(f"    Grype scan completed with {len(grype_results)} findings.")
                except Exception as grype_e:
                    print(f"    Grype fallback failed: {grype_e}")
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
