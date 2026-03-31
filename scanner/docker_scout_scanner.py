"""
Docker Scout integration for container vulnerability scanning.

This module wraps Docker Scout CLI to scan Docker images and containers.
Supports both SARIF and native JSON output formats with automatic fallback.

Key features:
- Automatic image cleanup to prevent disk bloat (configurable via CLEANUP_SCANNED_IMAGES)
- Package URL (PURL) parsing for accurate package identification
- Multi-source fix version extraction (SARIF fields + description text)
- Deduplication of image scans within a single run
"""

import json
import os
import re
import subprocess
from typing import List, Dict, Any, Tuple, Optional


from scanner.image_utils import find_compose_files, extract_images_from_compose, perform_all_logins

# ============================================================================
# Utility Functions
# ============================================================================

def run_command(cmd: List[str], timeout: int = 10) -> subprocess.CompletedProcess:
    """Run a subprocess command with timeout."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def extract_package_from_purl(description: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract package name and version from Package URL in description.
    
    Args:
        description: Text containing Package URL (e.g., "pkg:golang/github.com/foo@1.2.3")
    
    Returns:
        Tuple of (package_name, package_version) or (None, None) if not found
    """
    purl_match = re.search(r'Package\s*:\s*pkg:[^/]+/([^@\s]+)@([^\s?]+)', description)
    if purl_match:
        full_name = purl_match.group(1)
        package_name = full_name.split('/')[-1] if '/' in full_name else full_name
        package_version = purl_match.group(2)
        return package_name, package_version
    return None, None


def extract_fix_version_from_text(text: str) -> Optional[str]:
    """
    Extract fix version from description text.
    
    Args:
        text: Description text containing fix version (e.g., "Fixed version : 1.2.3")
    
    Returns:
        Fix version string or None if not found
    """
    fix_match = re.search(r'Fixed version\s*:\s*([^\s]+)', text, re.IGNORECASE)
    if fix_match:
        version = fix_match.group(1)
        # Filter out non-version strings (not, none, n/a, na, unavailable, etc.)
        invalid_versions = {'not', 'none', 'n/a', 'na', 'unavailable', 'unknown', 'null'}
        if version.lower() in invalid_versions:
            return None
        return version
    return None


def extract_fix_version_from_sarif(properties: Dict, result: Dict) -> Optional[str]:
    """
    Extract fix version from SARIF properties or result.
    
    Args:
        properties: SARIF result properties
        result: SARIF result object
    
    Returns:
        Fix version string or None if not found
    """
    # Check multiple possible locations in SARIF
    fix_version = (
        properties.get('fixedVersion') or 
        properties.get('fixVersion') or
        (properties.get('fixes', [None])[0] if isinstance(properties.get('fixes'), list) else None)
    )
    
    # Check result-level fixes array
    if not fix_version and 'fixes' in result:
        fixes = result.get('fixes', [])
        if isinstance(fixes, list) and fixes:
            fix_info = fixes[0]
            if isinstance(fix_info, dict):
                fix_version = fix_info.get('version') or fix_info.get('fixedVersion')
            elif isinstance(fix_info, str):
                fix_version = fix_info
    
    return fix_version if fix_version and fix_version not in ['', 'null', 'None'] else None


def normalize_fix_version(fix_version: Any, description: str = '') -> Optional[str]:
    """
    Normalize and validate fix version, with fallback to description parsing.
    
    Args:
        fix_version: Fix version from structured data
        description: Description text for fallback parsing
    
    Returns:
        Normalized fix version or None
    """
    # Clean up structured fix version
    if fix_version and fix_version not in ['', 'null', 'None', 'N/A']:
        return fix_version
    
    # Fall back to parsing from description
    if description:
        return extract_fix_version_from_text(description)
    
    return None


def get_image_recommendation(image: str) -> Optional[str]:
    """
    Get recommendation for switching from Bitnami images to Soldevelo's images.
    
    Args:
        image: Docker image name
    
    Returns:
        Recommendation string or None if not applicable
    """
    image_lower = image.lower()
    
    # Check for bitnamilegacy
    if 'bitnamilegacy' in image_lower:
        return "🐳 Consider switching to Soldevelo's container images as an alternative to Bitnami Legacy (https://github.com/SolDevelo/containers) for better security and support."
    
    # Check for bitnami
    if 'bitnami' in image_lower:
        return "🐳 Consider switching to Soldevelo's container images as an alternative to Bitnami (https://github.com/SolDevelo/containers) for cost reduction and enhanced support."
    
    return None


def create_finding_dict(
    file_path: str,
    rule_id: str,
    package_name: str,
    package_version: str,
    severity: str,
    description: str,
    fix_version: Optional[str],
    image: str,
    cvss_score: Any = 'N/A',
    package_type: str = 'unknown',
    occurrences: int = 1
) -> Dict[str, Any]:
    """
    Create a normalized finding dictionary.
    
    Returns:
        Finding dictionary in internal format
    """
    short_desc = f"{description[:200]}..." if len(description) > 200 else description
    
    # Build base remediation for package update
    base_remediation = (
        f"Update {package_name} from {package_version} to {fix_version}" 
        if fix_version 
        else f"Review {package_name}@{package_version} - no fix available"
    )
    
    # Check if image requires switching recommendation
    image_recommendation = get_image_recommendation(image)
    
    # Combine remediation with image recommendation if applicable
    remediation = base_remediation
    if image_recommendation:
        remediation = f"{base_remediation}. {image_recommendation}"
    
    return {
        'file': file_path,
        'rule_id': rule_id,
        'rule_name': f"Vulnerability in {package_name}",
        'severity': severity,
        'description': short_desc,
        'full_description': description,
        'remediation': remediation,
        'estimated_savings': f"Security risk mitigation ({severity})",
        'line': 0,
        'match_content': f"Image: {image}, Package: {package_name}@{package_version}" + (f" ({package_type})" if package_type != 'unknown' else ''),
        'scanner': 'docker-scout',
        'image': image,
        'package': package_name,
        'package_version': package_version,
        'fix_version': fix_version,
        'cvss_score': cvss_score,
        'occurrences': occurrences
    }


# ============================================================================
# Docker CLI Helpers
# ============================================================================

def is_docker_scout_available() -> bool:
    """Check if Docker Scout is installed and available."""
    try:
        return run_command(["docker-scout", "version"], timeout=5).returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError, OSError):
        return False


def check_image_exists(image: str) -> bool:
    """Check if a Docker image exists locally."""
    try:
        return run_command(["docker", "image", "inspect", image]).returncode == 0
    except Exception:
        return False


def cleanup_image(image: str) -> None:
    """Remove a Docker image from local cache."""
    try:
        print(f"  Removing image: {image}")
        result = run_command(["docker", "rmi", "-f", image], timeout=30)
        if result.returncode == 0:
            print(f"  ✓ Removed {image}")
        else:
            print(f"  Warning: Could not remove {image}: {result.stderr[:100]}")
    except Exception as e:
        print(f"  Warning: Failed to remove {image}: {e}")


# ============================================================================
# Main Scanning Functions
# ============================================================================

def run_docker_scout_scan(directory_path: str) -> Tuple[List[Dict[str, Any]], List[str], bool]:
    """
    Run Docker Scout scan on Docker Compose files and images in a directory.
    
    Args:
        directory_path: Path to directory containing Docker files
    
    Returns:
        Tuple of (findings, extra_recommendations, auth_failed):
        - findings: List of vulnerability findings in normalized format
        - extra_recommendations: List of additional recommendations
        - auth_failed: True if the scan failed due to missing Docker Hub credentials
    """
    if not is_docker_scout_available():
        raise ImportError(
            "Docker Scout is not installed. Install it with: curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh -s --"
        )
    
    findings = []
    extra_recommendations = []
    auth_failed = False
    scanned_images = set()  # Cache to avoid scanning same image multiple times
    images_to_cleanup = set()  # Track images pulled during scan for cleanup
    
    # Check if cleanup is enabled (default: yes)
    cleanup_enabled = os.getenv('CLEANUP_SCANNED_IMAGES', 'true').lower() == 'true'
    
    # Find Docker Compose files
    compose_files = find_compose_files(directory_path)
    
    if not compose_files:
        return findings, extra_recommendations, False
    
    print(f"Found {len(compose_files)} Docker Compose file(s) to scan")
    
    # Collect ALL images from ALL compose files first
    all_images_map = {} # image -> compose_file
    for compose_file in compose_files:
        images = extract_images_from_compose(compose_file)
        for image in images:
            if image not in all_images_map:
                all_images_map[image] = compose_file
    
    # Authenticate with registries (collecting all unique images first)
    if all_images_map:
        perform_all_logins(list(all_images_map.keys()))
    
    # Scan collected images
    for image, compose_file in all_images_map.items():
        # Check if image exists locally before scanning
        image_existed_before = check_image_exists(image)
        
        print(f"Scanning image: {image}")
        
        try:
            image_findings, image_auth_failed = scan_image(image, compose_file, directory_path)
            findings.extend(image_findings)
            
            if image_auth_failed:
                auth_failed = True
            
            if image_findings:
                print(f"  Found {len(image_findings)} vulnerabilities in {image}")
            elif not image_auth_failed:
                print(f"  No vulnerabilities found or image unavailable: {image}")

            recommendation = get_image_recommendation(image)
            if recommendation and recommendation not in extra_recommendations:
                extra_recommendations.append(recommendation)
                print(f"  Added recommendation for Bitnami image: {image}")
            
            # Track for cleanup if image was pulled during scan and cleanup is enabled
            if cleanup_enabled and not image_existed_before and check_image_exists(image):
                images_to_cleanup.add(image)
                
        except Exception as e:
            print(f"Warning: Failed to scan image {image}: {e}")
            continue
    
    # Cleanup images that were pulled during scan
    if cleanup_enabled and images_to_cleanup:
        print(f"\nCleaning up {len(images_to_cleanup)} image(s) pulled during scan...")
        for image in images_to_cleanup:
            try:
                cleanup_image(image)
            except Exception as e:
                print(f"Warning: Failed to cleanup image {image}: {e}")
    
    return findings, extra_recommendations, auth_failed


def scan_image(image: str, compose_file: str, base_path: str) -> Tuple[List[Dict[str, Any]], bool]:
    """
    Scan a Docker image with Docker Scout.
    
    Note: Docker Scout may be slower than Grype because:
    - It pulls images from registries if not locally cached
    - It performs more thorough vulnerability analysis
    - It connects to Docker Hub for latest CVE data
    
    Args:
        image: Docker image name
        compose_file: Path to the compose file containing this image
        base_path: Base directory path
    
    Returns:
        Tuple of (findings, auth_failed)
    """
    findings = []
    
    try:
        # Build command
        cmd = [
            "docker-scout", "cves",
            image,
            "--format", "sarif",
            "--only-severity", "critical,high,medium,low",
            "--exit-code"  # Returns non-zero if vulnerabilities found
        ]
        
        # If image exists locally, try to use --only-local to avoid unnecessary network/auth issues
        if check_image_exists(image):
            cmd.append("--only-local")
            
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        # 1. Detect Docker Hub login requirement specifically
        if result.returncode != 0 and ("Log in with your Docker ID" in result.stderr or "authentication required" in result.stderr.lower()):
            print(f"\n[!] Docker Scout Error: Authentication required to access vulnerability database.")
            print(f"    To fix this, either:")
            print(f"    a) Set DOCKER_HUB_USERNAME and DOCKER_HUB_PASSWORD environment variables")
            print(f"    b) Use CONTAINER_SCANNER=grype to use the alternative scanner that doesn't require login")
            print(f"    Skipping Docker Scout scan for: {image}")
            return findings, True

        # 2. Check for other errors in output (missing image, pull failures, etc.)
        if result.stdout.strip().startswith('ERROR') or 'MANIFEST_UNKNOWN' in result.stdout:
            error_msg = result.stdout.split('\n')[0] if '\n' in result.stdout else result.stdout[:200]
            print(f"Docker Scout error for image {image}: {error_msg}")
            return findings, False
        
        # 3. Handle non-zero exit code (with --exit-code, it means findings or real error)
        if result.returncode != 0 and not result.stdout.strip():
            # If stdout is empty and return code is non-zero, it's likely a real failure
            print(f"Docker Scout failed for image {image} (exit code {result.returncode})")
            if result.stderr:
                # Truncate stderr for cleaner output but keep the important part
                clean_stderr = result.stderr.strip().split('\n')[0]
                print(f"  Error: {clean_stderr}")
            return findings, False
        
        # 4. Parse successful output
        if result.stdout.strip():
            try:
                scout_data = json.loads(result.stdout)
                findings = parse_docker_scout_output(scout_data, image, compose_file, base_path)
            except json.JSONDecodeError as e:
                # Fallback check for text output
                if "Analyzing image" in result.stdout or "Target" in result.stdout:
                    print(f"  Docker Scout returned text instead of JSON for {image}. Trying fallback parser...")
                    findings = parse_text_output(result.stdout, image, compose_file, base_path)
                else:
                    print(f"  Failed to parse Docker Scout output for {image}: {e}")
        
        if result.stderr and ("error" in result.stderr.lower() and "Available version" not in result.stderr):
            # Log real errors from stderr that aren't just update notifications
            print(f"  Docker Scout stderr: {result.stderr.strip()}")
    
    except subprocess.TimeoutExpired:
        print(f"Timeout scanning image: {image}")
    except Exception as e:
        print(f"Error scanning image {image}: {e}")
    
    return findings, False


def parse_sarif_format(sarif_data: Dict[str, Any], image: str, compose_file: str, base_path: str) -> List[Dict[str, Any]]:
    """Parse Docker Scout SARIF format output."""
    findings = []
    
    try:
        for run in sarif_data.get('runs', []):
            for result in run.get('results', []):
                # Extract basic info
                rule_id = result.get('ruleId', 'UNKNOWN')
                level = result.get('level', 'warning')
                message = result.get('message', {}).get('text', 'No description available')
                properties = result.get('properties', {})
                
                # Map SARIF level to severity
                severity = {'error': 'High', 'warning': 'Medium', 'note': 'Low', 'none': 'Info'}.get(level, 'Medium')
                
                # Extract package info from locations (SARIF URI)
                package_name, package_version = 'unknown', 'unknown'
                for location in result.get('locations', []):
                    uri = location.get('physicalLocation', {}).get('artifactLocation', {}).get('uri', '')
                    if uri and '@' in uri:
                        parts = uri.split('/')[-1].split('@')
                        package_name, package_version = parts[0], parts[1] if len(parts) > 1 else package_version
                        break
                
                # Override with properties if available
                package_name = properties.get('packageName', package_name)
                package_version = properties.get('installedVersion') or properties.get('currentVersion') or package_version
                
                # Fallback: parse from description
                if package_name == 'unknown' or package_version == 'unknown':
                    purl_name, purl_version = extract_package_from_purl(message)
                    package_name = purl_name or package_name
                    package_version = purl_version or package_version
                
                # Extract fix version from SARIF and description
                fix_version = normalize_fix_version(
                    extract_fix_version_from_sarif(properties, result),
                    message
                )
                
                # Extract CVSS score
                cvss = properties.get('cvss', {})
                cvss_score = cvss.get('baseScore') or properties.get('cvssScore', 'N/A') if isinstance(cvss, dict) else 'N/A'
                
                # Build finding
                file_path = os.path.relpath(compose_file, base_path) if compose_file and base_path else compose_file
                findings.append(create_finding_dict(
                    file_path, rule_id, package_name, package_version,
                    severity, message, fix_version, image, cvss_score
                ))
    
    except Exception as e:
        print(f"Error parsing SARIF format: {e}")
        import traceback
        traceback.print_exc()
    
    return findings


# ============================================================================
# Output Format Parsers
# ============================================================================

def parse_docker_scout_output(scout_data: Dict[str, Any], image: str, compose_file: str, base_path: str) -> List[Dict[str, Any]]:
    """
    Parse Docker Scout JSON output into normalized format.
    Supports both SARIF and native JSON formats.
    
    Args:
        scout_data: Parsed JSON data from Docker Scout
        image: Docker image name
        compose_file: Path to compose file
        base_path: Base directory path
    
    Returns:
        List of normalized findings
    """
    findings = []
    
    try:
        # Check if this is SARIF format
        if 'runs' in scout_data and '$schema' in scout_data:
            return parse_sarif_format(scout_data, image, compose_file, base_path)
        
        # Docker Scout native structure: vulnerabilities array with packages
        vulnerabilities = scout_data.get('vulnerabilities', [])
        
        # Group by CVE ID to avoid duplicates
        vuln_map = {}
        
        for vuln in vulnerabilities:
            cve_id = vuln.get('id', vuln.get('cve', 'UNKNOWN'))
            severity = vuln.get('severity', 'Unknown')
            
            # Skip Negligible severity vulnerabilities
            if severity.lower() == 'negligible':
                continue
            
            # Docker Scout packages affected by this CVE
            packages = vuln.get('packages', [])
            
            for package in packages:
                package_name = package.get('name', 'unknown')
                package_key = f"{cve_id}:{package_name}"
                
                # Store highest severity for each vuln+package combo
                if package_key not in vuln_map:
                    vuln_map[package_key] = {
                        'vulnerability': vuln,
                        'package': package,
                        'severity': severity,
                        'count': 1
                    }
                else:
                    vuln_map[package_key]['count'] += 1
                    # Keep highest severity
                    current_sev = severity_to_number(severity)
                    stored_sev = severity_to_number(vuln_map[package_key]['severity'])
                    if current_sev > stored_sev:
                        vuln_map[package_key]['severity'] = severity
        
        # Convert to findings
        for package_key, data in vuln_map.items():
            finding = normalize_docker_scout_finding(
                data['vulnerability'],
                data['package'],
                image,
                compose_file,
                base_path,
                data['count']
            )
            findings.append(finding)
    
    except Exception as e:
        print(f"Error parsing Docker Scout output: {e}")
        import traceback
        traceback.print_exc()
    
    return findings

# ============================================================================
# Helper Functions
# ============================================================================

def severity_to_number(severity: str) -> int:
    """Convert severity to number for comparison."""
    severity_map = {
        'CRITICAL': 4,
        'HIGH': 3,
        'MEDIUM': 2,
        'LOW': 1,
        'UNSPECIFIED': 0,
        'UNKNOWN': 0
    }
    # Handle case-insensitive
    return severity_map.get(severity.upper(), 0)


def normalize_docker_scout_finding(vuln: Dict[str, Any], package: Dict[str, Any], image: str, compose_file: str, base_path: str, count: int = 1) -> Dict[str, Any]:
    """Normalize a Docker Scout vulnerability finding to internal format."""
    # Extract basic info
    cve_id = vuln.get('id') or vuln.get('cve', 'UNKNOWN')
    severity_raw = vuln.get('severity', 'Unknown')
    description = vuln.get('description') or vuln.get('title', 'No description available')
    
    # Get package info
    package_name = package.get('name', 'unknown')
    package_version = package.get('version', 'unknown')
    package_type = package.get('type', 'unknown')
    
    # Parse from description if package info missing
    if package_name == 'unknown' or package_version == 'unknown':
        purl_name, purl_version = extract_package_from_purl(description)
        package_name = purl_name or package_name
        package_version = purl_version or package_version
    
    # Get fix version from multiple sources
    fix_version = normalize_fix_version(
        package.get('fixedBy') or package.get('fixedIn') or package.get('fixVersion'),
        description
    )
    
    # Map severity (Docker Scout uses uppercase)
    severity_map = {'CRITICAL': 'Critical', 'HIGH': 'High', 'MEDIUM': 'Medium', 'LOW': 'Low', 'NEGLIGIBLE': 'Info', 'UNSPECIFIED': 'Info', 'UNKNOWN': 'Info'}
    normalized_severity = severity_map.get(severity_raw.upper(), 'Info')
    
    # Extract CVSS score
    cvss_score = vuln.get('cvss', {})
    cvss_base = cvss_score.get('baseScore') or cvss_score.get('score', 'N/A') if isinstance(cvss_score, dict) else 'N/A'
    
    # Build finding
    file_path = os.path.relpath(compose_file, base_path) if compose_file and base_path else compose_file
    return create_finding_dict(
        file_path, cve_id, package_name, package_version,
        normalized_severity, description, fix_version, image,
        cvss_base, package_type, count
    )


def parse_text_output(text_output: str, image: str, compose_file: str, base_path: str) -> List[Dict[str, Any]]:
    """
    Fallback parser for human-readable Docker Scout output.
    This is a best-effort parser - structured output is preferred.
    
    Args:
        text_output: Human-readable text output from Docker Scout
        image: Docker image name
        compose_file: Path to compose file
        base_path: Base directory path
        
    Returns:
        List of normalized findings (may be empty if parsing fails)
    """
    findings = []
    
    # This is a minimal fallback - just create a summary finding
    print("Warning: Using fallback text parser. Install latest Docker Scout for JSON output.")
    
    # Make file path relative
    file_path = os.path.relpath(compose_file, base_path) if compose_file and base_path else compose_file
    
    # Create a summary finding indicating structured output is needed
    finding = {
        'file': file_path,
        'rule_id': 'DOCKER-SCOUT-TEXT',
        'rule_name': f"Container vulnerabilities detected in {image}",
        'severity': 'Medium',
        'description': 'Docker Scout detected vulnerabilities but returned text format. Update Docker Scout for detailed findings.',
        'full_description': text_output[:500],
        'remediation': 'Install latest Docker Scout CLI with JSON output support',
        'estimated_savings': 'Security risk mitigation',
        'line': 0,
        'match_content': f"Image: {image}",
        'scanner': 'docker-scout',
        'image': image,
        'package': 'multiple',
        'package_version': 'various',
        'fix_version': 'N/A',
        'cvss_score': 'N/A',
        'occurrences': 1
    }
    
    findings.append(finding)
    
    return findings
