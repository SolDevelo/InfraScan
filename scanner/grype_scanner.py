"""
Grype integration for container vulnerability scanning.
This module wraps Grype to scan Docker images and containers.

Note: Docker Scout is the default scanner. To use Grype, set CONTAINER_SCANNER=grype in .env file.
"""

import json
import os
import subprocess
from typing import List, Dict, Any

from scanner.image_utils import find_compose_files, extract_images_from_compose, perform_all_logins

# Check if Grype is available
def is_grype_available() -> bool:
    """Check if Grype is installed and available."""
    try:
        result = subprocess.run(
            ["grype", "version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError, OSError):
        return False


def run_grype_scan(directory_path: str) -> List[Dict[str, Any]]:
    """
    Run Grype scan on Docker Compose files and images in a directory.
    
    Args:
        directory_path: Path to directory containing Docker files
    
    Returns:
        List of findings in a normalized format
    """
    if not is_grype_available():
        raise ImportError(
            "Grype is not installed. Install it with: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
        )
    
    findings = []
    
    # Find Docker Compose files
    compose_files = find_compose_files(directory_path)
    
    if not compose_files:
        return findings
    
    # Collect ALL images from ALL compose files first
    all_images_map = {} # image -> compose_file
    for compose_file in compose_files:
        images = extract_images_from_compose(compose_file)
        for image in images:
            if image not in all_images_map:
                all_images_map[image] = compose_file
                
    # Perform logins for ECR/Docker Hub if needed
    if all_images_map:
        perform_all_logins(list(all_images_map.keys()))
        
    # Extract images from compose files and scan them
    for image, compose_file in all_images_map.items():
        print(f"Scanning image with Grype: {image}")
        try:
            image_findings = scan_image(image, compose_file, directory_path)
            findings.extend(image_findings)
        except Exception as e:
            print(f"Warning: Failed to scan image {image}: {e}")
            continue
    
    return findings


def scan_image(image: str, compose_file: str, base_path: str) -> List[Dict[str, Any]]:
    """
    Scan a Docker image with Grype.
    
    Args:
        image: Docker image name
        compose_file: Path to the compose file containing this image
        base_path: Base directory path
    
    Returns:
        List of normalized findings
    """
    findings = []
    
    try:
        cmd = [
            "grype",
            image,
            "-o", "json",
            "--quiet"
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120  # 2 minute timeout for image scanning
        )
        
        if result.stdout.strip():
            try:
                grype_data = json.loads(result.stdout)
                findings = parse_grype_output(grype_data, image, compose_file, base_path)
            except json.JSONDecodeError as e:
                print(f"Failed to parse Grype JSON output: {e}")
        
        if result.stderr and "error" in result.stderr.lower():
            print(f"Grype stderr: {result.stderr}")
    
    except subprocess.TimeoutExpired:
        print(f"Timeout scanning image: {image}")
    except Exception as e:
        print(f"Error scanning image {image}: {e}")
    
    return findings


def parse_grype_output(grype_data: Dict[str, Any], image: str, compose_file: str, base_path: str) -> List[Dict[str, Any]]:
    """
    Parse Grype JSON output into normalized format.
    
    Args:
        grype_data: Parsed JSON data from Grype
        image: Docker image name
        compose_file: Path to compose file
        base_path: Base directory path
    
    Returns:
        List of normalized findings
    """
    findings = []
    
    try:
        matches = grype_data.get('matches', [])
        
        # Group by vulnerability ID to avoid duplicates
        vuln_map = {}
        
        for match in matches:
            vuln = match.get('vulnerability', {})
            artifact = match.get('artifact', {})
            
            vuln_id = vuln.get('id', 'UNKNOWN')
            severity = vuln.get('severity', 'Unknown')
            description = vuln.get('description', '')
            
            # Skip Negligible severity vulnerabilities
            if severity == 'Negligible':
                continue
            
            # Store highest severity for each vuln
            if vuln_id not in vuln_map:
                vuln_map[vuln_id] = {
                    'vulnerability': vuln,
                    'artifact': artifact,
                    'severity': severity,
                    'count': 1
                }
            else:
                vuln_map[vuln_id]['count'] += 1
                # Keep highest severity
                current_sev = severity_to_number(severity)
                stored_sev = severity_to_number(vuln_map[vuln_id]['severity'])
                if current_sev > stored_sev:
                    vuln_map[vuln_id]['severity'] = severity
        
        # Convert to findings
        for vuln_id, data in vuln_map.items():
            finding = normalize_grype_finding(
                data['vulnerability'],
                data['artifact'],
                image,
                compose_file,
                base_path,
                data['count']
            )
            findings.append(finding)
    
    except Exception as e:
        print(f"Error parsing Grype output: {e}")
        import traceback
        traceback.print_exc()
    
    return findings


def severity_to_number(severity: str) -> int:
    """Convert severity to number for comparison."""
    severity_map = {
        'Critical': 4,
        'High': 3,
        'Medium': 2,
        'Low': 1,
        'Negligible': 0,
        'Unknown': 0
    }
    return severity_map.get(severity, 0)


def normalize_grype_finding(vuln: Dict[str, Any], artifact: Dict[str, Any], image: str, compose_file: str, base_path: str, count: int = 1) -> Dict[str, Any]:
    """
    Normalize a Grype vulnerability finding to match our internal format.
    
    Args:
        vuln: Vulnerability data
        artifact: Artifact data
        image: Docker image name
        compose_file: Path to compose file
        base_path: Base directory path
        count: Number of occurrences
    
    Returns:
        Normalized finding dictionary
    """
    vuln_id = vuln.get('id', 'UNKNOWN')
    severity = vuln.get('severity', 'Unknown')
    description = vuln.get('description', 'No description available')
    
    # Get package info
    package_name = artifact.get('name', 'unknown')
    package_version = artifact.get('version', 'unknown')
    package_type = artifact.get('type', 'unknown')
    
    # Get fix version if available
    fix_versions = vuln.get('fix', {}).get('versions', [])
    fix_available = 'Yes' if fix_versions else 'No'
    fix_version = fix_versions[0] if fix_versions else 'N/A'
    
    # URLs
    urls = vuln.get('urls', [])
    references = ', '.join(urls[:2]) if urls else 'See CVE database'
    
    # Make file path relative
    file_path = os.path.relpath(compose_file, base_path) if compose_file and base_path else compose_file
    
    # Map severity
    severity_map = {
        'Critical': 'Critical',
        'High': 'High',
        'Medium': 'Medium',
        'Low': 'Low',
        'Negligible': 'Info',
        'Unknown': 'Info'
    }
    normalized_severity = severity_map.get(severity, 'Info')
    
    # Build finding
    finding = {
        'file': file_path,
        'rule_id': vuln_id,
        'rule_name': f"Vulnerability in {package_name}",
        'severity': normalized_severity,
        'description': f"{description[:200]}..." if len(description) > 200 else description,
        'full_description': description,  # Store full description for tooltips
        'remediation': f"Update {package_name} from {package_version} to {fix_version}" if fix_available == 'Yes' else f"Review {package_name}@{package_version} - no fix available",
        'estimated_savings': f"Security risk mitigation ({severity})",
        'line': 0,
        'match_content': f"Image: {image}, Package: {package_name}@{package_version} ({package_type})",
        'scanner': 'grype',
        'image': image,
        'package': package_name,
        'package_version': package_version,
        'fix_version': fix_version,
        'occurrences': count
    }
    
    return finding
