"""
Grype integration for container vulnerability scanning.
This module wraps Grype to scan Docker images and containers.

Note: Docker Scout is the default scanner. To use Grype, set CONTAINER_SCANNER=grype in .env file.
"""

import json
import os
import subprocess
from typing import List, Dict, Any, Optional

from scanner.base import Scanner, ScanResult
from scanner.image_utils import (
    find_compose_files,
    extract_images_from_compose,
    find_kubernetes_files,
    extract_images_from_kubernetes,
    perform_all_logins,
    filter_container_files
)


class GrypeScanner(Scanner):
    """Grype container vulnerability scanner."""

    name = "grype"

    # Extended-regex patterns (used by the CI skip-if-no-match check via grep -E).
    TRIGGER_PATTERNS = [
        r"(^|/)Dockerfile(\.[^/]+)?$",
        r"(^|/)docker-compose[^/]*\.ya?ml$",
        r"(^|/)compose\.ya?ml$",
    ]
    CI_SEVERITY_LIMITS = {
        "critical": None,
        "high":     10,
        "medium":   0,   # container MEDIUM CVEs are base-image noise
        "low":      0,
        "info":     0,
    }

    def is_available(self) -> bool:
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

    def scan(self, directory_path: str, files: Optional[List[str]] = None, **options) -> ScanResult:
        """
        Run Grype scan on Docker Compose files and images in a directory or specific files.

        Args:
            directory_path: Path to directory containing Docker files
            files: Optional list of specific files to scan

        Returns:
            ScanResult with normalized findings
        """
        if not self.is_available():
            raise ImportError(
                "Grype is not installed. Install it with: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
            )

        findings = []

        if files:
            compose_files, k8s_files = filter_container_files(files)
        else:
            # Find Docker Compose files
            compose_files = find_compose_files(directory_path)
            # Find Kubernetes files
            k8s_files = find_kubernetes_files(directory_path)

        if not compose_files and not k8s_files:
            return ScanResult()

        # Collect ALL images from ALL files first. Track every (file, line)
        # that references each image (not just the first) -- the same image
        # is often reused across multiple compose/k8s files, and each of
        # those files legitimately has the vulnerability too.
        all_images_map = {}  # image -> list of (source_file, line) referencing it
        for compose_file in compose_files:
            for image, line in extract_images_from_compose(compose_file):
                entry = (compose_file, line)
                if entry not in all_images_map.setdefault(image, []):
                    all_images_map[image].append(entry)

        for k8s_file in k8s_files:
            for image, line in extract_images_from_kubernetes(k8s_file):
                entry = (k8s_file, line)
                if entry not in all_images_map.setdefault(image, []):
                    all_images_map[image].append(entry)

        # Perform logins for ECR/Docker Hub if needed
        if all_images_map:
            perform_all_logins(list(all_images_map.keys()))
            ensure_db_ready()

        # Scan each unique image once regardless of how many files
        # reference it (re-scanning per file would be redundant, expensive
        # work against the same image). Each finding stays a single entry
        # -- grading, the severity breakdown and the PR comment all count
        # this list directly, so duplicating entries per file would double
        # (or N-x) count the same vulnerability. Extra referencing
        # (file, line) pairs are recorded on `also_in_files` instead,
        # purely for CI adapters that want to attach a per-file marker
        # (e.g. Bitbucket annotations) without inflating the finding count.
        for image, source_refs in all_images_map.items():
            print(f"Scanning image with Grype: {image}")
            try:
                primary_file, primary_line = source_refs[0]
                image_findings = scan_image(image, primary_file, directory_path, primary_line)
                if len(source_refs) > 1:
                    also_in = [
                        {'file': os.path.relpath(f, directory_path), 'line': ln}
                        for f, ln in source_refs[1:]
                    ]
                    for finding in image_findings:
                        finding['also_in_files'] = also_in
                findings.extend(image_findings)
            except Exception as e:
                print(f"Warning: Failed to scan image {image}: {e}")
                continue

        return ScanResult(findings=findings)


def ensure_db_ready(timeout: int = 300) -> None:
    """Make sure grype's vulnerability DB is present before scanning any
    images, with its own generous timeout.

    Without this, a fresh environment with no cached DB (no baked-in DB in
    the Docker image, no prior `grype db update`) pays the first-download
    cost (~140s+ observed) inside scan_image()'s per-image timeout below
    (120s), which is tuned for actual scan time, not a first-time DB
    download. That timeout expires before the download finishes, the
    exception is swallowed by scan()'s per-image try/except, and every
    image scan silently returns zero findings — the "containers" section
    of a report can come back looking clean when it was never actually
    scanned at all. `grype db check` is a fast no-network no-op once a
    valid DB is already present, so this is a no-op after the first run.
    """
    try:
        check = subprocess.run(["grype", "db", "check"], capture_output=True, text=True, timeout=10)
        if check.returncode == 0:
            return
    except Exception:
        pass
    print("Grype vulnerability DB not found or stale, downloading (first run only)...")
    try:
        result = subprocess.run(["grype", "db", "update"], capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            print(f"Warning: grype db update failed: {result.stderr[-300:]}")
    except subprocess.TimeoutExpired:
        print(f"Warning: grype db update did not finish within {timeout}s")


def scan_image(image: str, compose_file: str, base_path: str, line: int = 0) -> List[Dict[str, Any]]:
    """
    Scan a Docker image with Grype.

    Args:
        image: Docker image name
        compose_file: Path to the compose file containing this image
        base_path: Base directory path
        line: Source line of the image's declaring key in compose_file (0 if unknown)

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
            # 4 minutes: this covers grype's own image pull (not just DB
            # lookup/matching) for images not already present locally --
            # 120s was tight enough that large private-registry images
            # (multi-GB Java app images, observed directly in a real CI
            # pipeline) could time out on pull alone even with a warm DB.
            timeout=240
        )
        
        if result.stdout.strip():
            try:
                grype_data = json.loads(result.stdout)
                findings = parse_grype_output(grype_data, image, compose_file, base_path, line)
            except json.JSONDecodeError as e:
                print(f"Failed to parse Grype JSON output: {e}")
        
        if result.stderr and "error" in result.stderr.lower():
            print(f"Grype stderr: {result.stderr}")
    
    except subprocess.TimeoutExpired:
        print(f"Timeout scanning image: {image}")
    except Exception as e:
        print(f"Error scanning image {image}: {e}")
    
    return findings


def parse_grype_output(grype_data: Dict[str, Any], image: str, compose_file: str, base_path: str, line: int = 0) -> List[Dict[str, Any]]:
    """
    Parse Grype JSON output into normalized format.

    Args:
        grype_data: Parsed JSON data from Grype
        image: Docker image name
        compose_file: Path to compose file
        base_path: Base directory path
        line: Source line of the image's declaring key in compose_file (0 if unknown)

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
                data['count'],
                line
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


def normalize_grype_finding(vuln: Dict[str, Any], artifact: Dict[str, Any], image: str, compose_file: str, base_path: str, count: int = 1, line: int = 0) -> Dict[str, Any]:
    """
    Normalize a Grype vulnerability finding to match our internal format.

    Args:
        vuln: Vulnerability data
        artifact: Artifact data
        image: Docker image name
        compose_file: Path to compose file
        base_path: Base directory path
        count: Number of occurrences
        line: Source line of the image's declaring key in compose_file (0 if unknown)

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
        'description': description,
        'full_description': description,
        'remediation': f"Update {package_name} from {package_version} to {fix_version}" if fix_available == 'Yes' else f"Review {package_name}@{package_version} - no fix available",
        'estimated_savings': f"Security risk mitigation ({severity})",
        'line': line,
        'match_content': f"Image: {image}, Package: {package_name}@{package_version} ({package_type})",
        'scanner': 'grype',
        'image': image,
        'package': package_name,
        'package_version': package_version,
        'fix_version': fix_version,
        'occurrences': count
    }
    
    return finding
