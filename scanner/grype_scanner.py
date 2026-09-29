"""
Grype integration for container vulnerability scanning.
This module wraps Grype to scan Docker images and containers.

Note: Docker Scout is the default scanner when Docker Hub credentials are
available; otherwise Grype is used (see scanner/parser.py). Set
CONTAINER_SCANNER=grype to always use Grype.
"""

import json
import os
import re
import subprocess
from typing import List, Dict, Any, Optional, Tuple

from scanner.base import Scanner, ScanResult
from scanner.image_utils import (
    find_compose_files,
    extract_images_from_compose,
    find_kubernetes_files,
    extract_images_from_kubernetes,
    perform_all_logins,
    filter_container_files,
    drop_ignored_images,
    image_registry,
    unresolved_image_reason,
)

IMAGE_SCAN_TIMEOUT = 240

# Substrings of a failed scan's error that mean the *registry* is the
# problem, not the one image -- the next image from it would fail the same
# way, so there's no point waiting out another timeout per image.
_UNREACHABLE_MARKERS = (
    'no such host', 'i/o timeout', 'connection refused', 'network is unreachable',
    'deadline exceeded', 'tls handshake', 'timed out',
)
_UNAUTHORIZED_MARKERS = ('unauthorized', 'authentication required', 'denied', '401', '403')


def _registry_blocked(reason: str, registry: str, reachable: set) -> bool:
    # A registry that already served an image in this run is reachable --
    # one slow or broken image (e.g. a large one hitting the per-image
    # timeout) says nothing about the next.
    if registry in reachable:
        return False
    r = reason.lower()
    # Our own per-image timeout on Docker Hub is a slow pull, not an
    # unreachable registry.
    if registry == 'docker.io' and r.startswith('timed out after'):
        return False
    if any(m in r for m in _UNREACHABLE_MARKERS):
        return True
    # Docker Hub answers 401 for repositories that simply don't exist, so an
    # auth error there says nothing about the next (possibly public) image.
    return registry != 'docker.io' and any(m in r for m in _UNAUTHORIZED_MARKERS)


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
            for image, line in extract_images_from_compose(compose_file, directory_path):
                entry = (compose_file, line)
                if entry not in all_images_map.setdefault(image, []):
                    all_images_map[image].append(entry)

        for k8s_file in k8s_files:
            for image, line in extract_images_from_kubernetes(k8s_file):
                entry = (k8s_file, line)
                if entry not in all_images_map.setdefault(image, []):
                    all_images_map[image].append(entry)

        all_images_map = drop_ignored_images(all_images_map)

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
        #
        # A failed scan (image not pullable, registry unreachable or
        # rejecting credentials) is recorded in `unscanned` and reported,
        # never silently dropped -- otherwise it's indistinguishable from an
        # image with zero vulnerabilities.
        unscanned: List[Dict[str, str]] = []
        blocked_registries: Dict[str, str] = {}  # registry -> first failure reason
        reachable_registries: set = set()
        for image, source_refs in all_images_map.items():
            primary_file, primary_line = source_refs[0]
            rel_file = os.path.relpath(primary_file, directory_path)
            unresolved = unresolved_image_reason(image)
            if unresolved:
                print(f"[warn] Could not scan image {image} ({rel_file}): {unresolved}")
                unscanned.append({'image': image, 'file': rel_file, 'reason': unresolved})
                continue
            registry = image_registry(image)
            if registry in blocked_registries:
                reason = f"not attempted: {registry} already failed for an earlier image"
                print(f"[warn] Skipping image {image}: {reason}")
                unscanned.append({'image': image, 'file': rel_file, 'reason': reason})
                continue
            print(f"Scanning image with Grype: {image}")
            try:
                image_findings, error = scan_image(image, primary_file, directory_path, primary_line)
            except Exception as e:
                image_findings, error = [], str(e)
            if error:
                print(f"[warn] Could not scan image {image} ({rel_file}): {error}")
                unscanned.append({'image': image, 'file': rel_file, 'reason': error})
                if _registry_blocked(error, registry, reachable_registries):
                    blocked_registries[registry] = error
                    print(f"[warn] Skipping remaining images from {registry} -- "
                          f"unreachable or rejecting credentials from this runner.")
                continue
            reachable_registries.add(registry)
            if len(source_refs) > 1:
                also_in = [
                    {'file': os.path.relpath(f, directory_path), 'line': ln}
                    for f, ln in source_refs[1:]
                ]
                for finding in image_findings:
                    finding['also_in_files'] = also_in
            findings.extend(image_findings)

        total = len(all_images_map)
        if unscanned:
            print(f"[warn] Grype scanned {total - len(unscanned)} of {total} image(s); "
                  f"{len(unscanned)} could not be scanned -- their vulnerabilities are NOT in this report.")

        return ScanResult(findings=findings, unscanned_images=unscanned, images_total=total)


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


def _failure_reason(result: subprocess.CompletedProcess) -> str:
    # On a failed pull grype lists every image source it tried ("- docker:
    # docker not available", "- snap: ...", ...). Only the registry one says
    # what actually went wrong (no such host / UNAUTHORIZED / MANIFEST_UNKNOWN).
    lines = [ln.strip().lstrip('-* ').strip() for ln in (result.stderr or '').splitlines()]
    for ln in lines:
        if ln.startswith('oci-registry:'):
            detail = ln[len('oci-registry:'):].strip()
            detail = re.sub(r'^failed to get image descriptor from registry:\s*', '', detail)
            return detail[:300]
    lines = [ln for ln in lines if ln and not re.match(r'^\d+ errors? occurred:?$', ln)]
    if not lines:
        return f"grype exited with code {result.returncode} and no error output"
    return ' '.join(lines[-3:])[:300]


def scan_image(image: str, compose_file: str, base_path: str, line: int = 0) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Scan a Docker image with Grype.

    Args:
        image: Docker image name
        compose_file: Path to the compose file containing this image
        base_path: Base directory path
        line: Source line of the image's declaring key in compose_file (0 if unknown)

    Returns:
        (findings, error) -- error is None on success, otherwise a short
        reason the image couldn't be scanned (findings is then empty and
        means "unknown", not "clean").
    """
    # No --quiet: with it grype prints nothing at all on a failed pull, so
    # there'd be no reason to report. stdout stays pure JSON either way.
    cmd = ["grype", image, "-o", "json"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            # 4 minutes: this covers grype's own image pull (not just DB
            # lookup/matching) for images not already present locally --
            # 120s was tight enough that large private-registry images
            # (multi-GB Java app images, observed directly in a real CI
            # pipeline) could time out on pull alone even with a warm DB.
            timeout=IMAGE_SCAN_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        return [], f"timed out after {IMAGE_SCAN_TIMEOUT}s pulling/scanning the image"

    if result.returncode != 0 or not result.stdout.strip():
        return [], _failure_reason(result)

    try:
        grype_data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        return [], f"could not parse grype output: {e}"
    return parse_grype_output(grype_data, image, compose_file, base_path, line), None


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
