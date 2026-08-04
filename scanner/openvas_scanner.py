"""
OpenVAS integration for network vulnerability scanning.

This module spins up a disposable OpenVAS (Greenbone Vulnerability Manager)
Docker container, drives a scan against a caller-supplied list of target
hosts/IPs over the Greenbone Management Protocol (GMP), and parses the
resulting XML report into the normalized finding format shared by the other
scanners.

Unlike the other scanners, OpenVAS scans network targets rather than files,
so `targets` (and optionally `port_range`) must be passed explicitly to
`scan()` - there is no directory to infer them from.
"""

import os
import socket
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional

from scanner.base import Scanner, ScanResult

try:
    from gvm.connections import TLSConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeCheckCommandTransform
    GVM_AVAILABLE = True
except ImportError:
    GVM_AVAILABLE = False

READY_MARKER = "container is now ready to use"


def run_command(cmd: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a subprocess command with timeout."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def resolve_target(host: str) -> str:
    """Resolve a hostname to a single IPv4 address, passing through on failure."""
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, OSError):
        return host


def severity_from_score(score: Optional[float]) -> str:
    """Bucket a CVSS base score into our normalized severity scale."""
    if score is None:
        return 'Info'
    if score >= 9.0:
        return 'Critical'
    if score >= 7.0:
        return 'High'
    if score >= 4.0:
        return 'Medium'
    if score > 0.0:
        return 'Low'
    return 'Info'


def parse_nvt_tags(tags_text: str) -> Dict[str, str]:
    """Parse OpenVAS's pipe-delimited 'key=value|key=value' NVT tag string."""
    tags = {}
    if not tags_text:
        return tags
    for part in tags_text.split('|'):
        if '=' in part:
            key, _, value = part.partition('=')
            tags[key.strip()] = value.strip()
    return tags


class OpenvasScanner(Scanner):
    """OpenVAS (Greenbone) network vulnerability scanner."""

    name = "openvas"

    def is_available(self) -> bool:
        if not GVM_AVAILABLE:
            return False
        try:
            return run_command(["docker", "version"], timeout=5).returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError, OSError):
            return False

    def scan(
        self,
        directory_path: str,
        files: Optional[List[str]] = None,
        targets: Optional[List[str]] = None,
        port_range: Optional[str] = None,
        **options,
    ) -> ScanResult:
        """
        Spin up OpenVAS, scan the given targets, and return normalized findings.

        Args:
            directory_path: Unused (OpenVAS scans network targets, not files);
                kept for interface parity with the other scanners.
            files: Unused, see above.
            targets: Required list of target IPs/hostnames to scan.
            port_range: Optional OpenVAS port range string (e.g. "T:1-65535,U:1-65535").
                Defaults to the scan config's own port list when omitted.

        Returns:
            ScanResult with normalized findings.
        """
        if not GVM_AVAILABLE:
            raise ImportError(
                "python-gvm is not installed. Install it with: pip install python-gvm"
            )
        if not targets:
            raise ValueError(
                "OpenVAS scanner requires at least one target IP or hostname (targets=[...])"
            )
        if not self.is_available():
            raise ImportError(
                "Docker is not available. OpenVAS runs as a Docker container "
                "(https://hub.docker.com/r/immauss/openvas)."
            )

        image = os.getenv('OPENVAS_IMAGE', 'immauss/openvas:latest')
        container_name = os.getenv('OPENVAS_CONTAINER', 'infrascan-openvas')
        gmp_port = int(os.getenv('OPENVAS_GMP_PORT', '9390'))
        username = os.getenv('OPENVAS_USERNAME', 'admin')
        password = os.getenv('OPENVAS_PASSWORD', 'admin')
        ready_timeout = int(os.getenv('OPENVAS_READY_TIMEOUT', '3600'))
        scan_timeout = int(os.getenv('OPENVAS_SCAN_TIMEOUT', '7200'))
        scan_config_name = os.getenv('OPENVAS_SCAN_CONFIG', 'Full and fast')
        cleanup_enabled = os.getenv('CLEANUP_OPENVAS_CONTAINER', 'true').lower() == 'true'

        resolved_targets = [resolve_target(t.strip()) for t in targets if t.strip()]

        print(f"[INFO] Starting OpenVAS container ({image}) for targets: {', '.join(resolved_targets)}")
        self._start_container(image, container_name, gmp_port, username, password)

        try:
            self._wait_until_ready(container_name, gmp_port, ready_timeout)
            findings = self._run_gmp_scan(
                gmp_port, username, password, resolved_targets, port_range, scan_config_name, scan_timeout
            )
        finally:
            if cleanup_enabled:
                print("[INFO] Removing OpenVAS container...")
                try:
                    run_command(["docker", "rm", "-f", container_name], timeout=30)
                except Exception as e:
                    print(f"Warning: Failed to remove OpenVAS container: {e}")

        return ScanResult(findings=findings)

    # ------------------------------------------------------------------
    # Docker container lifecycle
    # ------------------------------------------------------------------

    def _start_container(
        self, image: str, container_name: str, gmp_port: int, username: str, password: str
    ) -> None:
        print(f"[INFO] Pulling OpenVAS image: {image}")
        pull_result = subprocess.run(["docker", "pull", image], capture_output=True, text=True)
        if pull_result.returncode != 0:
            print(
                "Warning: Failed to pull OpenVAS image (will try to use a local copy if "
                f"available): {pull_result.stderr.strip()[:200]}"
            )

        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)

        result = subprocess.run(
            [
                "docker", "run", "-d",
                "--name", container_name,
                "-p", f"{gmp_port}:9390",
                "-e", f"USERNAME={username}",
                "-e", f"PASSWORD={password}",
                "-e", "GMP=9390",
                image,
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to start OpenVAS container: {result.stderr.strip()}")

    def _wait_until_ready(self, container_name: str, gmp_port: int, ready_timeout: int) -> None:
        print(f"[INFO] Waiting for OpenVAS to become ready (up to {ready_timeout // 60} minutes)...")
        deadline = time.time() + ready_timeout
        while True:
            logs = subprocess.run(
                ["docker", "logs", container_name], capture_output=True, text=True
            ).stdout
            if READY_MARKER in logs and self._is_port_open("127.0.0.1", gmp_port):
                print("[INFO] OpenVAS is ready and GMP is reachable.")
                return
            if time.time() >= deadline:
                raise TimeoutError(f"OpenVAS did not become ready within {ready_timeout}s.")
            time.sleep(20)

    @staticmethod
    def _is_port_open(host: str, port: int, timeout: int = 5) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    # ------------------------------------------------------------------
    # GMP scan orchestration
    # ------------------------------------------------------------------

    def _run_gmp_scan(
        self,
        gmp_port: int,
        username: str,
        password: str,
        targets: List[str],
        port_range: Optional[str],
        scan_config_name: str,
        scan_timeout: int,
    ) -> List[Dict[str, Any]]:
        connection = TLSConnection(hostname="127.0.0.1", port=gmp_port, timeout=60)
        with Gmp(connection, transform=EtreeCheckCommandTransform()) as gmp:
            gmp.authenticate(username, password)

            config_id = self._find_id_by_name(gmp.get_scan_configs(), 'config', scan_config_name)
            scanner_id = self._find_id_by_name(gmp.get_scanners(), 'scanner', 'OpenVAS')

            scan_label = f"infrascan-{uuid.uuid4().hex[:8]}"
            target_id = None
            task_id = None
            try:
                create_target_kwargs = {"name": f"{scan_label}-target", "hosts": targets}
                if port_range:
                    create_target_kwargs["port_range"] = port_range
                target_resp = gmp.create_target(**create_target_kwargs)
                target_id = target_resp.get('id')

                task_resp = gmp.create_task(
                    name=scan_label,
                    config_id=config_id,
                    target_id=target_id,
                    scanner_id=scanner_id,
                )
                task_id = task_resp.get('id')

                print(f"[INFO] Starting OpenVAS scan task '{scan_label}'...")
                gmp.start_task(task_id)

                report_id = self._poll_task(gmp, task_id, scan_timeout)

                print(f"[INFO] Fetching OpenVAS report {report_id}...")
                report = gmp.get_report(report_id, details=True)
                return self._parse_report(report)
            finally:
                if task_id:
                    try:
                        gmp.delete_task(task_id, ultimate=True)
                    except Exception as e:
                        print(f"Warning: Failed to delete OpenVAS task: {e}")
                if target_id:
                    try:
                        gmp.delete_target(target_id, ultimate=True)
                    except Exception as e:
                        print(f"Warning: Failed to delete OpenVAS target: {e}")

    @staticmethod
    def _find_id_by_name(response, tag: str, name_contains: str) -> Optional[str]:
        """
        Find the id of the first <tag> element whose <name> contains name_contains
        (case-insensitive), falling back to the first available element.
        """
        elements = response.findall(tag)
        for el in elements:
            name = el.findtext('name') or ''
            if name_contains.lower() in name.lower():
                return el.get('id')
        return elements[0].get('id') if elements else None

    def _poll_task(self, gmp, task_id: str, scan_timeout: int) -> str:
        deadline = time.time() + scan_timeout
        last_progress = None
        while True:
            task_resp = gmp.get_task(task_id)
            task_el = task_resp.find('task')
            status = task_el.findtext('status') if task_el is not None else None
            progress = task_el.findtext('progress') if task_el is not None else None
            if progress != last_progress:
                print(f"[INFO] OpenVAS scan status: {status} ({progress}%)")
                last_progress = progress

            if status == 'Done':
                report_el = task_el.find('last_report/report')
                if report_el is not None and report_el.get('id'):
                    return report_el.get('id')
                raise RuntimeError("OpenVAS task finished but no report was found.")

            if status in ('Stopped', 'Interrupted'):
                raise RuntimeError(f"OpenVAS scan task ended with status: {status}")

            if time.time() >= deadline:
                raise TimeoutError(f"OpenVAS scan did not complete within {scan_timeout}s.")

            time.sleep(15)

    # ------------------------------------------------------------------
    # Report parsing
    # ------------------------------------------------------------------

    def _parse_report(self, report) -> List[Dict[str, Any]]:
        findings = []
        try:
            for result in report.iter('result'):
                findings.append(self._normalize_result(result))
        except Exception as e:
            print(f"Error parsing OpenVAS report: {e}")
            import traceback
            traceback.print_exc()
        return findings

    @staticmethod
    def _normalize_result(result) -> Dict[str, Any]:
        name = result.findtext('name') or 'Unknown finding'
        host = result.findtext('host') or 'unknown'
        port = result.findtext('port') or ''
        description = (result.findtext('description') or '').strip() or name

        nvt = result.find('nvt')
        oid = nvt.get('oid') if nvt is not None else 'UNKNOWN'
        cve = ((nvt.findtext('cve') if nvt is not None else None) or '').strip()
        tags_text = (nvt.findtext('tags') if nvt is not None else None) or ''
        tags = parse_nvt_tags(tags_text)

        severity_text = result.findtext('severity')
        try:
            severity_score = float(severity_text) if severity_text else None
        except ValueError:
            severity_score = None
        severity = severity_from_score(severity_score)

        solution = tags.get('solution', '').strip()
        remediation = (
            solution if solution
            else 'See the Greenbone/OpenVAS vulnerability database for remediation guidance.'
        )

        has_cve = cve and cve.upper() != 'NOCVE'

        return {
            'file': host,
            'rule_id': oid,
            'rule_name': name,
            'severity': severity,
            'description': description,
            'remediation': remediation,
            'estimated_savings': f"Security risk mitigation ({severity})",
            'line': 0,
            'match_content': (
                f"Host: {host}, Port: {port or 'n/a'}" + (f", CVE: {cve}" if has_cve else '')
            ),
            'scanner': 'openvas',
            'host': host,
            'port': port,
            'cve': cve if has_cve else None,
            'cvss_score': severity_score if severity_score is not None else 'N/A',
        }
