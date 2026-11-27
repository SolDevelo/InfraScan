import json
import subprocess
from pathlib import Path

from scanner import grype_scanner
from scanner.grype_scanner import parse_grype_output


def test_parse_grype_vulnerability():
    grype_data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-12345",
                    "severity": "High",
                    "description": "Example vulnerability",
                    "fix": {
                        "versions": ["2.0.0"]
                    }
                },
                "artifact": {
                    "name": "openssl",
                    "version": "1.0.0",
                    "type": "deb"
                }
            }
        ]
    }

    findings = parse_grype_output(
        grype_data,
        "nginx:latest",
        "/project/docker-compose.yml",
        "/project",
        line=5
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CVE-2024-12345"
    assert findings[0]["severity"] == "High"
    assert findings[0]["scanner"] == "grype"
    assert findings[0]["line"] == 5
    assert findings[0]["file"] == "docker-compose.yml"


def test_parse_grype_empty_results():
    grype_data = {
        "matches": []
    }

    findings = parse_grype_output(
        grype_data,
        "nginx:latest",
        "/project/docker-compose.yml",
        "/project"
    )

    assert findings == []


def test_parse_grype_ignores_negligible():
    grype_data = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-00001",
                    "severity": "Negligible"
                },
                "artifact": {
                    "name": "example-package",
                    "version": "1.0"
                }
            }
        ]
    }

    findings = parse_grype_output(
        grype_data,
        "nginx:latest",
        "/project/docker-compose.yml",
        "/project"
    )

    assert findings == []


def test_grype_scan_image_with_mocked_subprocess(monkeypatch):
    fixture_path = (
        Path(__file__).parent / "fixtures" / "grype_output.json"
    )
    report_data = json.loads(fixture_path.read_text(encoding="utf-8"))

    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=json.dumps(report_data),
            stderr=""
        )

    monkeypatch.setattr(grype_scanner.subprocess, "run", fake_run)

    findings, error = grype_scanner.scan_image(
        "nginx:1.25",
        "/project/compose.yml",
        "/project",
        line=4
    )

    assert error is None
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CVE-TEST-0001"
    assert findings[0]["severity"] == "High"
    assert findings[0]["line"] == 4
    assert findings[0]["file"] == "compose.yml"


def test_grype_scan_image_failure(monkeypatch):
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            args=command,
            returncode=1,
            stdout="",
            stderr="oci-registry: unauthorized"
        )

    monkeypatch.setattr(grype_scanner.subprocess, "run", fake_run)

    findings, error = grype_scanner.scan_image(
        "registry.example.com/private:1",
        "/project/compose.yml",
        "/project"
    )

    assert findings == []
    assert error is not None
    assert "unauthorized" in error


def test_grype_scan_image_invalid_json(monkeypatch):
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="not valid json",
            stderr=""
        )

    monkeypatch.setattr(grype_scanner.subprocess, "run", fake_run)

    findings, error = grype_scanner.scan_image(
        "nginx:1.25",
        "/project/compose.yml",
        "/project"
    )

    assert findings == []
    assert error is not None
    assert "could not parse grype output" in error


def test_grype_records_unscanned_image(tmp_path, monkeypatch):
    compose_file = tmp_path / "compose.yml"
    compose_file.write_text(
        "services:\n"
        "  web:\n"
        "    image: nginx:1.25\n",
        encoding="utf-8"
    )

    monkeypatch.setattr(
        grype_scanner.GrypeScanner,
        "is_available",
        lambda self: True
    )

    monkeypatch.setattr(
        grype_scanner,
        "filter_container_files",
        lambda files: ([str(compose_file)], [])
    )
    monkeypatch.setattr(
        grype_scanner,
        "extract_images_from_compose",
        lambda path, base: [("nginx:1.25", 3)]
    )
    monkeypatch.setattr(
        grype_scanner,
        "drop_ignored_images",
        lambda images: images
    )
    monkeypatch.setattr(
        grype_scanner,
        "perform_all_logins",
        lambda images: None
    )
    monkeypatch.setattr(
        grype_scanner,
        "ensure_db_ready",
        lambda: None
    )
    monkeypatch.setattr(
        grype_scanner,
        "scan_image",
        lambda *args: ([], "image could not be downloaded")
    )

    scanner = grype_scanner.GrypeScanner()
    result = scanner.scan(
        str(tmp_path),
        files=[str(compose_file)]
    )

    assert result.findings == []
    assert result.images_total == 1
    assert result.images_scanned == 0
    assert len(result.unscanned_images) == 1

    failed_image = result.unscanned_images[0]

    assert failed_image["image"] == "nginx:1.25"
    assert failed_image["file"] == "compose.yml"
    assert failed_image["reason"] == "image could not be downloaded"


def test_parse_recorded_grype_output():
    fixture_path = (
        Path(__file__).parent
        / "fixtures"
        / "grype_recorded_sample.json"
    )

    grype_data = json.loads(
        fixture_path.read_text(encoding="utf-8")
    )

    assert len(grype_data["matches"]) == 12

    findings = parse_grype_output(
        grype_data,
        "python:3.9-slim",
        "/project/docker-compose.yml",
        "/project",
        line=7
    )

    assert len(findings) > 0

    recorded_ids = {
        match["vulnerability"]["id"]
        for match in grype_data["matches"]
    }

    for finding in findings:
        assert finding["rule_id"] in recorded_ids
        assert finding["scanner"] == "grype"
        assert finding["severity"] in {
            "Critical",
            "High",
            "Medium",
            "Low",
            "Info"
        }
        assert finding["file"] == "docker-compose.yml"
        assert finding["line"] == 7


def test_grype_scan_image_with_recorded_output(monkeypatch):
    fixture_path = (
        Path(__file__).parent
        / "fixtures"
        / "grype_recorded_sample.json"
    )

    recorded_output = fixture_path.read_text(encoding="utf-8")
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)

        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=recorded_output,
            stderr=""
        )

    monkeypatch.setattr(
        grype_scanner.subprocess,
        "run",
        fake_run
    )

    findings, error = grype_scanner.scan_image(
        "python:3.9-slim",
        "/project/docker-compose.yml",
        "/project",
        line=7
    )

    assert error is None
    assert len(findings) > 0

    assert len(commands) == 1
    assert commands[0][0] == "grype"

    for finding in findings:
        assert finding["scanner"] == "grype"
        assert finding["line"] == 7
        assert finding["file"] == "docker-compose.yml"
