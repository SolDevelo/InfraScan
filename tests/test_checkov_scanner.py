import json
import subprocess
from pathlib import Path

from scanner import checkov_scanner
from scanner.checkov_scanner import parse_checkov_json_output


def test_parse_checkov_failed_check():
    report_data = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_19",
                    "check_name": "Ensure EBS volumes are encrypted",
                    "severity": "HIGH",
                    "file_path": "/main.tf",
                    "file_line_range": [1, 5],
                    "resource": "aws_ebs_volume.test",
                    "guideline": "Enable encryption"
                }
            ]
        }
    }

    findings = parse_checkov_json_output(report_data, "/project")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CKV_AWS_19"


def test_parse_checkov_empty_results():
    report_data = {
        "check_type": "terraform",
        "results": {
            "failed_checks": []
        }
    }

    findings = parse_checkov_json_output(report_data, "/project")

    assert findings == []


def test_parse_checkov_multiple_findings():
    report_data = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_19",
                    "severity": "HIGH"
                },
                {
                    "check_id": "CKV_AWS_20",
                    "severity": "MEDIUM"
                }
            ]
        }
    }

    findings = parse_checkov_json_output(report_data, "/project")

    assert len(findings) == 2

    rule_ids = {finding["rule_id"] for finding in findings}

    assert rule_ids == {"CKV_AWS_19", "CKV_AWS_20"}


def test_checkov_scan_with_mocked_subprocess(tmp_path, monkeypatch):
    fixture_path = (
        Path(__file__).parent / "fixtures" / "checkov_output.json"
    )
    report_data = json.loads(fixture_path.read_text(encoding="utf-8"))

    captured_commands = []

    def fake_run(command, **kwargs):
        captured_commands.append(command)
        return subprocess.CompletedProcess(
            args=command,
            returncode=1,
            stdout=json.dumps(report_data),
            stderr=""
        )

    monkeypatch.setattr(
        checkov_scanner.CheckovScanner,
        "is_available",
        lambda self: True
    )
    monkeypatch.setattr(
        checkov_scanner.subprocess,
        "run",
        fake_run
    )

    scanner = checkov_scanner.CheckovScanner()
    result = scanner.scan(str(tmp_path))

    assert len(result.findings) == 1
    assert result.findings[0]["rule_id"] == "CKV_AWS_19"
    assert result.findings[0]["severity"] == "High"
    assert result.findings[0]["scanner"] == "checkov"

    assert len(captured_commands) == 1
    assert captured_commands[0][0] == "checkov"
    assert "-o" in captured_commands[0]
    assert "json" in captured_commands[0]


def test_parse_recorded_checkov_output():
    fixture_path = (
        Path(__file__).parent / "fixtures" / "checkov_recorded.json"
    )

    report_data = json.loads(
        fixture_path.read_text(encoding="utf-8")
    )

    original_findings = report_data["results"]["failed_checks"]

    findings = checkov_scanner.parse_checkov_json_output(
        report_data,
        "/project",
    )

    assert len(original_findings) == 12
    assert len(findings) == 12

    rule_ids = {finding["rule_id"] for finding in findings}

    assert "CKV_AWS_79" in rule_ids

    for finding in findings:
        assert finding["scanner"] == "checkov"
        assert finding["rule_id"]
        assert finding["severity"] in {
            "Critical", "High", "Medium", "Low", "Info"
        }
        assert finding["file"] == "test_infra.tf"
        assert finding["line"] >= 0


def test_checkov_scan_with_recorded_output(tmp_path, monkeypatch):
    fixture_path = (
        Path(__file__).parent / "fixtures" / "checkov_recorded.json"
    )

    recorded_output = fixture_path.read_text(encoding="utf-8")
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)

        return subprocess.CompletedProcess(
            args=command,
            returncode=1,
            stdout=recorded_output,
            stderr="",
        )

    monkeypatch.setattr(
        checkov_scanner.CheckovScanner,
        "is_available",
        lambda self: True,
    )

    monkeypatch.setattr(
        checkov_scanner.subprocess,
        "run",
        fake_run,
    )

    scanner = checkov_scanner.CheckovScanner()

    result = scanner.scan(str(tmp_path))

    assert len(commands) == 1
    assert commands[0][0] == "checkov"
    assert "--framework" in commands[0]
    assert "json" in commands[0]

    assert len(result.findings) == 12
    assert all(
        finding["scanner"] == "checkov"
        for finding in result.findings
    )
