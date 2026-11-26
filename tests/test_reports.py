
import base64
import json
import re

import pytest

from reporter.grading import ReportGenerator
from reporter.html_generator import generate_standalone_html


def create_test_report(with_findings):
    findings = []

    if with_findings:
        findings = [
            {
                "rule_id": "CKV_AWS_19",
                "rule_name": "EBS encryption check",
                "severity": "High",
                "scanner": "checkov",
                "file": "main.tf",
                "line": 5,
                "resource": "aws_ebs_volume.test",
                "description": "EBS volume is not encrypted",
            }
        ]

    generator = ReportGenerator()

    report = generator.generate_report(
        findings=findings,
        resource_count=1 if with_findings else 0,
        scanner_type="checkov",
    )

    return report, report.to_dict()

@pytest.mark.parametrize("with_findings", [False, True])
def test_html_report(tmp_path, with_findings):
    report, report_dict = create_test_report(with_findings)

    html = generate_standalone_html(report_dict)

    output_file = tmp_path / "report.html"
    output_file.write_text(html, encoding="utf-8")

    saved_html = output_file.read_text(encoding="utf-8")

    assert "<html" in saved_html.lower()
    assert "Error generating HTML report" not in saved_html

    match = re.search(
        r'window\.CLI_INJECTED_DATA_B64\s*=\s*"([^"]+)"',
        saved_html,
    )

    assert match is not None

    encoded_data = match.group(1)
    decoded_data = base64.b64decode(encoded_data).decode("utf-8")
    embedded_report = json.loads(decoded_data)

    assert embedded_report == report_dict
    assert len(report.security_findings) == int(with_findings)

    if with_findings:
        assert "CKV_AWS_19" in decoded_data
        assert "main.tf" in decoded_data
    else:
        assert "CKV_AWS_19" not in decoded_data
