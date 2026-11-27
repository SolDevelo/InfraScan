
from types import SimpleNamespace

import pytest

from cli import should_fail


def make_args(fail_on):
    return SimpleNamespace(fail_on=fail_on)


def make_finding(rule_id, severity, file="main.tf", line=1):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "file": file,
        "line": line,
    }

def make_report(letter="A"):
    return {"overall": {"letter": letter}}

def make_baseline(security=(), container=(), cost=()):
    """Create a baseline matching the stored JSON report structure."""
    return {
        "overall": {"letter": "B"},
        "findings": {
            "security": list(security),
            "container": list(container),
            "cost": list(cost),
        },
    }


REPORT = make_report()

BASELINE = make_baseline(
    security=[
        make_finding("CKV_AWS_19", "High", "main.tf", line=10)
    ],
    container=[
        make_finding("CVE-2025-0001", "Critical", "compose.yml", line=3)
    ],
    cost=[
        make_finding("COST-009", "Medium", "storage.tf", line=7)
    ],
)


@pytest.mark.parametrize("findings", [
    [],
    [make_finding("TEST-001", "Critical")],
])
def test_fail_on_never(findings):
    result = should_fail(
        make_args("never"),
        make_report("F"),
        findings,
    )

    assert result is False


@pytest.mark.parametrize("findings, expected", [
    ([], False),
    ([make_finding("TEST-001", "Low")], True),
])
def test_fail_on_any(findings, expected):
    result = should_fail(
        make_args("any"),
        make_report(),
        findings,
    )

    assert result is expected


@pytest.mark.parametrize("severity, expected", [
    ("Critical", True),
    ("High", True),
    ("Medium", False),
    ("Low", False),
    ("Info", False),
])
def test_fail_on_high_critical(severity, expected):
    findings = [make_finding("TEST-001", severity)]

    result = should_fail(
        make_args("high_critical"),
        make_report(),
        findings,
    )

    assert result is expected


@pytest.mark.parametrize("fail_on, letter, expected", [
    ("grade_a", "A", True),
    ("grade_b", "A", False),
    ("grade_b", "B", True),
    ("grade_b", "C", True),
    ("grade_c", "B", False),
    ("grade_c", "C", True),
    ("grade_c", "D", True),
    ("grade_d", "C", False),
    ("grade_d", "D", True),
    ("grade_f", "D", False),
    ("grade_f", "F", True),
])
def test_fail_on_grade(fail_on, letter, expected):
    result = should_fail(
        make_args(fail_on),
        make_report(letter),
        [],
    )

    assert result is expected


@pytest.mark.parametrize("fail_on", [
    "new_any",
    "new_high_critical",
    "new_critical",
])
def test_fail_on_new_without_baseline(fail_on):
    findings = [make_finding("NEW-001", "Critical")]

    result = should_fail(
        make_args(fail_on),
        make_report(),
        findings,
        baseline=None,
    )

    assert result is False


@pytest.mark.parametrize(
    "fail_on, finding, expected",
    [
        # Same rule and file: not new, even if the line changed.
        (
            "new_any",
            make_finding("CKV_AWS_19", "High", "main.tf", line=42),
            False,
        ),

        # Existing findings in other report categories.
        (
            "new_any",
            make_finding("CVE-2025-0001", "Critical", "compose.yml"),
            False,
        ),
        (
            "new_any",
            make_finding("COST-009", "Medium", "storage.tf"),
            False,
        ),

        # Same rule in a different file is a new finding.
        (
            "new_any",
            make_finding("CKV_AWS_19", "High", "other.tf"),
            True,
        ),

        # Unknown rule in an existing file is a new finding.
        (
            "new_any",
            make_finding("CKV_AWS_20", "Low", "main.tf"),
            True,
        ),

        # Severity thresholds apply to new findings.
        (
            "new_high_critical",
            make_finding("CKV_AWS_20", "Medium", "main.tf"),
            False,
        ),
        (
            "new_high_critical",
            make_finding("CKV_AWS_20", "HIGH", "main.tf"),
            True,
        ),
        (
            "new_critical",
            make_finding("CKV_AWS_20", "High", "main.tf"),
            False,
        ),
        (
            "new_critical",
            make_finding("CKV_AWS_20", "critical", "main.tf"),
            True,
        ),

        # An existing critical finding must not fail new_critical.
        (
            "new_critical",
            make_finding("CVE-2025-0001", "Critical", "compose.yml"),
            False,
        ),
    ],
)
def test_fail_on_new_findings(fail_on, finding, expected):
    result = should_fail(
        make_args(fail_on),
        REPORT,
        [finding],
        baseline=BASELINE,
    )

    assert result is expected


def test_fail_on_new_uses_check_id_when_rule_id_missing():
    baseline = make_baseline(
        security=[
            {
                "check_id": "CKV_AWS_19",
                "file": "main.tf",
            }
        ]
    )

    finding = {
        "check_id": "CKV_AWS_19",
        "file": "main.tf",
        "severity": "Critical",
    }

    result = should_fail(
        make_args("new_any"),
        REPORT,
        [finding],
        baseline=baseline,
    )

    assert result is False


def test_fail_on_new_with_clean_baseline_treats_everything_as_new():
    finding = make_finding("CKV_AWS_19", "Low")

    result = should_fail(
        make_args("new_any"),
        REPORT,
        [finding],
        baseline=make_baseline(),
    )

    assert result is True

@pytest.mark.parametrize("severity, expected", [
    ("Critical", True),
    ("High", True),
    ("Medium", False),
    ("Low", False),
    ("Info", False),
])
def test_fail_on_priority_high(severity, expected):
    findings = [make_finding("TEST-001", severity)]

    result = should_fail(
        make_args("priority_high"),
        make_report(),
        findings,
    )

    assert result is expected


def test_fail_on_empty_results():
    result = should_fail(
        make_args("any"),
        make_report("A"),
        [],
    )

    assert result is False
