
from types import SimpleNamespace

import pytest

from cli import should_fail


def make_args(fail_on):
    return SimpleNamespace(fail_on=fail_on)


def make_finding(rule_id, severity):
    return {
        "rule_id": rule_id,
        "severity": severity,
    }


def make_report(letter="A"):
    return {"overall": {"letter": letter}}


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
    "fail_on, rule_id, severity, expected",
    [
        ("new_any", "OLD-001", "Critical", False),
        ("new_any", "NEW-001", "Low", True),
        ("new_high_critical", "NEW-001", "Medium", False),
        ("new_high_critical", "NEW-001", "High", True),
        ("new_critical", "NEW-001", "High", False),
        ("new_critical", "NEW-001", "Critical", True),
        ("new_critical", "OLD-001", "Critical", False),
    ],
)
def test_fail_on_new_findings(
    monkeypatch, fail_on, rule_id, severity, expected
):
    from reporter import cost_estimator

    monkeypatch.setattr(
        cost_estimator,
        "finding_key",
        lambda finding: finding["rule_id"],
    )

    monkeypatch.setattr(
        cost_estimator,
        "baseline_finding_keys",
        lambda baseline: set(baseline["keys"]),
    )

    baseline = {"keys": ["OLD-001"]}
    findings = [make_finding(rule_id, severity)]

    result = should_fail(
        make_args(fail_on),
        make_report(),
        findings,
        baseline=baseline,
    )

    assert result is expected


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
