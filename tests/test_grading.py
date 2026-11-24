import pytest

from reporter.grading import (
    GradeCalculator,
    ReportGenerator,
    container_grading_view,
)


def test_weighted_score_multiple():
    calculator = GradeCalculator()

    findings = [
        {"severity": "critical"},
        {"severity": "critical"},
        {"severity": "high"},
        {"severity": "medium"},
        {"severity": "medium"},
        {"severity": "low"}
    ]

    score, breakdown = calculator.calculate_weighted_score(findings)

    assert score == 16
    assert breakdown["critical"] == 2
    assert breakdown["high"] == 1
    assert breakdown["medium"] == 2
    assert breakdown["low"] == 1
    assert breakdown["info"] == 0


def test_letter_grade_a():
    calculator = GradeCalculator()

    result = calculator.get_letter_grade(98)

    assert result == "A"


def test_letter_grade_b():
    calculator = GradeCalculator()

    result = calculator.get_letter_grade(90)

    assert result == "B"


def test_letter_grade_f():
    calculator = GradeCalculator()

    result = calculator.get_letter_grade(40)

    assert result == "F"


def test_critical_caps_grade():
    calculator = GradeCalculator()

    findings = [
        {"severity": "critical"}
    ]

    percentage, grade, reason = calculator.apply_severity_caps(
        findings, 98, "A"
    )

    assert grade == "C"
    assert percentage == 84.9
    assert reason is not None


def test_high_caps_grade():
    calculator = GradeCalculator()

    findings = [
        {"severity": "high"}
    ]

    percentage, grade, reason = calculator.apply_severity_caps(
        findings, 99, "A"
    )

    assert grade == "B"
    assert percentage == 94.9
    assert reason is not None

def test_high_does_not_lower_grade_c():
    calculator = GradeCalculator()

    findings = [
        {"severity": "high"}
    ]

    percentage, grade, reason = calculator.apply_severity_caps(
        findings, 75, "C"
    )

    assert grade == "C"
    assert percentage == 75
    assert reason is None


def test_container_severity_without_fix():
    finding = {
        "severity": "critical",
        "fix_version": None
    }

    result = container_grading_view(finding)

    assert result["severity"] == "high"
    assert finding["severity"] == "critical"


def test_container_severity_with_fix():
    finding = {
        "severity": "critical",
        "fix_version": "2.0.0"
    }

    result = container_grading_view(finding)

    assert result["severity"] == "critical"


def test_container_severity_unknown_fix():
    finding = {
        "severity": "high"
    }

    result = container_grading_view(finding)

    assert result["severity"] == "high"


def test_worst_severity_per_container_image():
    generator = ReportGenerator()

    findings = [
        {"image": "nginx:latest", "severity": "low"},
        {"image": "nginx:latest", "severity": "critical"},
        {"image": "nginx:latest", "severity": "medium"},
        {"image": "python:3.9", "severity": "medium"},
        {"image": "python:3.9", "severity": "high"}
    ]

    result = generator._most_severe_per_container_image(findings)

    assert len(result) == 2

    severities = {
        finding["image"]: finding["severity"]
        for finding in result
    }

    assert severities["nginx:latest"] == "critical"
    assert severities["python:3.9"] == "high"


def test_overall_grade_single_scanner():
    generator = ReportGenerator()

    findings = [
        {
            "scanner": "regex",
            "severity": "medium",
            "rule_id": "COST-001",
            "file": "main.tf"
        }
    ]

    report = generator.generate_report(
        findings=findings,
        resource_count=5,
        scanner_type="regex",
        cost_file_count=1
    )

    assert report.cost_grade is not None
    assert report.overall_grade is not None
    assert report.overall_grade.letter == report.cost_grade.letter
    assert report.overall_grade.percentage == report.cost_grade.percentage
    assert report.security_grade is None
    assert report.container_grade is None


def test_not_applicable_categories():
    generator = ReportGenerator()

    report = generator.generate_report(
        findings=[],
        resource_count=5,
        scanner_type="comprehensive",
        cost_file_count=0,
        container_image_count=0
    )

    assert report.cost_grade is None
    assert report.container_grade is None
    assert report.security_grade is not None
    assert report.security_grade.letter == "A"
    assert report.overall_grade.letter == "A"



def test_overall_grade_critical_cap():
    generator = ReportGenerator()

    findings = [
        {
            "scanner": "regex",
            "severity": "critical",
            "rule_id": "COST-001",
            "file": "main.tf"
        }
    ]

    report = generator.generate_report(
        findings=findings,
        resource_count=100,
        scanner_type="regex",
        cost_file_count=1
    )

    assert report.overall_grade is not None
    assert report.cost_grade is not None

    assert report.overall_grade.letter == "C"
    assert report.overall_grade.percentage == 84.9
    assert report.cost_grade.cap_reason is not None


def test_overall_grade_high_cap():
    generator = ReportGenerator()

    findings = [
        {
            "scanner": "regex",
            "severity": "high",
            "rule_id": "COST-001",
            "file": "main.tf"
        }
    ]

    report = generator.generate_report(
        findings=findings,
        resource_count=100,
        scanner_type="regex",
        cost_file_count=1
    )

    assert report.overall_grade is not None
    assert report.cost_grade is not None

    assert report.overall_grade.letter == "B"
    assert report.overall_grade.percentage == 94.9
    assert report.cost_grade.cap_reason is not None


def test_container_scoring_by_worst_severity():
    generator = ReportGenerator()

    findings = [
        {
            "scanner": "grype",
            "image": "nginx:latest",
            "severity": "critical",
            "fix_version": "2.0"
        },
        {
            "scanner": "grype",
            "image": "nginx:latest",
            "severity": "medium",
            "fix_version": "2.0"
        },
        {
            "scanner": "grype",
            "image": "python:3.9",
            "severity": "medium",
            "fix_version": "2.0"
        }
    ]

    report = generator.generate_report(
        findings=findings,
        scanner_type="containers",
        container_image_count=2
    )

    assert report.container_grade is not None
    assert report.container_grade.score == 4.5
    assert report.container_grade.max_score == 8
    assert report.container_grade.violations == 3
    assert report.container_grade.severity_breakdown["critical"] == 1
    assert report.container_grade.severity_breakdown["medium"] == 2


def test_container_scoring_without_fix():
    generator = ReportGenerator()

    findings = [
        {
            "scanner": "grype",
            "image": "nginx:latest",
            "severity": "critical",
            "fix_version": None
        }
    ]

    report = generator.generate_report(
        findings=findings,
        scanner_type="containers",
        container_image_count=1
    )

    assert report.container_grade is not None
    assert report.container_grade.score == 3
    assert report.container_grade.severity_breakdown["critical"] == 1
    assert report.container_findings[0]["severity"] == "critical"


@pytest.mark.parametrize("percentage, expected_grade", [
    (100, "A"),
    (95, "A"),
    (94.9, "B"),
    (85, "B"),
    (84.9, "C"),
    (70, "C"),
    (69.9, "D"),
    (55, "D"),
    (54.9, "F"),
    (0, "F"),
])
def test_letter_grade_thresholds(percentage, expected_grade):
    calculator = GradeCalculator()

    result = calculator.get_letter_grade(percentage)

    assert result == expected_grade


def test_empty_findings_grade():
    calculator = GradeCalculator()

    grade = calculator.calculate_grade([])

    assert grade.letter == "A"
    assert grade.percentage == 100
    assert grade.score == 0
    assert grade.violations == 0
    assert grade.cap_reason is None
