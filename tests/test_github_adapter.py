
import json
from types import SimpleNamespace

import pytest

from ci_adapters import github


def make_finding(rule_id, severity):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "file": "main.tf",
        "line": 5,
        "description": "Example security finding",
    }


def test_github_annotations_severity_filter(monkeypatch, capsys):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    report = {
        "findings": {
            "security": [
                make_finding("CRITICAL-001", "Critical"),
                make_finding("HIGH-001", "High"),
                make_finding("LOW-001", "Low"),
            ],
            "container": [],
            "cost": [],
        }
    }

    github.emit_annotations(report, None, "high")

    output = capsys.readouterr().out

    assert "::error " in output
    assert "::warning " in output
    assert "CRITICAL-001" in output
    assert "HIGH-001" in output
    assert "LOW-001" not in output


def test_github_annotations_limit(monkeypatch, capsys):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    findings = [
        make_finding("CRITICAL-{:03d}".format(index), "Critical")
        for index in range(15)
    ]

    report = {
        "findings": {
            "security": findings,
            "container": [],
            "cost": [],
        }
    }

    github.emit_annotations(report, None, "critical")

    output = capsys.readouterr().out.splitlines()
    errors = [line for line in output if line.startswith("::error ")]

    assert len(errors) == 10
    assert "CRITICAL-000" in errors[0]
    assert "CRITICAL-009" in errors[-1]
    assert all("CRITICAL-010" not in line for line in errors)


def test_github_annotations_without_environment(monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)

    report = {
        "findings": {
            "security": [make_finding("CRITICAL-001", "Critical")]
        }
    }

    github.emit_annotations(report, None, "critical")

    assert capsys.readouterr().out == ""


def test_github_cost_increase_annotation(monkeypatch, capsys):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    report = {
        "findings": {},
        "metrics": {
            "resource_costs": [
                {
                    "resource_name": "web_server",
                    "total_usd_month": 120.0,
                    "file": "main.tf",
                    "line": 10,
                }
            ]
        },
    }

    baseline = {
        "metrics": {
            "resource_costs": [
                {
                    "resource_name": "web_server",
                    "total_usd_month": 100.0,
                }
            ]
        }
    }

    github.emit_annotations(report, baseline, "none")

    output = capsys.readouterr().out

    assert "::warning " in output
    assert "COST-DELTA" in output
    assert "+$20.00/mo" in output


def test_github_step_summary(tmp_path, monkeypatch):
    summary_file = tmp_path / "summary.md"

    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

    github.write_gh_step_summary("First summary")
    github.write_gh_step_summary("Second summary")

    content = summary_file.read_text(encoding="utf-8")

    assert content == "First summary\nSecond summary\n"


@pytest.mark.parametrize("existing_comment", [False, True])
def test_github_pr_comment(monkeypatch, tmp_path, existing_comment):
    event_file = tmp_path / "event.json"
    event_file.write_text(
        json.dumps({"pull_request": {"number": 42}}),
        encoding="utf-8",
    )

    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_file))
    monkeypatch.setenv("GITHUB_REPOSITORY", "example/repository")

    calls = []

    def fake_get(url, **kwargs):
        if existing_comment:
            comments = [
                {
                    "body": "<!-- infrascan-cost-report -->",
                    "url": "https://api.github.com/comments/123",
                }
            ]
        else:
            comments = []

        return SimpleNamespace(
            status_code=200,
            json=lambda: comments,
        )

    def fake_post(url, **kwargs):
        calls.append(("POST", url, kwargs))
        return SimpleNamespace(status_code=201)

    def fake_patch(url, **kwargs):
        calls.append(("PATCH", url, kwargs))
        return SimpleNamespace(status_code=200)

    monkeypatch.setattr(github.requests, "get", fake_get)
    monkeypatch.setattr(github.requests, "post", fake_post)
    monkeypatch.setattr(github.requests, "patch", fake_patch)

    github.post_pr_comment("InfraScan test report")

    assert len(calls) == 1

    method, url, kwargs = calls[0]

    assert method == ("PATCH" if existing_comment else "POST")
    assert "<!-- infrascan-cost-report -->" in kwargs["json"]["body"]
    assert "InfraScan test report" in kwargs["json"]["body"]

    if existing_comment:
        assert url == "https://api.github.com/comments/123"
    else:
        assert url.endswith("/issues/42/comments")


def test_github_actions_context(monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "example/repository")
    monkeypatch.setenv("GITHUB_RUN_ID", "12345")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_ACTOR", "test-user")
    monkeypatch.setenv("GITHUB_WORKFLOW", "InfraScan CI")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")

    context = github.build_gh_actions_context()

    assert context["repo"] == "example/repository"
    assert context["branch"] == "main"
    assert context["actor"] == "test-user"
    assert context["run_url"] == (
        "https://github.com/example/repository/actions/runs/12345"
    )
