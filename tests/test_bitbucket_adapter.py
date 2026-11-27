
import json
from types import SimpleNamespace

import pytest

from ci_adapters import bitbucket


def configure_bitbucket(monkeypatch):
    monkeypatch.setenv("BITBUCKET_WORKSPACE", "example")
    monkeypatch.setenv("BITBUCKET_REPO_SLUG", "repository")
    monkeypatch.setenv("BITBUCKET_COMMIT", "abc123")


def make_finding(rule_id, severity="High", image=None):
    finding = {
        "rule_id": rule_id,
        "severity": severity,
        "file": "compose.yml" if image else "main.tf",
        "line": 5,
        "description": "Example vulnerability",
    }

    if image:
        finding["image"] = image

    return finding


@pytest.mark.parametrize("content", [
    "a" * 3000,
    "Security issue " * 300,
    "Critical vulnerability \U0001f6a8 " * 200,
])
def test_bitbucket_details_limit(content):
    result = bitbucket._truncate_details(
        content,
        "https://bitbucket.org/example/repository",
    )

    assert bitbucket._json_wire_len(result) <= 2000
    assert "truncated" in result
    assert result.startswith(content[:100])


def test_bitbucket_short_details_unchanged():
    content = "InfraScan: A (100%)"

    result = bitbucket._truncate_details(content)

    assert result == content


def test_bitbucket_report_upsert(monkeypatch):
    configure_bitbucket(monkeypatch)

    calls = []

    def fake_api_call(method, path, json_body=None, timeout=15):
        calls.append((method, path, json_body))
        return SimpleNamespace(status_code=200, text="")

    monkeypatch.setattr(
        bitbucket,
        "_reports_api_call",
        fake_api_call,
    )

    report = {
        "overall": {
            "letter": "B",
            "percentage": 85,
            "severity_breakdown": {
                "critical": 0,
                "high": 2,
            },
        },
        "metrics": {},
    }

    bitbucket.upsert_bb_report(
        report,
        run_url="https://bitbucket.org/example/run/123",
    )

    assert len(calls) == 2
    assert calls[0][0] == "DELETE"
    assert calls[1][0] == "PUT"
    assert calls[0][1] == calls[1][1]

    body = calls[1][2]

    assert body["report_type"] == "SECURITY"
    assert body["result"] == "PASSED"
    assert "InfraScan: B" in body["title"]
    assert body["link"] == "https://bitbucket.org/example/run/123"
    assert bitbucket._json_wire_len(body["details"]) <= 2000


def test_bitbucket_annotations_per_image_limit(monkeypatch):
    configure_bitbucket(monkeypatch)

    calls = []

    def fake_api_call(method, path, json_body=None, timeout=15):
        calls.append((method, json_body))
        return SimpleNamespace(status_code=200, text="")

    monkeypatch.setattr(
        bitbucket,
        "_reports_api_call",
        fake_api_call,
    )

    report = {
        "findings": {
            "security": [
                make_finding("CKV-001", "High"),
            ],
            "container": [
                make_finding(
                    "CVE-TEST-{:03d}".format(index),
                    "Critical",
                    "nginx:1.25",
                )
                for index in range(15)
            ],
            "cost": [],
        }
    }

    bitbucket.emit_bb_annotations(
        report,
        baseline=None,
        alert_on="high",
        max_per_image=10,
    )

    assert len(calls) == 1
    assert calls[0][0] == "POST"

    annotations = calls[0][1]

    assert len(annotations) == 11

    critical = [
        annotation
        for annotation in annotations
        if annotation["severity"] == "CRITICAL"
    ]

    assert len(critical) == 10
    assert any("CKV-001" in a["summary"] for a in annotations)


def test_bitbucket_annotations_multiple_locations(monkeypatch):
    configure_bitbucket(monkeypatch)

    calls = []

    def fake_api_call(method, path, json_body=None, timeout=15):
        calls.append(json_body)
        return SimpleNamespace(status_code=200, text="")

    monkeypatch.setattr(
        bitbucket,
        "_reports_api_call",
        fake_api_call,
    )

    finding = make_finding(
        "CVE-TEST-001",
        "High",
        "nginx:1.25",
    )
    finding["also_in_files"] = [
        {"file": "other-compose.yml", "line": 12}
    ]

    report = {
        "findings": {
            "container": [finding],
        }
    }

    bitbucket.emit_bb_annotations(
        report,
        baseline=None,
        alert_on="high",
    )

    assert len(calls) == 1
    assert len(calls[0]) == 2

    paths = {item["path"] for item in calls[0]}

    assert paths == {"compose.yml", "other-compose.yml"}


def test_bitbucket_annotations_batch_limit(monkeypatch):
    configure_bitbucket(monkeypatch)

    calls = []

    def fake_api_call(method, path, json_body=None, timeout=15):
        calls.append(json_body)
        return SimpleNamespace(status_code=200, text="")

    monkeypatch.setattr(
        bitbucket,
        "_reports_api_call",
        fake_api_call,
    )

    findings = [
        make_finding("CKV-{:03d}".format(index))
        for index in range(105)
    ]

    report = {
        "findings": {
            "security": findings,
        }
    }

    bitbucket.emit_bb_annotations(
        report,
        baseline=None,
        alert_on="high",
    )

    assert len(calls) == 2
    assert len(calls[0]) == 100
    assert len(calls[1]) == 5


@pytest.mark.parametrize("existing_comment", [False, True])
def test_bitbucket_pr_comment(monkeypatch, existing_comment):
    configure_bitbucket(monkeypatch)

    monkeypatch.setenv("BITBUCKET_PR_ID", "42")
    monkeypatch.setenv("BITBUCKET_ACCESS_TOKEN", "test-token")

    calls = []

    def fake_get(url, **kwargs):
        values = [{"id": 123}] if existing_comment else []

        return SimpleNamespace(
            status_code=200,
            text="",
            json=lambda: {"values": values},
        )

    def fake_post(url, **kwargs):
        calls.append(("POST", url, kwargs))
        return SimpleNamespace(status_code=201, text="")

    def fake_put(url, **kwargs):
        calls.append(("PUT", url, kwargs))
        return SimpleNamespace(status_code=200, text="")

    monkeypatch.setattr(bitbucket.requests, "get", fake_get)
    monkeypatch.setattr(bitbucket.requests, "post", fake_post)
    monkeypatch.setattr(bitbucket.requests, "put", fake_put)

    bitbucket.post_bb_pr_comment("InfraScan test report")

    assert len(calls) == 1

    method, url, kwargs = calls[0]

    assert method == ("PUT" if existing_comment else "POST")
    assert "InfraScan test report" in kwargs["json"]["content"]["raw"]
    assert bitbucket.COMMENT_MARKER in kwargs["json"]["content"]["raw"]

    if existing_comment:
        assert url.endswith("/comments/123")
    else:
        assert url.endswith("/pullrequests/42/comments")
