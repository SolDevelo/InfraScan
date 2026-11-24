
import pytest

from scanner import docker_scout_scanner as scout


def test_extract_package_from_purl():
    package, version = scout.extract_package_from_purl(
        "Package: pkg:golang/github.com/example/library@1.2.3"
    )

    assert package == "library"
    assert version == "1.2.3"


def test_extract_package_from_purl_missing():
    package, version = scout.extract_package_from_purl(
        "No package URL available"
    )

    assert package is None
    assert version is None


@pytest.mark.parametrize(
    "description, expected",
    [
        ("Fixed version: 1.2.3", "1.2.3"),
        ("Fixed version: none", None),
        ("Fixed version: N/A", None),
        ("No fix available", None),
    ],
)
def test_extract_fix_version_from_text(description, expected):
    assert scout.extract_fix_version_from_text(description) == expected


def test_extract_fix_version_from_sarif_properties():
    result = scout.extract_fix_version_from_sarif(
        {"fixedVersion": "2.0.0"},
        {},
    )

    assert result == "2.0.0"


def test_extract_fix_version_from_sarif_result():
    result = scout.extract_fix_version_from_sarif(
        {},
        {"fixes": [{"version": "3.0.0"}]},
    )

    assert result == "3.0.0"


def test_normalize_fix_version():
    assert scout.normalize_fix_version("1.5.0") == "1.5.0"
    assert scout.normalize_fix_version(
        None,
        "Fixed version: 2.0.0",
    ) == "2.0.0"
    assert scout.normalize_fix_version(None) is None


def test_image_recommendation_bitnami():
    recommendation = scout.get_image_recommendation(
        "bitnami/redis:latest"
    )

    assert recommendation is not None
    assert "Soldevelo" in recommendation


def test_image_recommendation_other_image():
    assert scout.get_image_recommendation("nginx:latest") is None
