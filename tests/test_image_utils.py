
import pytest

from scanner.image_utils import (
    find_compose_files,
    find_kubernetes_files,
    filter_container_files,
    image_scan_timeout,
    compose_env_files,
)


def test_find_compose_files(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx\n",
        encoding="utf-8",
    )

    (tmp_path / "compose.yaml").write_text(
        "services:\n  api:\n    image: python\n",
        encoding="utf-8",
    )

    (tmp_path / "config.yml").write_text(
        "name: example\n",
        encoding="utf-8",
    )

    files = find_compose_files(str(tmp_path))
    filenames = {path.split("/")[-1] for path in files}

    assert filenames == {
        "docker-compose.yml",
        "compose.yaml",
    }


def test_find_compose_files_empty(tmp_path):
    files = find_compose_files(str(tmp_path))

    assert files == []


def test_find_kubernetes_files(tmp_path):
    (tmp_path / "deployment.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: example\n",
        encoding="utf-8",
    )

    (tmp_path / "settings.yaml").write_text(
        "name: example\n"
        "enabled: true\n",
        encoding="utf-8",
    )

    files = find_kubernetes_files(str(tmp_path))

    assert len(files) == 1
    assert files[0].endswith("deployment.yaml")


def test_find_kubernetes_files_empty(tmp_path):
    files = find_kubernetes_files(str(tmp_path))

    assert files == []


def test_filter_container_files(tmp_path):
    compose_file = tmp_path / "compose.yml"
    compose_file.write_text(
        "services:\n  web:\n    image: nginx\n",
        encoding="utf-8",
    )

    kubernetes_file = tmp_path / "deployment.yaml"
    kubernetes_file.write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n",
        encoding="utf-8",
    )

    other_file = tmp_path / "other.yaml"
    other_file.write_text(
        "name: example\n",
        encoding="utf-8",
    )

    compose_files, kubernetes_files = filter_container_files(
        [
            str(compose_file),
            str(kubernetes_file),
            str(other_file),
        ]
    )

    assert compose_files == [str(compose_file)]
    assert kubernetes_files == [str(kubernetes_file)]


@pytest.mark.parametrize(
    "value, expected",
    [
        ("120", 120),
        ("600", 600),
        ("1", 1),
        ("0", 300),
        ("-10", 300),
        ("invalid", 300),
        ("", 300),
    ],
)
def test_image_scan_timeout(monkeypatch, value, expected):
    monkeypatch.setenv("CONTAINER_SCAN_TIMEOUT", value)

    result = image_scan_timeout()

    assert result == expected


def test_image_scan_timeout_default(monkeypatch):
    monkeypatch.delenv(
        "CONTAINER_SCAN_TIMEOUT",
        raising=False,
    )

    assert image_scan_timeout() == 300


def test_compose_env_files_default(monkeypatch):
    monkeypatch.delenv(
        "CONTAINER_ENV_FILES",
        raising=False,
    )

    files = compose_env_files()

    assert files == [
        ".env",
        ".env.example",
        ".env.sample",
    ]


def test_compose_env_files_custom(monkeypatch):
    monkeypatch.setenv(
        "CONTAINER_ENV_FILES",
        ".env.production, .env.local",
    )

    files = compose_env_files()

    assert files == [
        ".env.production",
        ".env.local",
    ]


def test_compose_env_files_empty_entries(monkeypatch):
    monkeypatch.setenv(
        "CONTAINER_ENV_FILES",
        ".env,, .env.example, ",
    )

    files = compose_env_files()

    assert files == [
        ".env",
        ".env.example",
    ]


def test_read_env_file_parses_values(tmp_path):
    from scanner import image_utils

    env_file = tmp_path / ".env"
    env_file.write_text(
        "# Example configuration\n"
        "IMAGE_TAG=1.25\n"
        "export APP_NAME=example\n"
        'REGISTRY="docker.io"\n'
        "PORT=8080 # application port\n"
        "INVALID LINE\n",
        encoding="utf-8",
    )

    values = image_utils._read_env_file(str(env_file))

    assert values == {
        "IMAGE_TAG": "1.25",
        "APP_NAME": "example",
        "REGISTRY": "docker.io",
        "PORT": "8080",
    }


def test_read_env_file_missing(tmp_path):
    from scanner import image_utils

    missing_file = tmp_path / "missing.env"

    values = image_utils._read_env_file(str(missing_file))

    assert values == {}


def test_compose_variables_environment_priority(tmp_path, monkeypatch):
    from scanner import image_utils

    compose_file = tmp_path / "compose.yml"
    compose_file.write_text(
        "services:\n"
        "  app:\n"
        "    image: example\n",
        encoding="utf-8",
    )

    env_file = tmp_path / ".env.example"
    env_file.write_text(
        "TEST_IMAGE_VERSION=from-file\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("CONTAINER_ENV_FILES", raising=False)
    monkeypatch.setenv("TEST_IMAGE_VERSION", "from-environment")

    variables, used_files = image_utils.compose_variables(
        str(compose_file),
        str(tmp_path),
    )

    assert variables["TEST_IMAGE_VERSION"] == "from-environment"
    assert str(env_file) in used_files


def test_compose_variables_nearest_file_priority(
    tmp_path,
    monkeypatch,
):
    from scanner import image_utils

    nested_directory = tmp_path / "services"
    nested_directory.mkdir()

    root_env = tmp_path / ".env"
    root_env.write_text(
        "TEST_IMAGE_TAG=root\n",
        encoding="utf-8",
    )

    nested_env = nested_directory / ".env"
    nested_env.write_text(
        "TEST_IMAGE_TAG=nested\n",
        encoding="utf-8",
    )

    compose_file = nested_directory / "compose.yml"
    compose_file.write_text(
        "services:\n"
        "  app:\n"
        "    image: example\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("CONTAINER_ENV_FILES", raising=False)
    monkeypatch.delenv("TEST_IMAGE_TAG", raising=False)

    variables, used_files = image_utils.compose_variables(
        str(compose_file),
        str(tmp_path),
    )

    assert variables["TEST_IMAGE_TAG"] == "nested"
    assert str(root_env) in used_files
    assert str(nested_env) in used_files


@pytest.mark.parametrize(
    "value, variables, expected, unresolved",
    [
        ("nginx:$TAG", {"TAG": "1.25"}, "nginx:1.25", []),
        ("nginx:$TAG", {}, "nginx:$TAG", ["TAG"]),
        ("nginx:${TAG:-latest}", {}, "nginx:latest", []),
        ("nginx:${TAG:-latest}", {"TAG": ""}, "nginx:latest", []),
        ("nginx:${TAG-default}", {"TAG": ""}, "nginx:", []),
        ("nginx:${TAG:+stable}", {"TAG": "1.25"}, "nginx:stable", []),
        ("nginx:${TAG:+stable}", {"TAG": ""}, "nginx:", []),
        ("nginx:${TAG:?required}", {}, "nginx:${TAG:?required}", ["TAG"]),
        ("nginx:$$TAG", {"TAG": "1.25"}, "nginx:$TAG", []),
    ],
)
def test_interpolate_compose_variables(
    value, variables, expected, unresolved
):
    from scanner.image_utils import interpolate

    result, missing = interpolate(value, variables)

    assert result == expected
    assert missing == unresolved


def test_interpolate_nested_default():
    from scanner.image_utils import interpolate

    result, missing = interpolate(
        "nginx:${TAG:-$DEFAULT_TAG}",
        {"DEFAULT_TAG": "stable"},
    )

    assert result == "nginx:stable"
    assert missing == []


def test_unresolved_image_reason():
    from scanner.image_utils import unresolved_image_reason

    reason = unresolved_image_reason(
        "registry.example.com/$REGISTRY_IMAGE:${TAG}"
    )

    assert reason is not None
    assert "${REGISTRY_IMAGE}" in reason
    assert "${TAG}" in reason


def test_unresolved_image_reason_resolved():
    from scanner.image_utils import unresolved_image_reason

    assert unresolved_image_reason("nginx:1.25") is None


def test_extract_images_from_compose(tmp_path, monkeypatch):
    from scanner.image_utils import extract_images_from_compose

    monkeypatch.setenv("TEST_IMAGE_TAG", "1.25")

    compose_file = tmp_path / "compose.yml"
    compose_file.write_text(
        "services:\n"
        "  web:\n"
        "    image: nginx:${TEST_IMAGE_TAG}\n"
        "  api:\n"
        "    image: python:3.9-slim\n",
        encoding="utf-8",
    )

    images = extract_images_from_compose(
        str(compose_file),
        str(tmp_path),
    )

    assert ("nginx:1.25", 3) in images
    assert ("python:3.9-slim", 5) in images
    assert len(images) == 2


def test_extract_images_from_kubernetes(tmp_path):
    from scanner.image_utils import extract_images_from_kubernetes

    manifest = tmp_path / "deployment.yaml"
    manifest.write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: web\n"
        "          image: nginx:1.25\n"
        "        - name: api\n"
        "          image: python:3.9-slim\n",
        encoding="utf-8",
    )

    images = extract_images_from_kubernetes(str(manifest))

    assert ("nginx:1.25", 8) in images
    assert ("python:3.9-slim", 10) in images
    assert len(images) == 2
