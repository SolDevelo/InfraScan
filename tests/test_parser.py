
import pytest

from scanner import parser


def test_detect_terraform_framework(tmp_path):
    terraform_file = tmp_path / "main.tf"
    terraform_file.write_text(
        'resource "aws_instance" "example" {}\n',
        encoding="utf-8",
    )

    assert parser.detect_framework(path=str(tmp_path)) == "terraform"
    assert parser.detect_all_frameworks(path=str(tmp_path)) == [
        "terraform"
    ]


def test_detect_kubernetes_framework(tmp_path):
    manifest = tmp_path / "deployment.yaml"
    manifest.write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: example\n",
        encoding="utf-8",
    )

    assert parser.detect_framework(path=str(tmp_path)) == "kubernetes"


def test_detect_multiple_frameworks(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_instance" "example" {}\n',
        encoding="utf-8",
    )

    (tmp_path / "deployment.yaml").write_text(
        "apiVersion: v1\nkind: Pod\n",
        encoding="utf-8",
    )

    assert parser.detect_framework(path=str(tmp_path)) == "all"
    assert set(parser.detect_all_frameworks(path=str(tmp_path))) == {
        "terraform",
        "kubernetes",
    }


def test_detect_framework_empty_directory(tmp_path):
    assert parser.detect_framework(path=str(tmp_path)) == "all"
    assert parser.detect_all_frameworks(path=str(tmp_path)) == ["all"]


def test_count_terraform_resources(tmp_path):
    terraform_file = tmp_path / "main.tf"
    terraform_file.write_text(
        'resource "aws_instance" "web" {}\n'
        'resource "aws_s3_bucket" "storage" {}\n',
        encoding="utf-8",
    )

    assert parser.count_resources(
        path=str(tmp_path),
        framework="terraform",
    ) == 2


def test_count_kubernetes_resources(tmp_path):
    manifest = tmp_path / "resources.yaml"
    manifest.write_text(
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata:\n"
        "  name: settings\n"
        "---\n"
        "apiVersion: v1\n"
        "kind: Service\n"
        "metadata:\n"
        "  name: web\n",
        encoding="utf-8",
    )

    assert parser.count_resources(
        framework="kubernetes",
        files=[str(manifest)],
    ) == 2


def test_count_compose_services(tmp_path):
    compose_file = tmp_path / "compose.yml"
    compose_file.write_text(
        "services:\n"
        "  web:\n"
        "    image: nginx\n"
        "  api:\n"
        "    image: python\n",
        encoding="utf-8",
    )

    assert parser.count_resources(
        framework="containers",
        files=[str(compose_file)],
    ) == 2


def test_resolve_included_paths(tmp_path):
    terraform_file = tmp_path / "main.tf"
    terraform_file.write_text("", encoding="utf-8")

    result = parser.resolve_included_paths(
        str(tmp_path),
        ["main.tf"],
    )

    assert result == [str(terraform_file)]


def test_resolve_included_paths_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        parser.resolve_included_paths(
            str(tmp_path),
            ["missing.tf"],
        )


def test_resolve_included_paths_invalid_extension(tmp_path):
    text_file = tmp_path / "notes.txt"
    text_file.write_text("example", encoding="utf-8")

    with pytest.raises(ValueError):
        parser.resolve_included_paths(
            str(tmp_path),
            ["notes.txt"],
        )


def test_is_root_module_with_resource(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_instance" "web" {}\n',
        encoding="utf-8",
    )

    assert parser.is_root_module(str(tmp_path)) is True


def test_is_root_module_required_providers_only(tmp_path):
    (tmp_path / "versions.tf").write_text(
        'terraform {\n'
        '  required_providers {\n'
        '    aws = {\n'
        '      source = "hashicorp/aws"\n'
        '    }\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )

    assert parser.is_root_module(str(tmp_path)) is False
