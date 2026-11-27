import pytest

from scanner.paths import (
    normalize_excludes,
    is_excluded,
    excluding,
    active_excludes,
    walk,
    checkov_skip_paths,
)

def test_normalize_excludes():
    result = normalize_excludes(["./tests/", "docs"])
    assert result == ["tests", "docs"]


@pytest.mark.parametrize("path, patterns, result", [
    ("tests/test_logs.py", ["tests"], True),
    ("scanner/logs.py", ["tests"], False),
    ("logs/error.log", ["*.log"], True),
    ("main.py", ["*.log"], False),
    ("modules/legacy/main.tf", ["modules/legacy"], True),
    ("modules/new/main.tf", ["modules/legacy"], False)
])
def test_is_excluded(path, patterns, result):
    assert is_excluded(path, patterns) == result


@pytest.mark.parametrize("patterns, expected", [
    (["./tests/", "docs"], ["tests", "docs"]),
    (["tests", "tests"], ["tests"]),
    ([" ./tests/ ", "docs,*.log"], ["tests", "docs", "*.log"]),
    (["", "docs", ""], ["docs"]),
])
def test_normalize_excludes_multiple(patterns, expected):
    result = normalize_excludes(patterns)

    assert result == expected


@pytest.mark.parametrize("path, patterns, expected", [
    ("logs/error.log", ["*.log"], True),
    ("logs/error.txt", ["*.log"], False),
    ("modules/legacy/main.tf", ["modules/legacy"], True),
    ("modules/new/main.tf", ["modules/legacy"], False),
    ("docs/readme.md", ["docs"], True),
    ("scanner/parser.py", ["docs"], False),
])
def test_exclude_patterns_multiple(path, patterns, expected):
    result = is_excluded(path, patterns)

    assert result == expected


def test_excluding_context_manager():
    original_excludes = active_excludes()

    with excluding(["tests", "docs"]):
        assert active_excludes() == ("tests", "docs")
        assert is_excluded("tests/test_grading.py") is True
        assert is_excluded("scanner/parser.py") is False

    assert active_excludes() == original_excludes


def test_walk_finds_files(tmp_path):
    (tmp_path / "main.tf").write_text("terraform", encoding="utf-8")

    modules = tmp_path / "modules"
    modules.mkdir()

    (modules / "network.tf").write_text("terraform", encoding="utf-8")

    with excluding([]):
        results = list(walk(str(tmp_path)))

    found_files = [
        file
        for root, dirs, files in results
        for file in files
    ]

    assert "main.tf" in found_files
    assert "network.tf" in found_files


def test_walk_excludes_directory(tmp_path):
    (tmp_path / "main.tf").write_text("terraform", encoding="utf-8")

    excluded = tmp_path / "excluded"
    excluded.mkdir()

    (excluded / "secret.tf").write_text("terraform", encoding="utf-8")

    with excluding(["excluded"]):
        results = list(walk(str(tmp_path)))

    found_files = [
        file
        for root, dirs, files in results
        for file in files
    ]

    assert "main.tf" in found_files
    assert "secret.tf" not in found_files


def test_walk_excludes_files_by_pattern(tmp_path):
    (tmp_path / "main.tf").write_text("terraform", encoding="utf-8")
    (tmp_path / "debug.log").write_text("log", encoding="utf-8")

    with excluding(["*.log"]):
        results = list(walk(str(tmp_path)))

    found_files = [
        file
        for root, dirs, files in results
        for file in files
    ]

    assert "main.tf" in found_files
    assert "debug.log" not in found_files


def test_checkov_skip_paths():
    result = checkov_skip_paths(["tests", "*.log"])

    assert result == [
        "(^|/)tests(/|$)",
        "(^|/).*\\.log(/|$)"
    ]


def test_checkov_skip_paths_empty():
    result = checkov_skip_paths([])

    assert result == []
