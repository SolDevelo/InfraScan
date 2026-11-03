"""Paths left out of a scan (--exclude).

Patterns work like .gitignore entries, relative to the scanned directory:
- without a slash (``tests``, ``*.tftest.hcl``) they match a file or directory
  name at any depth;
- with a slash (``modules/legacy``, ``envs/*/old``) they match the path from
  the scanned directory, and everything under it.
``*`` and ``?`` are glob wildcards.

The active patterns live in a context variable, set with ``excluding()``, so
every directory walk (framework detection, resource counting, the regex rules,
container discovery, cost estimation) honours them without each caller
passing them along.
"""
import contextvars
import fnmatch
import os
import re
from contextlib import contextmanager
from typing import Iterable, List, Optional

_EXCLUDES: contextvars.ContextVar = contextvars.ContextVar("infrascan_excludes", default=())


def normalize_excludes(patterns: Optional[Iterable[str]]) -> List[str]:
    """Split comma-separated values and drop ``./`` prefixes and trailing slashes."""
    result = []
    for value in patterns or ():
        for pattern in str(value).split(","):
            pattern = pattern.strip().replace(os.sep, "/")
            while pattern.startswith("./"):
                pattern = pattern[2:]
            pattern = pattern.strip("/")
            if pattern and pattern not in result:
                result.append(pattern)
    return result


@contextmanager
def excluding(patterns: Optional[Iterable[str]]):
    """Make ``patterns`` the active excludes for the duration of the block."""
    token = _EXCLUDES.set(tuple(normalize_excludes(patterns)))
    try:
        yield
    finally:
        _EXCLUDES.reset(token)


def active_excludes() -> tuple:
    return _EXCLUDES.get()


def is_excluded(rel_path: str, excludes: Optional[Iterable[str]] = None) -> bool:
    """True when ``rel_path`` (relative to the scanned directory) is excluded."""
    excludes = active_excludes() if excludes is None else excludes
    if not excludes or not rel_path:
        return False
    parts = [p for p in rel_path.replace(os.sep, "/").split("/") if p and p != "."]
    for pattern in excludes:
        if "/" in pattern:
            if any(fnmatch.fnmatchcase("/".join(parts[:i]), pattern) for i in range(1, len(parts) + 1)):
                return True
        elif any(fnmatch.fnmatchcase(part, pattern) for part in parts):
            return True
    return False


def walk(path: str):
    """``os.walk`` that skips excluded directories and files."""
    excludes = active_excludes()
    for root, dirs, files in os.walk(path):
        if excludes:
            rel_root = os.path.relpath(root, path)
            rel_root = "" if rel_root == "." else rel_root
            dirs[:] = [d for d in dirs if not is_excluded(os.path.join(rel_root, d), excludes)]
            files = [f for f in files if not is_excluded(os.path.join(rel_root, f), excludes)]
        yield root, dirs, files


def checkov_skip_paths(excludes: Optional[Iterable[str]] = None) -> List[str]:
    """The excludes as regexes for Checkov's ``--skip-path``."""
    excludes = active_excludes() if excludes is None else excludes
    regexes = []
    for pattern in excludes:
        # Checkov rewrites these regexes and chokes on character classes, so
        # wildcards become ".*" / "." -- as with fnmatch, "*" may cross "/".
        body = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
        regexes.append(f"(^|/){body}(/|$)")
    return regexes
