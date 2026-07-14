"""Common interface implemented by all security/vulnerability scanners."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ScanResult:
    """Normalized output of a Scanner.scan() call."""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    extra_recommendations: List[str] = field(default_factory=list)
    auth_failed: bool = False


class Scanner(ABC):
    """Common interface for all scanners (Checkov, Grype, Docker Scout, ...)."""

    name: str

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the scanner's underlying tool is installed and available."""

    @abstractmethod
    def scan(self, directory_path: str, files: Optional[List[str]] = None, **options) -> ScanResult:
        """Run the scan and return normalized findings."""
