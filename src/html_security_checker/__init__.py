"""HTML Report Security Checker - scan AI-generated HTML for security risks."""

from ._version import __version__
from .checker import Checker, Finding, Severity, run_checks

__all__ = [
    "Checker",
    "Finding",
    "Severity",
    "run_checks",
    "__version__",
]
