"""HTML Report Security Checker — scan AI-generated HTML for security risks."""

from .checker import Checker, Finding, Severity, run_checks

__version__ = "1.0.0"
__all__ = ["Checker", "Finding", "Severity", "run_checks"]
