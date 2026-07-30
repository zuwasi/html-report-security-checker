"""Tests for the HTML security checker package."""

import sys
from pathlib import Path

sys.path.insert(0, "src")

from html_security_checker import Checker, Finding, Severity  # noqa: E402


SAMPLES_DIR = Path(__file__).parent / "samples"


def _findings_for(sample_name: str) -> list[Finding]:
    """Scan one HTML sample and return its findings."""
    return Checker().check_file(SAMPLES_DIR / sample_name)


def _assert_finding(
    sample_name: str, check_id: str, severity: Severity
) -> None:
    """Assert that a sample produces the expected check and severity."""
    findings = _findings_for(sample_name)
    assert any(
        finding.check_id == check_id and finding.severity is severity
        for finding in findings
    )


def test_clean_file_no_findings() -> None:
    """Verify that the clean sample produces no findings."""
    assert _findings_for("clean.html") == []


def test_sec01_leaked_secrets() -> None:
    """Verify that leaked secrets are reported as SEC-01 errors."""
    _assert_finding("leaked_secrets.html", "SEC-01", Severity.ERROR)


def test_sec02_hardcoded_password() -> None:
    """Verify that hardcoded passwords are reported as SEC-02 errors."""
    _assert_finding("hardcoded_password.html", "SEC-02", Severity.ERROR)


def test_sec03_tracking() -> None:
    """Verify that tracking is reported as an SEC-03 warning."""
    _assert_finding("tracking.html", "SEC-03", Severity.WARNING)


def test_sec04_missing_sri() -> None:
    """Verify that missing SRI is reported as an SEC-04 warning."""
    _assert_finding("missing_sri.html", "SEC-04", Severity.WARNING)


def test_sec05_missing_csp() -> None:
    """Verify that a missing CSP is reported as SEC-05 information."""
    _assert_finding("missing_csp.html", "SEC-05", Severity.INFO)


def test_sec06_youtube_embed() -> None:
    """Verify that YouTube embeds are reported as SEC-06 warnings."""
    _assert_finding("youtube_embed.html", "SEC-06", Severity.WARNING)


def test_sec07_leaked_prompt() -> None:
    """Verify that leaked prompts are reported as SEC-07 errors."""
    _assert_finding("leaked_prompt.html", "SEC-07", Severity.ERROR)


def test_sec08_unsafe_blank() -> None:
    """Verify that unsafe blank links are reported as SEC-08 information."""
    _assert_finding("unsafe_blank.html", "SEC-08", Severity.INFO)


def test_sec09_unversioned_cdn() -> None:
    """Verify that unversioned CDN links are reported as SEC-09 warnings."""
    _assert_finding("unversioned_cdn.html", "SEC-09", Severity.WARNING)


def test_directory_scan() -> None:
    """Verify that scanning the samples directory finds multiple files."""
    findings = Checker().check_directory(SAMPLES_DIR)
    finding_files = {finding.file_path for finding in findings}

    assert len(finding_files) > 1
    assert SAMPLES_DIR / "leaked_secrets.html" in finding_files
    assert SAMPLES_DIR / "tracking.html" in finding_files


def test_format_report() -> None:
    """Verify that the report includes error, warning, and info counts."""
    report = Checker().format_report(Checker().check_directory(SAMPLES_DIR))

    assert "error(s)" in report
    assert "warning(s)" in report
    assert "info finding(s)" in report


def test_run_exit_code_clean() -> None:
    """Verify that running the checker on clean HTML succeeds."""
    assert Checker().run(SAMPLES_DIR / "clean.html", False) == 0


def test_run_exit_code_with_errors() -> None:
    """Verify that running the checker on HTML with errors fails."""
    assert Checker().run(SAMPLES_DIR / "leaked_secrets.html", False) == 1


def test_finding_has_line_number() -> None:
    """Verify that detected findings include a positive line number."""
    findings = _findings_for("leaked_secrets.html")

    assert findings
    assert all(finding.line_number > 0 for finding in findings)


def test_finding_has_fix_suggestion() -> None:
    """Verify that detected findings include a non-empty fix suggestion."""
    findings = _findings_for("leaked_secrets.html")

    assert findings
    assert all(finding.fix_suggestion.strip() for finding in findings)
