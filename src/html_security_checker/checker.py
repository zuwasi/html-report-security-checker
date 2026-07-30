"""Core scanning and reporting functionality."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .patterns import CHECK_DEFINITIONS, CheckDefinition


class Severity(str, Enum):
    """Supported finding severity levels."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    """A security issue detected in an HTML file."""

    check_id: str
    severity: Severity
    file_path: Path
    line_number: int
    matched_text: str
    explanation: str
    fix_suggestion: str


FIX_SUGGESTIONS = {
    "SEC-01": "Remove the secret from the HTML and rotate the exposed credential.",
    "SEC-02": "Do not embed passwords in client-side code; use server-side authentication.",
    "SEC-03": "Remove the outbound call or disclose and restrict it to an approved endpoint.",
    "SEC-04": "Add a valid integrity hash and crossorigin attribute, or bundle the script locally.",
    "SEC-05": "Add a restrictive Content-Security-Policy meta tag or HTTP response header.",
    "SEC-06": "Replace youtube.com with youtube-nocookie.com in the iframe URL.",
    "SEC-07": "Remove prompt text and regenerate the report without internal instructions.",
    "SEC-08": "Add rel=\"noopener noreferrer\" to the link.",
    "SEC-09": "Pin the CDN dependency to an explicit semantic version.",
}


class Checker:
    """Scan HTML files for common report and presentation security risks."""

    def __init__(self) -> None:
        """Load the built-in check definitions."""
        self.check_definitions: list[CheckDefinition] = CHECK_DEFINITIONS

    def check_file(self, file_path: Path) -> list[Finding]:
        """Run all checks against one HTML file."""
        path = Path(file_path)
        content = path.read_text(encoding="utf-8")
        findings: list[Finding] = []

        for definition in self.check_definitions:
            severity = Severity(definition.severity)
            for pattern, explanation in definition.patterns:
                for match in pattern.finditer(content):
                    matched_text = match.group(0).strip()
                    findings.append(
                        Finding(
                            check_id=definition.id,
                            severity=severity,
                            file_path=path,
                            line_number=content.count("\n", 0, match.start()) + 1,
                            matched_text=matched_text[:200],
                            explanation=explanation,
                            fix_suggestion=FIX_SUGGESTIONS[definition.id],
                        )
                    )

        return sorted(findings, key=lambda item: (item.line_number, item.check_id))

    def check_directory(
        self, dir_path: Path, pattern: str = "**/*.html"
    ) -> list[Finding]:
        """Recursively scan matching HTML files in a directory."""
        findings: list[Finding] = []
        for file_path in sorted(Path(dir_path).glob(pattern)):
            if file_path.is_file():
                findings.extend(self.check_file(file_path))
        return findings

    def format_report(self, findings: list[Finding]) -> str:
        """Build a human-readable summary and severity-grouped report."""
        counts = {
            severity: sum(item.severity is severity for item in findings)
            for severity in Severity
        }
        lines = [
            "HTML Report Security Checker",
            "============================",
            (
                f"Summary: {counts[Severity.ERROR]} error(s), "
                f"{counts[Severity.WARNING]} warning(s), "
                f"{counts[Severity.INFO]} info finding(s)"
            ),
        ]
        if not findings:
            lines.extend(["", "No security issues found."])
            return "\n".join(lines)

        for severity in Severity:
            group = [item for item in findings if item.severity is severity]
            if not group:
                continue
            lines.extend(["", f"{severity.value.upper()} ({len(group)})", "-" * 20])
            for finding in group:
                lines.extend(
                    [
                        f"[{finding.check_id}] {finding.file_path}:{finding.line_number}",
                        f"  {finding.explanation}",
                        f"  Match: {finding.matched_text or '(file-level check)'}",
                        f"  Fix: {finding.fix_suggestion}",
                    ]
                )
        return "\n".join(lines)

    def run(self, path: Path, fail_on_warning: bool = False) -> int:
        """Scan a file or directory, print the report, and return an exit code."""
        target = Path(path)
        if target.is_file():
            findings = self.check_file(target)
        elif target.is_dir():
            findings = self.check_directory(target)
        else:
            raise FileNotFoundError(f"Path does not exist: {target}")

        print(self.format_report(findings))
        has_error = any(item.severity is Severity.ERROR for item in findings)
        has_warning = any(item.severity is Severity.WARNING for item in findings)
        return int(has_error or (fail_on_warning and has_warning))


def run_checks(path: str, fail_on_warning: bool = False) -> int:
    """Resolve and scan an HTML file or directory."""
    return Checker().run(Path(path).expanduser().resolve(), fail_on_warning)
