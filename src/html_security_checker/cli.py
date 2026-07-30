"""Command-line interface for the HTML security checker."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Optional, Sequence

from html_security_checker import __version__
from html_security_checker.checker import Checker, Finding, run_checks


def _summary(checker: Checker, findings: List[Finding]) -> str:
    """Return only the summary portion of a formatted report."""
    return "\n".join(checker.format_report(findings).splitlines()[:3])


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Parse command-line arguments, run checks, and return a process status."""
    parser = argparse.ArgumentParser(
        description="Scan HTML reports and presentations for security risks."
    )
    parser.add_argument("path", nargs="?", help="HTML file or directory to scan")
    parser.add_argument(
        "-w",
        "--fail-on-warning",
        action="store_true",
        help="return a failure status when warnings are found",
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="print only the report summary"
    )
    args = parser.parse_args(argv)

    if args.path is None:
        parser.error("the following arguments are required: path")

    target = Path(args.path).expanduser().resolve()
    if not target.exists():
        parser.error(f"path does not exist: {target}")

    checker = Checker()
    findings = (
        checker.check_file(target)
        if target.is_file()
        else checker.check_directory(target)
    )
    print(_summary(checker, findings) if args.quiet else checker.format_report(findings))
    has_error = any(finding.severity.value == "error" for finding in findings)
    has_warning = any(finding.severity.value == "warning" for finding in findings)
    return int(has_error or (args.fail_on_warning and has_warning))


if __name__ == "__main__":
    raise SystemExit(main())
