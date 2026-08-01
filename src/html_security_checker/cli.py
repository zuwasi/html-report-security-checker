"""Command-line interface for the HTML security checker."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Optional, Sequence

from html_security_checker import __version__
from html_security_checker.checker import Checker, Finding


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
    parser.add_argument(
        "--gui",
        action="store_true",
        help="launch the web-based GUI in your browser (no scan path needed)",
    )
    parser.add_argument(
        "--gui-port",
        type=int,
        default=0,
        help="port for the GUI server (default: auto-select free port)",
    )
    parser.add_argument(
        "--email",
        metavar="RECIPIENT",
        help="email scan results to RECIPIENT (requires SMTP config)",
    )
    parser.add_argument(
        "--email-test",
        metavar="RECIPIENT",
        help="send a test email to verify SMTP config",
    )
    parser.add_argument(
        "--smtp-host",
        help="SMTP server hostname (overrides config file/env vars)",
    )
    parser.add_argument(
        "--smtp-port",
        type=int,
        help="SMTP server port (overrides config file/env vars)",
    )
    parser.add_argument(
        "--smtp-user",
        help="SMTP username (overrides config file/env vars)",
    )
    parser.add_argument(
        "--smtp-pass",
        help="SMTP password (overrides config file/env vars)",
    )
    parser.add_argument(
        "--smtp-from",
        help="sender email address (overrides config file/env vars)",
    )
    args = parser.parse_args(argv)

    # --gui mode: launch web GUI
    if args.gui:
        from html_security_checker.gui import start_gui
        print("Starting HTML Report Security Checker GUI...")
        start_gui(port=args.gui_port, open_browser=True)
        return 0

    # --email-test mode: send test email
    if args.email_test:
        from html_security_checker.email_alert import EmailAlert, load_config
        config = load_config()
        if config is None:
            print("Error: No email configuration found.")
            print("Configure via environment variables (HSC_SMTP_HOST, HSC_SMTP_USER, etc.)")
            print("or run with --gui to configure through the GUI.")
            return 1
        alert = EmailAlert(config)
        if alert.send_test(args.email_test):
            print(f"Test email sent to {args.email_test}")
            return 0
        else:
            print(f"Failed to send test email to {args.email_test}")
            return 1

    # Normal scan mode
    if args.path is None:
        parser.error("the following arguments are required: path (or use --gui)")

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

    # Send email alert if requested
    if args.email:
        from html_security_checker.email_alert import EmailAlert, load_config, EmailConfig
        config = load_config()
        if config is None:
            print("\nError: No email configuration found. Cannot send alert.")
            print("Configure via --smtp-host, --smtp-user, --smtp-pass, --smtp-from flags")
            print("or environment variables (HSC_SMTP_HOST, etc.) or run --gui.")
            return 1
        # Override with CLI args if provided
        if args.smtp_host:
            config.smtp_host = args.smtp_host
        if args.smtp_port:
            config.smtp_port = args.smtp_port
        if args.smtp_user:
            config.smtp_user = args.smtp_user
        if args.smtp_pass:
            config.smtp_password = args.smtp_pass
        if args.smtp_from:
            config.from_addr = args.smtp_from

        alert = EmailAlert(config)
        if alert.should_alert(findings):
            if alert.send_report(findings, str(target), args.email):
                print(f"\nEmail alert sent to {args.email}")
            else:
                print(f"\nFailed to send email alert to {args.email}")
        else:
            print(f"\nNo errors or warnings found — no email alert sent to {args.email}")

    has_error = any(finding.severity.value == "error" for finding in findings)
    has_warning = any(finding.severity.value == "warning" for finding in findings)
    return int(has_error or (args.fail_on_warning and has_warning))


if __name__ == "__main__":
    raise SystemExit(main())
