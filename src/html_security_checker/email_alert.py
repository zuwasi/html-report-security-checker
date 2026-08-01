"""Email alert support for HTML Report Security Checker."""
from __future__ import annotations

import json
import os
import smtplib
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

_CONFIG_PATH = Path.home() / ".html-security-checker" / "email.json"
_COLORS = {"error": "#c62828", "warning": "#ef6c00", "info": "#1565c0"}


@dataclass
class EmailConfig:
    """SMTP configuration for email alerts."""
    smtp_host: str
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    from_addr: str = ""
    use_tls: bool = True


def _bool(value: object) -> bool:
    """Parse a boolean configuration value."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"0", "false", "no", "off"}


def load_config() -> EmailConfig | None:
    """Load configuration from the user file, overridden by environment values."""
    data: dict = {}
    try:
        if _CONFIG_PATH.is_file():
            loaded = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data.update(loaded)
    except (OSError, TypeError, ValueError):
        data = {}
    env = {
        "smtp_host": os.environ.get("HSC_SMTP_HOST"),
        "smtp_port": os.environ.get("HSC_SMTP_PORT"),
        "smtp_user": os.environ.get("HSC_SMTP_USER"),
        "smtp_password": os.environ.get("HSC_SMTP_PASS"),
        "from_addr": os.environ.get("HSC_SMTP_FROM"),
        "use_tls": os.environ.get("HSC_SMTP_TLS"),
    }
    data.update({key: value for key, value in env.items() if value is not None})
    if not data:
        return None
    try:
        return EmailConfig(
            smtp_host=str(data.get("smtp_host", "")),
            smtp_port=int(data.get("smtp_port", 587)),
            smtp_user=str(data.get("smtp_user", "")),
            smtp_password=str(data.get("smtp_password", "")),
            from_addr=str(data.get("from_addr", "")),
            use_tls=_bool(data.get("use_tls", True)),
        )
    except (TypeError, ValueError):
        return None


def save_config(config: EmailConfig) -> None:
    """Save configuration to the user's checker configuration file."""
    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "smtp_host": config.smtp_host, "smtp_port": config.smtp_port,
        "smtp_user": config.smtp_user, "smtp_password": config.smtp_password,
        "from_addr": config.from_addr, "use_tls": config.use_tls,
    }
    _CONFIG_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _get(finding: object, name: str, fallback: object = "") -> object:
    """Read a field from a finding object or mapping."""
    if isinstance(finding, dict):
        return finding.get(name, fallback)
    return getattr(finding, name, fallback)


def _severity(finding: object) -> str:
    """Return a finding's normalized severity."""
    severity = _get(finding, "severity")
    return str(getattr(severity, "value", severity)).lower()


def _escape(value: object) -> str:
    """Escape a value for insertion into HTML."""
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;")
            .replace("'", "&#x27;"))


def _fields(finding: object) -> tuple:
    """Extract the six displayed fields from a finding."""
    return (
        _get(finding, "check_id"), _severity(finding).upper(),
        _get(finding, "file_path", _get(finding, "file")),
        _get(finding, "line_number", _get(finding, "line")),
        _get(finding, "explanation", _get(finding, "description")),
        _get(finding, "fix_suggestion", _get(finding, "fix")),
    )


def format_findings_html(findings: list) -> str:
    """Format findings as an HTML table."""
    headers = ("Check ID", "Severity", "File", "Line", "Description", "Fix")
    head = "".join(f'<th style="padding:8px;border:1px solid #ddd">{h}</th>'
                   for h in headers)
    rows = []
    for finding in findings:
        color = _COLORS.get(_severity(finding), _COLORS["info"])
        cells = []
        for index, value in enumerate(_fields(finding)):
            emphasis = f"color:{color};font-weight:bold;" if index == 1 else ""
            cells.append(f'<td style="padding:8px;border:1px solid #ddd;{emphasis}">'
                         f'{_escape(value)}</td>')
        rows.append("<tr>" + "".join(cells) + "</tr>")
    body = "".join(rows) or '<tr><td colspan="6">No findings.</td></tr>'
    return (f'<table style="border-collapse:collapse;width:100%"><thead '
            f'style="background:#f2f2f2"><tr>{head}</tr></thead>'
            f'<tbody>{body}</tbody></table>')


def format_findings_text(findings: list) -> str:
    """Format findings as a plain-text table."""
    rows = [("Check ID", "Severity", "File", "Line", "Description", "Fix")]
    rows.extend(tuple(str(value).replace("\n", " ") for value in _fields(item))
                for item in findings)
    widths = [max(len(row[i]) for row in rows) for i in range(6)]
    lines = [" | ".join(value.ljust(widths[i]) for i, value in enumerate(row))
             for row in rows]
    lines.insert(1, "-+-".join("-" * width for width in widths))
    return "\n".join(lines)


class EmailAlert:
    """Send test messages and security finding reports over SMTP."""
    def __init__(self, config: EmailConfig):
        """Create an alert sender using *config*."""
        self.config = config

    @staticmethod
    def should_alert(findings: list) -> bool:
        """Return True when findings include an error or warning."""
        return any(_severity(item) in {"error", "warning"} for item in findings)

    def _send(self, recipient: str, subject: str, text: str, html: str) -> bool:
        """Send one multipart message without propagating SMTP failures."""
        message = MIMEMultipart("alternative")
        message["Subject"], message["From"], message["To"] = (
            subject, self.config.from_addr, recipient)
        message.attach(MIMEText(text, "plain", "utf-8"))
        message.attach(MIMEText(html, "html", "utf-8"))
        try:
            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port,
                              timeout=30) as server:
                if self.config.use_tls:
                    server.starttls()
                if self.config.smtp_user:
                    server.login(self.config.smtp_user, self.config.smtp_password)
                server.sendmail(self.config.from_addr, [recipient],
                                message.as_string())
            return True
        except Exception:
            return False

    def send_report(self, findings: list, scan_target: str,
                    recipient: str) -> bool:
        """Send a report if the scan contains an error or warning."""
        if not self.should_alert(findings):
            return False
        counts = {level: sum(_severity(item) == level for item in findings)
                  for level in ("error", "warning", "info")}
        subject = (f"[HTML Security] {counts['error']} errors, "
                   f"{counts['warning']} warnings in {scan_target}")
        summary = (f"Errors: {counts['error']} | Warnings: {counts['warning']} | "
                   f"Info: {counts['info']}")
        footer = ("Generated by HTML Report Security Checker â€” "
                  "https://github.com/zuwasi/html-report-security-checker")
        text = (f"{subject}\n\n{summary}\n\n{format_findings_text(findings)}"
                f"\n\n{footer}")
        html = (f'<html><body style="font-family:Arial,sans-serif;color:#222">'
                f'<h2>{_escape(subject)}</h2><div style="padding:12px;'
                f'background:#f5f5f5;margin-bottom:16px">'
                f'<b style="color:#c62828">Errors: {counts["error"]}</b> | '
                f'<b style="color:#ef6c00">Warnings: {counts["warning"]}</b> | '
                f'<b style="color:#1565c0">Info: {counts["info"]}</b></div>'
                f'{format_findings_html(findings)}<p style="color:#666;'
                f'font-size:12px">{footer}</p></body></html>')
        return self._send(recipient, subject, text, html)

    def send_test(self, recipient: str) -> bool:
        """Send a test message to verify the SMTP configuration."""
        subject = "[HTML Security] Test email"
        text = "HTML Report Security Checker email configuration is working."
        html = f"<html><body><h2>Email configuration test</h2><p>{text}</p></body></html>"
        return self._send(recipient, subject, text, html)
