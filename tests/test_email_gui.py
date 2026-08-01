"""Tests for email alerts and the browser-based GUI."""

import json
import sys
import threading
from contextlib import contextmanager
from email import message_from_string
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

import pytest

sys.path.insert(0, "src")

from html_security_checker import Checker, Finding, Severity  # noqa: E402
from html_security_checker import __version__  # noqa: E402
from html_security_checker import email_alert  # noqa: E402
from html_security_checker.email_alert import (  # noqa: E402
    EmailAlert,
    EmailConfig,
    load_config,
    save_config,
)
from html_security_checker.gui import (  # noqa: E402
    GUIHandler,
    ThreadingHTTPServer,
    start_gui,
)


SAMPLES_DIR = Path(__file__).parent / "samples"
ENV_VARS = (
    "HSC_SMTP_HOST",
    "HSC_SMTP_PORT",
    "HSC_SMTP_USER",
    "HSC_SMTP_PASS",
    "HSC_SMTP_FROM",
    "HSC_SMTP_TLS",
)


def _finding(severity: Severity = Severity.ERROR) -> Finding:
    """Create a representative finding for email tests."""
    return Finding(
        check_id="SEC-TEST",
        severity=severity,
        file_path=Path("report<script>.html"),
        line_number=12,
        matched_text="<script>alert('x')</script>",
        explanation="Unsafe <script> & content",
        fix_suggestion="Remove the <script>.",
    )


def _config() -> EmailConfig:
    """Create a complete SMTP configuration."""
    return EmailConfig(
        smtp_host="smtp.example.com",
        smtp_port=2525,
        smtp_user="alice",
        smtp_password="secret",
        from_addr="alerts@example.com",
        use_tls=True,
    )


def _start_server() -> tuple[ThreadingHTTPServer, int]:
    """Start a GUI server on an automatically selected localhost port."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), GUIHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server._test_thread = thread  # type: ignore[attr-defined]
    return server, server.server_address[1]


@contextmanager
def _running_server():
    """Run and reliably tear down a GUI test server."""
    server, port = _start_server()
    try:
        yield server, port
    finally:
        server.shutdown()
        server.server_close()
        server._test_thread.join(timeout=2)  # type: ignore[attr-defined]


def _request(port: int, path: str, data=None, headers=None):
    """Issue an HTTP request and return its status, headers, and body."""
    body = None if data is None else json.dumps(data).encode("utf-8")
    request = Request(
        f"http://127.0.0.1:{port}{path}",
        data=body,
        headers=headers or ({"Content-Type": "application/json"} if body else {}),
    )
    try:
        with urlopen(request, timeout=5) as response:
            return response.status, response.headers, response.read()
    except HTTPError as error:
        return error.code, error.headers, error.read()


def _clear_email_env(monkeypatch) -> None:
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def test_email_config_from_env(monkeypatch, tmp_path) -> None:
    """Environment variables populate every email configuration field."""
    monkeypatch.setattr(email_alert, "_CONFIG_PATH", tmp_path / "missing.json")
    values = {
        "HSC_SMTP_HOST": "mail.example.com",
        "HSC_SMTP_PORT": "465",
        "HSC_SMTP_USER": "user",
        "HSC_SMTP_PASS": "pass",
        "HSC_SMTP_FROM": "sender@example.com",
        "HSC_SMTP_TLS": "false",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    assert load_config() == EmailConfig(
        "mail.example.com", 465, "user", "pass", "sender@example.com", False
    )


def test_email_config_no_config_returns_none(monkeypatch, tmp_path) -> None:
    """Absent file and environment configuration produces no config."""
    _clear_email_env(monkeypatch)
    monkeypatch.setattr(email_alert, "_CONFIG_PATH", tmp_path / "missing.json")
    assert load_config() is None


def test_should_alert_with_errors() -> None:
    assert EmailAlert.should_alert([_finding(Severity.ERROR)]) is True


def test_should_alert_clean() -> None:
    assert EmailAlert.should_alert([]) is False


def test_should_alert_only_info() -> None:
    assert EmailAlert.should_alert([_finding(Severity.INFO)]) is False


def test_send_test_mocked() -> None:
    """A test email connects, authenticates, and sends through SMTP."""
    with patch("smtplib.SMTP") as smtp:
        server = smtp.return_value.__enter__.return_value
        assert EmailAlert(_config()).send_test("recipient@example.com") is True

    smtp.assert_called_once_with("smtp.example.com", 2525, timeout=30)
    server.starttls.assert_called_once_with()
    server.login.assert_called_once_with("alice", "secret")
    server.sendmail.assert_called_once()


def test_send_report_mocked() -> None:
    """A report email includes the finding in its MIME content."""
    with patch("smtplib.SMTP") as smtp:
        server = smtp.return_value.__enter__.return_value
        assert EmailAlert(_config()).send_report(
            [_finding()], "report.html", "recipient@example.com"
        ) is True

    sender, recipients, raw_message = server.sendmail.call_args.args
    message = message_from_string(raw_message)
    decoded_parts = "\n".join(
        part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8")
        for part in message.walk()
        if part.get_content_maintype() == "text"
    )
    assert sender == "alerts@example.com"
    assert recipients == ["recipient@example.com"]
    assert "SEC-TEST" in decoded_parts
    assert "report.html" in decoded_parts


def test_send_report_no_alerts() -> None:
    """Informational findings alone do not trigger SMTP activity."""
    with patch("smtplib.SMTP") as smtp:
        result = EmailAlert(_config()).send_report(
            [_finding(Severity.INFO)], "report.html", "recipient@example.com"
        )
    assert result is False
    smtp.assert_not_called()


def test_save_and_load_config(monkeypatch, tmp_path) -> None:
    _clear_email_env(monkeypatch)
    monkeypatch.setattr(email_alert, "_CONFIG_PATH", tmp_path / "email.json")
    save_config(_config())
    assert load_config() == _config()


def test_format_findings_html() -> None:
    output = email_alert.format_findings_html([_finding()])
    assert "SEC-TEST" in output
    assert "Unsafe &lt;script&gt; &amp; content" in output
    assert "Unsafe <script>" not in output


def test_format_findings_text() -> None:
    output = email_alert.format_findings_text([_finding()])
    assert "SEC-TEST" in output
    assert "Unsafe <script> & content" in output
    assert "report<script>.html" in output


def test_gui_version() -> None:
    with _running_server() as (_, port):
        status, _, body = _request(port, "/api/version")
    assert status == 200
    assert json.loads(body)["version"] == __version__


def test_gui_scan_clean() -> None:
    with _running_server() as (_, port):
        status, _, body = _request(port, "/api/scan", {"path": str(SAMPLES_DIR / "clean.html")})
    assert status == 200
    assert json.loads(body)["findings"] == []


def test_gui_scan_vulnerable() -> None:
    with _running_server() as (_, port):
        status, _, body = _request(
            port, "/api/scan", {"path": str(SAMPLES_DIR / "leaked_secrets.html")}
        )
    findings = json.loads(body)["findings"]
    counts = {level: sum(item["severity"] == level for item in findings)
              for level in ("error", "warning", "info")}
    assert status == 200
    assert len(findings) > 0
    assert counts["error"] >= 1
    assert sum(counts.values()) == len(findings)


def test_gui_scan_missing_file(tmp_path) -> None:
    with _running_server() as (_, port):
        status, _, body = _request(port, "/api/scan", {"path": str(tmp_path / "absent.html")})
    assert status == 404
    assert json.loads(body)["error"] == "File not found"


def test_gui_serves_html_page() -> None:
    with _running_server() as (_, port):
        status, headers, body = _request(port, "/")
    assert status == 200
    assert headers.get_content_type() == "text/html"
    assert b"HTML Report Security Checker" in body


def test_gui_localhost_only() -> None:
    with _running_server() as (server, _):
        assert server.server_address[0] == "127.0.0.1"


def test_gui_email_config_save_load(monkeypatch, tmp_path) -> None:
    _clear_email_env(monkeypatch)
    monkeypatch.setattr(email_alert, "_CONFIG_PATH", tmp_path / "email.json")
    config = {
        "host": "smtp.example.com", "port": 2525, "user": "alice",
        "password": "top-secret", "from": "alerts@example.com", "tls": False,
    }
    with _running_server() as (_, port):
        save_status, _, _ = _request(port, "/api/email-config", config)
        get_status, _, body = _request(port, "/api/config")
    returned = json.loads(body)
    assert save_status == get_status == 200
    assert returned == {
        "configured": True, "host": "smtp.example.com", "port": 2525,
        "user": "alice", "from": "alerts@example.com", "tls": False,
    }
    assert "password" not in returned


def test_gui_body_size_limit() -> None:
    request = Request(
        "http://127.0.0.1:{port}/api/scan",
        data=b"{}",
        headers={"Content-Type": "application/json", "Content-Length": str(10 * 1024 * 1024 + 1)},
    )
    with _running_server() as (_, port):
        request.full_url = request.full_url.format(port=port)
        with pytest.raises(HTTPError) as error:
            urlopen(request, timeout=5)
        body = error.value.read()
    assert error.value.code == 413
    assert b"exceeds 10 MB" in body


def test_gui_scan_content() -> None:
    """Verify /api/scan-content scans uploaded HTML content."""
    sample = (SAMPLES_DIR / "leaked_secrets.html").read_text(encoding="utf-8")
    with _running_server() as (_, port):
        status, _, body = _request(port, "/api/scan-content", {
            "filename": "leaked_secrets.html",
            "content": sample,
        })
    data = json.loads(body)
    assert status == 200
    assert len(data["findings"]) > 0
    assert data["findings"][0]["severity"] == "error"


def test_gui_scan_content_empty() -> None:
    """Verify /api/scan-content rejects empty content."""
    with _running_server() as (_, port):
        status, _, body = _request(port, "/api/scan-content", {
            "filename": "empty.html",
            "content": "",
        })
    assert status == 400
    assert json.loads(body)["error"] == "No content provided"


def test_check_content_matches_check_file() -> None:
    """Verify check_content produces the same findings as check_file."""
    sample_path = SAMPLES_DIR / "leaked_secrets.html"
    content = sample_path.read_text(encoding="utf-8")
    file_findings = Checker().check_file(sample_path)
    content_findings = Checker().check_content(content, sample_path)
    assert len(file_findings) == len(content_findings)
    for f, c in zip(file_findings, content_findings):
        assert f.check_id == c.check_id
        assert f.severity is c.severity
        assert f.line_number == c.line_number


def test_gui_file_content() -> None:
    """Verify /api/file-content returns file contents for the editor."""
    sample = SAMPLES_DIR / "leaked_secrets.html"
    with _running_server() as (_, port):
        status, _, body = _request(port, "/api/file-content", {
            "path": str(sample),
        })
    data = json.loads(body)
    assert status == 200
    assert "sk-proj" in data["content"]


def test_gui_file_content_not_found() -> None:
    """Verify /api/file-content returns 404 for missing files."""
    with _running_server() as (_, port):
        status, _, body = _request(port, "/api/file-content", {
            "path": str(SAMPLES_DIR / "nonexistent.html"),
        })
    assert status == 404
    assert json.loads(body)["error"] == "File not found"


def test_gui_file_save(tmp_path) -> None:
    """Verify /api/file-save writes content back to disk."""
    test_file = tmp_path / "editable.html"
    test_file.write_text("<p>original</p>", encoding="utf-8")
    with _running_server() as (_, port):
        status, _, body = _request(port, "/api/file-save", {
            "path": str(test_file),
            "content": "<p>fixed</p>",
        })
    data = json.loads(body)
    assert status == 200
    assert data["ok"] is True
    assert test_file.read_text(encoding="utf-8") == "<p>fixed</p>"


def test_gui_file_save_not_found() -> None:
    """Verify /api/file-save returns 404 for missing files."""
    with _running_server() as (_, port):
        status, _, body = _request(port, "/api/file-save", {
            "path": str(SAMPLES_DIR / "ghost.html"),
            "content": "test",
        })
    assert status == 404


# Keep imports required by the public GUI API contract covered by this module.
assert Checker and start_gui
