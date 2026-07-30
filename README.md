# HTML Report Security Checker

> 🔒 **Scan AI-generated HTML for secrets, tracking, prompt leakage, and unsafe dependencies — before it reaches the client's browser.**

## Why?

AI tools such as Claude and ChatGPT can generate polished, interactive HTML reports and presentations in seconds. But unlike a PDF, an HTML file is executable content: it can contain JavaScript that runs in the client's browser, communicate with external servers, track viewers, and expose prompts, credentials, or sensitive business logic hidden in the source.

In July 2026, Amit Tannenbaum raised this concern on LinkedIn. **HTML Report Security Checker** is the answer: a focused, automated safety gate for AI-generated HTML before publication or client delivery.

Built by the [Engineering Software Lab (ESL)](https://eswlab.com), the checker is used in production to protect **74+ AI-generated HTML presentations** published at [Public HTML Pages](https://zuwasi.github.io/Public-html-pages/).

📖 See the presentation that explains the full story:  
https://zuwasi.github.io/Public-html-pages/answer-to-tannenbaum-concern.html

## The 9 Security Checks

| ID | Check | Severity | What it catches |
|----|-------|----------|-----------------|
| SEC-01 | Secrets in comments | ❌ Error | API keys (`sk-`, `AKIA`, `ghp_`), private keys, passwords in HTML comments |
| SEC-02 | Hardcoded passwords | ❌ Error | Password comparisons and assignments in JavaScript |
| SEC-03 | Tracking & network calls | ⚠️ Warning | Analytics scripts, `fetch()` to external URLs, `sendBeacon()` |
| SEC-04 | Missing SRI | ⚠️ Warning | External script tags without Subresource Integrity |
| SEC-05 | Missing CSP | ℹ️ Info | No Content-Security-Policy meta tag |
| SEC-06 | YouTube embeds | ⚠️ Warning | YouTube iframes without privacy mode (`youtube-nocookie.com`) |
| SEC-07 | AI prompt leakage | ❌ Error | Leaked system prompts, "You are a...", instruction patterns |
| SEC-08 | Unsafe `_blank` links | ℹ️ Info | `target="_blank"` without `rel="noopener noreferrer"` |
| SEC-09 | Unversioned CDN | ⚠️ Warning | CDN script URLs without version pinning |

## Installation

### From PyPI (future)

```bash
pip install html-report-security-checker
```

### From source

```bash
git clone https://github.com/zuwasi/html-report-security-checker.git
cd html-report-security-checker
pip install -e .
```

## Usage

### Scan a single file

```bash
html-security-checker path/to/report.html
```

### Scan a directory

```bash
html-security-checker path/to/html/files/
```

### Fail on warnings (for CI)

```bash
html-security-checker path/to/reports/ --fail-on-warning
```

### Quiet mode (summary only)

```bash
html-security-checker path/to/reports/ --quiet
```

### As a Python module

```python
from html_security_checker import Checker

checker = Checker()
findings = checker.check_file("report.html")
print(checker.format_report(findings))
```

## Git Hooks (Automated Enforcement)

### Install hooks in your repo

```bash
# Linux/Mac
./install.sh

# Windows
.\install.ps1
```

This installs:

- **pre-commit**: scans staged `.html` files (fast, only changed files)
- **pre-push**: performs a full repository scan with `--fail-on-warning`

### What the hooks do

When you run `git commit` or `git push`, the hooks automatically run the security checker on your HTML files. If any errors are found, the commit or push is blocked—preventing unsafe reports from being published accidentally. ✅

## GitHub Actions CI

Copy this minimal workflow into `.github/workflows/security.yml`:

```yaml
name: HTML Security Check
on: [push, pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install html-report-security-checker
      - run: html-security-checker . --fail-on-warning
```

## Output Example

```text
=== HTML Report Security Check ===
Target: report.html

=== Results ===
  Errors:   2
  Warnings: 1
  Info:     1

--- ERRORS (2) ---
  [SEC-01] Secrets in comments
       Line 15: <!-- API key: sk-proj-abc123... -->
       Fix:  Remove secrets from HTML comments

  [SEC-07] AI prompt leakage
       Line 42: <!-- You are a helpful assistant... -->
       Fix:  Remove AI system prompts from the HTML

--- WARNINGS (1) ---
  [SEC-03] Tracking and outbound network calls
       Line 28: fetch("https://api.analytics.com/track...")
       Fix:  Remove or document tracking calls

--- INFO (1) ---
  [SEC-05] Missing Content-Security-Policy
       Fix:  Add a CSP meta tag with restrictive directives

[FAIL] 2 error(s) found.
```

## Testing

```bash
pip install -e . pytest
pytest -v
```

The test suite includes **10 sample HTML files with known vulnerabilities**, covering all 9 security checks.

## Contributing

Contributions are welcome! Please:

1. Fork the repository.
2. Create a feature branch.
3. Add tests for new checks.
4. Run `pytest -v` before submitting a pull request.

## License

MIT — see [LICENSE](LICENSE).

## Links

- **Live demo presentation**: https://zuwasi.github.io/Public-html-pages/answer-to-tannenbaum-concern.html
- **Production use**: https://zuwasi.github.io/Public-html-pages/ (74+ HTML files checked)
- **Author**: Engineering Software Lab — https://eswlab.com

## Acknowledgments

Inspired by [Amit Tannenbaum](https://www.linkedin.com/)'s LinkedIn post about the security risks of AI-generated HTML reports (July 2026).
